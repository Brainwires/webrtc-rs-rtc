//! A search of the whole process for a set of needles, Linux only: every readable and writable
//! mapping of `/proc/self/maps`, read through `/proc/self/mem`.
//!
//! Nothing is skipped silently. A page that cannot be read (a guard page made with
//! `MADV_GUARD_INSTALL`, which is no mapping of its own; a mapping that went away) is counted
//! per mapping and reported ([`Scan::unreadable`]); what the caller leaves out, it leaves out
//! by exact address range ([`scan`]'s `exclude`), never by whole mapping: `/proc/self/maps`
//! shows neighbouring anonymous mappings as one, so "the mapping holding this address" can be
//! several thread stacks and more.

#![allow(dead_code)]

use std::fs::File;
use std::ops::Range;
use std::os::unix::fs::FileExt;

use super::key_material::{Finder, MAX_NEEDLE, Needle};

/// One line of `/proc/self/maps`.
#[derive(Clone, Debug)]
pub struct Region {
    pub start: usize,
    pub end: usize,
    pub perms: String,
    /// The path or `[name]` of the mapping; empty for an anonymous one.
    pub name: String,
}

impl Region {
    pub fn describe(&self) -> String {
        let name = if self.name.is_empty() {
            // A heap of a glibc malloc arena other than the main one is aligned to its
            // maximum size, 64 MiB (HEAP_MAX_SIZE with 8-byte pointers).
            if self.start.is_multiple_of(64 << 20) {
                "anonymous, 64 MiB-aligned (a malloc arena's heap)"
            } else {
                "anonymous"
            }
        } else {
            &self.name
        };
        format!(
            "{name} {:#x}-{:#x} {} ({} KiB)",
            self.start,
            self.end,
            self.perms,
            (self.end - self.start) / 1024
        )
    }
}

/// Every mapping of the process, in address order.
pub fn regions() -> Vec<Region> {
    let maps = std::fs::read_to_string("/proc/self/maps").expect("/proc/self/maps");
    maps.lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let range = fields.next().expect("a range");
            let perms = fields.next().expect("permissions").to_owned();
            let name = fields.nth(3).unwrap_or("").to_owned();
            let (start, end) = range.split_once('-').expect("start-end");
            Region {
                start: usize::from_str_radix(start, 16).expect("a start address"),
                end: usize::from_str_radix(end, 16).expect("an end address"),
                perms,
                name,
            }
        })
        .collect()
}

pub fn page_size() -> usize {
    // SAFETY: sysconf with a valid name has no preconditions.
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(size).expect("a page size")
}

/// The stack of the calling thread, as the C library reports it (`pthread_getattr_np`): the
/// whole block, guard included.
pub fn own_thread_stack() -> Range<usize> {
    // SAFETY: the attribute object is filled by `pthread_getattr_np` for the calling thread
    // and destroyed after its two fields are read.
    unsafe {
        let mut attributes = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
        assert_eq!(
            0,
            libc::pthread_getattr_np(libc::pthread_self(), attributes.as_mut_ptr()),
            "pthread_getattr_np"
        );
        let mut address = std::ptr::null_mut();
        let mut size = 0;
        assert_eq!(
            0,
            libc::pthread_attr_getstack(attributes.as_ptr(), &mut address, &mut size)
        );
        libc::pthread_attr_destroy(attributes.as_mut_ptr());
        address as usize..address as usize + size
    }
}

/// One needle at one address.
#[derive(Clone, Copy, Debug)]
pub struct Hit {
    pub needle: usize,
    pub address: usize,
    /// The index in [`Scan::regions`] of the mapping holding it.
    pub region: usize,
}

pub struct Scan {
    pub regions: Vec<Region>,
    pub hits: Vec<Hit>,
    /// Mappings with pages that could not be read: the index in `regions` and the number of
    /// pages.
    pub unreadable: Vec<(usize, usize)>,
    /// How many bytes were read and searched.
    pub searched: usize,
}

impl Scan {
    /// The unreadable pages, one line per mapping.
    pub fn unreadable_lines(&self) -> Vec<String> {
        self.unreadable
            .iter()
            .map(|&(region, pages)| {
                format!(
                    "{pages} unreadable pages in {}",
                    self.regions[region].describe()
                )
            })
            .collect()
    }

    /// How many pages could not be read inside `range`'s mappings.
    pub fn unreadable_in(&self, range: &Range<usize>) -> usize {
        self.unreadable
            .iter()
            .filter(|&&(region, _)| {
                let region = &self.regions[region];
                region.start < range.end && range.start < region.end
            })
            .map(|&(_, pages)| pages)
            .sum()
    }
}

/// Searches every readable and writable mapping for `needles`. A needle that starts inside one
/// of the `exclude` ranges is not reported; the search's own buffer is left out too.
pub fn scan(needles: &[Needle], exclude: &[Range<usize>]) -> Scan {
    const CHUNK: usize = 1 << 20;
    const CARRY: usize = MAX_NEEDLE;
    let finder = Finder::new(needles);
    let page = page_size();
    let mem = File::open("/proc/self/mem").expect("/proc/self/mem");
    let mut buffer = vec![0u8; CARRY + CHUNK];
    let own = buffer.as_ptr() as usize..buffer.as_ptr() as usize + buffer.len();
    let regions = regions();
    let mut hits = Vec::new();
    let mut unreadable = Vec::new();
    let mut searched = 0;
    for (r, region) in regions.iter().enumerate() {
        if !region.perms.starts_with("rw") {
            continue;
        }
        let mut lost = 0;
        // How many bytes before `at` are still in the buffer, in front of the chunk: a needle
        // may straddle two chunks.
        let mut carried = 0;
        let mut at = region.start;
        while at < region.end {
            let len = (region.end - at).min(CHUNK);
            let chunk = &mut buffer[CARRY..CARRY + len];
            if mem.read_exact_at(chunk, at as u64).is_err() {
                for (p, part) in chunk.chunks_mut(page).enumerate() {
                    if mem.read_exact_at(part, (at + p * page) as u64).is_err() {
                        part.fill(0);
                        lost += 1;
                    }
                }
            }
            searched += len;
            let window = &buffer[CARRY - carried..CARRY + len];
            let window_start = at - carried;
            finder.each(window, |needle, offset| {
                // Reported with the chunk before this one.
                if offset + needles[needle].len() <= carried {
                    return;
                }
                let address = window_start + offset;
                if own.contains(&address) || exclude.iter().any(|range| range.contains(&address)) {
                    return;
                }
                hits.push(Hit {
                    needle,
                    address,
                    region: r,
                });
            });
            let keep = (carried + len).min(CARRY);
            buffer.copy_within(CARRY + len - keep..CARRY + len, CARRY - keep);
            carried = keep;
            at += len;
        }
        if lost > 0 {
            unreadable.push((r, lost));
        }
    }
    // The buffer held a copy of everything searched.
    buffer.fill(0);
    std::hint::black_box(&mut buffer);
    Scan {
        regions,
        hits,
        unreadable,
        searched,
    }
}
