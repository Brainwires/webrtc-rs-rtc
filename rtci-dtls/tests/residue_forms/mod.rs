//! What the DTLS key residue measurement (`key_residue.rs`) looks for: every secret a DTLS
//! association derives, in every form an implementation holds or computes on the way to a
//! keyed object.
//!
//! The secrets themselves come from the recording provider of `key_residue.rs` (what crossed
//! the provider boundary) and from recomputing the PRF and HKDF outputs with the provider's
//! own HMAC. This module turns each into its forms: an AES key into its round keys, the round
//! keys of the equivalent inverse cipher and, for AES-GCM, the GHASH key in the forms a table
//! set-up keeps it; an HMAC key into its padded key blocks and the SHA-1 / SHA-256 states
//! after them. The AES (FIPS-197), SHA-1 and SHA-256 (FIPS 180-4) here are the test's own,
//! checked against their standards' vectors (`check_local_primitives`), not the code under
//! test. The AES and SHA-1 parts are the ones of `rtci-srtp/tests/key_material`, whose needle
//! forms that measurement validated (the GHASH `H*x` entry was found in ring's key object).
//!
//! A needle is kept only inverted (each byte complemented), so the test's own copy never
//! matches a search; the plain bytes exist only in stack arrays of the function computing
//! them, which runs on a scratch worker whose stack is overwritten and unmapped afterwards.

#![allow(dead_code)]

/// The longest needle: a DTLS 1.2 master secret is 48 bytes, an HMAC-SHA-256 key up to 64.
pub const MAX_NEEDLE: usize = 64;

/// One byte string to look for, kept inverted.
#[derive(Clone, Copy)]
pub struct Needle {
    /// Which secret it comes from ("the AEAD key", "the PRF \"master secret\" key", ...).
    pub key: &'static str,
    /// Which form of it ("the key", "round key 3", "HMAC inner state", ...).
    pub form: &'static str,
    len: usize,
    inverted: [u8; MAX_NEEDLE],
}

impl Needle {
    /// A needle from plain bytes (at most [`MAX_NEEDLE`] are kept). The key name is leaked: a
    /// test makes a few thousand of them.
    pub fn plain(key: &str, form: &'static str, bytes: &[u8]) -> Self {
        let len = bytes.len().min(MAX_NEEDLE);
        let mut inverted = [0u8; MAX_NEEDLE];
        for (dst, src) in inverted.iter_mut().zip(&bytes[..len]) {
            *dst = !src;
        }
        Self {
            key: Box::leak(key.to_owned().into_boxed_str()),
            form,
            len,
            inverted,
        }
    }

    /// A needle from bytes already inverted.
    pub fn from_inverted(key: &str, form: &'static str, inverted_bytes: &[u8]) -> Self {
        let len = inverted_bytes.len().min(MAX_NEEDLE);
        let mut inverted = [0u8; MAX_NEEDLE];
        inverted[..len].copy_from_slice(&inverted_bytes[..len]);
        Self {
            key: Box::leak(key.to_owned().into_boxed_str()),
            form,
            len,
            inverted,
        }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    /// The needle's bytes, inverted.
    pub fn inverted(&self) -> &[u8] {
        &self.inverted[..self.len]
    }

    /// Whether `haystack` starts with the needle.
    pub fn starts(&self, haystack: &[u8]) -> bool {
        haystack.len() >= self.len
            && haystack[..self.len]
                .iter()
                .zip(&self.inverted[..self.len])
                .all(|(h, n)| *h == !*n)
    }

    /// The first two bytes, for a prefilter.
    pub fn prefix(&self) -> u16 {
        u16::from_le_bytes([!self.inverted[0], !self.inverted[1]])
    }

    pub fn describe(&self) -> String {
        format!("{} ({}, {} bytes)", self.form, self.key, self.len)
    }
}

/// Finds every needle of a set in a byte string: each position is looked up by its first two
/// bytes.
pub struct Finder<'a> {
    needles: &'a [Needle],
    by_prefix: Vec<Vec<u32>>,
}

impl<'a> Finder<'a> {
    pub fn new(needles: &'a [Needle]) -> Self {
        let mut by_prefix = vec![Vec::new(); 1 << 16];
        for (n, needle) in needles.iter().enumerate() {
            assert!(needle.len() >= 2, "a needle of {} bytes", needle.len());
            by_prefix[needle.prefix() as usize].push(n as u32);
        }
        Self { needles, by_prefix }
    }

    /// Calls `found(needle, offset)` for every needle at every offset of `haystack` it is at.
    pub fn each(&self, haystack: &[u8], mut found: impl FnMut(usize, usize)) {
        for i in 0..haystack.len().saturating_sub(1) {
            let prefix = u16::from_le_bytes([haystack[i], haystack[i + 1]]);
            for &n in &self.by_prefix[prefix as usize] {
                if self.needles[n as usize].starts(&haystack[i..]) {
                    found(n as usize, i);
                }
            }
        }
    }
}

/// Overwrites `bytes` so that the compiler cannot drop the stores.
pub fn wipe(bytes: &mut [u8]) {
    for b in bytes.iter_mut() {
        // SAFETY: `b` is a valid, aligned, exclusive reference.
        unsafe { std::ptr::write_volatile(b, 0) };
    }
    std::sync::atomic::compiler_fence(std::sync::atomic::Ordering::SeqCst);
}

/// The plain bytes of an inverted secret, in a stack array of the caller's (wipe it).
pub fn uninvert(inverted: &[u8], into: &mut [u8; MAX_NEEDLE]) -> usize {
    let len = inverted.len().min(MAX_NEEDLE);
    for (dst, src) in into.iter_mut().zip(&inverted[..len]) {
        *dst = !src;
    }
    len
}

// ---------------------------------------------------------------------------------------------
// AES (FIPS-197), byte-oriented, for the test's own use.

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

/// An expanded AES key: `rounds + 1` round keys of 16 bytes, in the byte order FIPS-197
/// section 5.2 defines them (the order AES-NI and ARMv8 implementations store them in).
pub struct Schedule {
    pub bytes: [u8; 240],
    pub rounds: usize,
}

impl Schedule {
    /// KeyExpansion (FIPS-197 section 5.2) of a 16, 24 or 32 byte key.
    pub fn expand(key: &[u8]) -> Self {
        let nk = key.len() / 4;
        assert!(matches!(nk, 4 | 6 | 8), "an AES key of {} bytes", key.len());
        let rounds = nk + 6;
        let words = 4 * (rounds + 1);
        let mut bytes = [0u8; 240];
        bytes[..key.len()].copy_from_slice(key);
        let mut rcon = 1u8;
        for i in nk..words {
            let mut t = [
                bytes[4 * (i - 1)],
                bytes[4 * (i - 1) + 1],
                bytes[4 * (i - 1) + 2],
                bytes[4 * (i - 1) + 3],
            ];
            if i % nk == 0 {
                t = [
                    SBOX[t[1] as usize] ^ rcon,
                    SBOX[t[2] as usize],
                    SBOX[t[3] as usize],
                    SBOX[t[0] as usize],
                ];
                rcon = xtime(rcon);
            } else if nk > 6 && i % nk == 4 {
                t = t.map(|b| SBOX[b as usize]);
            }
            for j in 0..4 {
                bytes[4 * i + j] = bytes[4 * (i - nk) + j] ^ t[j];
            }
            wipe(&mut t);
        }
        Self { bytes, rounds }
    }

    pub fn round_key(&self, i: usize) -> &[u8] {
        &self.bytes[16 * i..16 * (i + 1)]
    }

    /// Round key `i` of the equivalent inverse cipher (FIPS-197 section 5.3.5): InvMixColumns
    /// of round key `i`.
    pub fn inverse_round_key(&self, i: usize) -> [u8; 16] {
        let rk = self.round_key(i);
        let mut out = [0u8; 16];
        for c in 0..4 {
            let a = [rk[4 * c], rk[4 * c + 1], rk[4 * c + 2], rk[4 * c + 3]];
            for r in 0..4 {
                out[4 * c + r] = gmul(a[r], 0x0e)
                    ^ gmul(a[(r + 1) % 4], 0x0b)
                    ^ gmul(a[(r + 2) % 4], 0x0d)
                    ^ gmul(a[(r + 3) % 4], 0x09);
            }
        }
        out
    }

    /// The cipher (FIPS-197 section 5.1) on one block.
    pub fn encrypt(&self, block: &mut [u8; 16]) {
        add(block, self.round_key(0));
        for round in 1..=self.rounds {
            for b in block.iter_mut() {
                *b = SBOX[*b as usize];
            }
            let s = *block;
            for c in 0..4 {
                for r in 0..4 {
                    block[4 * c + r] = s[4 * ((c + r) % 4) + r];
                }
            }
            if round != self.rounds {
                for c in 0..4 {
                    let col = [
                        block[4 * c],
                        block[4 * c + 1],
                        block[4 * c + 2],
                        block[4 * c + 3],
                    ];
                    let all = col[0] ^ col[1] ^ col[2] ^ col[3];
                    for r in 0..4 {
                        block[4 * c + r] = col[r] ^ all ^ xtime(col[r] ^ col[(r + 1) % 4]);
                    }
                }
            }
            add(block, self.round_key(round));
        }
    }
}

impl Drop for Schedule {
    fn drop(&mut self) {
        wipe(&mut self.bytes);
    }
}

fn xtime(b: u8) -> u8 {
    (b << 1) ^ if b & 0x80 != 0 { 0x1b } else { 0 }
}

fn gmul(mut a: u8, mut b: u8) -> u8 {
    let mut product = 0;
    while b != 0 {
        if b & 1 != 0 {
            product ^= a;
        }
        a = xtime(a);
        b >>= 1;
    }
    product
}

fn add(block: &mut [u8; 16], round_key: &[u8]) {
    for (b, k) in block.iter_mut().zip(round_key) {
        *b ^= k;
    }
}

// ---------------------------------------------------------------------------------------------
// SHA-1 and SHA-256 (FIPS 180-4 sections 6.1.2 and 6.2.2), the compression functions only.

pub const SHA1_IV: [u32; 5] = [
    0x6745_2301,
    0xefcd_ab89,
    0x98ba_dcfe,
    0x1032_5476,
    0xc3d2_e1f0,
];

pub fn sha1_compress(state: &mut [u32; 5], block: &[u8; 64]) {
    let mut w = [0u32; 80];
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
    }
    for t in 16..80 {
        w[t] = (w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]).rotate_left(1);
    }
    let [mut a, mut b, mut c, mut d, mut e] = *state;
    for (t, wt) in w.iter().enumerate() {
        let (f, k) = match t {
            0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
            20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
            40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
            _ => (b ^ c ^ d, 0xca62_c1d6u32),
        };
        let temp = a
            .rotate_left(5)
            .wrapping_add(f)
            .wrapping_add(e)
            .wrapping_add(k)
            .wrapping_add(*wt);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = temp;
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e]) {
        *s = s.wrapping_add(v);
    }
    w.fill(0);
}

pub const SHA256_IV: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

const SHA256_K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

pub fn sha256_compress(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for t in 0..16 {
        w[t] = u32::from_be_bytes([
            block[4 * t],
            block[4 * t + 1],
            block[4 * t + 2],
            block[4 * t + 3],
        ]);
    }
    for t in 16..64 {
        let s0 = w[t - 15].rotate_right(7) ^ w[t - 15].rotate_right(18) ^ (w[t - 15] >> 3);
        let s1 = w[t - 2].rotate_right(17) ^ w[t - 2].rotate_right(19) ^ (w[t - 2] >> 10);
        w[t] = w[t - 16]
            .wrapping_add(s0)
            .wrapping_add(w[t - 7])
            .wrapping_add(s1);
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for t in 0..64 {
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ (!e & g);
        let temp1 = h
            .wrapping_add(s1)
            .wrapping_add(ch)
            .wrapping_add(SHA256_K[t])
            .wrapping_add(w[t]);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let temp2 = s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(temp1);
        d = c;
        c = b;
        b = a;
        a = temp1.wrapping_add(temp2);
    }
    for (s, v) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *s = s.wrapping_add(v);
    }
    w.fill(0);
}

fn words(state: &[u32], big_endian: bool, out: &mut [u8]) {
    for (chunk, word) in out.chunks_mut(4).zip(state) {
        chunk.copy_from_slice(&if big_endian {
            word.to_be_bytes()
        } else {
            word.to_le_bytes()
        });
    }
}

// ---------------------------------------------------------------------------------------------
// The forms.

const ROUND_KEYS: [&str; 15] = [
    "round key 0",
    "round key 1",
    "round key 2",
    "round key 3",
    "round key 4",
    "round key 5",
    "round key 6",
    "round key 7",
    "round key 8",
    "round key 9",
    "round key 10",
    "round key 11",
    "round key 12",
    "round key 13",
    "round key 14",
];

const INVERSE_ROUND_KEYS: [&str; 15] = [
    "inverse round key 0",
    "inverse round key 1",
    "inverse round key 2",
    "inverse round key 3",
    "inverse round key 4",
    "inverse round key 5",
    "inverse round key 6",
    "inverse round key 7",
    "inverse round key 8",
    "inverse round key 9",
    "inverse round key 10",
    "inverse round key 11",
    "inverse round key 12",
    "inverse round key 13",
    "inverse round key 14",
];

/// Every form of an AES key: the key, each round key not inside the key, the round keys of
/// the equivalent inverse cipher (rounds 1 to Nr - 1), and with `gcm` the GHASH key `H` in
/// the forms of `rtci-srtp/tests/key_material` (`H`, two host-order words, the table entry
/// `H*x` in both word orders).
pub fn aes_forms(out: &mut Vec<Needle>, name: &str, key: &[u8], gcm: bool) {
    out.push(Needle::plain(name, "the key", key));
    let schedule = Schedule::expand(key);
    let nk = key.len() / 4;
    for (i, form) in ROUND_KEYS.iter().enumerate().take(schedule.rounds + 1) {
        if 4 * i >= nk {
            out.push(Needle::plain(name, form, schedule.round_key(i)));
        }
    }
    for (i, form) in INVERSE_ROUND_KEYS
        .iter()
        .enumerate()
        .take(schedule.rounds)
        .skip(1)
    {
        let mut inverse = schedule.inverse_round_key(i);
        out.push(Needle::plain(name, form, &inverse));
        wipe(&mut inverse);
    }
    if gcm {
        let mut h = [0u8; 16];
        schedule.encrypt(&mut h);
        out.push(Needle::plain(name, "GHASH key H", &h));
        let mut value = u128::from_be_bytes(h);
        let mut w = [0u8; 16];
        w[..8].copy_from_slice(&((value >> 64) as u64).to_le_bytes());
        w[8..].copy_from_slice(&(value as u64).to_le_bytes());
        out.push(Needle::plain(
            name,
            "GHASH key H (two host-order words, little-endian host)",
            &w,
        ));
        let carry = value >> 127 != 0;
        value <<= 1;
        if carry {
            value ^= 0xc200_0000_0000_0000_0000_0000_0000_0001;
        }
        w = value.to_le_bytes();
        out.push(Needle::plain(
            name,
            "GHASH table entry H*x (low word first)",
            &w,
        ));
        w.rotate_left(8);
        out.push(Needle::plain(
            name,
            "GHASH table entry H*x (high word first)",
            &w,
        ));
        wipe(&mut w);
        wipe(&mut h);
        value = 0;
        let _ = std::hint::black_box(value);
    }
}

/// The hash of an HMAC, for its forms.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum HmacHash {
    Sha1,
    Sha256,
    /// SHA-384 / SHA-512: only the key and its padded blocks (no SHA-512 compression here).
    Wide,
}

/// Every form of an HMAC key (RFC 2104 section 2): the key (its first [`MAX_NEEDLE`] bytes),
/// the first 32 bytes (20 for SHA-1) of the padded key blocks `key XOR ipad` and `key XOR
/// opad`, and for SHA-1 and SHA-256 the two hash states after them in both word orders.
/// Whoever has a state can compute the MAC: it is the key in another form.
pub fn hmac_forms(out: &mut Vec<Needle>, name: &str, key: &[u8], hash: HmacHash) {
    out.push(Needle::plain(name, "the key", key));
    let block_len = if hash == HmacHash::Wide { 128 } else { 64 };
    if key.len() > block_len {
        // Hashed first: the padded blocks are of the hash, which the test does not compute.
        return;
    }
    let shown = if hash == HmacHash::Sha1 { 20 } else { 32 };
    let mut blocks = [[0u8; 64]; 2];
    for (block, (pad, form)) in blocks
        .iter_mut()
        .zip([(0x36u8, "key XOR ipad"), (0x5c, "key XOR opad")])
    {
        block.fill(pad);
        for (b, k) in block.iter_mut().zip(key) {
            *b ^= k;
        }
        out.push(Needle::plain(name, form, &block[..shown.min(key.len())]));
    }
    let forms = [
        (
            "HMAC inner state (little-endian words)",
            "HMAC inner state (big-endian words)",
        ),
        (
            "HMAC outer state (little-endian words)",
            "HMAC outer state (big-endian words)",
        ),
    ];
    match hash {
        HmacHash::Sha1 => {
            for (block, (le, be)) in blocks.iter().zip(forms) {
                let mut state = SHA1_IV;
                sha1_compress(&mut state, block);
                for (form, big_endian) in [(le, false), (be, true)] {
                    let mut bytes = [0u8; 20];
                    words(&state, big_endian, &mut bytes);
                    out.push(Needle::plain(name, form, &bytes));
                    wipe(&mut bytes);
                }
                state.fill(0);
            }
        }
        HmacHash::Sha256 => {
            for (block, (le, be)) in blocks.iter().zip(forms) {
                let mut state = SHA256_IV;
                sha256_compress(&mut state, block);
                for (form, big_endian) in [(le, false), (be, true)] {
                    let mut bytes = [0u8; 32];
                    words(&state, big_endian, &mut bytes);
                    out.push(Needle::plain(name, form, &bytes));
                    wipe(&mut bytes);
                }
                state.fill(0);
            }
        }
        HmacHash::Wide => {}
    }
    for block in &mut blocks {
        wipe(block);
    }
}

/// The local primitives against their standards' vectors. Panics on a mismatch.
pub fn check_local_primitives() {
    fn hex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }
    // FIPS-197 appendix A.1: the last round key of 2b7e1516....
    let schedule = Schedule::expand(&hex("2b7e151628aed2a6abf7158809cf4f3c"));
    assert_eq!(
        hex("d014f9a8c9ee2589e13f0cc8b6630ca6"),
        schedule.round_key(10)
    );
    // FIPS-197 appendix C.1, equivalent inverse cipher: round[1].ik_sch.
    let schedule = Schedule::expand(&hex("000102030405060708090a0b0c0d0e0f"));
    assert_eq!(
        hex("13aa29be9c8faff6f770f58000f7bf03"),
        schedule.inverse_round_key(9)
    );
    // FIPS-197 appendix C.1 to C.3.
    for (key, expected) in [
        (
            "000102030405060708090a0b0c0d0e0f",
            "69c4e0d86a7b0430d8cdb78070b4c55a",
        ),
        (
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            "dda97ca4864cdfe06eaf70a0ec0d7191",
        ),
        (
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "8ea2b7ca516745bfeafc49904b496089",
        ),
    ] {
        let mut block: [u8; 16] = hex("00112233445566778899aabbccddeeff").try_into().unwrap();
        Schedule::expand(&hex(key)).encrypt(&mut block);
        assert_eq!(hex(expected), block, "FIPS-197 appendix C, key {key}");
    }
    // FIPS 180-4 (FIPS 180-2 appendices A.1 and B.1): SHA-1("abc") and SHA-256("abc").
    let mut block = [0u8; 64];
    block[..3].copy_from_slice(b"abc");
    block[3] = 0x80;
    block[63] = 24;
    let mut state = SHA1_IV;
    sha1_compress(&mut state, &block);
    let mut digest = [0u8; 20];
    words(&state, true, &mut digest);
    assert_eq!(hex("a9993e364706816aba3e25717850c26c9cd0d89d"), digest);
    let mut state = SHA256_IV;
    sha256_compress(&mut state, &block);
    let mut digest = [0u8; 32];
    words(&state, true, &mut digest);
    assert_eq!(
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
        digest
    );
}
