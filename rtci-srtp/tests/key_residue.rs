//! RFC 7714 section 13.1: "All keys MUST be properly erased when no longer needed", measured where the heap searches cannot look: the dead stack frames of the
//! thread that handled the keys.
//!
//! Each step of a session's life runs on a worker thread of its own whose stack the test owns
//! (`owned_stack`): building the contexts, protecting and unprotecting packets, re-keying,
//! tearing down. The contexts are handed from one worker to the next as boxes, so what a
//! worker's dead frames hold afterwards is what THAT step left, and the test reads those bytes
//! itself while the worker waits. Every key the session derives is looked for in every form an
//! implementation holds or computes on the way (`key_material::every_needle`: keys, AES round
//! keys of both schedules, GHASH keys and table entries, HMAC padded keys and states, salts).
//! On Linux the whole process is searched as well (`process_scan`), while the contexts are
//! alive (the search must find the keys where the contexts keep them) and after the teardown
//! (nothing may be left outside the workers' dead frames).
//!
//! The answer does not depend on the C library's treatment of thread stacks, on which mapping
//! the kernel reports a stack in, or on what an earlier thread left: the stacks are the
//! test's, filled with a known byte before use and read while their threads are alive, and
//! the process search leaves nothing out but its own buffer: the keys looked for are computed
//! on a scratch worker whose stack is overwritten and unmapped before anything is searched. `the_search_finds_what_is_left_and_not_what_is_erased`
//! is the control: a key deliberately left on a stack, in the heap, in a freed block and in
//! static data is found in each, and one that was erased, or never there, is not.
//!
//! What is asserted (`check`, and each test's documentation): nothing outside dead stack frames
//! after the teardown; nothing in them after building and tearing down, in any build, with
//! either provider; with the ring provider nothing in them after any step, in any build. What the dead frames hold after each step is printed either way (`STAGE`, `FORM`,
//! `SUMMARY`, `INVENTORY` lines; `scripts/key-residue-report.sh` collects them).

#[cfg(unix)]
mod key_material;
#[cfg(unix)]
mod owned_stack;
#[cfg(target_os = "linux")]
mod process_scan;

/// Unix only: a thread on a stack of the test's own needs `pthread_attr_setstack`.
#[cfg(unix)]
mod residue_tests {
    use std::ops::Range;
    use std::sync::{Arc, Mutex};

    use super::key_material::{
        Finder, Needle, check_local_primitives, every_needle, rtcp, rtp, rtp_with_extension, wipe,
    };
    use super::owned_stack::{Parked, on_scratch_stack, run_parked};
    use crypto::{RTCCryptoProvider, SecretVec};
    use rtci_srtp::context::Context;
    use rtci_srtp::header_extension::EncryptedHeaderExtensions;
    use rtci_srtp::keying::{KeyDerivationRate, Keying};
    use rtci_srtp::protection_profile::ProtectionProfile;

    /// One measurement at a time: the process searches see every thread's memory.
    static SERIAL: Mutex<()> = Mutex::new(());

    #[allow(clippy::vec_init_then_push)]
    fn providers() -> Vec<Arc<dyn RTCCryptoProvider>> {
        let mut providers: Vec<Arc<dyn RTCCryptoProvider>> = Vec::new();
        #[cfg(feature = "crypto-ring")]
        providers.push(Arc::new(crypto::providers::RingProvider::new()));
        #[cfg(feature = "crypto-aws-lc-rs")]
        providers.push(Arc::new(crypto::providers::AwsLcRsProvider::new()));
        providers
    }

    /// How a session is keyed.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Variant {
        /// `Context::new`: one master key, no MKI, key derivation rate zero. What DTLS-SRTP
        /// uses. Steps: build, packets, teardown.
        Dtls,
        /// `Context::with_keying`: an MKI and a key derivation rate of two packets, so the
        /// session keys are derived again on the packet path; then a second master key is
        /// added, sent with, and the first removed. Steps: build, packets, rekey, teardown.
        Keyed,
    }

    impl Variant {
        fn name(self) -> &'static str {
            match self {
                Variant::Dtls => "dtls",
                Variant::Keyed => "keyed",
            }
        }
    }

    const FIRST_MKI: [u8; 1] = [1];
    const SECOND_MKI: [u8; 1] = [2];
    /// The key derivation rate of [`Variant::Keyed`].
    const RATE: u64 = 2;
    /// Packets protected before the re-keying, and with the second master key.
    const PACKETS: u16 = 4;
    const PACKETS_AFTER_REKEY: u16 = 2;

    /// A master key and salt for one master key of one session of one test: 46 bytes of a
    /// SplitMix64 stream seeded with all of them, so no two sessions, tests or master keys
    /// look for the same bytes.
    fn master(
        test: u8,
        provider: &str,
        profile: ProtectionProfile,
        variant: Variant,
        nth: u8,
    ) -> ([u8; 32], [u8; 14]) {
        let mut state = 0x5eed_0f5e_c2e7_5000u64
            ^ u64::from(test) << 40
            ^ u64::from(provider.len() as u8) << 32
            ^ u64::from(profile as u16) << 16
            ^ u64::from(variant as u8) << 8
            ^ u64::from(nth);
        let mut bytes = [0u8; 48];
        for chunk in bytes.chunks_mut(8) {
            state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = state;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            chunk.copy_from_slice(&(z ^ (z >> 31)).to_le_bytes());
        }
        let mut key = [0u8; 32];
        let mut salt = [0u8; 14];
        key.copy_from_slice(&bytes[..32]);
        salt.copy_from_slice(&bytes[32..46]);
        wipe(&mut bytes);
        (key, salt)
    }

    /// A master key and salt as the engine is handed them: in zeroizing heap buffers.
    struct MasterKey {
        key: SecretVec,
        salt: SecretVec,
    }

    /// A session between two workers: only pointers, so handing it over leaves no key bytes in
    /// a worker's own frame.
    struct Session {
        sender: Box<Context>,
        receiver: Box<Context>,
        /// Held, like the application's own copy, until the teardown drops it.
        #[allow(dead_code)]
        first: MasterKey,
        second: Option<MasterKey>,
    }

    fn build(
        provider: Arc<dyn RTCCryptoProvider>,
        profile: ProtectionProfile,
        variant: Variant,
        first: MasterKey,
        second: Option<MasterKey>,
    ) -> Session {
        let context = || {
            let mut context = Box::new(
                match variant {
                    Variant::Dtls => Context::new(
                        first.key.as_ref(),
                        first.salt.as_ref(),
                        profile,
                        None,
                        None,
                        provider.crypto(),
                    ),
                    Variant::Keyed => Context::with_keying(
                        first.key.as_ref(),
                        first.salt.as_ref(),
                        profile,
                        Keying {
                            key_derivation_rate: KeyDerivationRate::new(RATE).expect("a rate"),
                            mki: Some(FIRST_MKI.to_vec()),
                        },
                        None,
                        None,
                        provider.clone(),
                    ),
                }
                .expect("a context"),
            );
            // RFC 6904: the element of `rtp_with_extension` is encrypted, with k_he and k_hs.
            context.set_encrypted_header_extensions(
                EncryptedHeaderExtensions::new(&[1]).expect("an id"),
            );
            context
        };
        let (sender, receiver) = (context(), context());
        Session {
            sender,
            receiver,
            first,
            second,
        }
    }

    /// Protects and unprotects `sequence_numbers` RTP packets (every other one with an
    /// encrypted header extension) and as many RTCP packets.
    fn packets(mut session: Session, sequence_numbers: Range<u16>) -> Session {
        for sequence_number in sequence_numbers {
            let packet = if sequence_number % 2 == 0 {
                rtp(sequence_number)
            } else {
                rtp_with_extension(sequence_number)
            };
            let protected = session.sender.encrypt_rtp(&packet).expect("SRTP");
            let unprotected = session.receiver.decrypt_rtp(&protected).expect("RTP");
            assert_eq!(packet, unprotected, "RTP packet {sequence_number}");
            let protected = session.sender.encrypt_rtcp(&rtcp()).expect("SRTCP");
            let unprotected = session.receiver.decrypt_rtcp(&protected).expect("RTCP");
            assert_eq!(rtcp(), unprotected, "RTCP packet {sequence_number}");
        }
        session
    }

    /// Re-keys with an MKI (RFC 3711 section 8.1): adds the second master key, protects with
    /// it, removes the first.
    fn rekey(mut session: Session) -> Session {
        {
            let second = session.second.as_ref().expect("a second master key");
            for context in [&mut session.sender, &mut session.receiver] {
                context
                    .add_master_key(&SECOND_MKI, second.key.as_ref(), second.salt.as_ref())
                    .expect("a second master key added");
                context.set_sending_mki(&SECOND_MKI).expect("sending MKI");
            }
        }
        let mut session = packets(session, PACKETS..PACKETS + PACKETS_AFTER_REKEY);
        for context in [&mut session.sender, &mut session.receiver] {
            context
                .remove_master_key(&FIRST_MKI)
                .expect("the first master key removed");
        }
        session
    }

    /// One needle in one worker's dead frames.
    struct Residue {
        needle: usize,
        copies: usize,
        /// How far below the worker's floor the nearest and the farthest copy start.
        depth: Range<usize>,
    }

    /// What one step left.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    struct Stage {
        name: &'static str,
        /// How deep the step went below the floor, in bytes.
        used: usize,
        residue: Vec<Residue>,
        /// The worker's dead frames and its whole stack.
        dead: Range<usize>,
        stack: Range<usize>,
    }

    /// Searches the dead frames of `worker` for `needles`, reading them directly.
    fn dead_frames<T>(finder: &Finder<'_>, worker: &Parked<T>) -> Stage {
        worker.verify();
        let dead = worker.dead();
        let mut residue: Vec<Residue> = Vec::new();
        finder.each(dead, |needle, offset| {
            let depth = dead.len() - offset;
            match residue.iter_mut().find(|r| r.needle == needle) {
                Some(found) => {
                    found.copies += 1;
                    found.depth = found.depth.start.min(depth)..found.depth.end.max(depth);
                }
                None => residue.push(Residue {
                    needle,
                    copies: 1,
                    depth: depth..depth,
                }),
            }
        });
        residue.sort_by_key(|r| r.needle);
        Stage {
            name: worker.name,
            used: worker.used(),
            residue,
            dead: worker.dead_range(),
            stack: worker.stack(),
        }
    }

    /// What one session showed.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    struct Measured {
        provider: &'static str,
        profile: ProtectionProfile,
        variant: Variant,
        needles: Vec<Needle>,
        stages: Vec<Stage>,
        /// Found after the teardown outside the workers' dead frames: one line each.
        left: Vec<String>,
        /// What the search could not read, and what else is worth a line.
        notes: Vec<String>,
    }

    /// The whole-process searches of one session (Linux): the live one must find the session
    /// keys where the contexts keep them; the last one must find nothing outside the workers'
    /// dead frames, and there exactly what the direct reading found.
    #[cfg(target_os = "linux")]
    mod process {
        use super::super::process_scan::{Scan, scan};
        use super::*;

        pub(super) fn search(
            needles: &[Needle],
            stages: &[Stage],
            notes: &mut Vec<String>,
        ) -> Scan {
            // Nothing is left out: the needles were computed on a scratch worker whose stack is
            // gone, so this thread's own stack is searched like everything else.
            let found = scan(needles, &[]);
            for stage in stages {
                assert_eq!(
                    0,
                    found.unreadable_in(&stage.stack),
                    "pages of the `{}` worker's stack could not be read",
                    stage.name
                );
            }
            for line in found.unreadable_lines() {
                if !notes.contains(&line) {
                    notes.push(line);
                }
            }
            found
        }

        /// While the contexts are alive: each key in `expected` is, in some form, somewhere
        /// outside the workers' stacks (where the contexts keep it).
        pub(super) fn live(m: &mut Measured, expected: &[String]) {
            let found = search(&m.needles, &m.stages, &mut m.notes);
            for key in expected {
                let seen = found.hits.iter().any(|hit| {
                    let needle = &m.needles[hit.needle];
                    needle.key == key.as_str()
                        && !m.stages.iter().any(|s| s.stack.contains(&hit.address))
                });
                assert!(
                    seen,
                    "{} {:?} {}: the {key} was not found outside the workers' stacks while \
                     the contexts were alive: the search does not see what it must",
                    m.provider,
                    m.profile,
                    m.variant.name()
                );
            }
            let outside = found
                .hits
                .iter()
                .filter(|hit| !m.stages.iter().any(|s| s.stack.contains(&hit.address)))
                .map(|hit| hit.needle)
                .collect::<std::collections::BTreeSet<_>>();
            m.notes.push(format!(
                "{} key forms were outside the workers' stacks while the contexts were alive",
                outside.len()
            ));
            // The contexts hold session keys, and the master key itself where a key derivation
            // rate needs it again; nothing holds the master key's AES schedule once the keys
            // are derived. Found here it would be what a derivation left on the stack, carried
            // into the heap in the unused bytes of an object built over it.
            for &needle in &outside {
                let needle = &m.needles[needle];
                if needle.key.ends_with("master key") && needle.form != "the key" {
                    m.left.push(format!(
                        "{} {:?} {}: {} outside the workers' stacks while the contexts were \
                         alive",
                        m.provider,
                        m.profile,
                        m.variant.name(),
                        needle.describe()
                    ));
                }
            }
        }

        /// After the teardown.
        pub(super) fn after(m: &mut Measured) {
            let found = search(&m.needles, &m.stages, &mut m.notes);
            let mut in_dead: Vec<Vec<usize>> = vec![Vec::new(); m.stages.len()];
            for hit in &found.hits {
                let needle = &m.needles[hit.needle];
                if let Some(s) = m.stages.iter().position(|s| s.dead.contains(&hit.address)) {
                    if !in_dead[s].contains(&hit.needle) {
                        in_dead[s].push(hit.needle);
                    }
                    continue;
                }
                let place = match m.stages.iter().find(|s| s.stack.contains(&hit.address)) {
                    Some(stage) => format!(
                        "the `{}` worker's stack at or above its floor (its own frames, the \
                         thread's start, its thread-local storage)",
                        stage.name
                    ),
                    None => found.regions[hit.region].describe(),
                };
                m.left.push(format!(
                    "{} {:?} {}: {} at {:#x} in {place}",
                    m.provider,
                    m.profile,
                    m.variant.name(),
                    needle.describe(),
                    hit.address
                ));
            }
            // The two ways of reading a worker's dead frames agree.
            for (stage, mut through_proc) in m.stages.iter().zip(in_dead) {
                through_proc.sort_unstable();
                let direct: Vec<usize> = stage.residue.iter().map(|r| r.needle).collect();
                assert_eq!(
                    direct, through_proc,
                    "the `{}` worker's dead frames read directly and through /proc/self/mem",
                    stage.name
                );
            }
        }
    }

    /// One session of `profile` with `provider`, each step on a worker of its own.
    fn session(
        test: u8,
        provider: &Arc<dyn RTCCryptoProvider>,
        profile: ProtectionProfile,
        variant: Variant,
    ) -> Measured {
        let salt_len = profile.salt_len();
        let key_len = profile.key_len();
        let (epochs, masters): (&'static [u64], u8) = match variant {
            Variant::Dtls => (&[0], 1),
            // Packet indexes 0 to 5 at a rate of two; the second master key's cipher derives
            // epoch 0 when it is built and epoch 2 for its packets.
            Variant::Keyed => (&[0, 1, 2], 2),
        };
        // The keys this session looks for, and the master keys as the engine is handed them,
        // are made on a scratch worker: no frame of this thread ever holds one in the clear.
        let name = provider.name();
        let (needles, mut keys) = on_scratch_stack(move || {
            let mut needles = Vec::new();
            let mut keys = Vec::new();
            for nth in 1..=masters {
                let (mut key, mut salt) = master(test, name, profile, variant, nth);
                let who = match variant {
                    Variant::Dtls => String::new(),
                    Variant::Keyed => format!("master key {nth}: "),
                };
                needles.extend(every_needle(
                    profile,
                    &key[..key_len],
                    &salt[..salt_len],
                    epochs,
                    &who,
                ));
                keys.push(MasterKey {
                    key: SecretVec::new(key[..key_len].to_vec()),
                    salt: SecretVec::new(salt[..salt_len].to_vec()),
                });
                wipe(&mut key);
                wipe(&mut salt);
            }
            (needles, keys)
        });
        let second = (masters == 2).then(|| keys.pop().expect("two master keys"));
        let first = keys.pop().expect("a master key");
        let finder = Finder::new(&needles);
        let mut stages = Vec::new();

        let worker_provider = provider.clone();
        let mut built = run_parked("build", move || {
            build(worker_provider, profile, variant, first, second)
        });
        stages.push(dead_frames(&finder, &built));
        let handed = built.take();

        let mut sent = run_parked("packets", move || packets(handed, 0..PACKETS));
        stages.push(dead_frames(&finder, &sent));
        drop(finder);

        let mut m = Measured {
            provider: provider.name(),
            profile,
            variant,
            needles,
            stages,
            left: Vec::new(),
            notes: Vec::new(),
        };
        #[cfg(target_os = "linux")]
        {
            let key = if profile.is_null_cipher() {
                "SRTP salting key"
            } else {
                "SRTP encryption key"
            };
            let expected: Vec<String> = match variant {
                Variant::Dtls => vec![key.to_owned()],
                // After four packets at a rate of two the contexts hold epochs 0 and 1.
                Variant::Keyed => vec![
                    format!("master key 1: epoch 0 {key}"),
                    format!("master key 1: epoch 1 {key}"),
                ],
            };
            process::live(&mut m, &expected);
        }
        let finder = Finder::new(&m.needles);
        let mut handed = sent.take();

        let mut rekeyed = None;
        if variant == Variant::Keyed {
            let mut worker = run_parked("rekey", move || rekey(handed));
            m.stages.push(dead_frames(&finder, &worker));
            handed = worker.take();
            rekeyed = Some(worker);
        }

        let torn_down = run_parked("teardown", move || drop(handed));
        m.stages.push(dead_frames(&finder, &torn_down));
        drop(finder);
        #[cfg(target_os = "linux")]
        process::after(&mut m);

        built.finish();
        sent.finish();
        if let Some(worker) = rekeyed {
            worker.finish();
        }
        torn_down.finish();
        m
    }

    /// Everything one test measured.
    struct Inventory {
        /// Key forms found in dead stack frames, over every session and step.
        forms: usize,
        /// The same per step: "build", "packets", "rekey", "teardown".
        by_step: Vec<(&'static str, usize)>,
        /// Found outside the workers' dead frames after the teardown, or where it must not be
        /// while the contexts were alive.
        left: Vec<String>,
    }

    impl Inventory {
        fn in_step(&self, step: &str) -> usize {
            self.by_step
                .iter()
                .find(|(name, _)| *name == step)
                .map_or(0, |(_, forms)| *forms)
        }
    }

    /// Every profile and variant with the provider named `name`, printed.
    fn measure(test: u8, name: &str) -> Inventory {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        check_local_primitives();
        let mut inventory = Inventory {
            forms: 0,
            by_step: Vec::new(),
            left: Vec::new(),
        };
        // FNV-1a over the residue, to compare two runs at a glance.
        let mut digest = 0xcbf2_9ce4_8422_2325u64;
        let mut summary: Vec<(String, usize, usize)> = Vec::new();
        let mut notes: Vec<String> = Vec::new();
        for provider in providers().into_iter().filter(|p| p.name() == name) {
            for variant in [Variant::Dtls, Variant::Keyed] {
                for profile in ProtectionProfile::ALL {
                    let m = session(test, &provider, profile, variant);
                    let session = format!("{}|{:?}|{}", m.provider, m.profile, variant.name());
                    for stage in &m.stages {
                        println!(
                            "STAGE {session}|{}|stack used {} bytes|{} key forms left",
                            stage.name,
                            stage.used,
                            stage.residue.len()
                        );
                        for residue in &stage.residue {
                            let needle = &m.needles[residue.needle];
                            let form =
                                format!("{session}|{}|{}|{}", stage.name, needle.key, needle.form);
                            for byte in form.bytes().chain(*b"\n") {
                                digest = (digest ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
                            }
                            println!(
                                "FORM {form}|{} copies|{} to {} bytes below the floor",
                                residue.copies, residue.depth.start, residue.depth.end
                            );
                            let key = format!(
                                "{}|{}|{}|{}",
                                m.provider,
                                variant.name(),
                                stage.name,
                                needle.key
                            );
                            match summary.iter_mut().find(|(k, _, _)| *k == key) {
                                Some((_, forms, copies)) => {
                                    *forms += 1;
                                    *copies += residue.copies;
                                }
                                None => summary.push((key, 1, residue.copies)),
                            }
                        }
                        inventory.forms += stage.residue.len();
                        match inventory.by_step.iter_mut().find(|(n, _)| *n == stage.name) {
                            Some((_, forms)) => *forms += stage.residue.len(),
                            None => inventory.by_step.push((stage.name, stage.residue.len())),
                        }
                    }
                    for line in &m.left {
                        println!("LEFT {line}");
                    }
                    for note in m.notes {
                        let note = format!("{}: {note}", m.provider);
                        if !notes.contains(&note) {
                            notes.push(note);
                        }
                    }
                    inventory.left.extend(m.left);
                }
            }
        }
        for (key, forms, copies) in &summary {
            println!("SUMMARY {key}|{forms} key forms over the ten profiles|{copies} copies");
        }
        for note in &notes {
            println!("NOTE {note}");
        }
        println!(
            "INVENTORY {name}: {} key forms in dead stack frames {:?}, {} left elsewhere, digest {digest:016x}, {} build",
            inventory.forms,
            inventory.by_step,
            inventory.left.len(),
            if cfg!(debug_assertions) {
                "unoptimised"
            } else {
                "optimised"
            }
        );
        inventory
    }

    /// What every test here requires of a measurement: nothing outside dead stack frames after
    /// the teardown, no master key schedule in the heap while the contexts are alive (Linux:
    /// both need the process search), and nothing in dead stack frames after the steps whose
    /// stack the engine overwrites, whatever the build: building the contexts, and tearing
    /// them down.
    fn check(inventory: &Inventory) {
        assert!(
            inventory.left.is_empty(),
            "found where no key may be: {:#?}",
            inventory.left
        );
        for step in ["build", "teardown"] {
            assert_eq!(
                0,
                inventory.in_step(step),
                "key forms left in dead stack frames by the `{step}` step (the FORM lines above \
                 name each)"
            );
        }
    }

    /// RFC 7714 section 13.1 with the ring provider (the default): handling a session's keys
    /// leaves none of them behind. For every profile, with `Context::new` and with an MKI and
    /// a key derivation rate, each step on a worker whose stack the test reads: after building
    /// the contexts, protecting and unprotecting RTP and RTCP (with re-derivation on the
    /// packet path), re-keying and tearing down, no key the session derives is found, in any
    /// form, in the dead stack frames of the thread that did it; on Linux none is found
    /// anywhere else in the process after the teardown either, and the search is shown to see
    /// the live keys.
    ///
    /// Every step is asserted in every build. In an unoptimised build the AES and SHA-1
    /// routines store their intermediate values in stack slots, round keys included; rtci-crypto
    /// overwrites the stack after each record operation of RustCrypto's AES there
    /// (`scrub_record_stack`), which removed the 72 and 108 AES-CTR round-key forms the packet
    /// path left with rustc 1.89 and 1.99.1 (18 on AArch64 macOS; runs 46030856312, 46030861874:
    /// 0 with the overwrite, those counts without it).
    #[cfg(feature = "crypto-ring")]
    #[test]
    fn with_ring_key_handling_leaves_no_key_in_dead_stack_frames() {
        let inventory = measure(1, "ring");
        check(&inventory);
        assert_eq!(
            0, inventory.forms,
            "key forms left in dead stack frames (the FORM lines above name each)"
        );
    }

    /// The same with the AWS-LC provider, for what holds with it: building the contexts and
    /// tearing them down leave no key in dead stack frames, and (Linux) nothing is left
    /// elsewhere in the process. Its packet path is the known limit below.
    #[cfg(feature = "crypto-aws-lc-rs")]
    #[test]
    fn with_aws_lc_building_and_tearing_down_leave_no_key_in_dead_stack_frames() {
        check(&measure(2, "aws-lc-rs"));
    }

    /// A KNOWN LIMIT of the AWS-LC provider (docs/test-exclusions.md, docs/key-erasure.md):
    /// AWS-LC computes each HMAC on a copy of the keyed context in its own stack frame and
    /// its AES-GCM leaves a GHASH table entry in one, so protecting or unprotecting a packet
    /// leaves the SRTP / SRTCP HMAC-SHA1 states and a form of the GCM key in dead stack
    /// frames, in every build. The engine does not overwrite the stack after every packet.
    /// This is the requirement as a test: it fails while any key form is found after any
    /// step. Run with `-- --ignored known_limit_ --nocapture`.
    #[cfg(feature = "crypto-aws-lc-rs")]
    #[test]
    #[ignore = "known limit: the AWS-LC provider's packet path leaves keys in dead stack frames (docs/test-exclusions.md)"]
    fn known_limit_with_aws_lc_the_packet_path_leaves_keys_in_dead_stack_frames() {
        let inventory = measure(4, "aws-lc-rs");
        check(&inventory);
        assert_eq!(
            0, inventory.forms,
            "key forms left in dead stack frames (the FORM lines above name each)"
        );
    }

    // -----------------------------------------------------------------------------------------
    // The control.

    /// The control keys, kept inverted like every needle: left on a stack, erased on a stack,
    /// held in the heap, left in a freed block, held in static data, and never anywhere.
    const CONTROLS: [[u8; 32]; 6] = [
        *b"\x1f\x83\xd9\xab\xfb\x41\xbd\x6b\x5b\xe0\xcd\x19\x13\x7e\x21\x79\x9b\x05\x68\x8c\x51\x0e\x52\x7f\xbb\x67\xae\x85\x3c\x6e\xf3\x72",
        *b"\xa5\x4f\xf5\x3a\x51\x0e\x52\x7f\x9b\x05\x68\x8c\x1f\x83\xd9\xab\x5b\xe0\xcd\x19\xc1\x05\x9e\xd8\x36\x7c\xd5\x07\x30\x70\xdd\x17",
        *b"\x42\x8a\x2f\x98\x71\x37\x44\x91\xb5\xc0\xfb\xcf\xe9\xb5\xdb\xa5\x39\x56\xc2\x5b\x59\xf1\x11\xf1\x92\x3f\x82\xa4\xab\x1c\x5e\xd5",
        *b"\xd8\x07\xaa\x98\x12\x83\x5b\x01\x24\x31\x85\xbe\x55\x0c\x7d\xc3\x72\xbe\x5d\x74\x80\xde\xb1\xfe\x9b\xdc\x06\xa7\xc1\x9b\xf1\x74",
        *b"\xe4\x9b\x69\xc1\xef\xbe\x47\x86\x0f\xc1\x9d\xc6\x24\x0c\xa1\xcc\x2d\xe9\x2c\x6f\x4a\x74\x84\xaa\x5c\xb0\xa9\xdc\x76\xf9\x88\xda",
        *b"\x98\x3e\x51\x52\xa8\x31\xc6\x6d\xb0\x03\x27\xc8\xbf\x59\x7f\xc7\xc6\xe0\x0b\xf3\xd5\xa7\x91\x47\x06\xca\x63\x51\x14\x29\x29\x67",
    ];
    const LEFT_ON_STACK: usize = 0;
    const ERASED_ON_STACK: usize = 1;
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const HELD_IN_HEAP: usize = 2;
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const LEFT_IN_FREED_BLOCK: usize = 3;
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const HELD_IN_STATIC: usize = 4;
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    const NEVER_THERE: usize = 5;
    const CONTROL_NAMES: [&str; 6] = [
        "left on the stack",
        "erased on the stack",
        "held in the heap",
        "left in a freed block",
        "held in static data",
        "never there",
    ];

    /// Writes control `which` in the clear into `to`, byte by byte.
    fn write_control(which: usize, to: &mut [u8]) {
        for (plain, inverted) in to.iter_mut().zip(&CONTROLS[which]) {
            // SAFETY: `plain` is a valid, aligned, exclusive reference.
            unsafe { std::ptr::write_volatile(plain, !*inverted) };
        }
    }

    /// Puts control `which` in the clear into a local of this frame, and erases it or not.
    #[inline(never)]
    fn on_the_stack(which: usize, erase: bool) {
        let mut plain = [0u8; 32];
        write_control(which, &mut plain);
        std::hint::black_box(&mut plain);
        if erase {
            wipe(&mut plain);
        }
    }

    /// Calls `on_the_stack` from 4 KiB further down, so that a later, shallower call does not
    /// land on what this one leaves. The call is the last thing this does: any call made after
    /// it from here would put its return address and frame exactly where the key was left
    /// (the first form of this control did, and on x86-64 found nothing: run 45871064780).
    #[inline(never)]
    fn deeper_on_the_stack(which: usize, erase: bool) {
        let mut distance = [0u8; 4096];
        std::hint::black_box(&mut distance);
        on_the_stack(which, erase);
    }

    /// In static data (initialised, so it is in the binary's own writable mapping).
    #[cfg(target_os = "linux")]
    static STATIC_DATA: Mutex<[u8; 40]> = Mutex::new([0x11; 40]);

    /// The search finds a key that is left behind and does not find one that is not: a key
    /// left in a dead stack frame of a worker is found in that worker's dead frames (and the
    /// same key erased before the frame returned is not); on Linux, a key held in the heap,
    /// one left in a freed block and one held in static data are each found, outside every
    /// stack, and a key that was never in the process is not found. Without this, "nothing
    /// found" in the tests above would prove nothing.
    #[test]
    fn the_search_finds_what_is_left_and_not_what_is_erased() {
        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        let needles: Vec<Needle> = on_scratch_stack(|| {
            (0..CONTROLS.len())
                .map(|which| {
                    let mut plain = [0u8; 32];
                    write_control(which, &mut plain);
                    let needle = Needle::named("control".to_owned(), CONTROL_NAMES[which], &plain);
                    wipe(&mut plain);
                    needle
                })
                .collect()
        });
        let finder = Finder::new(&needles);

        let worker = run_parked("control", || {
            deeper_on_the_stack(LEFT_ON_STACK, false);
            on_the_stack(ERASED_ON_STACK, true);
        });
        let stage = dead_frames(&finder, &worker);
        let found: Vec<usize> = stage.residue.iter().map(|r| r.needle).collect();
        println!(
            "CONTROL stack: used {} bytes, found {:?}",
            stage.used,
            found.iter().map(|&n| CONTROL_NAMES[n]).collect::<Vec<_>>()
        );
        assert_eq!(
            vec![LEFT_ON_STACK],
            found,
            "in the worker's dead frames: the key left there and no other"
        );

        #[cfg(target_os = "linux")]
        {
            use super::process_scan::scan;
            let mut held = Box::new([0u8; 64]);
            write_control(HELD_IN_HEAP, &mut held[16..48]);
            std::hint::black_box(&mut held);
            write_control(
                HELD_IN_STATIC,
                &mut STATIC_DATA.lock().unwrap_or_else(|e| e.into_inner())[4..36],
            );
            // Freed without erasure, by a thread that stays alive: the block stays in that
            // thread's free list, which nothing else allocates from. The key is past the
            // bytes the allocator links free blocks with.
            let (freed_tx, freed_rx) = std::sync::mpsc::channel::<()>();
            let (end_tx, end_rx) = std::sync::mpsc::channel::<()>();
            let freer = std::thread::spawn(move || {
                let mut block = vec![0u8; 1000];
                write_control(LEFT_IN_FREED_BLOCK, &mut block[512..544]);
                std::hint::black_box(&mut block);
                drop(block);
                let _ = freed_tx.send(());
                let _ = end_rx.recv();
            });
            freed_rx.recv().expect("the freeing thread");

            let scanned = scan(&needles, &[]);
            let mut places: Vec<Vec<String>> = vec![Vec::new(); needles.len()];
            for hit in &scanned.hits {
                let place = if stage.dead.contains(&hit.address) {
                    "the worker's dead frames".to_owned()
                } else if stage.stack.contains(&hit.address) {
                    "the worker's stack at or above its floor".to_owned()
                } else {
                    scanned.regions[hit.region].describe()
                };
                places[hit.needle].push(place);
            }
            for (name, places) in CONTROL_NAMES.iter().zip(&places) {
                println!("CONTROL process: the key {name}: {places:?}");
            }
            for line in scanned.unreadable_lines() {
                println!("CONTROL process: {line}");
            }
            println!("CONTROL process: {} KiB searched", scanned.searched / 1024);
            assert_eq!(0, scanned.unreadable_in(&stage.stack));
            assert_eq!(
                vec!["the worker's dead frames".to_owned()],
                places[LEFT_ON_STACK],
                "the key left on the stack, through /proc/self/mem"
            );
            assert!(places[ERASED_ON_STACK].is_empty(), "the erased key");
            assert!(
                places[NEVER_THERE].is_empty(),
                "the key that was never there"
            );
            for which in [HELD_IN_HEAP, LEFT_IN_FREED_BLOCK, HELD_IN_STATIC] {
                assert_eq!(
                    1,
                    places[which].len(),
                    "the key {}: found once, outside every stack",
                    CONTROL_NAMES[which]
                );
                assert!(
                    !places[which][0].starts_with("the worker"),
                    "the key {}",
                    CONTROL_NAMES[which]
                );
            }
            assert!(
                !places[HELD_IN_STATIC][0].starts_with("anonymous")
                    && !places[HELD_IN_STATIC][0].starts_with('['),
                "the key held in static data is in a file's mapping: {:?}",
                places[HELD_IN_STATIC]
            );

            // Tidy up: nothing of the control is left for the tests after this one.
            wipe(&mut held[..]);
            wipe(&mut STATIC_DATA.lock().unwrap_or_else(|e| e.into_inner())[..]);
            let _ = end_tx.send(());
            freer.join().expect("the freeing thread ends");
        }
        worker.finish();
    }

    // -----------------------------------------------------------------------------------------
    // Why searching the stack of an ordinary thread gave different answers in different places.

    /// AN INVESTIGATION TOOL, not a check (docs/test-exclusions.md): prints how this system's
    /// C library and kernel treat the stack of an ordinary thread, which is what decided
    /// whether the search this file replaced (`key_erasure_process_memory.rs`, in 0.2.0: a
    /// `std::thread` worker, searched through `/proc/self/maps` after it had ended) saw key
    /// residue: 20 of 20 runs in the test-environment image (glibc 2.39), 0 of 40 on GitHub's
    /// runners (glibc 2.43), from the same sources.
    ///
    /// A worker thread writes a mark every 4 KiB down the first mebibyte of its stack and
    /// waits. Printed while it is alive: the C library's and the kernel's versions, the
    /// thread's stack as the C library reports it, the lines of `/proc/self/maps` around it,
    /// whether the mapping that holds the worker's frame also holds the searching thread's
    /// stack (the earlier search left out the whole mapping holding its own stack), whether
    /// the guard is a mapping of its own, and how much of the stack's mapping `/proc/self/mem`
    /// reads in 1 MiB pieces (the earlier search dropped a piece that failed) and page by
    /// page. Printed after it has ended: whether its stack is still mapped, and which marks
    /// are still there. Last, the same marks on a stack of the test's own whose thread has
    /// ended. Run with `-- --ignored investigate_ --nocapture`.
    #[cfg(target_os = "linux")]
    #[test]
    #[ignore = "an investigation tool: prints how the C library treats thread stacks (docs/test-exclusions.md)"]
    fn investigate_how_the_c_library_treats_thread_stacks() {
        use super::owned_stack::{FILL, OwnedStack, STACK_SIZE, run_to_exit};
        use super::process_scan::{own_thread_stack, page_size, regions};
        use std::os::unix::fs::FileExt;
        use std::sync::mpsc;

        const MARK: [u8; 8] = *b"\x9eSTKMRK\x9e";
        const SPAN: usize = 1 << 20;
        const STEP: usize = 4096;

        /// Writes [`MARK`] every [`STEP`] bytes of a [`SPAN`]-byte local.
        #[inline(never)]
        fn mark_the_stack() {
            let mut area = [0u8; SPAN];
            for at in (0..SPAN).step_by(STEP) {
                for (i, byte) in MARK.iter().enumerate() {
                    // SAFETY: `at + i` is inside `area`.
                    unsafe { std::ptr::write_volatile(area.as_mut_ptr().add(at + i), *byte) };
                }
            }
            std::hint::black_box(&mut area);
        }

        /// Reads `range` through /proc/self/mem page by page: the bytes (zeros where a page
        /// could not be read) and the unreadable pages' offsets from the range's start.
        fn read(range: &Range<usize>) -> (Vec<u8>, Vec<usize>) {
            let mem = std::fs::File::open("/proc/self/mem").expect("/proc/self/mem");
            let page = page_size();
            let mut bytes = vec![0u8; range.len()];
            let mut unreadable = Vec::new();
            for (p, part) in bytes.chunks_mut(page).enumerate() {
                if mem
                    .read_exact_at(part, (range.start + p * page) as u64)
                    .is_err()
                {
                    part.fill(0);
                    unreadable.push(p * page);
                }
            }
            (bytes, unreadable)
        }

        /// Where the marks are in `bytes`, as distances of the first and last one from the
        /// END of `bytes` (the top of a stack), and how many.
        fn marks(bytes: &[u8]) -> String {
            let at: Vec<usize> = bytes
                .windows(MARK.len())
                .enumerate()
                .filter(|(_, w)| *w == MARK)
                .map(|(i, _)| bytes.len() - i)
                .collect();
            match (at.first(), at.last()) {
                (Some(deepest), Some(nearest)) => format!(
                    "{} marks, from {} to {} bytes below the top",
                    at.len(),
                    nearest,
                    deepest
                ),
                _ => "0 marks".to_owned(),
            }
        }

        let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
        // SAFETY: both return pointers to static NUL-terminated strings / fill a struct.
        let (libc_version, kernel) = unsafe {
            let version = std::ffi::CStr::from_ptr(libc::gnu_get_libc_version())
                .to_string_lossy()
                .into_owned();
            let mut name = std::mem::zeroed::<libc::utsname>();
            libc::uname(&mut name);
            let release = std::ffi::CStr::from_ptr(name.release.as_ptr())
                .to_string_lossy()
                .into_owned();
            (version, release)
        };
        let page = page_size();
        println!("ENV glibc {libc_version}, kernel {kernel}, page size {page}");
        println!(
            "ENV available parallelism {:?}, RUST_MIN_STACK {:?}",
            std::thread::available_parallelism().ok(),
            std::env::var("RUST_MIN_STACK").ok()
        );
        let own = own_thread_stack();
        println!(
            "ENV the searching thread's stack (pthread_getattr_np): {:#x}-{:#x}",
            own.start, own.end
        );

        for round in 1..=3 {
            let (ready_tx, ready_rx) = mpsc::channel::<(Range<usize>, usize, usize)>();
            let (go_tx, go_rx) = mpsc::channel::<()>();
            let worker = std::thread::spawn(move || {
                let marker = 0u8;
                let frame = std::hint::black_box(&marker) as *const u8 as usize;
                mark_the_stack();
                // SAFETY: as `own_thread_stack`, with the guard size read too.
                let guard = unsafe {
                    let mut attributes = std::mem::MaybeUninit::<libc::pthread_attr_t>::uninit();
                    libc::pthread_getattr_np(libc::pthread_self(), attributes.as_mut_ptr());
                    let mut guard = 0;
                    libc::pthread_attr_getguardsize(attributes.as_ptr(), &mut guard);
                    libc::pthread_attr_destroy(attributes.as_mut_ptr());
                    guard
                };
                ready_tx
                    .send((own_thread_stack(), guard, frame))
                    .expect("the test thread waits");
                let _ = go_rx.recv();
            });
            let (stack, guard, frame) = ready_rx.recv().expect("the worker is ready");
            println!(
                "ROUND {round} worker stack (pthread_getattr_np) {:#x}-{:#x} ({} KiB), guard size {guard}, its frame {} bytes below the top",
                stack.start,
                stack.end,
                stack.len() / 1024,
                stack.end - frame
            );
            let before = regions();
            for region in before
                .iter()
                .filter(|r| r.start < stack.end + (1 << 20) && stack.start < r.end + (1 << 20))
            {
                println!("ROUND {round}   maps (alive): {}", region.describe());
            }
            let holder = before
                .iter()
                .find(|r| (r.start..r.end).contains(&frame))
                .expect("the worker's frame is mapped");
            let merged = holder.start < own.end && own.start < holder.end;
            println!(
                "ROUND {round} the mapping holding the worker's frame is {} KiB and {} the searching thread's stack => the earlier search {} the worker's stack",
                (holder.end - holder.start) / 1024,
                if merged {
                    "ALSO HOLDS"
                } else {
                    "does not hold"
                },
                if merged { "LEFT OUT" } else { "searched" },
            );
            let below = before.iter().find(|r| r.end == holder.start);
            println!(
                "ROUND {round} the mapping below it: {}",
                below.map_or("none adjacent".to_owned(), |r| r.describe())
            );
            println!(
                "ROUND {round} the guard {} a mapping of its own",
                if before.iter().any(|r| r.perms.starts_with("---")
                    && r.end - r.start == guard
                    && (r.end == stack.start
                        || r.start + guard == stack.start
                        || r.end == holder.start))
                {
                    "is"
                } else {
                    "is NOT"
                }
            );
            // The earlier search: 1 MiB pieces (plus the longest needle), a failed piece dropped.
            let mem = std::fs::File::open("/proc/self/mem").expect("/proc/self/mem");
            let mut piece = vec![0u8; (1 << 20) + 32];
            let (mut pieces, mut dropped) = (0, 0);
            let mut at = holder.start;
            while at < holder.end {
                let len = (holder.end - at).min(piece.len());
                pieces += 1;
                if mem.read_exact_at(&mut piece[..len], at as u64).is_err() {
                    dropped += 1;
                }
                at += 1 << 20;
            }
            let whole = holder.start..holder.end;
            let (bytes, unreadable) = read(&whole);
            println!(
                "ROUND {round} /proc/self/mem over that mapping: {dropped} of {pieces} 1 MiB pieces fail; page by page {} pages unreadable (first at {:?} bytes above its start)",
                unreadable.len(),
                unreadable.first()
            );
            let in_stack =
                stack.start.max(whole.start) - whole.start..stack.end.min(whole.end) - whole.start;
            println!("ROUND {round} alive: {}", marks(&bytes[in_stack.clone()]));
            go_tx.send(()).expect("the worker waits");
            worker.join().expect("the worker ends");
            let after = regions();
            let still = after
                .iter()
                .filter(|r| r.start < stack.end && stack.start < r.end)
                .map(|r| r.describe())
                .collect::<Vec<_>>();
            println!("ROUND {round} ended: its stack's addresses are now in {still:?}");
            if !still.is_empty() {
                let (bytes, unreadable) = read(&stack);
                let zero_pages = bytes
                    .chunks(page)
                    .filter(|p| p.iter().all(|&b| b == 0))
                    .count();
                println!(
                    "ROUND {round} ended: {}; {} of {} pages read as zeros, {} unreadable",
                    marks(&bytes),
                    zero_pages,
                    bytes.len() / page,
                    unreadable.len()
                );
            }
        }

        // A stack of the test's own, its thread ended.
        let stack = OwnedStack::new();
        run_to_exit(&stack, mark_the_stack_twice);
        #[inline(never)]
        fn mark_the_stack_twice() {
            // Half the span of the ordinary thread's: this stack is 1 MiB in all.
            let mut area = [0u8; SPAN / 2];
            for at in (0..SPAN / 2).step_by(STEP) {
                for (i, byte) in MARK.iter().enumerate() {
                    // SAFETY: `at + i` is inside `area`.
                    unsafe { std::ptr::write_volatile(area.as_mut_ptr().add(at + i), *byte) };
                }
            }
            std::hint::black_box(&mut area);
        }
        let range = stack.range();
        // SAFETY: the stack is mapped and its thread has ended: nothing writes it.
        let bytes = unsafe { std::slice::from_raw_parts(range.start as *const u8, STACK_SIZE) };
        let untouched = bytes.iter().filter(|&&b| b == FILL).count();
        let zero_pages = bytes
            .chunks(page)
            .filter(|p| p.iter().all(|&b| b == 0))
            .count();
        println!(
            "OWNED stack, its thread ended: {}; {} bytes still hold the fill, {} of {} pages read as zeros",
            marks(bytes),
            untouched,
            zero_pages,
            STACK_SIZE / page
        );
    }
}
