//! HMAC-SHA1 of every built-in provider against RFC 2202 section 3 (test cases 1 to 7), and
//! one keyed object used again and again: the providers compute a MAC in the keyed object
//! and put it back for the next one, so the second MAC of an object is as much under test as
//! the first, with the message handed over in one part and in several.

use std::sync::Arc;

use rtci_crypto::{HmacAlgorithm, RTCCryptoProvider};

#[allow(clippy::vec_init_then_push)]
fn providers() -> Vec<Arc<dyn RTCCryptoProvider>> {
    let mut providers: Vec<Arc<dyn RTCCryptoProvider>> = Vec::new();
    #[cfg(feature = "crypto-ring")]
    providers.push(Arc::new(rtci_crypto::providers::RingProvider::new()));
    #[cfg(feature = "crypto-aws-lc-rs")]
    providers.push(Arc::new(rtci_crypto::providers::AwsLcRsProvider::new()));
    providers
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
        .collect()
}

const CASES: [(&[u8], &[u8], &str); 7] = [
    (
        &[0x0b; 20],
        b"Hi There",
        "b617318655057264e28bc0b6fb378c8ef146be00",
    ),
    (
        b"Jefe",
        b"what do ya want for nothing?",
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79",
    ),
    (
        &[0xaa; 20],
        &[0xdd; 50],
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3",
    ),
    (
        &[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        ],
        &[0xcd; 50],
        "4c9007f4026250c6bc8414f9bf50c86c2d7235da",
    ),
    (
        &[0x0c; 20],
        b"Test With Truncation",
        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04",
    ),
    (
        &[0xaa; 80],
        b"Test Using Larger Than Block-Size Key - Hash Key First",
        "aa4ae5e15272d00e95705637ce8a3b55ed402112",
    ),
    (
        &[0xaa; 80],
        b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data",
        "e8e99d0f45237d786d6bbaa7965c7808bbff1a91",
    ),
];

#[test]
fn hmac_sha1_matches_rfc_2202_with_every_provider_and_a_keyed_object_is_reusable() {
    for provider in providers() {
        for (n, (key, data, expected)) in CASES.iter().enumerate() {
            let expected = hex(expected);
            let mut mac = provider
                .crypto()
                .new_hmac(HmacAlgorithm::Sha1, key)
                .expect("a keyed HMAC-SHA1");
            assert_eq!(20, mac.output_len());
            // Whole, then split at every position, then whole again: the same object.
            let mut splits: Vec<usize> = (0..=data.len()).collect();
            splits.push(0);
            for (use_number, split) in splits.into_iter().enumerate() {
                let (head, tail) = data.split_at(split);
                let mut tag = [0u8; 20];
                mac.sign(&[head, &[], tail], &mut tag).expect("a tag");
                assert_eq!(
                    expected,
                    tag,
                    "{} test case {}, use {use_number} of the object, split at {split}",
                    provider.name(),
                    n + 1
                );
                mac.verify(&[data], &tag).expect("the tag verifies");
                let mut wrong = tag;
                wrong[0] ^= 0x80;
                assert!(mac.verify(&[data], &wrong).is_err());
            }
        }
    }
}
