//! Property-based round-trip tests (kept fast: bounded cases).

use lp_crypto::{Envelope, SymmetricKey};
use proptest::prelude::*;

proptest! {
    // Keep case counts modest so the suite stays quick.
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// seal → to_bytes → from_bytes → open round-trips for arbitrary
    /// plaintext and AAD.
    #[test]
    fn seal_open_roundtrip_arbitrary(plaintext in proptest::collection::vec(any::<u8>(), 0..512),
                                     aad in proptest::collection::vec(any::<u8>(), 0..128)) {
        let key = SymmetricKey::generate();
        let envelope = key.seal(&plaintext, &aad).unwrap();
        let bytes = envelope.to_bytes();
        let parsed = Envelope::from_bytes(&bytes).unwrap();
        let opened = key.open(&parsed, &aad).unwrap();
        prop_assert_eq!(opened, plaintext);
    }

    /// Any wrong AAD (differing from the real one) must fail to open.
    #[test]
    fn wrong_aad_always_fails(plaintext in proptest::collection::vec(any::<u8>(), 0..256),
                              aad in proptest::collection::vec(any::<u8>(), 1..64),
                              other in proptest::collection::vec(any::<u8>(), 1..64)) {
        prop_assume!(aad != other);
        let key = SymmetricKey::generate();
        let envelope = key.seal(&plaintext, &aad).unwrap();
        prop_assert!(key.open(&envelope, &other).is_err());
    }

    /// Envelope::from_bytes must never panic on arbitrary input, and never
    /// accept an input whose first byte is not the version.
    #[test]
    fn from_bytes_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..128)) {
        let res = Envelope::from_bytes(&bytes);
        if let Some(&first) = bytes.first() {
            if first != 0x01 {
                prop_assert!(res.is_err());
            }
        } else {
            prop_assert!(res.is_err());
        }
    }
}
