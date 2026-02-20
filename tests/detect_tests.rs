use feroxripper::detect::{detect_possible_hashes, HashType};

#[test]
fn test_md5_detection() {
    let hashes = detect_possible_hashes("0df70868a807d1cc89c11a41eb5b876f");
    assert!(hashes.contains(&HashType::MD5));
}

#[test]
fn test_md6_256_detection() {
    let hashes = detect_possible_hashes("6a62eb7a36c5c05472f5b2a823a8d27b5e4035e763a1c62eb76b05fdba60133b");
    assert!(hashes.contains(&HashType::MD6_256));
}

#[test]
fn test_md6_512_detection() {
    let hashes = detect_possible_hashes(
        "9061f1c1fbdc2bb9996a5c82cb83b24857e60c2c67e0a99a74047662c8883e64d4f68799e524d8bdf263fc8ec178ee50347c29ae44fa0ecb544fc18f50d584a8"
    );
    assert!(hashes.contains(&HashType::MD6_512));
}

#[test]
fn test_sha1_detection() {
    let hashes = detect_possible_hashes("03e2ad3de8d21b93a4a35517d5666ed143bf63fc");
    assert!(hashes.contains(&HashType::SHA1));
}

#[test]
fn test_sha256_detection() {
    let hashes = detect_possible_hashes("617b17d38947695a7be15b61395f447b617b17d38947695a7be15b61395f447b");
    assert!(hashes.contains(&HashType::SHA256));
}

#[test]
fn test_sha512_detection() {
    let hashes = detect_possible_hashes(
        "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
    );
    assert!(hashes.contains(&HashType::SHA512));
}

#[test]
fn test_sha3_256_detection() {
    let hashes = detect_possible_hashes("a63f3d5b9cc6dcbd26e06b7f0d118f21a3d2f3969b5e45e6be6341d22fc1286b");
    assert!(hashes.contains(&HashType::SHA3_256));
}

#[test]
fn test_sha3_512_detection() {
    let hashes = detect_possible_hashes(
        "a6cd610a4f54727ebee30856db9116f979b3b848d42bafc44c62f123e0a73cc4031e90208e1dbac6c5d4cf6713c9dbf57c8aaff60b11ecbb4b56cb9a1fc2ed31"
    );
    assert!(hashes.contains(&HashType::SHA3_512));
}

#[test]
fn test_ntlm_detection() {
    let hashes = detect_possible_hashes("31d6cfe0d16ae931b73c59d7e0c089c0");
    assert!(hashes.contains(&HashType::NTLM));
}

#[test]
fn test_whirlpool_detection() {
    let hashes = detect_possible_hashes(
        "b97de3c078f5a90cf653f2f034e5a6a62dcac72715136c7c37d1f1e44f3e9b6b87fa35ba2d7058b2b63075b8310a1f4dfbc120b2e7fa77f39b0c61c5a2f79ac6"
    );
    assert!(hashes.contains(&HashType::Whirlpool));
}

#[test]
fn test_unknown_hash() {
    let hashes = detect_possible_hashes("notavalidhash123");
    assert_eq!(hashes, vec![HashType::Unknown]);
}
