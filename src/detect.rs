use regex::Regex;
use std::fmt;

/// All supported hash algorithms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashType {
    MD5,
    MD6_256,
    MD6_512,
    SHA1,
    SHA256,
    SHA512,
    SHA3_256,
    SHA3_512,
    NTLM,
    Whirlpool,
    Unknown,
}

impl fmt::Display for HashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let name = match self {
            HashType::MD5       => "MD5",
            HashType::MD6_256   => "MD6-256",
            HashType::MD6_512   => "MD6-512",
            HashType::SHA1      => "SHA1",
            HashType::SHA256    => "SHA256",
            HashType::SHA512    => "SHA512",
            HashType::SHA3_256  => "SHA3-256",
            HashType::SHA3_512  => "SHA3-512",
            HashType::NTLM      => "NTLM",
            HashType::Whirlpool => "Whirlpool",
            HashType::Unknown   => "Unknown",
        };
        write!(f, "{}", name)
    }
}

/// Returns all possible hash types based on the length and content of the hash string.
pub fn detect_possible_hashes(hash: &str) -> Vec<HashType> {
    // Must be a valid hex string
    let hex_regex = Regex::new(r"^[a-fA-F0-9]+$").unwrap();
    if !hex_regex.is_match(hash) {
        return vec![HashType::Unknown];
    }

    match hash.len() {
        32  => vec![HashType::MD5, HashType::NTLM],
        40  => vec![HashType::SHA1],
        64  => vec![HashType::SHA256, HashType::SHA3_256, HashType::MD6_256],
        128 => vec![HashType::SHA512, HashType::SHA3_512, HashType::Whirlpool, HashType::MD6_512],
        _   => vec![HashType::Unknown],
    }
}

/// Parses a user-supplied algorithm name into a `HashType`.
/// Case-insensitive; accepts common aliases (e.g. "sha-256", "sha256", "SHA256").
pub fn parse_hash_type(name: &str) -> Option<HashType> {
    let n = name.trim().to_ascii_lowercase();
    let algo = match n.as_str() {
        "md5"                           => HashType::MD5,
        "md6" | "md6-256" | "md6_256"  => HashType::MD6_256,
        "md6-512" | "md6_512"           => HashType::MD6_512,
        "sha1" | "sha-1"                => HashType::SHA1,
        "sha256" | "sha-256"            => HashType::SHA256,
        "sha512" | "sha-512"            => HashType::SHA512,
        "sha3" | "sha3-256" | "sha3_256" => HashType::SHA3_256,
        "sha3-512" | "sha3_512"         => HashType::SHA3_512,
        "ntlm"                          => HashType::NTLM,
        "whirlpool"                     => HashType::Whirlpool,
        _                               => return None,
    };
    Some(algo)
}
