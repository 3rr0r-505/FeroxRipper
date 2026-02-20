use regex::Regex;
use std::fmt;

/// Supported hash algorithms
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
        write!(
            f,
            "{}",
            match self {
                HashType::MD5 => "MD5",
                HashType::MD6_256 => "MD6-256",
                HashType::MD6_512 => "MD6-512",
                HashType::SHA1 => "SHA1",
                HashType::SHA256 => "SHA256",
                HashType::SHA512 => "SHA512",
                HashType::SHA3_256 => "SHA3-256",
                HashType::SHA3_512 => "SHA3-512",
                HashType::NTLM => "NTLM",
                HashType::Whirlpool => "Whirlpool",
                HashType::Unknown => "Unknown",
            }
        )
    }
}

/// Returns all possible hash types based on the given hash string
pub fn detect_possible_hashes(hash: &str) -> Vec<HashType> {
    let length = hash.len();

    // Ensure the input is a valid hex string
    let hex_regex = Regex::new(r"^[a-fA-F0-9]+$").unwrap();
    if !hex_regex.is_match(hash) {
        return vec![HashType::Unknown];
    }

    match length {
        32 => vec![HashType::MD5, HashType::NTLM], // Both MD5 and NTLM are possible
        40 => vec![HashType::SHA1],
        64 => vec![HashType::SHA256, HashType::SHA3_256, HashType::MD6_256],
        128 => vec![HashType::SHA512, HashType::SHA3_512, HashType::Whirlpool, HashType::MD6_512],
        _ => vec![HashType::Unknown], // No common hash type matches this length
    }
}
