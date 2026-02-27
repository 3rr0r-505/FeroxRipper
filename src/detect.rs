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

/// Parse a user-provided hash algorithm name/alias into a `HashType`.
/// Accepts common variants like `md5`, `MD5`, `sha-256`, `SHA256`, etc.
pub fn parse_hash_type(name: &str) -> Option<HashType> {
    let normalized = name.trim().to_ascii_lowercase();

    let algo = match normalized.as_str() {
        // MD5 / MD6
        "md5" => HashType::MD5,
        "md6" | "md6-256" | "md6_256" => HashType::MD6_256,
        "md6-512" | "md6_512" => HashType::MD6_512,

        // SHA-1
        "sha1" | "sha-1" => HashType::SHA1,

        // SHA-2
        "sha256" | "sha-256" => HashType::SHA256,
        "sha512" | "sha-512" => HashType::SHA512,

        // SHA-3
        "sha3" | "sha3-256" | "sha3_256" => HashType::SHA3_256,
        "sha3-512" | "sha3_512" => HashType::SHA3_512,

        // NTLM
        "ntlm" => HashType::NTLM,

        // Whirlpool
        "whirlpool" => HashType::Whirlpool,

        _ => return None,
    };

    Some(algo)
}
