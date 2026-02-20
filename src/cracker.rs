use crate::detect::HashType;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use hex::decode;
use ring::digest;
use ring::digest::Algorithm;

/// Attempts to crack the provided hash using a wordlist
/// `hash`: The hash to crack
/// `wordlist`: Path to the wordlist file
/// `hash_type`: The specific hash type (e.g., MD5, SHA256, etc.)
// Returns the cracked password if found, otherwise None.
pub fn crack_hash(hash: &str, wordlist: &str, hash_type: HashType) -> Option<String> {
    // Open the wordlist file
    let wordlist_path = Path::new(wordlist);
    let file = File::open(wordlist_path).expect("Unable to open wordlist file.");
    let reader = io::BufReader::new(file);

    // Iterate over each word in the wordlist and check if it matches the hash
    for line in reader.lines() {
        let password = line.expect("Error reading line from wordlist.");

        // Hash the current word with the detected hash algorithm
        if let Some(cracked_password) = match hash_type {
            HashType::MD5 => Some(crack_md5(&password, hash)),
            HashType::MD6_256 => Some(crack_md6_256(&password, hash)),
            HashType::MD6_512 => Some(crack_md6_512(&password, hash)),
            HashType::SHA1 => Some(crack_sha1(&password, hash)),
            HashType::SHA256 => Some(crack_sha256(&password, hash)),
            HashType::SHA512 => Some(crack_sha512(&password, hash)),
            HashType::SHA3_256 => Some(crack_sha3_256(&password, hash)),
            HashType::SHA3_512 => Some(crack_sha3_512(&password, hash)),
            HashType::NTLM => Some(crack_ntlm(&password, hash)),
            HashType::Whirlpool => Some(crack_whirlpool(&password, hash)),
            HashType::Unknown => None,
        } {
            if cracked_password {
                return Some(password);
            }
        }
    }

    // If no match found, return None
    None
}

// Cracks MD5 hash using ring
fn crack_md5(password: &str, hash: &str) -> bool {
    let md5_hash = digest::digest(&digest::MD5, password.as_bytes());
    match decode(hash) {
        Ok(decoded_hash) => md5_hash.as_ref() == decoded_hash,
        Err(_) => false,
    }
}

// Cracks MD6-256 hash (placeholder: MD6 is not natively supported in Rust)
fn crack_md6_256(password: &str, _hash: &str) -> bool {
    // Placeholder: MD6-256 is not implemented, return false
    false
}

// Cracks MD6-512 hash (placeholder: MD6 is not natively supported in Rust)
fn crack_md6_512(password: &str, _hash: &str) -> bool {
    // Placeholder: MD6-512 is not implemented, return false
    false
}

// Cracks SHA1 hash using ring
fn crack_sha1(password: &str, hash: &str) -> bool {
    let sha1_hash = digest::digest(&digest::SHA1, password.as_bytes());
    match decode(hash) {
        Ok(decoded_hash) => sha1_hash.as_ref() == decoded_hash,
        Err(_) => false,
    }
}

// Cracks SHA256 hash using ring
fn crack_sha256(password: &str, hash: &str) -> bool {
    let sha256_hash = digest::digest(&digest::SHA256, password.as_bytes());
    match decode(hash) {
        Ok(decoded_hash) => sha256_hash.as_ref() == decoded_hash,
        Err(_) => false,
    }
}

// Cracks SHA512 hash using ring
fn crack_sha512(password: &str, hash: &str) -> bool {
    let sha512_hash = digest::digest(&digest::SHA512, password.as_bytes());
    match decode(hash) {
        Ok(decoded_hash) => sha512_hash.as_ref() == decoded_hash,
        Err(_) => false,
    }
}

// Cracks SHA3-256 hash using ring
fn crack_sha3_256(password: &str, hash: &str) -> bool {
    let sha3_256_hash = digest::digest(&digest::SHA3_256, password.as_bytes());
    match decode(hash) {
        Ok(decoded_hash) => sha3_256_hash.as_ref() == decoded_hash,
        Err(_) => false,
    }
}

// Cracks SHA3-512 hash using ring
fn crack_sha3_512(password: &str, hash: &str) -> bool {
    let sha3_512_hash = digest::digest(&digest::SHA3_512, password.as_bytes());
    match decode(hash) {
        Ok(decoded_hash) => sha3_512_hash.as_ref() == decoded_hash,
        Err(_) => false,
    }
}

// Cracks NTLM hash (using a separate NTLM hash function)
fn crack_ntlm(password: &str, hash: &str) -> bool {
    // Assuming you have a separate NTLM hashing function
    let ntlm_hash = ntlm::hash(password.as_bytes());
    match decode(hash) {
        Ok(decoded_hash) => ntlm_hash == decoded_hash,
        Err(_) => false,
    }
}

// Cracks Whirlpool hash (use an external library or your own implementation)
fn crack_whirlpool(password: &str, hash: &str) -> bool {
    // Whirlpool hash using OpenSSL or another library
    false
}
