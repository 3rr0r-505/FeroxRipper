use crate::detect::HashType;
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use hex::decode;
use md5;
use ntlm_hash;
use sha1::{Digest as Sha1Digest, Sha1};
use sha2::{Digest as Sha2Digest, Sha256, Sha512};
use sha3::{Digest as Sha3Digest, Sha3_256, Sha3_512};
use whirlpool::{Digest as WhirlpoolDigest, Whirlpool};

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

    // Pre-decode the target hash once when possible
    let decoded_target = decode(hash).ok();

    // Iterate over each word in the wordlist and check if it matches the hash
    for line in reader.lines() {
        let password = line.expect("Error reading line from wordlist.");

        // Hash the current word with the detected hash algorithm
        if let Some(cracked_password) = match hash_type {
            HashType::MD5 => decoded_target.as_ref().map(|target| crack_md5(&password, target)),
            HashType::MD6_256 => Some(crack_md6_256(&password, hash)),
            HashType::MD6_512 => Some(crack_md6_512(&password, hash)),
            HashType::SHA1 => decoded_target.as_ref().map(|target| crack_sha1(&password, target)),
            HashType::SHA256 => decoded_target.as_ref().map(|target| crack_sha256(&password, target)),
            HashType::SHA512 => decoded_target.as_ref().map(|target| crack_sha512(&password, target)),
            HashType::SHA3_256 => decoded_target.as_ref().map(|target| crack_sha3_256(&password, target)),
            HashType::SHA3_512 => decoded_target.as_ref().map(|target| crack_sha3_512(&password, target)),
            HashType::NTLM => Some(crack_ntlm(&password, hash)),
            HashType::Whirlpool => decoded_target.as_ref().map(|target| crack_whirlpool(&password, target)),
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

// Cracks MD5 hash
fn crack_md5(password: &str, target: &[u8]) -> bool {
    let digest = md5::compute(password.as_bytes());
    digest.as_ref() == target
}

// Cracks MD6-256 hash (placeholder: MD6 is not natively supported in Rust)
fn crack_md6_256(_password: &str, _hash: &str) -> bool {
    // Placeholder: MD6-256 is not implemented, return false
    false
}

// Cracks MD6-512 hash (placeholder: MD6 is not natively supported in Rust)
fn crack_md6_512(_password: &str, _hash: &str) -> bool {
    // Placeholder: MD6-512 is not implemented, return false
    false
}

// Cracks SHA1 hash
fn crack_sha1(password: &str, target: &[u8]) -> bool {
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    digest.as_slice() == target
}

// Cracks SHA256 hash
fn crack_sha256(password: &str, target: &[u8]) -> bool {
    let digest = Sha256::new_with_prefix(password.as_bytes()).finalize();
    digest.as_slice() == target
}

// Cracks SHA512 hash
fn crack_sha512(password: &str, target: &[u8]) -> bool {
    let digest = Sha512::new_with_prefix(password.as_bytes()).finalize();
    digest.as_slice() == target
}

// Cracks SHA3-256 hash
fn crack_sha3_256(password: &str, target: &[u8]) -> bool {
    let mut hasher = Sha3_256::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    digest.as_slice() == target
}

// Cracks SHA3-512 hash
fn crack_sha3_512(password: &str, target: &[u8]) -> bool {
    let mut hasher = Sha3_512::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    digest.as_slice() == target
}

// Cracks NTLM hash using the `ntlm-hash` crate (compares hex strings, case-insensitive)
fn crack_ntlm(password: &str, hash: &str) -> bool {
    let computed = ntlm_hash::ntlm_hash(password);
    computed.eq_ignore_ascii_case(hash)
}

// Cracks Whirlpool hash
fn crack_whirlpool(password: &str, target: &[u8]) -> bool {
    let mut hasher = Whirlpool::new();
    hasher.update(password.as_bytes());
    let digest = hasher.finalize();
    digest.as_slice() == target
}
