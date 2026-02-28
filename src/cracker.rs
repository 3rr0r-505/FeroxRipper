#[allow(unused_imports)]
use crate::detect::HashType;
use hex::decode;
use md4::{Md4, Digest as Md4Digest};
use md5;
use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use whirlpool::Whirlpool;

// Bring Digest trait into scope for .update() / .finalize() / .new_with_prefix()
#[allow(unused_imports)]
use sha1::digest::Digest;

/// Attempts to crack `hash` by checking every word in `wordlist` against `hash_type`.
/// Returns the plaintext password if found, otherwise `None`.
///
/// Uses Rayon for parallel line processing with an early-exit flag.
pub fn crack_hash(hash: &str, wordlist: &str, hash_type: HashType) -> Option<String> {
    // Validate wordlist path up front for a clear error message
    let path = Path::new(wordlist);
    if !path.exists() {
        eprintln!("[-] Wordlist not found: {}", wordlist);
        return None;
    }

    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[-] Failed to open wordlist '{}': {}", wordlist, e);
            return None;
        }
    };

    // Pre-decode the hex target once so per-word comparisons are byte-level (fast).
    // NTLM compares hex strings so it doesn't use this.
    let decoded_target: Option<Vec<u8>> = decode(hash).ok();

    // Collect all lines into memory so Rayon can parallelise over them.
    // For very large wordlists (rockyou, ~133 MB) this is fine — it's I/O bound anyway
    // and we get a clean early-exit via the atomic flag.
    let lines: Vec<String> = io::BufReader::new(file)
        .lines()
        .filter_map(|l| l.ok())
        .collect();

    // Shared early-exit flag: once one thread finds the password it signals the rest to stop.
    let found = Arc::new(AtomicBool::new(false));

    let result = lines
        .par_iter()
        .find_any(|password| {
            // Bail out as soon as another thread has found the answer
            if found.load(Ordering::Relaxed) {
                return false;
            }

            let matched = match hash_type {
                HashType::MD5 => decoded_target
                    .as_deref()
                    .map(|t| crack_md5(password, t))
                    .unwrap_or(false),

                HashType::SHA1 => decoded_target
                    .as_deref()
                    .map(|t| crack_sha1(password, t))
                    .unwrap_or(false),

                HashType::SHA256 => decoded_target
                    .as_deref()
                    .map(|t| crack_sha256(password, t))
                    .unwrap_or(false),

                HashType::SHA512 => decoded_target
                    .as_deref()
                    .map(|t| crack_sha512(password, t))
                    .unwrap_or(false),

                HashType::SHA3_256 => decoded_target
                    .as_deref()
                    .map(|t| crack_sha3_256(password, t))
                    .unwrap_or(false),

                HashType::SHA3_512 => decoded_target
                    .as_deref()
                    .map(|t| crack_sha3_512(password, t))
                    .unwrap_or(false),

                HashType::NTLM => crack_ntlm(password, hash),

                HashType::Whirlpool => decoded_target
                    .as_deref()
                    .map(|t| crack_whirlpool(password, t))
                    .unwrap_or(false),

                // MD6 is not yet implemented
                HashType::MD6_256 | HashType::MD6_512 => false,

                HashType::Unknown => false,
            };

            if matched {
                found.store(true, Ordering::Relaxed);
            }
            matched
        })
        .cloned();

    result
}

// ── Individual hash functions ────────────────────────────────────────────────

fn crack_md5(password: &str, target: &[u8]) -> bool {
    let digest = md5::compute(password.as_bytes());
    digest.as_ref() == target
}

fn crack_sha1(password: &str, target: &[u8]) -> bool {
    let mut h = Sha1::new();
    h.update(password.as_bytes());
    h.finalize().as_slice() == target
}

fn crack_sha256(password: &str, target: &[u8]) -> bool {
    Sha256::new_with_prefix(password.as_bytes())
        .finalize()
        .as_slice()
        == target
}

fn crack_sha512(password: &str, target: &[u8]) -> bool {
    Sha512::new_with_prefix(password.as_bytes())
        .finalize()
        .as_slice()
        == target
}

fn crack_sha3_256(password: &str, target: &[u8]) -> bool {
    let mut h = Sha3_256::new();
    h.update(password.as_bytes());
    h.finalize().as_slice() == target
}

fn crack_sha3_512(password: &str, target: &[u8]) -> bool {
    let mut h = Sha3_512::new();
    h.update(password.as_bytes());
    h.finalize().as_slice() == target
}

/// NTLM = MD4( UTF-16LE(password) )
///
/// This replaces the `ntlm-hash` crate which was limited to 31-character passwords
/// and had no meaningful maintenance. The implementation is correct per MS-NLMP spec.
fn crack_ntlm(password: &str, hash: &str) -> bool {
    // Encode password as UTF-16 little-endian (what Windows uses internally)
    let utf16le: Vec<u8> = password
        .encode_utf16()
        .flat_map(|c| c.to_le_bytes())
        .collect();

    let mut h = Md4::new();
    h.update(&utf16le);
    let digest = h.finalize();

    // Compare as lowercase hex strings (case-insensitive)
    hex::encode(digest).eq_ignore_ascii_case(hash)
}

fn crack_whirlpool(password: &str, target: &[u8]) -> bool {
    let mut h = Whirlpool::new();
    h.update(password.as_bytes());
    h.finalize().as_slice() == target
}