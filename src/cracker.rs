#[allow(unused_imports)]
use crate::detect::HashType;
use hex::decode;
use md4::{Digest as Md4Digest, Md4};
use md5;
use rayon::prelude::*;
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use sha3::{Sha3_256, Sha3_512};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use whirlpool::Whirlpool;

#[allow(unused_imports)]
use sha1::digest::Digest;

// 1MB read buffer — reduces syscalls from ~17,000 to ~133 for rockyou.txt
const BUF_SIZE: usize = 1024 * 1024;

// Chunk size for parallel processing — each Rayon worker gets 2000 lines at a time,
// avoiding the mutex contention bottleneck of par_bridge() on a raw line iterator
const CHUNK_SIZE: usize = 2000;

pub fn crack_hash(hash: &str, wordlist: &str, hash_type: HashType) -> Option<String> {
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

    // Pre-decode target hash bytes once — used by all algorithms except NTLM
    let hash_lower = hash.to_ascii_lowercase();
    let decoded_target: Option<Vec<u8>> = decode(&hash_lower).ok();

    // NTLM target as fixed-size byte array — enables zero-alloc byte comparison
    let ntlm_target: Option<[u8; 16]> = decoded_target.as_deref().and_then(|b| {
        if b.len() == 16 { b.try_into().ok() } else { None }
    });

    // Resolve the hash function ONCE before the loop as a closure.
    // This guarantees the match is never evaluated inside the hot path —
    // the compiler cannot always prove hash_type is loop-invariant across threads.
    let check: Box<dyn Fn(&str) -> bool + Send + Sync> = match hash_type {
        HashType::MD5 => {
            let t = decoded_target.clone();
            Box::new(move |p| t.as_deref().map(|b| crack_md5(p, b)).unwrap_or(false))
        }
        HashType::SHA1 => {
            let t = decoded_target.clone();
            Box::new(move |p| t.as_deref().map(|b| crack_sha1(p, b)).unwrap_or(false))
        }
        HashType::SHA256 => {
            let t = decoded_target.clone();
            Box::new(move |p| t.as_deref().map(|b| crack_sha256(p, b)).unwrap_or(false))
        }
        HashType::SHA512 => {
            let t = decoded_target.clone();
            Box::new(move |p| t.as_deref().map(|b| crack_sha512(p, b)).unwrap_or(false))
        }
        HashType::SHA3_256 => {
            let t = decoded_target.clone();
            Box::new(move |p| t.as_deref().map(|b| crack_sha3_256(p, b)).unwrap_or(false))
        }
        HashType::SHA3_512 => {
            let t = decoded_target.clone();
            Box::new(move |p| t.as_deref().map(|b| crack_sha3_512(p, b)).unwrap_or(false))
        }
        HashType::NTLM => {
            Box::new(move |p| ntlm_target.map(|t| crack_ntlm(p, &t)).unwrap_or(false))
        }
        HashType::Whirlpool => {
            let t = decoded_target.clone();
            Box::new(move |p| t.as_deref().map(|b| crack_whirlpool(p, b)).unwrap_or(false))
        }
        HashType::MD6_256 | HashType::MD6_512 | HashType::Unknown => {
            Box::new(|_| false)
        }
    };

    // Read the entire file into a string buffer with a large I/O buffer.
    // This is faster than line-by-line BufReader for large files because
    // it does far fewer syscalls and lets us split + chunk on our own terms.
    // Read as raw bytes first, then convert to string lossily.
    // This handles files with non-UTF-8 encoding (e.g. Windows-1252) gracefully
    // instead of silently returning None and skipping the entire wordlist.
    let mut raw_bytes = Vec::new();
    io::BufReader::with_capacity(BUF_SIZE, file)
        .read_to_end(&mut raw_bytes)
        .ok()?;
    let raw = String::from_utf8(raw_bytes)
        .unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned());

    // Split into lines, chunk into groups, process chunks in parallel.
    // Each Rayon worker owns a full chunk — no mutex contention between workers.
    let lines: Vec<&str> = raw.lines().collect();

    lines
        .par_chunks(CHUNK_SIZE)
        .find_map_any(|chunk| {
            chunk.iter().find(|&&pw| check(pw)).map(|s| s.to_string())
        })
}

// ── Individual hash functions ────────────────────────────────────────────────

#[inline(always)]
fn crack_md5(password: &str, target: &[u8]) -> bool {
    md5::compute(password.as_bytes()).as_ref() == target
}

#[inline(always)]
fn crack_sha1(password: &str, target: &[u8]) -> bool {
    let mut h = Sha1::new();
    h.update(password.as_bytes());
    h.finalize().as_slice() == target
}

#[inline(always)]
fn crack_sha256(password: &str, target: &[u8]) -> bool {
    Sha256::new_with_prefix(password.as_bytes())
        .finalize()
        .as_slice()
        == target
}

#[inline(always)]
fn crack_sha512(password: &str, target: &[u8]) -> bool {
    Sha512::new_with_prefix(password.as_bytes())
        .finalize()
        .as_slice()
        == target
}

#[inline(always)]
fn crack_sha3_256(password: &str, target: &[u8]) -> bool {
    let mut h = Sha3_256::new();
    h.update(password.as_bytes());
    h.finalize().as_slice() == target
}

#[inline(always)]
fn crack_sha3_512(password: &str, target: &[u8]) -> bool {
    let mut h = Sha3_512::new();
    h.update(password.as_bytes());
    h.finalize().as_slice() == target
}

/// NTLM = MD4( UTF-16LE(password) )
/// Stack-allocates the UTF-16LE buffer (covers passwords up to 128 UTF-16 chars).
/// Compares digest bytes directly — zero heap allocation for the common case.
#[inline(always)]
fn crack_ntlm(password: &str, target: &[u8; 16]) -> bool {
    let mut buf = [0u8; 256];
    let mut len = 0;

    for unit in password.encode_utf16() {
        if len + 2 > buf.len() {
            // Heap fallback for unusually long passwords (>128 UTF-16 chars)
            let heap: Vec<u8> = password
                .encode_utf16()
                .flat_map(|c| c.to_le_bytes())
                .collect();
            let mut h = Md4::new();
            h.update(&heap);
            return h.finalize().as_slice() == target;
        }
        let bytes = unit.to_le_bytes();
        buf[len]     = bytes[0];
        buf[len + 1] = bytes[1];
        len += 2;
    }

    let mut h = Md4::new();
    h.update(&buf[..len]);
    h.finalize().as_slice() == target
}

#[inline(always)]
fn crack_whirlpool(password: &str, target: &[u8]) -> bool {
    let mut h = Whirlpool::new();
    h.update(password.as_bytes());
    h.finalize().as_slice() == target
}