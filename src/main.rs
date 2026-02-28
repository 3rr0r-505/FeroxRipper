mod args;
mod banner;
mod cracker;
mod detect;

use std::time::Instant;

fn main() {
    banner::print_banner();

    let config = args::parse_args();

    // ── Hash format resolution ────────────────────────────────────────────────
    let algos_to_try: Vec<detect::HashType> = if let Some(ref algo_str) = config.algo {
        match detect::parse_hash_type(algo_str) {
            Some(algo) => vec![algo],
            None => {
                eprintln!("[-] Unknown algorithm '{}'. Run with --help to see supported formats.", algo_str);
                std::process::exit(1);
            }
        }
    } else {
        let detected = detect::detect_possible_hashes(&config.hash);
        if detected == vec![detect::HashType::Unknown] {
            eprintln!("[-] Could not detect hash type. Please specify one with -f/--format.");
            std::process::exit(1);
        }
        detected
    };

    // ── Wordlist resolution ───────────────────────────────────────────────────
    let wordlist_path = config.wordlist.clone().unwrap_or_else(|| {
        let base = std::env::current_dir()
            .unwrap()
            .join("wordlist");
        let rockyou = base.join("rockyou.txt");
        if rockyou.exists() {
            return rockyou.to_string_lossy().into_owned();
        }
        base.join("wordlist.txt").to_string_lossy().into_owned()
    });

    let algo_display = algos_to_try
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    println!("[*] Hash    : {}", config.hash);
    println!("[*] Format  : {}", algo_display);
    println!("[*] Wordlist: {}", wordlist_path);
    println!();

    // ── Cracking ─────────────────────────────────────────────────────────────
    // Try each candidate algorithm in order; stop as soon as one succeeds.
    // Each call to crack_hash uses Rayon internally for parallel line processing.
    let timer = Instant::now();
    let mut cracked: Option<(detect::HashType, String)> = None;

    for algo in &algos_to_try {
        println!("[~] Trying {} ...", algo);
        if let Some(password) = cracker::crack_hash(&config.hash, &wordlist_path, *algo) {
            cracked = Some((*algo, password));
            break;
        }
    }

    let elapsed = timer.elapsed();

    // ── Result ────────────────────────────────────────────────────────────────
    println!();
    match cracked {
        Some((algo, password)) => {
            println!("[+] Hash cracked!");
            println!("[+] Algorithm : {}", algo);
            println!("[+] Password  : {}", password);
        }
        None => {
            println!("[-] Password not found in wordlist.");
        }
    }
    println!("[*] Time elapsed: {:.2?}", elapsed);
}
