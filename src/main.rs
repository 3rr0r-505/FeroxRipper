mod args;
mod banner;
mod detect;
mod cracker;

use std::sync::{Arc, Mutex};
use std::thread;
use std::sync::atomic::{AtomicBool, Ordering};

fn main() {
    banner::print_banner();
    let config = args::parse_args();

    // Detect possible algorithms based on hash characteristics
    let detected_algos = detect::detect_possible_hashes(&config.hash);

    // If the user specified an algorithm, try to honor it; otherwise use all detected algorithms
    let algos_to_use = if let Some(algo_str) = &config.algo {
        match detect::parse_hash_type(algo_str) {
            Some(algo) => vec![algo],
            None => {
                eprintln!("[-] Unknown hash format: {}", algo_str);
                std::process::exit(1);
            }
        }
    } else {
        detected_algos.clone()
    };

    let detected_algo = algos_to_use
        .iter()
        .map(|algo| algo.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    // Wordlist path
    let wordlist_path = config.wordlist.clone().unwrap_or_else(|| {
        let current_dir = std::env::current_dir().unwrap();
        let wordlist_dir = current_dir.join("wordlist");

        // Prefer a large default wordlist if present: ./wordlist/rockyou.txt
        let rockyou_path = wordlist_dir.join("rockyou.txt");
        if rockyou_path.exists() {
            return rockyou_path.to_string_lossy().into_owned();
        }

        // Fallback to a smaller bundled wordlist in the same folder: ./wordlist/wordlist.txt
        let small_default = wordlist_dir.join("wordlist.txt");
        small_default.to_string_lossy().into_owned()
    });

    println!("Provided Hash: {}", config.hash);
    println!("Hash Format: {}", detected_algo);
    println!("Wordlist: {}", wordlist_path);
    println!();
    println!("Ferris is cracking...");


    // Shared state to stop all threads if one succeeds
    let stop_flag = Arc::new(AtomicBool::new(false));
    // Mutex for shared data across threads
    let cracked_password = Arc::new(Mutex::new(None));

    let threads: Vec<_> = algos_to_use
        .into_iter()
        .map(|hash_type| {
            let stop_flag = Arc::clone(&stop_flag);
            let cracked_password = Arc::clone(&cracked_password);
            let hash = config.hash.clone();
            let wordlist = wordlist_path.clone();

            thread::spawn(move || {
                if stop_flag.load(Ordering::Relaxed) {
                    return;
                }

                let result = cracker::crack_hash(&hash, &wordlist, hash_type);

                if let Some(password) = result {
                    let mut password_guard = cracked_password.lock().unwrap();
                    *password_guard = Some(password);
                    stop_flag.store(true, Ordering::Relaxed);  // Stop all threads
                }
            })
        })
        .collect();

    // Join all threads and wait for one to succeed
    for thread in threads {
        thread.join().unwrap();
    }

    // If any thread cracked the password, print it
    if let Some(password) = cracked_password.lock().unwrap().take() {
        println!("Cracked Password: {}", password);
    } else {
        println!("Failed to crack the password.");
    }
}
