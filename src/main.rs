mod args;
mod banner;
mod cracker;
mod detect;

use std::fs;
use std::path::PathBuf;
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
    // If -w is explicitly set, use only that file.
    // If the path doesn't exist as-is, also try looking it up inside ./wordlist/
    // so that `-w top-200.txt` works without needing the full path.
    // Otherwise, discover all .txt files in ./wordlist/ and try them all in order:
    //   1. wordlist.txt first (small/fast)
    //   2. rockyou.txt second (large)
    //   3. any other .txt files found in the folder
    let wordlists: Vec<PathBuf> = if let Some(ref w) = config.wordlist {
        let given = PathBuf::from(w);
        if given.exists() {
            // exact path works — use it directly
            vec![given]
        } else {
            // try resolving as a filename inside ./wordlist/
            let fallback = std::env::current_dir()
                .unwrap()
                .join("wordlist")
                .join(&given);
            if fallback.exists() {
                println!("[!] '{}' not found directly, using wordlist/{} instead.", w, w);
                vec![fallback]
            } else {
                eprintln!("[-] Wordlist not found: '{}' (also tried wordlist/{})", w, w);
                std::process::exit(1);
            }
        }
    } else {
        let base = std::env::current_dir().unwrap().join("wordlist");

        if !base.exists() {
            eprintln!("[-] No wordlist/ folder found. Use -w to specify a wordlist.");
            std::process::exit(1);
        }

        // Check for rockyou.zip hint before building the list
        let rockyou_txt = base.join("rockyou.txt");
        let rockyou_zip = base.join("rockyou.zip");
        if !rockyou_txt.exists() && rockyou_zip.exists() {
            println!("[!] rockyou.zip detected but rockyou.txt is missing.");
            println!("[!] Tip: cd wordlist && unzip rockyou.zip  to unlock it.");
        }

        // Collect all .txt files, putting wordlist.txt first, rockyou.txt second,
        // then everything else alphabetically
        let mut files: Vec<PathBuf> = fs::read_dir(&base)
            .expect("Failed to read wordlist/ directory")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().map(|e| e == "txt").unwrap_or(false))
            .collect();

        // Sort: wordlist.txt → rockyou.txt → rest alphabetically
        files.sort_by(|a, b| {
            let name_a = a.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            let name_b = b.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
            let rank = |n: &str| match n {
                "wordlist.txt" => 0,
                "rockyou.txt"  => 1,
                _              => 2,
            };
            rank(&name_a).cmp(&rank(&name_b)).then(name_a.cmp(&name_b))
        });

        if files.is_empty() {
            eprintln!("[-] No .txt wordlist files found in wordlist/ folder.");
            eprintln!("[-] Use -w to specify a wordlist explicitly.");
            std::process::exit(1);
        }

        files
    };

    let algo_display = algos_to_try
        .iter()
        .map(|a| a.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    println!("[*] Hash   : {}", config.hash);
    println!("[*] Format : {}", algo_display);
    println!();

    // ── Cracking — iterate wordlists, then algorithms ─────────────────────────
    let timer = Instant::now();
    let mut cracked: Option<(detect::HashType, String, String)> = None;

    'outer: for wordlist in &wordlists {
        let wl_display = wordlist.display().to_string();
        println!("[*] Wordlist: {}", wl_display);

        for algo in &algos_to_try {
            println!("[~] Trying {} ...", algo);
            if let Some(password) = cracker::crack_hash(&config.hash, &wl_display, *algo) {
                cracked = Some((*algo, password, wl_display));
                break 'outer;
            }
        }

        println!("[-] Not found in '{}', trying next wordlist...", wordlist.file_name().unwrap_or_default().to_string_lossy());
        println!();
    }

    let elapsed = timer.elapsed();

    // ── Result ────────────────────────────────────────────────────────────────
    println!();
    match cracked {
        Some((algo, password, wordlist)) => {
            println!("[+] Hash cracked!");
            println!("[+] Algorithm : {}", algo);
            println!("[+] Password  : {}", password);
            println!("[+] Wordlist  : {}", wordlist);
        }
        None => {
            println!("[-] Password not found in any wordlist.");
        }
    }
    println!("[*] Time elapsed: {:.2?}", elapsed);
}