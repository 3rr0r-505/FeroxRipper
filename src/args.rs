use clap::{Arg, Command};
use std::env;
use std::process::exit;

pub struct Args {
    pub hash: String,
    pub algo: Option<String>,
    pub wordlist: Option<String>,
}

fn print_help() {
    println!(
        r#"
FeroxRipper - Fast hash cracker written in Rust

USAGE:
    feroxripper --hash <HASH> [OPTIONS]

OPTIONS:
    -h, --hash      <HASH>      Hash string to crack (required)
    -f, --format    <FORMAT>    Hash algorithm (optional, auto-detected if omitted)
    -w, --wordlist  <FILE>      Wordlist file (optional, see defaults below)
        --help                  Show this help message

SUPPORTED FORMATS:
    md5, sha1, sha256, sha512, sha3-256, sha3-512,
    ntlm, whirlpool, md6-256, md6-512

DEFAULT WORDLIST (in order of preference):
    1. ./wordlist/rockyou.txt   (unzip rockyou.zip first if needed)
    2. ./wordlist/wordlist.txt  (small bundled wordlist)

EXAMPLES:
    feroxripper --hash 0df70868a807d1cc89c11a41eb5b876f -f md5 -w rockyou.txt
    feroxripper -h 03e2ad3de8d21b93a4a35517d5666ed143bf63fc -w rock.txt
    feroxripper --hash 617B17D38947695A7BE15B61395F447B
    "#
    );
    exit(0);
}

pub fn parse_args() -> Args {
    // Handle --help manually before clap so our custom help is shown
    let raw: Vec<String> = env::args().collect();
    if raw.iter().any(|a| a == "--help") {
        print_help();
    }

    let matches = Command::new("FeroxRipper")
        .version("0.1.0")
        .about("Fast hash cracker written in Rust")
        .disable_help_flag(true)
        .arg(
            Arg::new("hash")
                .short('h')
                .long("hash")
                .help("Hash string to crack (required)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("algo")
                .short('f')
                .long("format")
                .help("Hash algorithm (optional, auto-detected if omitted)")
                .num_args(1),
        )
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .help("Wordlist file path (optional)")
                .num_args(1),
        )
        .get_matches();

    Args {
        hash:     matches.get_one::<String>("hash").unwrap().to_string(),
        algo:     matches.get_one::<String>("algo").map(|s| s.to_string()),
        wordlist: matches.get_one::<String>("wordlist").map(|s| s.to_string()),
    }
}
