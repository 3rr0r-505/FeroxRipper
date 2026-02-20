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
Usage: feroxripper [options]... hash |hash string|, format |hash format|, wordlist

Options:
      -h, --hash       string      The hash string to crack (mandatory)
      -f, --format     string      Specify the hash algorithm (optional, auto-detect supported)
      -w, --wordlist   string      Specify the wordlist file (optional, default: rockyou.txt)

Examples:
       feroxripper --hash 0df70868a807d1cc89c11a41eb5b876f -f md5 --wordlist word.txt
       feroxripper -h 03e2ad3de8d21b93a4a35517d5666ed143bf63fc -w rock.txt
       feroxripper --hash 617B17D38947695A7BE15B61395F447B
    "#
    );
    exit(0);
}

pub fn parse_args() -> Args {
    // Check if the user provided --help BEFORE parsing arguments
    let args: Vec<String> = env::args().collect();
    if args.contains(&"--help".to_string()) {
        print_help();
    }

    let matches = Command::new("FeroxRipper")
        .version("0.1.0")
        .about("A simple hash cracker")
        .disable_help_flag(true) // Disable automatic help flag
        .arg(
            Arg::new("hash")
                .short('h')
                .long("hash")
                .help("The hash string to crack (mandatory)")
                .required(true)
                .num_args(1),
        )
        .arg(
            Arg::new("algo")
                .short('f')
                .long("format")
                .help("Specify the hash algorithm (optional, auto-detect supported)")
                .num_args(1),
        )
        .arg(
            Arg::new("wordlist")
                .short('w')
                .long("wordlist")
                .help("Specify the wordlist file (optional, default: rockyou.txt)")
                .num_args(1),
        )
        .get_matches();

    Args {
        hash: matches.get_one::<String>("hash").unwrap().to_string(),
        algo: matches.get_one::<String>("algo").map(|s| s.to_string()),
        wordlist: matches.get_one::<String>("wordlist").map(|s| s.to_string()),
    }
}
