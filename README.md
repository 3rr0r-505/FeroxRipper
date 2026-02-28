# FeroxRipper

<div align="center">

```
  +--------------------------------------------------------------+
  |     ______                     ____  _                       |
  |    / ____/__  _________  _  __/ __ \(_)___  ____  ___  _____ |
  |   / /_  / _ \/ ___/ __ \| |/_/ /_/ / / __ \/ __ \/ _ \/ ___/ |
  |  / __/ /  __/ /  / /_/ />  </ _, _/ / /_/ / /_/ /  __/ /     |
  | /_/    \___/_/   \____/_/|_/_/ |_/_/ .___/ .___/\___/_/      |
  |                                   /_/   /_/                  |
  +--------------------------------------------------------------+
```

**Fast and efficient dictionary-based hash cracker built with Rust.**

[![Rust](https://img.shields.io/badge/Rust-%3E%3D1.50-orange?logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/3rr0r-505/FeroxRipper/blob/main/LICENSE)
[![Latest Release](https://img.shields.io/github/v/release/3rr0r-505/FeroxRipper?color=green&label=Latest)](https://github.com/3rr0r-505/FeroxRipper/releases)
[![CI](https://img.shields.io/github/actions/workflow/status/3rr0r-505/FeroxRipper/ci.yml?label=CI&logo=githubactions&logoColor=white)](https://github.com/3rr0r-505/FeroxRipper/actions)
[![Issues](https://img.shields.io/github/issues/3rr0r-505/FeroxRipper?label=Issues)](https://github.com/3rr0r-505/FeroxRipper/issues)
[![Pull Requests](https://img.shields.io/github/issues-pr/3rr0r-505/FeroxRipper?label=PRs)](https://github.com/3rr0r-505/FeroxRipper/pulls)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-informational)](https://github.com/3rr0r-505/FeroxRipper/releases)

</div>

---

## 📖 Overview

**FeroxRipper** is a command-line hash cracker written in Rust, designed for speed and efficiency. It uses dictionary-based attacks to recover plaintext passwords from their hash digests, with parallel processing powered by Rayon to maximise throughput across all CPU cores.

---

## ✨ Features

- 🔐 **Multi-Algorithm Support** — MD5, SHA1, SHA256, SHA512, SHA3-256, SHA3-512, NTLM, Whirlpool
- 📖 **Dictionary Attacks** — use any wordlist, with smart auto-discovery of available wordlists
- ⚡ **Parallel Cracking** — Rayon-powered multi-core processing with early exit on first match
- 🔎 **Auto Hash Detection** — automatically detects possible hash algorithms from hash length
- 🗂️ **Multi-Wordlist Fallback** — tries all wordlists in `wordlist/` automatically if `-w` is not set
- 🪟 **Cross-Platform** — native binaries for Windows, Linux, and macOS (x86_64 + ARM64)

---

## 🔑 Supported Algorithms

| Algorithm | Status |
|-----------|--------|
| MD5 | ✅ Supported |
| SHA1 | ✅ Supported |
| SHA256 | ✅ Supported |
| SHA512 | ✅ Supported |
| SHA3-256 | ✅ Supported |
| SHA3-512 | ✅ Supported |
| NTLM | ✅ Supported |
| Whirlpool | ✅ Supported |
| MD6-256 | 🔄 Detection only (cracking not yet implemented) |
| MD6-512 | 🔄 Detection only (cracking not yet implemented) |

---

## 📦 Installation

### Option 1 — Download Pre-built Binary (Recommended)

Grab the latest binary for your platform from the [Releases](https://github.com/3rr0r-505/FeroxRipper/releases) page:

| Platform | File |
|----------|------|
| Windows x86_64 | `feroxripper-<version>-windows-x86_64.exe` |
| Windows ARM64 | `feroxripper-<version>-windows-aarch64.exe` |
| Linux x86_64 | `feroxripper-<version>-linux-x86_64` |
| Linux ARM64 | `feroxripper-<version>-linux-aarch64` |
| macOS Intel | `feroxripper-<version>-macos-x86_64` |
| macOS Apple Silicon | `feroxripper-<version>-macos-aarch64` |

On Linux/macOS, make the binary executable after downloading:
```bash
chmod +x feroxripper-*
```

### Option 2 — Build from Source

**Prerequisites:** Rust >= 1.50 ([install here](https://rustup.rs))

```bash
git clone https://github.com/3rr0r-505/FeroxRipper.git
cd FeroxRipper
cargo build --release
./target/release/feroxripper --help
```

---

## 🚀 Usage

```
feroxripper [OPTIONS] --hash <HASH>

Options:
  -h, --hash      <HASH>      Hash string to crack (required)
  -f, --format    <FORMAT>    Hash algorithm (optional, auto-detected if omitted)
  -w, --wordlist  <FILE>      Wordlist file (optional, see defaults below)
      --help                  Show help message
```

### Examples

```bash
# Auto-detect algorithm, use default wordlist
feroxripper --hash 5f4dcc3b5aa765d61d8327deb882cf99

# Specify algorithm explicitly
feroxripper --hash 5f4dcc3b5aa765d61d8327deb882cf99 -f md5

# Use a custom wordlist (full path or just filename inside wordlist/)
feroxripper --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w rockyou.txt
feroxripper --hash 5f4dcc3b5aa765d61d8327deb882cf99 -w /path/to/custom.txt

# Crack an NTLM hash
feroxripper --hash 8846f7eaee8fb117ad06bdd830b7586c -f ntlm
```

---

## 🗂️ Wordlist

When `-w` is not specified, FeroxRipper automatically discovers and tries **all `.txt` files** in the `wordlist/` folder in this order:

1. `wordlist/wordlist.txt` — small bundled wordlist, fast for quick tests
2. `wordlist/rockyou.txt` — large wordlist (~14M passwords), unzip from `rockyou.zip` first
3. Any other `.txt` files found in `wordlist/`, tried alphabetically

To set up rockyou:
```bash
cd wordlist && unzip rockyou.zip
```

You can always override with `-w`:
```bash
feroxripper --hash <HASH> -w /path/to/wordlist.txt
```

> Large wordlists like `rockyou.txt` are not committed to the repository due to size and licensing. Download them separately from trusted sources.

---

## 🤝 Contributing

Contributions are welcome! Feel free to open issues or pull requests for improvements and bug fixes.

Please read [CONTRIBUTING.md](https://github.com/3rr0r-505/FeroxRipper/blob/main/CONTRIBUTING.md) before submitting a PR.

---

## ⚖️ Legal Disclaimer

The use of code contained in this repository, either in part or in its totality, for engaging targets without prior mutual consent is **illegal**. It is the end user's responsibility to obey all applicable local, state, and federal laws.

Developers assume **no liability** and are not responsible for misuses or damages caused by any code contained in this repository. The use of this tool is **only** endorsed in circumstances directly related to **educational environments** or **authorized penetration testing engagements**.

---

## 📄 License

This project is licensed under the [MIT License](https://github.com/3rr0r-505/FeroxRipper/blob/main/LICENSE).
