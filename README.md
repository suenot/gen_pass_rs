# gen_pass

Secure password generation **library** and **CLI** written in Rust.

## Features

- Configurable password length and character sets (lowercase, uppercase, digits, symbols)
- Combines multiple entropy sources for strong randomness:
  - `rand::rngs::OsRng` (system entropy)
  - `rand_chacha::ChaCha20Rng` seeded from system entropy
  - `rand::rngs::StdRng` seeded with SHA-256 digest of previous random data
- Can be used as a library in your own Rust projects **or** as a standalone command-line tool.
- Optional clipboard copy (macOS `pbcopy`, Linux `xclip`).

## Installation

### As a Library

Add to your `Cargo.toml`:

```toml
[dependencies]
gen_pass = { git = "https://github.com/suenot/gen_pass_rs", tag = "v0.1.0" }
```

### As a CLI

```bash
# Clone and install
cargo install --path .

# Or install directly from crates.io (after publishing)
cargo install gen_pass
```

## Usage (CLI)

```bash
$ gen_pass --help
Generate secure passwords

Usage: gen_pass [OPTIONS]

Options:
  -l, --length <LENGTH>      Desired password length [default: 16]
      --lowercase <BOOL>     Include lowercase letters [default: true]
      --uppercase <BOOL>     Include uppercase letters [default: true]
      --digits <BOOL>        Include digits [default: true]
      --symbols <BOOL>       Include symbols [default: true]
  -o, --output <OUTPUT>      Output format [default: plain] [possible values: plain, copy]
  -h, --help                 Print help info
  -V, --version              Print version info
```

Examples:

```bash
# 24-character password with all character sets
$ gen_pass -l 24

# 32-character password without symbols, copy to clipboard
$ gen_pass -l 32 --symbols false -o copy
```

## Usage (Library)

```rust
use gen_pass::{PassConfig, PasswordGenerator};

fn main() -> anyhow::Result<()> {
    let cfg = PassConfig {
        length: 24,
        ..Default::default()
    };

    let generator = PasswordGenerator::from_config(&cfg)?;
    let password = generator.generate(cfg.length);
    println!("{password}");
    Ok(())
}
```

## License

MIT
