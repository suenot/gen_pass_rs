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

### Algorithm Flow

```mermaid
flowchart TD
    A[Start] --> B{CLI or Library?}
    B -->|CLI| C[Parse CLI Args]
    B -->|Library| D[Use PassConfig]
    C --> E[Build PassConfig]
    D --> E
    E --> F[Select RNG Algorithm]
    F --> G[Collect Random Bytes]
    G --> H[Map To Allowed Charset]
    H --> I[Return / Print Password]
    I --> J{Copy to Clipboard?}
    J -->|Yes| K[Invoke pbcopy/xclip]
    J -->|No| L[Done]
```

### Supported Random Algorithms

| Name | Crate / Source | Crypto-secure | Complexity (1-10) | Notes |
|------|----------------|---------------|-------------------|-------|
| `mixed` (default) | `OsRng` + `ChaCha20Rng` + `StdRng` (SHA-256 seed) | ✔ | 10 | Multi-stage entropy mixing |
| `os` | `rand::rngs::OsRng` | ✔ | 9 | Direct system CSPRNG |
| `chacha20` | `rand_chacha::ChaCha20Rng` | ✔ | 9 | ChaCha20 stream cipher RNG |
| `hc128` | `rand_hc::Hc128Rng` | ✔ | 8 | HC-128 stream cipher RNG |
| `ring` | `ring::rand::SystemRandom` | ✔ | 9 | Implementation from *ring* crypto lib |
| `xoshiro` | `rand_xoshiro::Xoshiro256PlusPlus` | ✖ | 3 | Very fast, not cryptographically secure |
| `pcg64` | `rand_pcg::Pcg64Mcg` | ✖ | 3 | Permuted Congruential Generator |
| `rdrand` | `rdrand` crate (Intel HW) | ✔ | 8 | Uses CPU instruction `RDRAND` when available |

#### Algorithm Details

* **mixed** – Combines several independent entropy sources: the OS CSPRNG, a ChaCha20 stream cipher RNG seeded from that entropy, and finally `StdRng` re-seeded with SHA-256 of previous bytes. Усиление стойкости за счёт смешивания.
* **os** – Прямое чтение из системного крипто-стойкого генератора (`/dev/urandom`, `getrandom(2)`, `BCryptGenRandom`). Максимально надёжен, но может быть медленнее на отдельных платформах.
* **chacha20** – Реализация ChaCha20 stream cipher RNG (IETF variant). Используется в TLS и OpenSSH; обеспечивает высокую скорость и криптостойкость.
* **hc128** – HC-128 генератор из семейства eSTREAM. Предлагает отличное соотношение скорость/безопасность; подходит для встроенных устройств.
* **ring** – Обёртка над C-кодом *ring*, использует системный RNG и дополнительно проверяет ошибки; удобен, если проект уже тянет `ring`.
* **xoshiro** – Семейство Xoshiro/Xoroshiro (non-crypto). Очень быстрый, малое состояние. Не предназначен для паролей, но полезен, когда нужна псевдослучайность без крипто-требований.
* **pcg64** – Permuted Congruential Generator 64-битной версии. Хорошие статистические свойства, но не криптостойкий.
* **rdrand** – Использует аппаратную инструкцию Intel/AMD `RDRAND`. Быстро, криптостойко, но работает только на поддерживаемых CPU и зависит от доверия к микрокоду.

Select algorithm via CLI flag `-a/--algo`, or by setting `algorithm` field in `PassConfig`.

### Algorithm Diagrams

#### mixed

```mermaid
flowchart LR
    A[OsRng] --> B[ChaCha20Rng]
    B --> C[SHA-256]
    C --> D[StdRng]
    D --> E[Password bytes]
```

#### os

```mermaid
flowchart LR
    A[OsRng / getrandom] --> B[Password bytes]
```

#### chacha20

```mermaid
flowchart LR
    A[Seed via OsRng] --> B[ChaCha20Rng]
    B --> C[Password bytes]
```

#### hc128

```mermaid
flowchart LR
    A[Seed via OsRng] --> B[Hc128Rng]
    B --> C[Password bytes]
```

#### ring

```mermaid
flowchart LR
    A[ring::SystemRandom] --> B[Password bytes]
```

#### xoshiro

```mermaid
flowchart LR
    A[Seed via OsRng] --> B[Xoshiro256++]
    B --> C[Password bytes]
```

#### pcg64

```mermaid
flowchart LR
    A[Seed via OsRng] --> B[PCG64Mcg]
    B --> C[Password bytes]
```

#### rdrand

```mermaid
flowchart LR
    A[CPU RDRAND] --> B[Password bytes]
```

## License

MIT
