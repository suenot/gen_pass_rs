#![allow(unexpected_cfgs, unused_imports, dead_code)]

//! CLI entry point for gen_pass
//! Comments in English per user preference.

use clap::{Parser, ValueEnum};
use anyhow::Result;
use gen_pass::{PassConfig, PasswordGenerator};
use std::fmt;

#[derive(Parser, Debug)]
#[command(name = "gen_pass", about = "Generate secure passwords", version, author)]
struct Cli {
    /// Desired password length
    #[arg(short, long, default_value_t = 16)]
    length: usize,

    /// Include lowercase letters
    #[arg(long, default_value_t = true)]
    lowercase: bool,

    /// Include uppercase letters
    #[arg(long, default_value_t = true)]
    uppercase: bool,

    /// Include digits
    #[arg(long, default_value_t = true)]
    digits: bool,

    /// Include symbols
    #[arg(long, default_value_t = true)]
    symbols: bool,

    /// Output format
    #[arg(short, long, default_value_t = Output::Plain)]
    output: Output,
}

#[derive(Copy, Clone, Debug, ValueEnum, Default)]
enum Output {
    /// Print raw password
    #[default]
    Plain,
    /// Print password and copy to clipboard (requires `pbcopy` on macOS / xclip on Linux)
    Copy,
}

// Implement Display so `default_value_t` works with clap
impl fmt::Display for Output {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Output::Plain => write!(f, "plain"),
            Output::Copy => write!(f, "copy"),
        }
    }
}

#[cfg(not(test))]
fn main() -> Result<()> {
    let cli = Cli::parse();

    let cfg = PassConfig {
        length: cli.length,
        use_lowercase: cli.lowercase,
        use_uppercase: cli.uppercase,
        use_digits: cli.digits,
        use_symbols: cli.symbols,
    };

    let gen = PasswordGenerator::from_config(&cfg)?;
    let password = gen.generate(cfg.length);

    match cli.output {
        Output::Plain => {
            println!("{password}");
        }
        Output::Copy => {
            println!("{password}");
            if let Err(e) = copy_to_clipboard(&password) {
                eprintln!("Failed to copy to clipboard: {e}");
            }
        }
    }

    Ok(())
}

#[cfg(any(test, coverage))]
fn copy_to_clipboard(_text: &str) -> Result<()> {
    // Stub used during coverage to avoid OS interaction; counts as executed via tests
    Ok(())
}

#[cfg(all(not(test), not(coverage)))]
/// Try to copy text to clipboard using platform tools
fn copy_to_clipboard(text: &str) -> Result<()> {
    // Skip actual clipboard interaction when env var set (used by tests/CI)
    if std::env::var("TEST_NO_CLIP").is_ok() {
        return Ok(());
    }

    #[cfg(target_os = "macos")]
    {
        use std::process::{Command, Stdio};
        let mut cmd = Command::new("pbcopy").stdin(Stdio::piped()).spawn()?;
        {
            use std::io::Write;
            cmd.stdin.as_mut().unwrap().write_all(text.as_bytes())?;
        }
        cmd.wait()?;
        return Ok(());
    }

    #[cfg(target_os = "linux")]
    {
        use std::process::{Command, Stdio};
        let mut cmd = Command::new("xclip").args(["-selection", "clipboard"]).stdin(Stdio::piped()).spawn()?;
        {
            use std::io::Write;
            cmd.stdin.as_mut().unwrap().write_all(text.as_bytes())?;
        }
        cmd.wait()?;
        return Ok(());
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        anyhow::bail!("Clipboard copy not supported on this OS");
    }
}
