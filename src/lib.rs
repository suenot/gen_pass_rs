//! Secure password generation library
//! Provides flexible password generator with multiple random sources.
//! Comments in English per user preference.

use rand::{RngCore, SeedableRng};
use rand::rngs::{OsRng, StdRng};
use rand_chacha::ChaCha20Rng;
use sha2::{Digest, Sha256};

/// Character sets
pub const LOWERCASE: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPERCASE: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
pub const SYMBOLS: &str = r#"!@#$%^&*()-_=+[]{};:'\",.<>/?`~|\\"#;

/// Password generator configuration
#[derive(Debug, Clone)]
pub struct PassConfig {
    pub length: usize,
    pub use_lowercase: bool,
    pub use_uppercase: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            length: 16,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_symbols: true,
        }
    }
}

/// Core password generator structure
pub struct PasswordGenerator {
    charset: Vec<char>,
}

impl PasswordGenerator {
    /// Create new generator from config
    pub fn from_config(cfg: &PassConfig) -> anyhow::Result<Self> {
        let mut charset = String::new();
        if cfg.use_lowercase { charset.push_str(LOWERCASE); }
        if cfg.use_uppercase { charset.push_str(UPPERCASE); }
        if cfg.use_digits    { charset.push_str(DIGITS); }
        if cfg.use_symbols   { charset.push_str(SYMBOLS); }

        if charset.is_empty() {
            anyhow::bail!("Character set is empty; enable at least one category");
        }
        Ok(Self { charset: charset.chars().collect() })
    }

    /// Generate password using mixed entropy from multiple RNGs and SHA-256
    pub fn generate(&self, length: usize) -> String {
        // Collect raw random bytes from multiple sources
        let mut buf = vec![0u8; length * 2];
        // OsRng (system entropy)
        OsRng.fill_bytes(&mut buf);

        // ChaCha20 seeded with OsRng-derived seed for extra unpredictability
        let mut seed = [0u8; 32];
        OsRng.fill_bytes(&mut seed);
        let mut chacha = ChaCha20Rng::from_seed(seed);
        chacha.fill_bytes(&mut buf);

        // StdRng seeded with SHA256 of previous buffer
        let hash = Sha256::digest(&buf);
        let mut std_rng = StdRng::from_seed(hash.into());
        std_rng.fill_bytes(&mut buf);

        // Convert random bytes to password characters
        buf.iter()
            .take(length)
            .map(|b| {
                let idx = (*b as usize) % self.charset.len();
                self.charset[idx]
            })
            .collect()
    }
}
