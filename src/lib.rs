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
/// Basic punctuation subset: widely accepted by sites, shell-safe, no
/// ambiguous or escape-prone characters.
pub const SAFE_SYMBOLS: &str = "!@#$%*+-";

/// Password generator configuration
#[derive(Debug, Clone)]
pub struct PassConfig {
    pub length: usize,
    pub use_lowercase: bool,
    pub use_uppercase: bool,
    pub use_digits: bool,
    pub use_symbols: bool,
    /// Use only the basic, shell-safe punctuation subset (`SAFE_SYMBOLS`)
    /// instead of the full `SYMBOLS` set.
    pub safe_symbols: bool,
    pub salt: Option<String>,
    /// Minimum count of characters required from EACH enabled category.
    /// e.g. 4 means at least 4 lowercase, 4 uppercase, 4 digits, 4 symbols
    /// (only for enabled categories). Default 1 guarantees every enabled
    /// type appears at least once. 0 disables the constraint.
    pub min_per_type: usize,
}

impl Default for PassConfig {
    fn default() -> Self {
        Self {
            length: 16,
            use_lowercase: true,
            use_uppercase: true,
            use_digits: true,
            use_symbols: true,
            safe_symbols: false,
            salt: Some("suenot".to_string()), // Easter egg with author's nickname
            min_per_type: 1,
        }
    }
}

/// A character category and its alphabet.
struct Category {
    chars: Vec<char>,
}

/// Classify a char into a category index within `cats`, if any.
fn category_of(c: char, cats: &[Category]) -> Option<usize> {
    cats.iter().position(|cat| cat.chars.contains(&c))
}

/// Core password generator structure
pub struct PasswordGenerator {
    charset: Vec<char>,
    cats: Vec<Category>,
    min_per_type: usize,
    salt: Option<String>,
}

impl PasswordGenerator {
    /// Create new generator from config
    pub fn from_config(cfg: &PassConfig) -> anyhow::Result<Self> {
        let mut cats = Vec::new();
        if cfg.use_lowercase { cats.push(Category { chars: LOWERCASE.chars().collect() }); }
        if cfg.use_uppercase { cats.push(Category { chars: UPPERCASE.chars().collect() }); }
        if cfg.use_digits    { cats.push(Category { chars: DIGITS.chars().collect() }); }
        if cfg.use_symbols   {
            let set = if cfg.safe_symbols { SAFE_SYMBOLS } else { SYMBOLS };
            cats.push(Category { chars: set.chars().collect() });
        }

        if cats.is_empty() {
            anyhow::bail!("Character set is empty; enable at least one category");
        }
        let required_min = cfg.min_per_type * cats.len();
        if required_min > cfg.length {
            anyhow::bail!(
                "length={} is too short: min_per_type={} across {} categories needs at least {} characters",
                cfg.length, cfg.min_per_type, cats.len(), required_min
            );
        }

        let charset: Vec<char> = cats.iter().flat_map(|c| c.chars.iter().copied()).collect();
        Ok(Self {
            charset,
            cats,
            min_per_type: cfg.min_per_type,
            salt: cfg.salt.clone(),
        })
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

        // Apply salt if provided
        if let Some(salt) = &self.salt {
            // Create a hash of the salt
            let mut hasher = Sha256::new();
            hasher.update(salt.as_bytes());
            let salt_hash = hasher.finalize();
            
            // XOR the salt hash with the buffer for additional entropy
            for (i, byte) in salt_hash.iter().enumerate() {
                if i < buf.len() {
                    buf[i] ^= *byte;
                }
            }
        }

        // StdRng seeded with SHA256 of previous buffer
        let hash = Sha256::digest(&buf);
        let mut std_rng = StdRng::from_seed(hash.into());
        std_rng.fill_bytes(&mut buf);

        // Convert random bytes to password characters
        let mut password: Vec<char> = buf.iter()
            .take(length)
            .map(|b| {
                let idx = (*b as usize) % self.charset.len();
                self.charset[idx]
            })
            .collect();

        // Guarantee each enabled category meets its minimum count.
        // Deterministic given the RNG stream, so salt reproducibility holds.
        self.enforce_min_per_type(&mut password, &mut std_rng);

        password.into_iter().collect()
    }

    /// Ensure each enabled category appears at least `min_per_type` times.
    /// Overwrites only positions held by a category that is above its own
    /// minimum, so no other category is ever pushed below the requirement.
    fn enforce_min_per_type(&self, password: &mut [char], rng: &mut StdRng) {
        let need = self.min_per_type;
        if need == 0 {
            return;
        }
        loop {
            let mut counts = vec![0usize; self.cats.len()];
            for &c in password.iter() {
                if let Some(i) = category_of(c, &self.cats) {
                    counts[i] += 1;
                }
            }
            // Find a category still short of its minimum.
            let deficient = match counts.iter().position(|&n| n < need) {
                Some(i) => i,
                None => break,
            };
            // Find a position whose category has a surplus (above its minimum).
            let pos = match (0..password.len()).find(|&p| {
                category_of(password[p], &self.cats).map_or(true, |i| counts[i] > need)
            }) {
                Some(p) => p,
                // Should be unreachable given length validation, but bail safely.
                None => break,
            };
            let alphabet = &self.cats[deficient].chars;
            password[pos] = alphabet[(rng.next_u32() as usize) % alphabet.len()];
        }
    }
}
