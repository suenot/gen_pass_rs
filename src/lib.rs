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
    /// Minimum number of DISTINCT characters required from EACH enabled
    /// category. e.g. 4 means at least 4 different lowercase, 4 different
    /// uppercase, 4 different digits, 4 different symbols (only for enabled
    /// categories). Default 1 guarantees every enabled type appears at least
    /// once. 0 disables the constraint. Capped by each category's alphabet
    /// size (e.g. safe symbols have only 8 distinct characters).
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
        // Each category must be able to supply `min_per_type` DISTINCT chars.
        if let Some(smallest) = cats.iter().map(|c| c.chars.len()).min() {
            if cfg.min_per_type > smallest {
                anyhow::bail!(
                    "min_per_type={} exceeds the smallest enabled alphabet size ({}); lower min_each or use a larger symbol set",
                    cfg.min_per_type, smallest
                );
            }
        }
        let required_min = cfg.min_per_type * cats.len();
        if required_min > cfg.length {
            anyhow::bail!(
                "length={} is too short: min_each={} across {} categories needs at least {} characters",
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

    /// Ensure each enabled category contributes at least `min_per_type`
    /// DISTINCT characters. Overwrites only "safe" positions — a duplicated
    /// character, or a character in a category that already has more distinct
    /// characters than required — so no category is ever pushed below its
    /// requirement. Deterministic given the RNG stream (salt reproducibility).
    fn enforce_min_per_type(&self, password: &mut [char], rng: &mut StdRng) {
        use std::collections::{BTreeSet, HashMap};
        let need = self.min_per_type;
        if need == 0 {
            return;
        }
        loop {
            // Distinct characters per category, and total count per character.
            let mut distinct: Vec<BTreeSet<char>> = vec![BTreeSet::new(); self.cats.len()];
            let mut char_count: HashMap<char, usize> = HashMap::new();
            for &c in password.iter() {
                *char_count.entry(c).or_insert(0) += 1;
                if let Some(i) = category_of(c, &self.cats) {
                    distinct[i].insert(c);
                }
            }

            // Find a category short of its distinct-character minimum.
            let deficient = match (0..self.cats.len()).find(|&i| distinct[i].len() < need) {
                Some(i) => i,
                None => break,
            };

            // Pick a new distinct character for that category (guaranteed to
            // exist: alphabet size >= need > current distinct count).
            let alphabet = &self.cats[deficient].chars;
            let unused: Vec<char> = alphabet
                .iter()
                .copied()
                .filter(|c| !distinct[deficient].contains(c))
                .collect();
            let new_char = unused[(rng.next_u32() as usize) % unused.len()];

            // Choose a safe position to overwrite:
            //  A) a duplicated character (removing one copy keeps distinct), else
            //  B) a character whose category has more distinct than required.
            let pos = (0..password.len())
                .find(|&p| char_count.get(&password[p]).copied().unwrap_or(0) > 1)
                .or_else(|| {
                    (0..password.len()).find(|&p| {
                        category_of(password[p], &self.cats)
                            .map_or(true, |j| distinct[j].len() > need)
                    })
                });
            let pos = match pos {
                Some(p) => p,
                // Unreachable given length/alphabet validation; bail safely.
                None => break,
            };
            password[pos] = new_char;
        }
    }
}
