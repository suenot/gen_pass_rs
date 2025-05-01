//! Tests for gen_pass library
//! Comments in English per user preference.

use gen_pass::{PassConfig, PasswordGenerator, UPPERCASE, DIGITS, SYMBOLS};

fn charset_only_contains(password: &str, allowed: &str) {
    assert!(password.chars().all(|c| allowed.contains(c)), "password contains disallowed characters");
}

#[test]
fn default_generation_length() {
    let cfg = PassConfig::default();
    let gen = PasswordGenerator::from_config(&cfg).expect("generator");
    let pw = gen.generate(cfg.length);
    assert_eq!(pw.len(), cfg.length);
}

#[test]
fn uppercase_only() {
    let cfg = PassConfig {
        length: 20,
        use_lowercase: false,
        use_uppercase: true,
        use_digits: false,
        use_symbols: false,
    };
    let gen = PasswordGenerator::from_config(&cfg).unwrap();
    let pw = gen.generate(cfg.length);
    charset_only_contains(&pw, UPPERCASE);
}

#[test]
fn digits_and_symbols() {
    let cfg = PassConfig {
        length: 30,
        use_lowercase: false,
        use_uppercase: false,
        use_digits: true,
        use_symbols: true,
    };
    let allowed: String = format!("{}{}", DIGITS, SYMBOLS);
    let gen = PasswordGenerator::from_config(&cfg).unwrap();
    let pw = gen.generate(cfg.length);
    charset_only_contains(&pw, &allowed);
}

#[test]
fn error_on_empty_charset() {
    let cfg = PassConfig {
        length: 10,
        use_lowercase: false,
        use_uppercase: false,
        use_digits: false,
        use_symbols: false,
    };
    assert!(PasswordGenerator::from_config(&cfg).is_err());
}

#[test]
fn randomness() {
    let cfg = PassConfig { length: 32, ..Default::default() };
    let gen = PasswordGenerator::from_config(&cfg).unwrap();
    let pw1 = gen.generate(cfg.length);
    let pw2 = gen.generate(cfg.length);
    assert_ne!(pw1, pw2, "two consecutive passwords should differ");
}
