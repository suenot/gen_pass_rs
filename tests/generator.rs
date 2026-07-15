//! Tests for gen_pass library
//! Comments in English per user preference.

use gen_pass::{PassConfig, PasswordGenerator, LOWERCASE, UPPERCASE, DIGITS, SYMBOLS};

fn charset_only_contains(password: &str, allowed: &str) {
    assert!(password.chars().all(|c| allowed.contains(c)), "password contains disallowed characters");
}

/// Count how many of the four categories appear in the password.
fn distinct_types(password: &str) -> usize {
    let cats = [LOWERCASE, UPPERCASE, DIGITS, SYMBOLS];
    cats.iter().filter(|set| password.chars().any(|c| set.contains(c))).count()
}

#[test]
fn default_generation_length() {
    let cfg = PassConfig::default();
    let gen = PasswordGenerator::from_config(&cfg).expect("generator");
    let pw = gen.generate(cfg.length);
    assert_eq!(pw.len(), cfg.length);
}

#[test]
fn default_salt_is_suenot() {
    let cfg = PassConfig::default();
    assert_eq!(cfg.salt, Some("suenot".to_string()), "Default salt should be 'suenot'");
}

#[test]
fn uppercase_only() {
    let cfg = PassConfig {
        length: 20,
        use_lowercase: false,
        use_uppercase: true,
        use_digits: false,
        use_symbols: false,
        salt: None,
        min_types: 1,
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
        salt: None,
        min_types: 2,
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
        salt: None,
        min_types: 0,
    };
    assert!(PasswordGenerator::from_config(&cfg).is_err());
}

#[test]
fn enforces_min_three_types() {
    // Rule: at least three of uppercase, lowercase, digits, symbols.
    for len in 8..=20 {
        let cfg = PassConfig { length: len, salt: None, ..Default::default() };
        let gen = PasswordGenerator::from_config(&cfg).unwrap();
        for _ in 0..50 {
            let pw = gen.generate(cfg.length);
            assert_eq!(pw.len(), len);
            assert!(!pw.contains(' '), "password must not contain spaces");
            assert!(distinct_types(&pw) >= 3, "expected >=3 types, got {} in {pw}", distinct_types(&pw));
        }
    }
}

#[test]
fn min_types_exceeds_categories_errors() {
    let cfg = PassConfig {
        length: 16,
        use_lowercase: true,
        use_uppercase: false,
        use_digits: false,
        use_symbols: false,
        salt: None,
        min_types: 3,
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

#[test]
fn salt_changes_output() {
    // Generate password without salt
    let cfg_no_salt = PassConfig { length: 16, ..Default::default() };
    let gen_no_salt = PasswordGenerator::from_config(&cfg_no_salt).unwrap();
    let pw_no_salt = gen_no_salt.generate(cfg_no_salt.length);
    
    // Generate password with salt
    let cfg_with_salt = PassConfig { 
        length: 16, 
        salt: Some("test_salt".to_string()),
        ..Default::default() 
    };
    let gen_with_salt = PasswordGenerator::from_config(&cfg_with_salt).unwrap();
    let pw_with_salt = gen_with_salt.generate(cfg_with_salt.length);
    
    // Same salt should produce different passwords than no salt
    assert_ne!(pw_no_salt, pw_with_salt, "salt should change password output");
}

#[test]
fn different_salts_different_outputs() {
    // Generate passwords with two different salts
    let cfg_salt1 = PassConfig { 
        length: 16, 
        salt: Some("salt1".to_string()),
        ..Default::default() 
    };
    let gen_salt1 = PasswordGenerator::from_config(&cfg_salt1).unwrap();
    let pw_salt1 = gen_salt1.generate(cfg_salt1.length);
    
    let cfg_salt2 = PassConfig { 
        length: 16, 
        salt: Some("salt2".to_string()),
        ..Default::default() 
    };
    let gen_salt2 = PasswordGenerator::from_config(&cfg_salt2).unwrap();
    let pw_salt2 = gen_salt2.generate(cfg_salt2.length);
    
    // Different salts should produce different passwords
    assert_ne!(pw_salt1, pw_salt2, "different salts should produce different passwords");
}
