//! Integration tests that spawn the CLI binary
//! Comments in English per user preference.

use assert_cmd::Command;
use predicates::prelude::*;

fn binary() -> Command {
    Command::cargo_bin("gen_pass").expect("binary built")
}

#[test]
fn help_shows_usage() {
    binary()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("Generate secure passwords"));
}

#[test]
fn length_flag_changes_size() {
    let len = 24u32;
    binary()
        .args(["-l", &len.to_string()])
        .assert()
        .success()
        .stdout(predicate::function(move |out: &str| out.trim_end().len() == len as usize));
}

#[test]
fn copy_output_variant() {
    binary()
        .args(["-l", "10", "--output", "copy"])
        .env("TEST_NO_CLIP", "1")
        .assert()
        .success();
}
