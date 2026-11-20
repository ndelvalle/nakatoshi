use std::io::{BufRead, BufReader};
use std::process::{Command, Output, Stdio};

use serde_json::Value;

fn nakatoshi(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_nakatoshi"))
        .args(args)
        .output()
        .unwrap()
}

// The address of a search that is expected to find one.
fn address(args: &[&str]) -> String {
    let output = nakatoshi(args);
    assert!(output.status.success(), "{:?}", args);

    let result: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(result["private_key"].is_string());
    assert!(result["public_key"].is_string());
    assert!(result["attempts"].is_u64());
    result["address"].as_str().unwrap().to_owned()
}

// The error message of a search that is expected to fail.
fn error(args: &[&str]) -> String {
    let output = nakatoshi(args);
    assert_eq!(output.status.code(), Some(2), "{:?}", args);
    assert!(output.stdout.is_empty());
    String::from_utf8(output.stderr).unwrap()
}

#[test]
fn finds_a_legacy_address() {
    assert!(address(&["1a"]).to_lowercase().starts_with("1a"));
    assert!(address(&["--case-sensitive", "1A"]).starts_with("1A"));
    assert!(
        address(&["--uncompressed", "1a"])
            .to_lowercase()
            .starts_with("1a")
    );
    assert!(
        address(&["--threads", "2", "1a"])
            .to_lowercase()
            .starts_with("1a")
    );
}

#[test]
fn finds_a_bech32_address() {
    assert!(address(&["--bech32", "bc1qq"]).starts_with("bc1qq"));
    assert!(address(&["-b", "BC1QQ"]).starts_with("bc1qq"));
}

#[test]
fn finds_a_taproot_address() {
    let address = address(&["--taproot", "bc1pq"]);
    assert!(address.starts_with("bc1pq"));
    assert_eq!(address.len(), 62);
}

#[test]
fn finds_an_address_for_one_of_several_prefixes() {
    let address = address(&["--case-sensitive", "1A", "1B", "Kids"]);
    assert!(address.starts_with("1A") || address.starts_with("1B"));
}

#[test]
fn keeps_going_after_a_match() {
    let mut search = Command::new(env!("CARGO_BIN_EXE_nakatoshi"))
        .args(["--keep-going", "1a"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    let stdout = BufReader::new(search.stdout.take().unwrap());
    let addresses: Vec<String> = stdout
        .lines()
        .take(3)
        .map(|line| {
            let result: Value = serde_json::from_str(&line.unwrap()).unwrap();
            result["address"].as_str().unwrap().to_owned()
        })
        .collect();
    search.kill().unwrap();
    search.wait().unwrap();

    assert_eq!(addresses.len(), 3);
    assert!(
        addresses
            .iter()
            .all(|address| address.to_lowercase().starts_with("1a"))
    );
    assert_ne!(addresses[0], addresses[1]);
}

#[test]
fn fails_without_a_prefix() {
    assert!(error(&[]).contains("required arguments were not provided"));
}

#[test]
fn fails_for_prefixes_without_addresses() {
    // A lowercase l is not in Base58.
    let message = error(&["--case-sensitive", "1Nicol"]);
    assert!(message.contains("No address starts with \"1Nicol\""));

    assert!(error(&["Kids", "0abc"]).contains("No address starts with any of the prefixes"));
    assert!(error(&["--bech32", "bc1qb"]).contains("Bech32 addresses start with bc1q"));
    assert!(error(&["--taproot", "bc1qq"]).contains("Taproot addresses start with bc1p"));
}

#[test]
fn fails_for_too_many_variants() {
    let prefix = format!("1{}", "a".repeat(30));
    assert!(error(&[&prefix]).contains("Use fewer or shorter prefixes"));
}

#[test]
fn fails_for_arguments_that_do_not_go_together() {
    let message = error(&["--bech32", "--uncompressed", "bc1qq"]);
    assert!(message.contains("cannot be used with"));

    let message = error(&["--taproot", "--bech32", "bc1pq"]);
    assert!(message.contains("cannot be used with"));
}

#[test]
fn fails_for_an_invalid_number_of_threads() {
    for threads in ["abc", "0", "1.5"] {
        let message = error(&["--threads", threads, "1a"]);
        assert!(message.contains("invalid value"), "{}", threads);
    }
}
