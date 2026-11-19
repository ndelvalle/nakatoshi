use bitcoin::secp256k1::Secp256k1;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::json;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

mod address;
mod cli;

use address::{AddressType, BitcoinAddress, KeyWalker, PrefixMatcher};

fn main() {
    let matches = cli::prompt().get_matches();
    let secp = Secp256k1::new();

    let address_type = if matches.get_flag("taproot") {
        AddressType::Taproot
    } else if matches.get_flag("bech32") {
        AddressType::Bech32
    } else {
        AddressType::Legacy
    };
    let is_taproot = address_type == AddressType::Taproot;
    // Bech32 and Taproot addresses are always lowercase, so case-sensitive
    // matching makes no sense for them; ignore the flag in that case.
    let is_case_sensitive =
        matches.get_flag("case-sensitive") && address_type == AddressType::Legacy;
    let is_compressed = !matches.get_flag("uncompressed");
    let is_keep_going = matches.get_flag("keep-going");

    let num_threads = matches
        .get_one::<String>("threads")
        .and_then(|num_threads| num_threads.parse().ok())
        .unwrap_or_else(num_cpus::get);

    let prefixes = match matches.get_one::<String>("prefix") {
        Some(prefix) => vec![prefix.to_owned()],
        None => {
            let file_name = matches.get_one::<String>("input-file").unwrap();
            get_prefixes_from_file(file_name)
        }
    };
    if prefixes.is_empty() {
        exit_with_error("The input file has no prefixes");
    }

    let matcher = PrefixMatcher::new(&prefixes, is_case_sensitive, address_type);
    if matcher.is_empty() {
        let subject = match prefixes.as_slice() {
            [prefix] => format!("\"{prefix}\""),
            _ => "any of the prefixes".to_owned(),
        };
        let format = match address_type {
            AddressType::Legacy => "Legacy addresses start with 1, and have no 0, O, I or l",
            AddressType::Bech32 => {
                "Bech32 addresses start with bc1q, and have no 1, b, i or o after that"
            }
            AddressType::Taproot => {
                "Taproot addresses start with bc1p, and have no 1, b, i or o after that"
            }
        };
        exit_with_error(format!("No address starts with {subject}. {format}"));
    }

    let rayon_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .expect("Failed to create thread pool");

    let progress = ProgressBar::new_spinner();
    let template = ProgressStyle::default_bar()
        .template("[{elapsed_precise}] {pos} attempts")
        .unwrap();
    progress.set_style(template);
    // progress.set_draw_rate(10);

    let is_found = AtomicBool::new(false);
    let found: Mutex<Option<(BitcoinAddress, u64)>> = Mutex::new(None);

    rayon_pool.broadcast(|_| {
        let mut keys = KeyWalker::new(&secp, is_compressed, address_type);

        while !is_found.load(Ordering::Relaxed) {
            let batch_len = keys.next_batch(&secp);
            let mut attempts = 0;
            let mut matched = None;

            'batch: for index in 0..batch_len {
                if is_taproot {
                    attempts += 1;
                    if matcher.matches_output_key(&keys.output_key(index)) {
                        matched = Some(index);
                        break 'batch;
                    }
                    continue;
                }
                for pubkey_hash in keys.pubkey_hashes(index) {
                    attempts += 1;
                    if matcher.matches(&pubkey_hash) {
                        matched = Some(index);
                        break 'batch;
                    }
                }
            }
            progress.inc(attempts);

            let Some(index) = matched else { continue };
            let secret_keys = keys.secret_keys(index);
            // Consecutive keys are related, so don't hand out more than one of them.
            keys.restart(&secp);

            let address = secret_keys
                .into_iter()
                .map(|secret_key| {
                    BitcoinAddress::from_secret_key(&secp, secret_key, is_compressed, address_type)
                })
                .find(|address| address.starts_with_any(&prefixes, is_case_sensitive));
            let Some(address) = address else { continue };

            if is_keep_going {
                let result = address_json(&address, progress.position());
                progress.suspend(|| println!("{}", result));
            } else {
                let mut found = found.lock().unwrap();
                if found.is_none() {
                    *found = Some((address, progress.position()));
                }
                is_found.store(true, Ordering::Relaxed);
            }
        }
    });

    let (bitcoin_address, attempts) = found
        .into_inner()
        .unwrap()
        .expect("Failed to find Bitcoin address match");
    progress.finish_and_clear();

    print!("{}", address_json(&bitcoin_address, attempts));
}

fn address_json(bitcoin_address: &BitcoinAddress, attempts: u64) -> serde_json::Value {
    json!({
        "private_key": bitcoin_address.private_key.to_string(),
        "public_key": bitcoin_address.public_key.to_string(),
        "address": bitcoin_address.address.to_string(),
        "attempts": attempts
    })
}

fn get_prefixes_from_file(file_name: &str) -> Vec<String> {
    let file = fs::File::open(file_name).unwrap();
    let buffer = BufReader::new(file);

    let mut prefixes = buffer
        .lines()
        .map(|line| line.expect("Failed to read Bitcoin address pattern from input file"))
        .map(|line| line.trim().to_owned())
        .filter(|line| !line.is_empty())
        .collect::<Vec<String>>();

    prefixes.sort_by_key(|a| a.len());
    prefixes
}

/// Prints an error the way the argument parser does, and exits.
fn exit_with_error(message: impl std::fmt::Display) -> ! {
    cli::prompt()
        .error(clap::error::ErrorKind::ValueValidation, message)
        .exit()
}

#[cfg(test)]
mod tests {
    use crate::address::{AddressType, BitcoinAddress, KeyWalker, PrefixMatcher};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn create_compressed_bitcoin_public_key() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Legacy;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);

        let actual = bitcoin_address.public_key.to_string().len();
        let expected = 66;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_uncompressed_bitcoin_public_key() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Legacy;
        let is_compressed = false;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);

        let actual = bitcoin_address.public_key.to_string().len();
        let expected = 130;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bech32_address() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Bech32;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);
        let address = bitcoin_address.address.to_string();

        assert!(address.starts_with("bc1q"));
    }

    #[test]
    fn create_taproot_address() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Taproot;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);
        let address = bitcoin_address.address.to_string();

        assert!(address.starts_with("bc1p"));
        assert_eq!(address.len(), 62);
    }

    #[test]
    fn create_bitcoin_private_key() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Legacy;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);

        let actual = bitcoin_address.private_key.to_string().len();
        let expected = 52;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bitcoin_address() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Legacy;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);

        let actual = bitcoin_address.address.to_string().len();
        let expected = 34;

        assert_eq!(actual, expected);
    }

    #[test]
    fn walked_keys_match_their_secret_key() {
        let secp = Secp256k1::new();

        for is_compressed in [true, false] {
            let mut keys = KeyWalker::new(&secp, is_compressed, AddressType::Legacy);
            let mut seen = std::collections::HashSet::new();

            for batch in 0..6 {
                if batch == 3 {
                    keys.restart(&secp);
                }
                let batch_len = keys.next_batch(&secp);
                for index in 0..batch_len {
                    let mut expected: Vec<[u8; 20]> = keys
                        .secret_keys(index)
                        .into_iter()
                        .map(|secret_key| {
                            let address_type = AddressType::Legacy;
                            BitcoinAddress::from_secret_key(
                                &secp,
                                secret_key,
                                is_compressed,
                                address_type,
                            )
                            .public_key
                            .pubkey_hash()
                            .to_byte_array()
                        })
                        .collect();
                    let mut hashes = keys.pubkey_hashes(index).to_vec();
                    expected.sort();
                    hashes.sort();
                    assert_eq!(hashes, expected);
                    // No key is tried twice.
                    assert!(hashes.into_iter().all(|hash| seen.insert(hash)));
                }
            }
        }
    }

    #[test]
    fn walked_output_keys_match_their_secret_key() {
        let secp = Secp256k1::new();
        let mut keys = KeyWalker::new(&secp, true, AddressType::Taproot);
        let mut seen = std::collections::HashSet::new();

        for batch in 0..3 {
            if batch == 2 {
                keys.restart(&secp);
            }
            let batch_len = keys.next_batch(&secp);
            for index in 0..batch_len {
                let output_key = keys.output_key(index);
                // Both secret keys have the same address.
                for secret_key in keys.secret_keys(index) {
                    let address_type = AddressType::Taproot;
                    let address =
                        BitcoinAddress::from_secret_key(&secp, secret_key, true, address_type);
                    let program = address.address.witness_program().unwrap();
                    assert_eq!(program.program().as_bytes(), output_key);
                }
                // No key is tried twice.
                assert!(seen.insert(output_key));
            }
        }
    }

    #[test]
    fn matcher_agrees_with_address() {
        let secp = Secp256k1::new();
        let mut keys = KeyWalker::new(&secp, true, AddressType::Legacy);
        keys.next_batch(&secp);

        for index in 0..200 {
            for (address_type, is_case_sensitive, len) in [
                (AddressType::Bech32, false, 3),
                (AddressType::Bech32, false, 7),
                (AddressType::Bech32, false, 36),
                (AddressType::Taproot, false, 3),
                (AddressType::Taproot, false, 7),
                (AddressType::Taproot, false, 31),
                (AddressType::Taproot, false, 56),
                (AddressType::Legacy, true, 1),
                (AddressType::Legacy, true, 4),
                (AddressType::Legacy, false, 4),
                (AddressType::Legacy, false, 9),
                (AddressType::Legacy, true, 34),
                // Too many variants, this uses the slow matcher.
                (AddressType::Legacy, false, 30),
            ] {
                let is_legacy = address_type == AddressType::Legacy;
                let secret_key = keys.secret_keys(index)[0];
                let address =
                    BitcoinAddress::from_secret_key(&secp, secret_key, true, address_type);
                let hash = address.public_key.pubkey_hash().to_byte_array();
                let matches = |prefix: String| {
                    let matcher = PrefixMatcher::new(&[prefix], is_case_sensitive, address_type);
                    if address_type == AddressType::Taproot {
                        let program = address.address.witness_program().unwrap();
                        let output_key = program.program().as_bytes().try_into().unwrap();
                        assert!(!matcher.matches(&hash));
                        matcher.matches_output_key(&output_key)
                    } else {
                        assert!(!matcher.matches_output_key(&[0u8; 32]));
                        matcher.matches(&hash)
                    }
                };
                let address = address.address.to_string();
                let len = len.min(address.len());

                let prefix = if is_case_sensitive {
                    address[..len].to_string()
                } else {
                    address[..len].to_uppercase()
                };
                assert!(matches(prefix));

                // Change the last character of the prefix, it should not match anymore.
                // The end of a Base58 address is the checksum, which the matcher
                // does not look at.
                if len < 4 || (is_legacy && len > 20) {
                    continue;
                }
                let last = if address[len - 1..len].eq_ignore_ascii_case("q") {
                    "p"
                } else {
                    "q"
                };
                let prefix = format!("{}{}", &address[..len - 1], last);
                assert!(!matches(prefix));
            }
        }
    }

    #[test]
    fn taproot_matcher_agrees_with_address() {
        let secp = Secp256k1::new();
        let mut keys = KeyWalker::new(&secp, true, AddressType::Taproot);
        let batch_len = keys.next_batch(&secp);

        // Short prefixes, so a lot of the addresses match.
        let prefixes = [
            "bc1p", "bc1pq", "BC1P5", "bc1pl", "bc1pqq", "bc1q", "bc1pb", "1",
        ];
        let mut matches = 0;
        for prefix in prefixes {
            let matcher = PrefixMatcher::new(&[prefix.to_string()], false, AddressType::Taproot);
            for index in 0..batch_len {
                let output_key = keys.output_key(index);
                let secret_key = keys.secret_keys(index)[0];
                let address_type = AddressType::Taproot;
                let address =
                    BitcoinAddress::from_secret_key(&secp, secret_key, true, address_type);
                let expected = address.starts_with(prefix, false);
                assert_eq!(
                    matcher.matches_output_key(&output_key),
                    expected,
                    "{}",
                    prefix
                );
                matches += usize::from(expected);
            }
        }
        assert!(matches > batch_len);
    }

    #[test]
    fn base58_ranges_agree_with_slow_matcher() {
        let secp = Secp256k1::new();
        let mut keys = KeyWalker::new(&secp, true, AddressType::Legacy);
        let batch_len = keys.next_batch(&secp);

        // Short prefixes, so a lot of the addresses match.
        let prefixes = [
            "1", "11", "1a", "1B", "1c2", "12", "1Q", "1z", "2", "1l", "1O",
        ];
        for is_case_sensitive in [true, false] {
            let mut matches = 0;
            for prefix in prefixes {
                let prefixes = [prefix.to_string()];
                let address_type = AddressType::Legacy;
                let matcher = PrefixMatcher::new(&prefixes, is_case_sensitive, address_type);
                assert!(matches!(matcher, PrefixMatcher::Base58(_)));

                for index in 0..batch_len {
                    for hash in keys.pubkey_hashes(index) {
                        let mut payload = [0u8; 21];
                        payload[1..].copy_from_slice(&hash);
                        let address = bitcoin::base58::encode_check(&payload);
                        let expected = if is_case_sensitive {
                            address.starts_with(prefix)
                        } else {
                            address.to_lowercase().starts_with(&prefix.to_lowercase())
                        };
                        assert_eq!(matcher.matches(&hash), expected, "{} {}", prefix, address);
                        matches += usize::from(expected);
                    }
                }
            }
            assert!(matches > batch_len);
        }
    }

    #[test]
    fn matcher_is_empty_for_impossible_prefixes() {
        let is_empty = |prefix: &str, is_case_sensitive: bool, address_type: AddressType| {
            PrefixMatcher::new(&[prefix.to_string()], is_case_sensitive, address_type).is_empty()
        };

        assert!(!is_empty("1Kids", false, AddressType::Legacy));
        assert!(!is_empty("1Kids", true, AddressType::Legacy));
        // Legacy addresses start with 1.
        assert!(is_empty("Kids", false, AddressType::Legacy));
        assert!(is_empty("bc1qkd", false, AddressType::Legacy));
        // A lowercase l is not in Base58, an uppercase L is.
        assert!(is_empty("1Nicol", true, AddressType::Legacy));
        assert!(!is_empty("1Nicol", false, AddressType::Legacy));
        assert!(is_empty("1O0", false, AddressType::Legacy));

        assert!(!is_empty("bc1qkd", false, AddressType::Bech32));
        assert!(!is_empty("BC1QKD", false, AddressType::Bech32));
        assert!(!is_empty("bc", false, AddressType::Bech32));
        // The letter b is not in Bech32.
        assert!(is_empty("bc1qkb", false, AddressType::Bech32));
        assert!(is_empty("bc1pkd", false, AddressType::Bech32));
        assert!(is_empty("1Kids", false, AddressType::Bech32));

        assert!(!is_empty("bc1pkd", false, AddressType::Taproot));
        assert!(is_empty("bc1pko", false, AddressType::Taproot));
        assert!(is_empty("bc1qkd", false, AddressType::Taproot));
    }
}
