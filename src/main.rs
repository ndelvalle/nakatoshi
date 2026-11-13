use bitcoin::secp256k1::Secp256k1;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::json;
use std::fs;
use std::io::BufRead;
use std::io::BufReader;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;

mod address;
mod cli;

use address::{BitcoinAddress, KeyWalker, PrefixMatcher};

// How many attempts a thread makes before it reports them.
const PROGRESS_BATCH_SIZE: u64 = 1024;

fn main() {
    let matches = cli::prompt().get_matches();
    let secp = Secp256k1::new();

    let is_bech32 = matches.get_flag("bech32");
    // Bech32 addresses are always lowercase, so case-sensitive matching
    // makes no sense for them; ignore the flag in that case.
    let is_case_sensitive = matches.get_flag("case-sensitive") && !is_bech32;
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

    let matcher = PrefixMatcher::new(&prefixes, is_case_sensitive, is_bech32);
    let is_found = AtomicBool::new(false);
    let found: Mutex<Option<(BitcoinAddress, u64)>> = Mutex::new(None);

    rayon_pool.broadcast(|_| {
        let mut keys = KeyWalker::new(&secp);
        let mut attempts = 0;

        loop {
            if attempts == PROGRESS_BATCH_SIZE {
                progress.inc(attempts);
                attempts = 0;
                if is_found.load(Ordering::Relaxed) {
                    return;
                }
            }
            attempts += 1;

            if !matcher.matches(&keys.pubkey_hash(is_compressed)) {
                keys.advance(&secp);
                continue;
            }

            let secret_key = keys.secret_key();
            // Consecutive keys are related, so don't hand out more than one of them.
            keys = KeyWalker::new(&secp);

            let address =
                BitcoinAddress::from_secret_key(&secp, secret_key, is_compressed, is_bech32);
            if !address.starts_with_any(&prefixes, is_case_sensitive) {
                continue;
            }

            progress.inc(attempts);
            attempts = 0;
            if is_keep_going {
                let result = address_json(&address, progress.position());
                progress.suspend(|| println!("{}", result));
            } else {
                let mut found = found.lock().unwrap();
                if found.is_none() {
                    *found = Some((address, progress.position()));
                }
                is_found.store(true, Ordering::Relaxed);
                return;
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
        .collect::<Vec<String>>();

    prefixes.sort_by_key(|a| a.len());
    prefixes
}

#[cfg(test)]
mod tests {
    use crate::address::{BitcoinAddress, KeyWalker, PrefixMatcher};
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn create_compressed_bitcoin_public_key() {
        let secp = Secp256k1::new();
        let is_bech32 = false;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, is_bech32);

        let actual = bitcoin_address.public_key.to_string().len();
        let expected = 66;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_uncompressed_bitcoin_public_key() {
        let secp = Secp256k1::new();
        let is_bech32 = false;
        let is_compressed = false;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, is_bech32);

        let actual = bitcoin_address.public_key.to_string().len();
        let expected = 130;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bech32_address() {
        let secp = Secp256k1::new();
        let is_bech32 = true;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, is_bech32);
        let address = bitcoin_address.address.to_string();

        assert!(address.starts_with("bc1q"));
    }

    #[test]
    fn create_bitcoin_private_key() {
        let secp = Secp256k1::new();
        let is_bech32 = false;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, is_bech32);

        let actual = bitcoin_address.private_key.to_string().len();
        let expected = 52;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bitcoin_address() {
        let secp = Secp256k1::new();
        let is_bech32 = false;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, is_bech32);

        let actual = bitcoin_address.address.to_string().len();
        let expected = 34;

        assert_eq!(actual, expected);
    }

    #[test]
    fn walked_keys_match_their_secret_key() {
        let secp = Secp256k1::new();
        let mut keys = KeyWalker::new(&secp);

        for _ in 0..100 {
            for is_compressed in [true, false] {
                let address =
                    BitcoinAddress::from_secret_key(&secp, keys.secret_key(), is_compressed, false);
                assert_eq!(
                    address.public_key.pubkey_hash().to_byte_array(),
                    keys.pubkey_hash(is_compressed)
                );
            }
            keys.advance(&secp);
        }
    }

    #[test]
    fn matcher_agrees_with_address() {
        let secp = Secp256k1::new();
        let mut keys = KeyWalker::new(&secp);

        for _ in 0..100 {
            for (is_bech32, is_case_sensitive, len) in
                [(true, false, 7), (true, false, 36), (false, true, 4), (false, false, 4)]
            {
                let address =
                    BitcoinAddress::from_secret_key(&secp, keys.secret_key(), true, is_bech32);
                let address = address.address.to_string();
                let hash = keys.pubkey_hash(true);

                let prefix = if is_case_sensitive {
                    address[..len].to_string()
                } else {
                    address[..len].to_uppercase()
                };
                let matcher = PrefixMatcher::new(&[prefix], is_case_sensitive, is_bech32);
                assert!(matcher.matches(&hash));

                // Change the last character of the prefix, it should not match anymore.
                let last = if address[len - 1..len].eq_ignore_ascii_case("q") { "p" } else { "q" };
                let prefix = format!("{}{}", &address[..len - 1], last);
                let matcher = PrefixMatcher::new(&[prefix], is_case_sensitive, is_bech32);
                assert!(!matcher.matches(&hash));
            }
            keys.advance(&secp);
        }
    }
}
