mod address;

use address::Couple;
use rayon::iter::ParallelIterator;
use secp256k1::Secp256k1;
use serde_json::json;
use spinners::{Spinner, Spinners};
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::process;
use std::time::Instant;

mod cli;

fn main() {
    let matches = cli::ask().get_matches();

    if !matches.is_present("starts-with") && !matches.is_present("file") {
        eprintln!("Start with prefix must be provided use --starts-with or --file");
        process::exit(1);
    }

    let spinner = Spinner::new(Spinners::Dots12, "Finding Bitcoin vanity address".into());
    let started_at = Instant::now();
    let secp = Secp256k1::new();

    let is_case_sensitive: bool = matches.is_present("case-sensitive");
    let is_bech32: bool = matches.is_present("bech32");

    let num_threads: usize = matches
        .value_of("threads")
        .and_then(|duration| duration.parse().ok())
        .unwrap_or_else(num_cpus::get);

    let rayon_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .expect("Failed to create thread pool");

    let couple: Couple = rayon_pool.install(|| {
        rayon::iter::repeat(Couple::new)
            .map(|couple_new| couple_new(&secp, is_bech32))
            .find_any(|couple| match matches.value_of("starts-with") {
                Some(prefix) => couple.starts_with(&prefix, is_case_sensitive),
                None => {
                    let file_name: &str = matches.value_of("file").unwrap();
                    let addresses = get_addresses_from_file(file_name);

                    couple.starts_with_any(&addresses, is_case_sensitive)
                }
            })
            .expect("Failed to find address match")
    });

    spinner.stop();

    let result = json!({
        "uncompressed": {
            "private_key": couple.uncompressed.private_key.to_string(),
            "public_key": couple.uncompressed.public_key.to_string(),
            "address": couple.uncompressed.address.to_string()
        },
        "compressed": {
            "private_key": couple.compressed.private_key.to_string(),
            "public_key": couple.compressed.public_key.to_string(),
            "address": couple.compressed.address.to_string()
        },
        "creation_time": started_at.elapsed()
    });

    println!("{}", result.to_string());
}

fn get_addresses_from_file(file_name: &str) -> Vec<String> {
    let file = File::open(file_name).unwrap();
    let buffer = BufReader::new(file);

    buffer
        .lines()
        .map(|line| line.expect("Failed to read address pattern from input file"))
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::address::Couple;
    use secp256k1::Secp256k1;

    #[test]
    fn create_bitcoin_public_key() {
        let secp = Secp256k1::new();
        let couple = Couple::new(&secp, false);

        let actual = couple.compressed.public_key.to_string().len();
        let expected = 66;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bitcoin_private_key() {
        let secp = Secp256k1::new();
        let couple = Couple::new(&secp, false);

        let actual = couple.compressed.private_key.to_string().len();
        let expected = 52;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bitcoin_address() {
        let secp = Secp256k1::new();
        let couple = Couple::new(&secp, false);

        let actual = couple.compressed.address.to_string().len();
        let expected = 34;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bech32_address() {
        let secp = Secp256k1::new();
        let couple = Couple::new(&secp, true);

        assert!(couple.uncompressed.address.to_string().starts_with("bc1q"));
        assert!(couple.compressed.address.to_string().starts_with("bc1q"));
    }
}
