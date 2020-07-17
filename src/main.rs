mod address;

use address::Couple;
use rayon::iter::ParallelIterator;
use secp256k1::Secp256k1;
use serde_json::json;
use spinners::{Spinner, Spinners};
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;
use std::process;
use std::time::Instant;

mod cli;

fn main() {
    let matches = cli::ask().get_matches();

    if !matches.is_present("starts-with") && !matches.is_present("file-input") {
        eprintln!("Start with prefix must be provided use --starts-with or --file-input");
        process::exit(1);
    }

    let spinner = Spinner::new(Spinners::Dots12, "Calculating vanity address".into());
    let started_at = Instant::now();
    let secp = Secp256k1::new();

    let case_sensitive: bool = matches.is_present("case-sensitive");
    let is_bech32: bool = matches.is_present("bech32");

    let couple: Couple = if matches.is_present("file-input") {
        let file_name: &str = matches.value_of("file-input").unwrap();
        let addresses = load_file_into_vector(file_name);

        rayon::iter::repeat(Couple::new)
            .map(|couple_new| couple_new(&secp, is_bech32))
            .find_any(|couple| couple.starts_with_any(&addresses, case_sensitive))
            .unwrap()
    } else {
        let starts_with: String = if case_sensitive {
            matches.value_of("starts-with").unwrap().to_string()
        } else {
            matches.value_of("starts-with").unwrap().to_lowercase()
        };

        rayon::iter::repeat(Couple::new)
            .map(|couple_new| couple_new(&secp, is_bech32))
            .find_any(|couple| couple.starts_with(&starts_with, case_sensitive))
            .unwrap()
    };

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

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}

fn load_file_into_vector(file_name: &str) -> Vec<String> {
    let mut addresses: Vec<String> = Vec::new();
    if let Ok(lines) = read_lines(file_name) {
        // Consumes the iterator, returns an (Optional) String
        for line in lines {
            if let Ok(address) = line {
                addresses.push(address);
            }
        }
    }
    addresses
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
