mod address;

use address::Address;
use rayon::iter::ParallelIterator;
use secp256k1::Secp256k1;
use serde_json::json;
use spinners::{Spinner, Spinners};
use std::time::Instant;

fn main() {
    let matches = clap::App::new("Bitcoin vanity address generator")
        .version("0.1.0")
        .about("This tool creates a set of Bitcoin mainnet private, public key and vanity address")
        .author("ndelvalle <nicolas.delvalle@gmail.com>")
        .args(
            &[
                clap::Arg::with_name("startswith")
                    .required(true)
                    .takes_value(true)
                    .index(1)
                    .help("Address starts with"),
                clap::Arg::with_name("case_sensitive")
                    .short("i")
                    .long("sensitive")
                    .takes_value(false)
                    .help("case insensitive searches for matches")
            ]
        )
        .get_matches();

    let spinner = Spinner::new(Spinners::Dots9, "Calculating vanity address".into());
    let started_at = Instant::now();
    let secp = Secp256k1::new();
    let case_sensitive: bool = !matches.is_present("case_sensitive");
    let starts_with: String = match case_sensitive {
        true => matches.value_of("startswith").unwrap().to_string(),
        false => matches.value_of("startswith").unwrap().to_lowercase()
    };

    let address = rayon::iter::repeat(Address::new)
        .map(|compute_addr| compute_addr(&secp))
        .find_any(|addr| addr.starts_with(&starts_with, case_sensitive))
        .unwrap();

    spinner.stop();

    let result = json!({
        "private_key": address.private_key.to_string(),
        "public_key": address.public_key.to_string(),
        "address": address.address.to_string(),
        "creation_time": started_at.elapsed()
    });

    println!("{}", result.to_string());
}

#[cfg(test)]
mod tests {
    use super::address::Address;
    use secp256k1::Secp256k1;

    #[test]
    fn create_bitcoin_public_key() {
        let secp = Secp256k1::new();
        let address = Address::new(&secp);

        let actual = address.public_key.to_string().len();
        let expected = 66;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bitcoin_private_key() {
        let secp = Secp256k1::new();
        let address = Address::new(&secp);

        let actual = address.private_key.to_string().len();
        let expected = 52;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bitcoin_address() {
        let secp = Secp256k1::new();
        let address = Address::new(&secp);

        let actual = address.address.to_string().len();
        let expected = 34;

        assert_eq!(actual, expected);
    }
}
