use address::BitcoinAddress;
use rayon::iter::ParallelIterator;
use secp256k1::Secp256k1;
use spinners::{Spinner, Spinners};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::path::PathBuf;
use std::time::Instant;

mod address;
mod cli;
mod output;

fn main() {
    let matches = cli::prompt().get_matches();

    // let spinner = Spinner::new(Spinners::Dots12, "Finding Bitcoin vanity address".into());
    let started_at = Instant::now();
    let secp = Secp256k1::new();

    let is_case_sensitive = matches.is_present("case-sensitive");
    let is_bech32 = matches.is_present("bech32");
    let is_compressed = !matches.is_present("uncompressed");

    let num_threads = matches
        .value_of("threads")
        .and_then(|duration| duration.parse().ok())
        .unwrap_or_else(num_cpus::get);

    let mut output = output::Output::new();

    // Feature #18 not implemented yet
    let multiple_iterations = false;

    let stdout = Box::leak(Box::new(std::io::stdout()));
    let handle = stdout.lock();

    if multiple_iterations {
        output.set_log_stream(Some(Box::new(handle)));
    } else {
        output.add_output_stream(Box::new(handle));
    }

    if let Some(output_filename) = matches.value_of("output-file") {
        let file_path = PathBuf::from(output_filename);
        let output_file = OpenOptions::new()
            .write(true)
            .append(true)
            .create_new(true)
            .open(file_path)
            .expect("Failed to open output file.");

        output.add_output_stream(Box::new(output_file));
    }

    let rayon_pool = rayon::ThreadPoolBuilder::new()
        .num_threads(num_threads)
        .build()
        .expect("Failed to create thread pool");

    let bitcoin_address: BitcoinAddress = rayon_pool.install(|| {
        rayon::iter::repeat(BitcoinAddress::new)
            .map(|create| create(&secp, is_compressed, is_bech32))
            .find_any(|bitcoin_address| match matches.value_of("prefix") {
                Some(prefix) => {
                    println!("Asd");
                    bitcoin_address.starts_with(&prefix, is_case_sensitive)
                },
                None => {
                    // TODO: File content should be in memory already
                    let file_name: &str = matches.value_of("input-file").unwrap();
                    let addresses = get_addresses_from_file(file_name);

                    bitcoin_address.starts_with_any(&addresses, is_case_sensitive)
                }
            })
            .expect("Failed to find Bitcoin address match")
    });

    // spinner.stop();

    output.write(&bitcoin_address, started_at);
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
    use crate::address::BitcoinAddress;
    use secp256k1::Secp256k1;

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
}
