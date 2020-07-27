use address::Couple;
use rayon::iter::ParallelIterator;
use secp256k1::Secp256k1;
use spinners::{Spinner, Spinners};
use std::fs::File;
use std::fs::OpenOptions;
use std::io::BufRead;
use std::io::BufReader;
use std::path::PathBuf;
use std::process;
use std::time::Instant;

mod address;
mod cli;
mod print_result;

use print_result::Output;

fn main() {
    let matches = cli::ask().get_matches();

    if !matches.is_present("starts-with") && !matches.is_present("file") {
        eprintln!("Start with prefix must be provided use --starts-with or --file");
        process::exit(1);
    }

    let spinner = Spinner::new(Spinners::Dots12, "Finding Bitcoin vanity address\n".into());
    let started_at = Instant::now();
    let secp = Secp256k1::new();

    let is_case_sensitive: bool = matches.is_present("case-sensitive");
    let is_bech32: bool = matches.is_present("bech32");

    let num_threads: usize = matches
        .value_of("threads")
        .and_then(|duration| duration.parse().ok())
        .unwrap_or_else(num_cpus::get);

    let mut output = Output::new();

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
            .expect("Can not open the output file.");

        output.add_output_stream(Box::new(output_file));
    }

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

    match matches.value_of("starts-with") {
        Some(prefix) => output.write(&couple, started_at, prefix, is_case_sensitive),
        None => {
            let file_name: &str = matches.value_of("file").unwrap();
            let addresses = get_addresses_from_file(file_name);

            output.write_from_multiple_addresses(&couple, started_at, addresses, is_case_sensitive);
        }
    }
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
