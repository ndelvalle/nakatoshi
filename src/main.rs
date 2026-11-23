use bitcoin::secp256k1::Secp256k1;
use indicatif::{ProgressBar, ProgressStyle};
use serde_json::json;
use std::io::{self, Write};
use std::num::NonZeroUsize;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

mod address;
mod cli;
mod matcher;
mod walker;

use address::{AddressType, BitcoinAddress};
use matcher::PrefixMatcher;
use walker::KeyWalker;

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
        .get_one::<NonZeroUsize>("threads")
        .map_or_else(num_cpus::get, |num_threads| num_threads.get());

    let prefixes: Vec<String> = matches
        .get_many::<String>("prefix")
        .unwrap_or_default()
        .cloned()
        .collect();

    let matcher = PrefixMatcher::new(&prefixes, is_case_sensitive, address_type);
    let matcher = matcher.unwrap_or_else(|_| {
        let limit = matcher::BASE58_MAX_VARIANTS;
        exit_with_error(if is_case_sensitive {
            format!("There are more than {limit} prefixes")
        } else {
            format!(
                "The prefixes can be written in more than {limit} ways in upper and lowercase. \
                 Use fewer or shorter prefixes, or --case-sensitive"
            )
        })
    });
    if matcher.is_empty() {
        let subject = match prefixes.as_slice() {
            [prefix] => format!("\"{prefix}\""),
            _ => "any of the prefixes".to_owned(),
        };
        let format = match address_type {
            AddressType::Legacy => {
                "Legacy addresses start with 1, have no 0, O, I or l, \
                 and are at most 34 characters long"
            }
            AddressType::Bech32 => {
                "Bech32 addresses start with bc1q, have no 1, b, i or o after that, \
                 and are 42 characters long"
            }
            AddressType::Taproot => {
                "Taproot addresses start with bc1p, have no 1, b, i or o after that, \
                 and are 62 characters long"
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
        .template("[{elapsed_precise}] {pos} attempts ({per_sec:0})")
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
                    if matcher.matches(&keys.output_key(index)) {
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
                let is_printed = progress.suspend(|| writeln!(io::stdout(), "{result}").is_ok());
                if !is_printed {
                    // Nobody is reading the matches anymore.
                    progress.finish_and_clear();
                    std::process::exit(0);
                }
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
        "address_type": bitcoin_address.address_type.name(),
        "attempts": attempts
    })
}

/// Prints an error the way the argument parser does, and exits.
fn exit_with_error(message: impl std::fmt::Display) -> ! {
    cli::prompt()
        .error(clap::error::ErrorKind::ValueValidation, message)
        .exit()
}
