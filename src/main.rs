#![feature(test)]

mod address;

use std::time::Instant;
use std::{thread, iter::repeat_with};

use indicatif::{ MultiProgress, ProgressBar };
use rayon::iter::ParallelIterator;
use secp256k1::Secp256k1;

use address::Address;

fn main() {
    let started_at = Instant::now();
    let cpus = num_cpus::get();
    let multi_progress_bar = MultiProgress::new();
    let matches = clap::App::new("Bitcoin vanity address generator")
        .version("0.1.0")
        .about("This tool creates a set of Bitcoin mainnet private, public key and vanity address")
        .author("ndelvalle <nicolas.delvalle@gmail.com>")
        .arg(clap::Arg::with_name("startswith")
            .required(true)
            .takes_value(true)
            .index(1)
            .help("Address starts with")
        )
        .get_matches();

    let spinners = repeat_with(|| multi_progress_bar.add(ProgressBar::new_spinner()))
        .take(cpus)
        .collect::<Vec<_>>();

    let work_handle = thread::spawn(move || {
        let secp = Secp256k1::new();
        let starts_with = matches.value_of("startswith").unwrap();

        let report_progress = |addr: &Address| {
            let cpu_idx = rayon::current_thread_index().unwrap();
            let message = format!("CPU {}: Finding vanity address {}", cpu_idx + 1, addr.address);
            spinners[cpu_idx].set_message(&message);
        };

        let address = rayon::iter::repeat(Address::new)
            .map(|compute_addr| compute_addr(&secp))
            .inspect(report_progress)
            .find_any(|addr| addr.starts_with(starts_with))
            .unwrap();

        for spinner in spinners {
            spinner.finish()
        }

        address
    });

    multi_progress_bar.join_and_clear().unwrap();
    let address = work_handle.join().unwrap();

    println!("Private key:  {}", address.private_key);
    println!("Public key:   {}", address.public_key);
    println!("Address:      {}", address.address);
    println!("Time elapsed: {:?}", started_at.elapsed());
}

#[cfg(test)]
mod tests {
    extern crate test;

    use test::Bencher;
    use super::*;

    #[bench]
    fn find_address_reusing_secp(bencher: &mut Bencher) {
        let secp = Secp256k1::new();

        bencher.iter(|| Address::new(&secp))
    }

    #[bench]
    fn find_address_reinstantiating_secp(bencher: &mut Bencher) {
        bencher.iter(|| Address::new(&Secp256k1::new()))
    }
}
