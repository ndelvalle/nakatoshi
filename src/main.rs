mod address;

use std::time::Instant;
use std::{thread, iter::repeat_with};

use address::Address;
use indicatif::{ MultiProgress, ProgressBar, HumanDuration };
use rayon::iter::ParallelIterator;

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
        let starts_with = matches.value_of("startswith").unwrap();

        let report_progress = |addr: &Address| {
            let cpu_idx = rayon::current_thread_index().unwrap();
            let message = format!("CPU {}: Finding vanity address {}", cpu_idx + 1, addr.address);
            spinners[cpu_idx].set_message(&message);
        };

        let address = rayon::iter::repeat(Address::new)
            .map(|compute_addr| compute_addr())
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
    println!("Time elapsed: {}", HumanDuration(started_at.elapsed()));
}
