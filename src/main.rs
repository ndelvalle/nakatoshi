extern crate secp256k1;
extern crate bitcoin;
extern crate clap;
extern crate indicatif;
extern crate time;
extern crate num_cpus;

mod address;

use std::time::Instant;
use std::sync::mpsc;
use std::sync::{ Arc, Mutex, atomic };
use std::{ thread };

use address::Address;
use indicatif::{ MultiProgress, ProgressBar, HumanDuration };

fn calculate_address (starts_with: &str, should_stop: &atomic::AtomicBool, cpu_num: usize, spinner: ProgressBar) -> Address {
    let mut address = Address::new();

    while !address.starts_with(starts_with) && !should_stop.load(atomic::Ordering::Relaxed) {
        address = Address::new();
        let message = format!("CPU {}: Finding vanity address {}", cpu_num, address.address.to_string());
        spinner.set_message(&message)
    }

    spinner.finish_and_clear();
    return address
}

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

    let starts_with = String::from(matches.value_of("startswith").unwrap());
    let (tx, rx) = mpsc::channel();
    let has_finished = Arc::new(atomic::AtomicBool::new(false));
    let address = Arc::new(Mutex::new(Address::new()));

    for cpu_num in 0..cpus {
        let progress_bar = multi_progress_bar.add(ProgressBar::new_spinner());
        let starts_with = starts_with.clone();
        let should_stop = has_finished.clone();
        let (address, tx) = (Arc::clone(&address), tx.clone());

        thread::spawn(move || {
            let found_address = calculate_address(&starts_with, &should_stop, cpu_num + 1, progress_bar);
            should_stop.store(true, atomic::Ordering::Relaxed);

            // We unwrap() the return value to assert that we are not expecting
            // threads to ever fail while holding the lock.
            let mut address = address.lock().unwrap();
            *address = found_address;
            tx.send(()).unwrap();
        });
    }

    multi_progress_bar.join().unwrap();
    rx.recv().unwrap();

    let unwraped_address = address.lock().unwrap();

    println!("Private key:  {}", unwraped_address.private_key);
    println!("Public key:   {}", unwraped_address.public_key);
    println!("Address:      {}", unwraped_address.address);
    println!("Time elapsed: {}", HumanDuration(started_at.elapsed()));
}
