extern crate secp256k1;
extern crate bitcoin;
extern crate clap;
extern crate indicatif;

mod address_resource;

use address_resource::AddressResource;
use indicatif::ProgressBar;

fn main() {
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

    let starts_with = matches.value_of("startswith").unwrap();
    let mut addr_resource = AddressResource::new();
    let spinner = ProgressBar::new_spinner();

    while !addr_resource.address_starts_with(starts_with) {
        addr_resource = AddressResource::new();
        let message = format!("Finding vanity address {}", addr_resource.address.to_string());
        spinner.set_message(&message)
    }

    spinner.finish_and_clear();

    println!("Private key: {}", addr_resource.private_key);
    println!("Public key:  {}", addr_resource.public_key);
    println!("Address:     {}", addr_resource.address);
}
