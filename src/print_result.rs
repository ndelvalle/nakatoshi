use serde_json::json;
use std::time::Instant;

use crate::address;

pub fn print_result(couple: address::Couple, started_at: Instant, starts_with: &str, is_case_sensitive: bool) {
    let is_compressed = couple
        .compressed
        .starts_with(starts_with, is_case_sensitive);
    let address = if is_compressed {
        couple.compressed
    } else {
        couple.uncompressed
    };

    let result = json!({
        "private_key": address.private_key.to_string(),
        "public_key": address.public_key.to_string(),
        "address": address.address.to_string(),
        "compressed": is_compressed,
        "creation_time": started_at.elapsed()
    });

    println!("{}", result.to_string());
}

pub fn print_result_from_multiple_addresses_options(
    couple: address::Couple,
    started_at: Instant,
    addresses: Vec<String>,
    is_case_sensitive: bool,
) {
    for address in addresses {
        if couple
            .compressed
            .starts_with(address.as_str(), is_case_sensitive)
            || couple
                .uncompressed
                .starts_with(address.as_str(), is_case_sensitive)
        {
            return print_result(couple, started_at, address.as_str(), is_case_sensitive);
        }
    }
}
