use serde_json::json;
use std::io::Write;
use std::time::Instant;

use crate::address;

pub struct Output {
    last_print_time: Instant,
    results_since_last_print: usize,
    output_streams: Vec<Box<dyn Write>>,
    log_stream: Option<Box<dyn Write>>,
}

impl Output {
    pub fn new() -> Output {
        Output {
            last_print_time: Instant::now(),
            results_since_last_print: 0,
            output_streams: vec![],
            log_stream: None,
        }
    }

    pub fn add_output_stream(&mut self, stream: Box<dyn Write>) {
        self.output_streams.push(stream);
    }

    pub fn set_log_stream(&mut self, stream: Option<Box<dyn Write>>) {
        self.log_stream = stream;
    }

    pub fn write(
        &mut self,
        couple: &address::Couple,
        started_at: Instant,
        starts_with: &str,
        is_case_sensitive: bool,
    ) {
        let is_compressed = couple
            .compressed
            .starts_with(starts_with, is_case_sensitive);
        let (private_key, public_key, address) = if is_compressed {
            (
                couple.compressed.private_key.to_string(),
                couple.compressed.public_key.to_string(),
                couple.compressed.address.to_string(),
            )
        } else {
            (
                couple.uncompressed.private_key.to_string(),
                couple.uncompressed.public_key.to_string(),
                couple.uncompressed.address.to_string(),
            )
        };

        if let Some(log_stream) = &mut self.log_stream {
            let duration = Instant::now() - self.last_print_time;
            let millis = duration.as_millis();
            let minutes = millis / (1000 * 60);
            if minutes % 5 == 0 || minutes >= 20 || self.results_since_last_print >= 100 {
                let last_results = self.results_since_last_print;
                self.results_since_last_print = 0;
                self.last_print_time = Instant::now();

                let log_output =
                    format!("{} addresses found in {} minutes.", last_results, minutes);
                let _result = log_stream.write_all(log_output.as_bytes());
            } else {
                self.results_since_last_print += 1;
            }
        }

        let result = json!({
            "private_key": private_key,
            "public_key": public_key,
            "address": address,
            "compressed": is_compressed,
            "creation_time": started_at.elapsed()
        });

        for stream in self.output_streams.iter_mut() {
            let result_string = result.to_string() + "\n";
            let _written = stream.write_all(result_string.as_bytes());
        }
    }

    pub fn write_from_multiple_addresses(
        &mut self,
        couple: &address::Couple,
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
                self.write(couple, started_at, address.as_str(), is_case_sensitive);
            }
        }
    }
}
