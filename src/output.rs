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
        bitcoin_address: &address::BitcoinAddress,
        started_at: Instant,
        iterations: usize,
    ) {
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
            "private_key": bitcoin_address.private_key.to_string(),
            "public_key": bitcoin_address.public_key.to_string(),
            "address": bitcoin_address.address.to_string(),
            "seconds": started_at.elapsed().as_secs(),
            "iterations": iterations
        });

        for stream in self.output_streams.iter_mut() {
            let result_string = result.to_string() + "\n";
            stream
                .write_all(result_string.as_bytes())
                .expect("Failed to write Bitcoin address result");
        }
    }
}
