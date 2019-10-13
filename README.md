# rust-bitcoin-vanity

This tool creates a set of Bitcoin mainnet private, public key and vanity address (Essentially a personalized bitcoin address). This project is a proof of concept to play around with Rust lang.

bitcoin-vanity accepts as input a "starts with" pattern to search for, and produces an address and private / public keys. The amount of time required to find a given pattern depends on how complex the pattern is, the speed of your computer, and whether you get lucky.

## Development

```shell
# Build
cargo build

# Run
cargo run

# Example using a start with pattern
cargo run 1n

#Finished dev [unoptimized + debuginfo] target(s) in 0.05s
#     Running `target/debug/bitcoin-vanity 1n`
#Private key: KxXruWMF332bafiBSnXY48Yr3oUbgg4vZNQhoj1QQFPAQhmN9PBL
#Public key:  02230073187af84cd6e4a85c4607cea6bae3c8fd8be50c4caae27b85829331d6a3
#Address:     1nK5tgJC4EuJ96KGGo8pZdTGN54B2iAt5

# Help
cargo run -- -help
```

## TODOs

- [ ] Create a release build
- [ ] Improve API adding more options
- [ ] Implement multi thread support
- [ ] Create tests
- [ ] Integrate with a CI
