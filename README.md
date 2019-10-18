# nakatoshi :crab:

A [Bitcoin Vanity Address](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#vanity-addresses) generator.

nakatoshi accepts as input a "starts with" string to search for, and produces an address and private / public keys. The amount of time required to find a given pattern depends on how long the string is, the speed of your computer, and whether you get lucky.

## Development

```shell
# Build
cargo build

# Run
cargo run

# Example using a start with string
cargo run 1Lov

#    Finished dev [unoptimized + debuginfo] target(s) in 0.16s
#     Running `target/debug/nakatoshi 1Ki`
#Private key:  L5cwwXrcbLLibKmPgCewh2ueGCV6nV1zm1aUFRgW5q8mg2ufdEcc
#Public key:   020e225a9d3c700a2544af1d9bd935aac380dee6c5716b19d5d26e6fe3d415310b
#Address:      1KioF2fBWMmrHZy8ctGBQgmkjpcqTw4j3c
#Time elapsed: 45.551637ms

# Help
cargo run -- -help
```

## TODOs

- [x] Create a release build
- [ ] Create a release build
- [ ] Improve API adding more options
- [ ] Create tests
- [x] Integrate with a CI
