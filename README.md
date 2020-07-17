# nakatoshi

[![](https://github.com/ndelvalle/nakatoshi/workflows/Rust/badge.svg)](https://github.com/ndelvalle/nakatoshi/actions?query=workflow%3ARust)

A [Bitcoin Vanity Address](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#vanity-addresses) generator.

nakatoshi accepts as input a "starts with" string to search for, and produces an address and private / public keys. The amount of time required to find a given pattern depends on how long the string is, the speed of your computer, and whether you get lucky.

## Installation

```shell
$ cargo install nakatoshi
```

## Usage

#### Generate a vanity address (case sensitive)
```shell
nakatoshi 1ki
```

#### Generate a vanity address (case insensitive)

(Note: might be a bit faster since matching is less strict)
```shell
nakatoshi 1ki -i
```

#### Use a file with multiple possible matches
A file with 1 pattern per newline can be used to search for vanity addresses.
When for example you have a file called `input.txt` it would look like this:
```shell
nakatoshi -f input.txt
```
And running everything case insensitive would be:
```shell
nakatoshi -f input.txt -i
```
The contents of the file would look like:
```
1git
1hub
1etc
```

#### Search for a Bech32 address
```shell
nakatoshi -b bc1qki
```
(Note: There is no need to search with the case-insensitive flag because `bc1q` addresses are lowercase.)

## Development

```shell
# Build
$ cargo build

# Run
$ cargo run

# Example using a start with string
$ cargo run 1Ki

#    Finished dev [unoptimized + debuginfo] target(s) in 0.16s
#     Running `target/debug/nakatoshi 1Ki`
#Private key:  L5cwwXrcbLLibKmPgCewh2ueGCV6nV1zm1aUFRgW5q8mg2ufdEcc
#Public key:   020e225a9d3c700a2544af1d9bd935aac380dee6c5716b19d5d26e6fe3d415310b
#Address:      1KioF2fBWMmrHZy8ctGBQgmkjpcqTw4j3c
#Time elapsed: 45.551637ms

# Help
$ cargo run -- -help
```
Note: `Cargo run` creates an unoptimized executable with debug info.
When testing the speed/throughput of the application, be sure to `cargo run --release` to get the best performance from the application.

Adding parameters in this context looks like `cargo run --release -- -f somefile.txt -i`

## TODOs

- [ ] Create a release build
- [ ] Improve API adding more options
- [ ] Add more tests
- [X] Add commandline argument for case-insensitive option (`-i`)
- [ ] Add commandline argument to keep going after finding an address (`-k`)
- [ ] Add commandline argument for saving results to file (`-o output.txt`)
- [X] Add commandline argument for using a file as input (`-f input.txt`)
- [X] Add commandline argument for Bech32 `bc1q` addresses (`-b`)
