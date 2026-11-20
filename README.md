# nakatoshi

[![](https://github.com/ndelvalle/nakatoshi/workflows/Rust/badge.svg)](https://github.com/ndelvalle/nakatoshi/actions?query=workflow%3ARust)

A [Bitcoin Vanity Address](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#vanity-addresses) generator.

nakatoshi accepts as input a prefix string (Or a file with multiple prefixes) to search for and produce
a Bitcoin address and private / public keys. The amount of time required to find a given pattern depends
on how long the string is, the speed of your computer, and whether you get lucky.

## Install

### MacOS

```
$ brew tap ndelvalle/utilities
$ brew install nakatoshi
```

### Cargo

```
$ cargo install nakatoshi
```

Requires Rust 1.88 or newer.

### Manually

Download the latest [released binary](https://github.com/ndelvalle/nakatoshi/releases)
and extract it:

```bash
# Linux example:
$ wget "https://github.com/ndelvalle/nakatoshi/releases/latest/download/nakatoshi-linux-amd64.tar.gz"
$ tar -xzf nakatoshi-linux-amd64.tar.gz
```

## CLI

```
Usage: nakatoshi [OPTIONS] [prefix]

Arguments:
  [prefix]  Prefix used to match addresses

Options:
  -i, --input-file <input-file>  File with prefixes to match addresses with
  -t, --threads <threads>        Number of threads to be used [default: the number of CPUs]
  -c, --case-sensitive           Use case sensitive comparison to match addresses
  -b, --bech32                   Use Bech32 addresses. Starting with bc1q (Lowercase address)
  -r, --taproot                  Use Taproot addresses. Starting with bc1p (Lowercase address) [alias: --p2tr]
  -k, --keep-going               Don't stop at the first match, print every match and keep searching
  -u, --uncompressed             Use uncompressed private and public keys
  -h, --help                     Print help
  -V, --version                  Print version
```


## Examples:

#### Generate a vanity address

```shell
nakatoshi 1Kids
```

#### Generate a vanity address and parse JSON response

```shell
nakatoshi 1Bitc | jq
```

#### Use a file with multiple prefixes

A file with one address prefix on each newline can be used to search for a vanity
address. This reduces the time to find a result.

Example:

```shell
nakatoshi --input-file input.txt
```

The contents of the `input.txt` file looks like this:
```
1Kids
1Love
```

#### Keep searching after the first match

```shell
nakatoshi --keep-going 1Kids
```

Every match is printed as a line of JSON, until the search is stopped with `Ctrl+C`.

#### Bech32 addresses

```shell
nakatoshi -b bc1qki
```

Note: There is no need to search with the `case-sensitive` flag because `bc1q` addresses are
always lowercase.

#### Taproot addresses

```shell
nakatoshi -r bc1pki
```

The address can only be spent with the private key, there are no scripts in it ([BIP 86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)).
It is the address of the `tr(<private_key>)` descriptor.

Note: Searching for a Taproot address is a lot slower than for the other address types, as
every attempt takes a lot more work.

## Development

```shell
# Build
$ cargo build

# Help
$ cargo run -- --help

# Checks that run in CI
$ cargo fmt --all -- --check
$ cargo clippy -- -D warnings
$ cargo test
```

Note: `Cargo run` creates an unoptimized executable with debug info. When testing
the speed/throughput of the application, make sure to use `cargo run --release`.
