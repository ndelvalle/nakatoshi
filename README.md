# nakatoshi

[![](https://github.com/ndelvalle/nakatoshi/workflows/Rust/badge.svg)](https://github.com/ndelvalle/nakatoshi/actions?query=workflow%3ARust)

A [Bitcoin Vanity Address](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#vanity-addresses) generator.

nakatoshi accepts as input one or more prefix strings to search for and produce
a Bitcoin address and private / public keys. The amount of time required to find a given pattern depends
on how long the string is, the speed of your computer, and whether you get lucky.

nakatoshi searches on the CPU, using all cores by default. GPU-based tools are much faster for
long prefixes.

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
Usage: nakatoshi [OPTIONS] <prefix>...

Arguments:
  <prefix>...  Prefixes used to match addresses, any one of them is a match

Options:
  -t, --threads <threads>  Number of threads to be used [default: the number of CPUs]
  -c, --case-sensitive     Use case sensitive comparison to match addresses
  -b, --bech32             Use Bech32 addresses. Starting with bc1q (Lowercase address)
  -r, --taproot            Use Taproot addresses. Starting with bc1p (Lowercase address) [alias: --p2tr]
  -k, --keep-going         Don't stop at the first match, print every match and keep searching
  -u, --uncompressed       Use uncompressed private and public keys
  -h, --help               Print help
  -V, --version            Print version
```


## Examples:

#### Generate a vanity address

```shell
nakatoshi 1Kids
```

#### Search for several prefixes

```shell
nakatoshi 1Kids 1Love
```

The first address that starts with any of the prefixes is the result, which takes less
time than searching for a single one.

#### Use a file with prefixes

```shell
nakatoshi $(cat prefixes.txt)
```

The `prefixes.txt` file has one prefix on each line:
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
