# nakatoshi

[![](https://github.com/ndelvalle/nakatoshi/workflows/Rust/badge.svg)](https://github.com/ndelvalle/nakatoshi/actions?query=workflow%3ARust)

A [Bitcoin Vanity Address](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04_keys.adoc#vanity-addresses) generator.

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
nakatoshi -b bc1qcat
```

Note: There is no need to search with the `case-sensitive` flag because `bc1q` addresses are
always lowercase. After `bc1q` they have no `1`, `b`, `i` or `o`.

#### Taproot addresses

```shell
nakatoshi -r bc1pcat
```

The address can only be spent with the private key, there are no scripts in it ([BIP 86](https://github.com/bitcoin/bips/blob/master/bip-0086.mediawiki)).
It is the address of the `tr(<private_key>)` descriptor.

The `public_key` of the result is not the key that is in the address. A Taproot address has the
public key tweaked with a hash of itself, as BIP 86 describes. Wallets do the same tweak when they
import the private key, so there is nothing extra to do to spend from it.

Note: Searching for a Taproot address is a lot slower than for the other address types, as
every attempt takes a lot more work.

## Importing the keys

The result looks like this:

```json
{"address":"1Kids...","address_type":"legacy","attempts":1052817,"private_key":"L1...","public_key":"03..."}
```

The private key is in [WIF](https://en.bitcoin.it/wiki/Wallet_import_format), which doesn't say
which type of address it is for, so the result has the `address_type` as well. Every key has an
address of each type, so a wallet has to know which one to use. An
[output descriptor](https://github.com/bitcoin/bips/blob/master/bip-0380.mediawiki) is a short
text with both, the key and the type of address, which wallets such as Bitcoin Core can import.
These are the descriptors of each address type:

| `address_type` | Address starts with | Descriptor            |
| -------------- | ------------------- | --------------------- |
| `legacy`       | `1`                 | `pkh(<private_key>)`  |
| `bech32`       | `bc1q`              | `wpkh(<private_key>)` |
| `taproot`      | `bc1p`              | `tr(<private_key>)`   |

Bitcoin Core only imports a descriptor with its checksum after a `#`, which `getdescriptorinfo`
returns. These commands import a Bech32 address, the other types only change the descriptor:

```shell
bitcoin-cli getdescriptorinfo "wpkh(<private_key>)"
bitcoin-cli -rpcwallet=<wallet> importdescriptors '[{"desc": "wpkh(<private_key>)#<checksum>", "timestamp": "now"}]'
```

Use the `checksum` that `getdescriptorinfo` returns, not its `descriptor`. That one has the
public key instead of the private key, so the wallet couldn't spend from the address.
