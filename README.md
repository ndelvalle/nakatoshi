# nakatoshi

[![](https://github.com/ndelvalle/nakatoshi/workflows/Rust/badge.svg)](https://github.com/ndelvalle/nakatoshi/actions?query=workflow%3ARust)

A [Bitcoin Vanity Address](https://github.com/bitcoinbook/bitcoinbook/blob/develop/ch04.asciidoc#vanity-addresses) generator.

nakatoshi accepts as input a "starts with" string to search for, and produces an address and private / public keys. The amount of time required to find a given pattern depends on how long the string is, the speed of your computer, and whether you get lucky.

## Install


### Cargo

```
$ cargo install nakatoshi
```

### Manually

Download the latest [released binary](https://github.com/ndelvalle/nakatoshi/releases)
and add executable permissions:

```bash
# Linux example:
$ wget -O nakatoshi "https://github.com/ndelvalle/nakatoshi/releases/download/v0.1.1/nakatoshi-linux-amd64"
$ chmod +x nakatoshi
```

## CLI information


```
nakatoshi 0.1.0
Bitcoin vanity address generator

USAGE:
    nakatoshi [FLAGS] [OPTIONS]

FLAGS:
    -b, --bech32            Use Bech32 addresses starting with bc1q (Lowercase address)
    -c, --case-sensitive    Use case sensitive to match addresses
    -h, --help              Prints help information
    -V, --version           Prints version information

OPTIONS:
    -f, --file <file>                  File with starts-with prefixes to generate addresses
    -s, --starts-with <starts-with>    Start with prefix used to match addresses
    -t, --threads <threads>            Number of threads to be used [default: The number of CPUs available on the
                                       current system]
```


## Use examples:

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

# Help
$ cargo run -- -help
```

Note: `Cargo run` creates an unoptimized executable with debug info.
When testing the speed/throughput of the application, be sure to `cargo run --release` to get the best performance from the application.

Adding parameters in this context looks like `cargo run --release -- -f somefile.txt -i`
