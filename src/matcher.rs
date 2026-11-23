use crate::address::AddressType;

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_PREFIX: &[u8; 4] = b"bc1q";
const TAPROOT_PREFIX: &[u8; 4] = b"bc1p";
const BECH32_CHECKSUM_LEN: usize = 6;

// The prefixes are matched against this many bytes, which is all of a public
// key hash and the start of an output key.
const MATCHED_LEN: usize = 20;

const BASE58_CHARSET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// Version byte, 20 byte hash and 4 byte checksum.
const BASE58_PAYLOAD_LEN: usize = 25;
const BASE58_MAX_ADDRESS_LEN: usize = 35;
// Every upper/lowercase variant of a prefix has ranges of its own to match,
// which take about 50 bytes. This is how many variants all the prefixes can
// have, to keep that within 500 megabytes.
pub const BASE58_MAX_VARIANTS: usize = 1 << 23;

/// Matches prefixes against a public key hash, or against the output key for
/// Taproot addresses, without creating an address.
///
/// It might match a little too much, so a match has to be confirmed with
/// `BitcoinAddress::starts_with_any`.
pub struct PrefixMatcher {
    // These are sorted, and don't overlap.
    ranges: Vec<HashRange>,
}

/// The prefixes have more than `BASE58_MAX_VARIANTS` upper/lowercase variants.
#[derive(Debug)]
pub struct TooManyVariants;

/// A range of public key hashes (or of the start of output keys), that has
/// all the addresses starting with a certain prefix. Both ends are inclusive.
///
/// The addresses at the very ends of the range of a Base58 prefix might not
/// start with the prefix, as that depends on the checksum.
struct HashRange {
    first: [u8; MATCHED_LEN],
    last: [u8; MATCHED_LEN],
}

impl PrefixMatcher {
    pub fn new(
        prefixes: &[String],
        is_case_sensitive: bool,
        address_type: AddressType,
    ) -> Result<Self, TooManyVariants> {
        let mut ranges = Vec::new();
        match address_type {
            AddressType::Legacy => {
                let variants: Vec<Base58Variants> = prefixes
                    .iter()
                    .filter_map(|prefix| Base58Variants::new(prefix.as_bytes(), is_case_sensitive))
                    .collect();
                let count = variants.iter().try_fold(0usize, |count, variants| {
                    count.checked_add(variants.count()?)
                });
                if count.is_none_or(|count| count > BASE58_MAX_VARIANTS) {
                    return Err(TooManyVariants);
                }
                for variants in variants {
                    variants.add_ranges(&mut ranges);
                }
            }
            AddressType::Bech32 => ranges.extend(
                prefixes
                    .iter()
                    .filter_map(|prefix| bech32_range(prefix, BECH32_PREFIX, 20)),
            ),
            AddressType::Taproot => ranges.extend(
                prefixes
                    .iter()
                    .filter_map(|prefix| bech32_range(prefix, TAPROOT_PREFIX, 32)),
            ),
        }

        ranges.sort_unstable_by_key(|range| range.first);
        // Merge the ranges that overlap, so there is only one that can match.
        ranges.dedup_by(|range, previous| {
            let is_overlapping = range.first <= previous.last;
            if is_overlapping {
                previous.last = previous.last.max(range.last);
            }
            is_overlapping
        });
        Ok(Self { ranges })
    }

    /// Returns true if an address with this public key hash, or this output
    /// key for a Taproot address, could start with one of the prefixes.
    pub fn matches(&self, hash: &[u8]) -> bool {
        let Some(hash) = hash.first_chunk::<MATCHED_LEN>() else {
            return false;
        };
        let index = self.ranges.partition_point(|range| range.first <= *hash);
        index > 0 && *hash <= self.ranges[index - 1].last
    }

    /// Returns true if there is no address that starts with any of the
    /// prefixes.
    pub fn is_empty(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// The range that has all the addresses starting with a Bech32 prefix.
/// `start` is what all the addresses start with, and `encoded_len` how many
/// bytes they encode after that.
///
/// Returns nothing if there are no addresses starting with the prefix.
fn bech32_range(prefix: &str, start: &[u8; 4], encoded_len: usize) -> Option<HashRange> {
    let prefix = prefix.to_lowercase().into_bytes();
    // Every character encodes 5 bits, and the checksum follows them.
    let data_len = (encoded_len * 8).div_ceil(5);
    if prefix.len() > start.len() + data_len + BECH32_CHECKSUM_LEN {
        return None;
    }

    let start_len = prefix.len().min(start.len());
    if prefix[..start_len] != start[..start_len] {
        return None;
    }

    // The bits that are not set by the prefix are zeros for the first of the
    // range, and ones for the last of it.
    let mut first = [0u8; MATCHED_LEN];
    let mut last = [0xffu8; MATCHED_LEN];
    for (i, character) in prefix[start_len..].iter().enumerate() {
        let value = BECH32_CHARSET.iter().position(|c| c == character)?;
        // The checksum depends on all of the data, so only its characters are checked.
        if i >= data_len {
            continue;
        }
        for bit in 0..5 {
            let position = i * 5 + bit;
            let is_set = value & (0x10 >> bit) != 0;
            if position >= encoded_len * 8 {
                // The last character has some bits left, they are always zero.
                if is_set {
                    return None;
                }
            } else if position < MATCHED_LEN * 8 {
                let mask = 0x80 >> (position % 8);
                if is_set {
                    first[position / 8] |= mask;
                } else {
                    last[position / 8] &= !mask;
                }
            }
        }
    }
    Some(HashRange { first, last })
}

/// The ways to write a prefix in Base58, which is more than one way if upper
/// and lowercase don't matter.
struct Base58Variants {
    // One of the variants.
    variant: Vec<u8>,
    // The positions of the characters that can be written in two ways.
    alternatives: Vec<(usize, [u8; 2])>,
}

impl Base58Variants {
    /// Returns nothing if there are no addresses starting with the prefix.
    fn new(prefix: &[u8], is_case_sensitive: bool) -> Option<Self> {
        let mut variant = Vec::with_capacity(prefix.len());
        let mut alternatives = Vec::new();
        for character in prefix {
            let mut options = vec![*character];
            if !is_case_sensitive {
                options = vec![
                    character.to_ascii_lowercase(),
                    character.to_ascii_uppercase(),
                ];
                options.dedup();
            }
            options.retain(|option| BASE58_CHARSET.contains(option));

            let first = *options.first()?;
            if let Some(second) = options.get(1) {
                alternatives.push((variant.len(), [first, *second]));
            }
            variant.push(first);
        }
        Some(Self {
            variant,
            alternatives,
        })
    }

    /// The number of variants, or nothing if that is too many to count.
    fn count(&self) -> Option<usize> {
        // Every character that can be written in two ways doubles it.
        let doublings = u32::try_from(self.alternatives.len()).ok()?;
        1usize.checked_shl(doublings)
    }

    /// Adds the ranges of public key hashes that have all the addresses
    /// starting with any of the variants to `ranges`.
    fn add_ranges(mut self, ranges: &mut Vec<HashRange>) {
        for index in 0..self.count().unwrap_or(0) {
            for (bit, (position, options)) in self.alternatives.iter().enumerate() {
                self.variant[*position] = options[index >> bit & 1];
            }
            base58_variant_ranges(&self.variant, ranges);
        }
    }
}

/// Follows a number by one more Base58 digit. Returns nothing if that makes
/// it too large for a payload.
fn push_base58_digit(
    mut number: [u8; BASE58_PAYLOAD_LEN],
    digit: u8,
) -> Option<[u8; BASE58_PAYLOAD_LEN]> {
    let mut carry = u32::from(digit);
    for byte in number.iter_mut().rev() {
        carry += u32::from(*byte) * 58;
        *byte = carry as u8;
        carry >>= 8;
    }
    (carry == 0).then_some(number)
}

/// Adds the ranges of public key hashes that have all the addresses starting
/// with one variant of a prefix (a case sensitive one) to `ranges`.
fn base58_variant_ranges(prefix: &[u8], ranges: &mut Vec<HashRange>) {
    // Every leading '1' of an address is a leading zero byte of the payload,
    // the rest of the address is the rest of the payload as a number.
    let zeros = prefix
        .iter()
        .take_while(|character| **character == b'1')
        .count();
    // The first byte of the payload is the version, which is zero.
    if zeros == 0 || zeros > BASE58_PAYLOAD_LEN {
        return;
    }
    let digits: Vec<u8> = prefix[zeros..]
        .iter()
        .map(|character| BASE58_CHARSET.iter().position(|c| c == character).unwrap() as u8)
        .collect();

    // The smallest and largest payload with this many leading zero bytes.
    let mut smallest = [0u8; BASE58_PAYLOAD_LEN];
    let mut largest = [0xffu8; BASE58_PAYLOAD_LEN];
    largest[..zeros].fill(0);

    let mut add_range = |first: [u8; BASE58_PAYLOAD_LEN], last: [u8; BASE58_PAYLOAD_LEN]| {
        ranges.push(HashRange {
            first: first[1..21].try_into().unwrap(),
            last: last[1..21].try_into().unwrap(),
        });
    };

    if digits.is_empty() {
        // Only leading zeros, more of them is fine as well.
        add_range(smallest, largest);
        return;
    }
    if zeros == BASE58_PAYLOAD_LEN {
        return;
    }
    // There are no more leading zeros than the ones in the prefix.
    smallest[zeros] = 1;

    // The prefix sets the first digits of the number, try every number of
    // digits that could follow them. Zeros give the first number of that
    // length, and the highest digit gives the last one.
    let first = digits
        .iter()
        .try_fold([0u8; BASE58_PAYLOAD_LEN], |number, digit| {
            push_base58_digit(number, *digit)
        });
    let Some(mut first) = first else {
        return;
    };
    let mut last = Some(first);
    for _ in digits.len()..=BASE58_MAX_ADDRESS_LEN {
        // Too large numbers have no first, too small ones have a last that
        // is too small.
        let last_or_largest = last.unwrap_or(largest);
        if first <= largest && last_or_largest >= smallest {
            add_range(first.max(smallest), last_or_largest.min(largest));
        }

        let Some(next) = push_base58_digit(first, 0) else {
            break;
        };
        first = next;
        last = last.and_then(|last| push_base58_digit(last, 57));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::BitcoinAddress;
    use crate::walker::KeyWalker;
    use bitcoin::hashes::Hash;
    use bitcoin::secp256k1::Secp256k1;

    #[test]
    fn matcher_agrees_with_address() {
        let secp = Secp256k1::new();
        let mut keys = KeyWalker::new(&secp, true, AddressType::Legacy);
        keys.next_batch(&secp);

        for index in 0..200 {
            for (address_type, is_case_sensitive, len) in [
                (AddressType::Bech32, false, 3),
                (AddressType::Bech32, false, 7),
                (AddressType::Bech32, false, 36),
                (AddressType::Taproot, false, 3),
                (AddressType::Taproot, false, 7),
                (AddressType::Taproot, false, 31),
                (AddressType::Taproot, false, 56),
                (AddressType::Legacy, true, 1),
                (AddressType::Legacy, true, 4),
                (AddressType::Legacy, false, 4),
                (AddressType::Legacy, false, 9),
                (AddressType::Legacy, true, 34),
            ] {
                let is_legacy = address_type == AddressType::Legacy;
                let secret_key = keys.secret_keys(index)[0];
                let address =
                    BitcoinAddress::from_secret_key(&secp, secret_key, true, address_type);
                let hash = address.public_key.pubkey_hash().to_byte_array();
                let matches = |prefix: &str| {
                    let prefixes = [prefix.to_string()];
                    let matcher = PrefixMatcher::new(&prefixes, is_case_sensitive, address_type);
                    let matcher = matcher.unwrap();
                    if address_type == AddressType::Taproot {
                        let program = address.address.witness_program().unwrap();
                        matcher.matches(program.program().as_bytes())
                    } else {
                        matcher.matches(&hash)
                    }
                };
                let address = address.address.to_string();
                let len = len.min(address.len());

                let prefix = if is_case_sensitive {
                    address[..len].to_string()
                } else {
                    address[..len].to_uppercase()
                };
                assert!(matches(&prefix), "{prefix} {address}");

                // Change the last character of the prefix, it should not match anymore.
                // The matcher does not look at the checksum at the end of a Base58
                // address, or at more than the first 36 characters of other ones.
                if len < 4 || (is_legacy && len > 20) || len > 36 {
                    continue;
                }
                let last = if address[len - 1..len].eq_ignore_ascii_case("q") {
                    "p"
                } else {
                    "q"
                };
                let prefix = format!("{}{}", &address[..len - 1], last);
                assert!(!matches(&prefix), "{prefix} {address}");
            }
        }
    }

    #[test]
    fn bech32_ranges_agree_with_address() {
        let secp = Secp256k1::new();

        let address_types = [
            (AddressType::Bech32, "bc1q", "bc1p"),
            (AddressType::Taproot, "bc1p", "bc1q"),
        ];
        for (address_type, start, other_start) in address_types {
            let mut keys = KeyWalker::new(&secp, true, address_type);
            let batch_len = keys.next_batch(&secp);
            // The addresses of the batch, with what they encode.
            let addresses: Vec<(BitcoinAddress, Vec<u8>)> = (0..batch_len)
                .map(|index| {
                    let secret_key = keys.secret_keys(index)[0];
                    let address =
                        BitcoinAddress::from_secret_key(&secp, secret_key, true, address_type);
                    let program = address.address.witness_program().unwrap();
                    let encoded = program.program().as_bytes().to_vec();
                    (address, encoded)
                })
                .collect();

            // Short prefixes, so a lot of the addresses match. The last ones
            // have no addresses at all.
            let prefixes = [
                start.to_string(),
                format!("{start}q"),
                format!("{}5", start.to_uppercase()),
                format!("{start}l"),
                format!("{start}qq"),
                "bc".to_string(),
                other_start.to_string(),
                format!("{start}b"),
                "1".to_string(),
            ];
            // Every one of them on its own, and then a list of prefixes. Some
            // of those are the start of another one, so their ranges overlap.
            let mut lists: Vec<Vec<String>> =
                prefixes.iter().map(|prefix| vec![prefix.clone()]).collect();
            lists.push(
                ["qq", "q", "5x", "5", "l8", "b", "zz"]
                    .map(|end| format!("{start}{end}"))
                    .to_vec(),
            );

            let mut matches = 0;
            for prefixes in &lists {
                let matcher = PrefixMatcher::new(prefixes, false, address_type).unwrap();
                for (address, encoded) in &addresses {
                    let expected = address.starts_with_any(prefixes, false);
                    let message = format!("{:?} {}", prefixes, address.address);
                    assert_eq!(matcher.matches(encoded), expected, "{message}");
                    matches += usize::from(expected);
                }
            }
            assert!(matches > batch_len);
        }
    }

    #[test]
    fn base58_ranges_agree_with_address() {
        let secp = Secp256k1::new();
        let mut keys = KeyWalker::new(&secp, true, AddressType::Legacy);
        let batch_len = keys.next_batch(&secp);

        // Short prefixes, so a lot of the addresses match.
        let prefixes = [
            "1", "11", "1a", "1B", "1c2", "12", "1Q", "1z", "2", "1l", "1O",
        ];
        // Every one of them on its own, and then a list of prefixes. Some of
        // those are the start of another one, so their ranges overlap.
        let mut lists: Vec<Vec<String>> = prefixes
            .iter()
            .map(|prefix| vec![prefix.to_string()])
            .collect();
        lists.push(
            ["1c2", "1c", "11", "1a", "1aB", "12", "2", "1l"]
                .map(String::from)
                .to_vec(),
        );

        for is_case_sensitive in [true, false] {
            let mut matches = 0;
            for prefixes in &lists {
                let address_type = AddressType::Legacy;
                let matcher = PrefixMatcher::new(prefixes, is_case_sensitive, address_type);
                let matcher = matcher.unwrap();

                for index in 0..batch_len {
                    for hash in keys.pubkey_hashes(index) {
                        let mut payload = [0u8; 21];
                        payload[1..].copy_from_slice(&hash);
                        let address = bitcoin::base58::encode_check(&payload);
                        let expected = prefixes.iter().any(|prefix| {
                            if is_case_sensitive {
                                address.starts_with(prefix.as_str())
                            } else {
                                address.to_lowercase().starts_with(&prefix.to_lowercase())
                            }
                        });
                        assert_eq!(
                            matcher.matches(&hash),
                            expected,
                            "{:?} {}",
                            prefixes,
                            address
                        );
                        matches += usize::from(expected);
                    }
                }
            }
            assert!(matches > batch_len);
        }
    }

    #[test]
    fn matcher_fails_for_too_many_variants() {
        let new = |prefixes: &[String], is_case_sensitive: bool| {
            PrefixMatcher::new(prefixes, is_case_sensitive, AddressType::Legacy)
        };

        // Every one of these letters can be written in two ways.
        let letters = [format!("1{}", "a".repeat(30))];
        assert!(new(&letters, false).is_err());
        assert!(new(&letters, true).is_ok());
        // A digit can only be written in one way.
        let digits = [format!("1{}", "2".repeat(30))];
        assert!(new(&digits, false).is_ok());

        // The variants of all the prefixes count.
        let prefix = format!("1{}", "a".repeat(10));
        let limit = BASE58_MAX_VARIANTS;
        let prefixes = vec![prefix; limit / 1024 + 1];
        assert!(new(&prefixes, false).is_err());
        assert!(new(&prefixes[..4], false).is_ok());
    }

    #[test]
    fn matcher_is_empty_for_impossible_prefixes() {
        let is_empty = |prefix: &str, is_case_sensitive: bool, address_type: AddressType| {
            let matcher =
                PrefixMatcher::new(&[prefix.to_string()], is_case_sensitive, address_type);
            matcher.unwrap().is_empty()
        };

        assert!(!is_empty("1Kids", false, AddressType::Legacy));
        assert!(!is_empty("1Kids", true, AddressType::Legacy));
        // Legacy addresses start with 1.
        assert!(is_empty("Kids", false, AddressType::Legacy));
        assert!(is_empty("bc1qkd", false, AddressType::Legacy));
        // A lowercase l is not in Base58, an uppercase L is.
        assert!(is_empty("1Nicol", true, AddressType::Legacy));
        assert!(!is_empty("1Nicol", false, AddressType::Legacy));
        assert!(is_empty("1O0", false, AddressType::Legacy));

        assert!(!is_empty("bc1qkd", false, AddressType::Bech32));
        assert!(!is_empty("BC1QKD", false, AddressType::Bech32));
        assert!(!is_empty("bc", false, AddressType::Bech32));
        // The letter b is not in Bech32.
        assert!(is_empty("bc1qkb", false, AddressType::Bech32));
        assert!(is_empty("bc1pkd", false, AddressType::Bech32));
        assert!(is_empty("1Kids", false, AddressType::Bech32));

        assert!(!is_empty("bc1pkd", false, AddressType::Taproot));
        assert!(is_empty("bc1pko", false, AddressType::Taproot));
        assert!(is_empty("bc1qkd", false, AddressType::Taproot));
    }

    #[test]
    fn matcher_is_empty_for_impossible_long_prefixes() {
        let is_empty = |prefix: &str, address_type: AddressType| {
            let matcher = PrefixMatcher::new(&[prefix.to_string()], true, address_type);
            matcher.unwrap().is_empty()
        };

        let addresses = [
            (AddressType::Legacy, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
            (
                AddressType::Bech32,
                "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
            ),
            (
                AddressType::Taproot,
                "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
            ),
        ];
        for (address_type, address) in addresses {
            assert!(!is_empty(address, address_type), "{address}");
            assert!(is_empty(&format!("{address}q"), address_type), "{address}");
        }

        // The letter b is not in Bech32, not even in the checksum.
        let (_, bech32) = addresses[1];
        let bech32 = format!("{}b", &bech32[..41]);
        assert!(is_empty(&bech32, AddressType::Bech32));
        let (_, taproot) = addresses[2];
        let taproot = format!("{}b", &taproot[..61]);
        assert!(is_empty(&taproot, AddressType::Taproot));
        // Addresses with 34 characters only go up to 1Q.
        let legacy = format!("1R{}", "q".repeat(32));
        assert!(is_empty(&legacy, AddressType::Legacy));
    }

    #[test]
    fn matcher_agrees_with_short_addresses() {
        // Every leading zero byte is a 1, so the address of the zero hash has 27
        // characters. The uncompressed address of the Bitcoin wiki example key has 33.
        let addresses = [
            (
                "1111111111111111111114oLvT2",
                ["12", "111111111111111111112"],
            ),
            ("16UwLL9Risc3QfPqBUvKofHmBQ7wMtjvM", ["11", "16UwLM"]),
        ];
        let matches = |prefix: &str, hash: &[u8]| {
            let matcher = PrefixMatcher::new(&[prefix.to_string()], true, AddressType::Legacy);
            matcher.unwrap().matches(hash)
        };

        for (address, other_prefixes) in addresses {
            let payload = bitcoin::base58::decode_check(address).unwrap();
            let hash = &payload[1..];
            for len in [1, 2, 6, 21, address.len()] {
                let prefix = &address[..len];
                assert!(matches(prefix, hash), "{prefix}");
            }
            for prefix in other_prefixes {
                assert!(!matches(prefix, hash), "{prefix}");
            }
        }
    }
}
