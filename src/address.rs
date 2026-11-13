use std::sync::OnceLock;

use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1;
use bitcoin::secp256k1::{Scalar, Secp256k1, SecretKey, Signing};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, PublicKey};
use k256::{FieldBytes, FieldElement};

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_PREFIX: &[u8; 4] = b"bc1q";
// "bc1q" followed by the 32 characters that encode the 20 byte hash.
const BECH32_HASH_PART_LEN: usize = 36;

const BASE58_CHARSET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// Version byte, 20 byte hash and 4 byte checksum.
const BASE58_PAYLOAD_LEN: usize = 25;
const BASE58_MAX_ADDRESS_LEN: usize = 35;
// Above this many upper/lowercase variants of the prefixes, the slow matcher is used.
const BASE58_MAX_VARIANTS: usize = 1 << 16;

// A batch has a center key, and this many keys on both sides of it.
const HALF_BATCH_SIZE: usize = 1024;
const BATCH_SIZE: usize = 2 * HALF_BATCH_SIZE + 1;

pub struct BitcoinAddress {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub address: Address,
}

impl BitcoinAddress {
    #[allow(dead_code)]
    pub fn new(secp: &Secp256k1<impl Signing>, is_compressed: bool, is_bech32: bool) -> Self {
        Self::from_secret_key(secp, random_secret_key(), is_compressed, is_bech32)
    }

    pub fn from_secret_key(
        secp: &Secp256k1<impl Signing>,
        secret_key: SecretKey,
        is_compressed: bool,
        is_bech32: bool,
    ) -> Self {
        let private_key = PrivateKey {
            compressed: is_compressed,
            network: NetworkKind::Main,
            inner: secret_key,
        };

        let public_key = PublicKey::from_private_key(secp, &private_key);

        let address: Address = if is_bech32 {
            let compressed = CompressedPublicKey::try_from(public_key)
                .expect("Failed to create Bitcoin bech32 address");
            Address::p2wpkh(&compressed, Network::Bitcoin)
        } else {
            Address::p2pkh(public_key, Network::Bitcoin)
        };

        Self {
            private_key,
            public_key,
            address,
        }
    }

    pub fn starts_with(&self, prefix: &str, is_case_sensitive: bool) -> bool {
        if is_case_sensitive {
            self.address.to_string().starts_with(prefix)
        } else {
            self.address
                .to_string()
                .to_lowercase()
                .starts_with(prefix.to_lowercase().as_str())
        }
    }

    pub fn starts_with_any(&self, prefixes: &[String], is_case_sensitive: bool) -> bool {
        for prefix in prefixes {
            if self.starts_with(prefix, is_case_sensitive) {
                return true;
            }
        }
        false
    }
}

/// A point on the curve, both coordinates are normalized.
#[derive(Clone, Copy)]
struct Point {
    x: FieldElement,
    y: FieldElement,
}

impl Point {
    fn from_public_key(public_key: &secp256k1::PublicKey) -> Self {
        let bytes = public_key.serialize_uncompressed();
        Self {
            x: field_element(&bytes[1..33]),
            y: field_element(&bytes[33..65]),
        }
    }
}

fn field_element(bytes: &[u8]) -> FieldElement {
    let bytes: [u8; 32] = bytes.try_into().expect("Failed to create Bitcoin public key");
    Option::<FieldElement>::from(FieldElement::from_bytes(&FieldBytes::from(bytes)))
        .expect("Failed to create Bitcoin public key")
}

/// Multiples of the generator point G, shared by all the threads.
struct GeneratorMultiples {
    // 1G, 2G, .. up to HALF_BATCH_SIZE times G.
    multiples: Vec<Point>,
    // BATCH_SIZE times G, the distance between the centers of two batches.
    step: Point,
}

impl GeneratorMultiples {
    fn get(secp: &Secp256k1<impl Signing>) -> &'static Self {
        static MULTIPLES: OnceLock<GeneratorMultiples> = OnceLock::new();

        MULTIPLES.get_or_init(|| {
            let one = SecretKey::from_slice(&secp256k1::constants::ONE)
                .expect("Failed to create Bitcoin secret key");
            let generator = secp256k1::PublicKey::from_secret_key(secp, &one);

            let mut multiple = generator;
            let mut multiples = Vec::with_capacity(BATCH_SIZE);
            for _ in 0..BATCH_SIZE {
                multiples.push(Point::from_public_key(&multiple));
                multiple = multiple
                    .combine(&generator)
                    .expect("Failed to create Bitcoin public key");
            }

            let step = multiples[BATCH_SIZE - 1];
            multiples.truncate(HALF_BATCH_SIZE);
            Self { multiples, step }
        })
    }
}

/// Walks over consecutive keys in batches, starting at a random key.
///
/// Deriving a public key from a secret key is by far the most expensive step
/// of generating an address, so that is only done for the key we start at.
/// The public key of secret key `k + i` is the public key of `k` plus `i`
/// times G, which is a lot cheaper to calculate:
///
/// - Adding two points takes a division, which is the expensive part of it.
///   All the divisions of a batch are replaced by a single one (and some
///   multiplications) using Montgomery's trick.
/// - The points `i` times G and minus `i` times G only differ in the sign of
///   `y`, so adding and subtracting it from the center of the batch can share
///   that division.
/// - Negating a public key gives the public key of the negated secret key. As
///   that again only changes the sign of `y`, every point is used for two
///   keys.
pub struct KeyWalker {
    is_compressed: bool,
    multiples: &'static GeneratorMultiples,
    // The secret key at offset 0.
    base: SecretKey,
    // The offset of the center of the current batch.
    center_offset: u64,
    // The center of the next batch.
    next_center: Point,
    next_center_offset: u64,
    // The points of the current batch, `x` followed by `y`. `y` is only there
    // for uncompressed keys, it is not needed for compressed ones.
    points: Vec<[u8; 64]>,
    // Scratch space for the divisions.
    deltas: Vec<FieldElement>,
    products: Vec<FieldElement>,
}

impl KeyWalker {
    pub fn new(secp: &Secp256k1<impl Signing>, is_compressed: bool) -> Self {
        let mut walker = Self {
            is_compressed,
            multiples: GeneratorMultiples::get(secp),
            base: random_secret_key(),
            center_offset: 0,
            next_center: Point { x: FieldElement::ZERO, y: FieldElement::ZERO },
            next_center_offset: 0,
            points: vec![[0u8; 64]; BATCH_SIZE],
            deltas: vec![FieldElement::ZERO; HALF_BATCH_SIZE + 1],
            products: vec![FieldElement::ZERO; HALF_BATCH_SIZE + 1],
        };
        walker.restart(secp);
        walker
    }

    /// Start over at a new random key. The current batch is not valid until
    /// `next_batch` is called.
    pub fn restart(&mut self, secp: &Secp256k1<impl Signing>) {
        loop {
            self.base = random_secret_key();
            self.next_center_offset = HALF_BATCH_SIZE as u64;
            let Some(center) = secret_key_at(&self.base, self.next_center_offset) else {
                continue;
            };
            let center = secp256k1::PublicKey::from_secret_key(secp, &center);
            self.next_center = Point::from_public_key(&center);
            return;
        }
    }

    /// Move on to the next batch of keys, returns the number of points in it.
    /// Every point is the public key of two secret keys.
    pub fn next_batch(&mut self, secp: &Secp256k1<impl Signing>) -> usize {
        // Practically this always works, if not just start over somewhere else.
        while self.next_center_offset > u64::MAX / 2 || !self.calculate_batch() {
            self.restart(secp);
        }
        BATCH_SIZE
    }

    fn calculate_batch(&mut self) -> bool {
        let multiples = self.multiples;
        let center = self.next_center;
        let neg_center_x = center.x.negate(1);
        let neg_center_y = center.y.negate(1);

        // What we have to divide by to add every multiple (and the step) to
        // the center.
        for (delta, multiple) in self.deltas.iter_mut().zip(&multiples.multiples) {
            *delta = multiple.x + neg_center_x;
        }
        self.deltas[HALF_BATCH_SIZE] = multiples.step.x + neg_center_x;

        // Montgomery's trick: invert the product of all of them, and get the
        // individual inverses out of that.
        let mut product = self.deltas[0];
        self.products[0] = product;
        for i in 1..=HALF_BATCH_SIZE {
            product = product.mul(&self.deltas[i]);
            self.products[i] = product;
        }
        let Some(mut inverse) = Option::<FieldElement>::from(product.normalize().invert()) else {
            // One of the points is the same as (or the inverse of) the center.
            return false;
        };
        let mut next_center = center;

        for i in (0..=HALF_BATCH_SIZE).rev() {
            let delta_inverse = if i == 0 {
                inverse
            } else {
                inverse.mul(&self.products[i - 1])
            };
            inverse = inverse.mul(&self.deltas[i]);

            if i == HALF_BATCH_SIZE {
                let step = &multiples.step;
                let slope = (step.y + neg_center_y).mul(&delta_inverse);
                let x = (slope.square() + (center.x + step.x).negate(2)).normalize();
                let y = (slope.mul(&(center.x + x.negate(1))) + neg_center_y).normalize();
                next_center = Point { x, y };
                continue;
            }

            let multiple = &multiples.multiples[i];
            let neg_x_sum = (center.x + multiple.x).negate(2);

            // The center plus the multiple.
            let slope = (multiple.y + neg_center_y).mul(&delta_inverse);
            let x = (slope.square() + neg_x_sum).normalize();
            let point = &mut self.points[1 + 2 * i];
            point[..32].copy_from_slice(&x.to_bytes());
            if !self.is_compressed {
                let y = (slope.mul(&(center.x + x.negate(1))) + neg_center_y).normalize();
                point[32..].copy_from_slice(&y.to_bytes());
            }

            // The center minus the multiple.
            let slope = (multiple.y + center.y).negate(2).mul(&delta_inverse);
            let x = (slope.square() + neg_x_sum).normalize();
            let point = &mut self.points[2 + 2 * i];
            point[..32].copy_from_slice(&x.to_bytes());
            if !self.is_compressed {
                let y = (slope.mul(&(center.x + x.negate(1))) + neg_center_y).normalize();
                point[32..].copy_from_slice(&y.to_bytes());
            }
        }

        self.points[0][..32].copy_from_slice(&center.x.to_bytes());
        self.points[0][32..].copy_from_slice(&center.y.to_bytes());

        self.center_offset = self.next_center_offset;
        self.next_center = next_center;
        self.next_center_offset += BATCH_SIZE as u64;
        true
    }

    /// The hash160 of both public keys of a point in the current batch, this
    /// is what addresses encode.
    pub fn pubkey_hashes(&self, index: usize) -> [[u8; 20]; 2] {
        let point = &self.points[index];

        if self.is_compressed {
            let mut public_key = [0u8; 33];
            public_key[1..].copy_from_slice(&point[..32]);
            public_key[0] = 2;
            let even = hash160::Hash::hash(&public_key).to_byte_array();
            public_key[0] = 3;
            let odd = hash160::Hash::hash(&public_key).to_byte_array();
            [even, odd]
        } else {
            let mut public_key = [0u8; 65];
            public_key[0] = 4;
            public_key[1..].copy_from_slice(point);
            let positive = hash160::Hash::hash(&public_key).to_byte_array();

            let y = field_element(&point[32..]);
            public_key[33..].copy_from_slice(&y.negate(1).normalize().to_bytes());
            let negative = hash160::Hash::hash(&public_key).to_byte_array();
            [positive, negative]
        }
    }

    /// The secret keys of a point in the current batch. Which of the two
    /// belongs to which of the hashes is not known.
    pub fn secret_keys(&self, index: usize) -> [SecretKey; 2] {
        let distance = index.div_ceil(2) as u64;
        let offset = if index % 2 == 1 {
            self.center_offset + distance
        } else {
            self.center_offset - distance
        };
        let secret_key =
            secret_key_at(&self.base, offset).expect("Failed to create Bitcoin secret key");
        [secret_key, secret_key.negate()]
    }
}

fn secret_key_at(base: &SecretKey, offset: u64) -> Option<SecretKey> {
    let mut tweak = [0u8; 32];
    tweak[24..].copy_from_slice(&offset.to_be_bytes());
    let tweak = Scalar::from_be_bytes(tweak).ok()?;
    base.add_tweak(&tweak).ok()
}

/// Matches prefixes against a public key hash, without creating an address.
///
/// It might match a little too much, so a match has to be confirmed with
/// `BitcoinAddress::starts_with_any`.
pub enum PrefixMatcher {
    Bech32(Vec<Bech32Prefix>),
    Base58(Vec<Base58Range>),
    // Fallback for when there would be too many ranges.
    Base58Slow { prefixes: Vec<Vec<u8>>, is_case_sensitive: bool },
}

/// The bits of a public key hash that are set by a Bech32 prefix.
pub struct Bech32Prefix {
    // The first 16 bytes and the last 4 bytes of the hash.
    mask: (u128, u32),
    bits: (u128, u32),
}

/// A range of public key hashes, that has all the Base58 addresses starting
/// with a certain prefix. Both ends are inclusive.
///
/// The addresses of the hashes at the very ends of the range might not start
/// with the prefix, as that depends on the checksum.
pub struct Base58Range {
    first: [u8; 20],
    last: [u8; 20],
}

impl PrefixMatcher {
    pub fn new(prefixes: &[String], is_case_sensitive: bool, is_bech32: bool) -> Self {
        if is_bech32 {
            let prefixes = prefixes.iter().filter_map(|prefix| Bech32Prefix::new(prefix));
            return Self::Bech32(prefixes.collect());
        }

        let mut variants = Vec::new();
        for prefix in prefixes {
            if !base58_variants(prefix.as_bytes(), is_case_sensitive, &mut variants) {
                let prefixes = prefixes.iter().map(|prefix| {
                    if is_case_sensitive {
                        prefix.clone().into_bytes()
                    } else {
                        prefix.to_lowercase().into_bytes()
                    }
                });
                return Self::Base58Slow { prefixes: prefixes.collect(), is_case_sensitive };
            }
        }

        let mut ranges = Vec::new();
        for variant in &variants {
            base58_ranges(variant, &mut ranges);
        }
        ranges.sort_by_key(|range| range.first);
        // Merge the ranges that overlap, so there is only one that can match.
        let mut merged: Vec<Base58Range> = Vec::with_capacity(ranges.len());
        for range in ranges {
            match merged.last_mut() {
                Some(previous) if range.first <= previous.last => {
                    previous.last = previous.last.max(range.last);
                }
                _ => merged.push(range),
            }
        }
        Self::Base58(merged)
    }

    pub fn matches(&self, pubkey_hash: &[u8; 20]) -> bool {
        match self {
            Self::Bech32(prefixes) => {
                let head = u128::from_be_bytes(pubkey_hash[..16].try_into().unwrap());
                let tail = u32::from_be_bytes(pubkey_hash[16..].try_into().unwrap());
                prefixes.iter().any(|prefix| {
                    head & prefix.mask.0 == prefix.bits.0 && tail & prefix.mask.1 == prefix.bits.1
                })
            }
            Self::Base58(ranges) => {
                let index = ranges.partition_point(|range| range.first <= *pubkey_hash);
                index > 0 && *pubkey_hash <= ranges[index - 1].last
            }
            Self::Base58Slow { prefixes, is_case_sensitive } => {
                let mut payload = [0u8; 21];
                payload[1..].copy_from_slice(pubkey_hash);
                let mut address = bitcoin::base58::encode_check(&payload).into_bytes();
                if !is_case_sensitive {
                    address.make_ascii_lowercase();
                }
                prefixes.iter().any(|prefix| address.starts_with(prefix))
            }
        }
    }
}

impl Bech32Prefix {
    /// Returns nothing if there are no addresses starting with the prefix.
    fn new(prefix: &str) -> Option<Self> {
        let prefix = prefix.to_lowercase().into_bytes();
        // The checksum of a Bech32 address is not looked at here.
        let prefix = &prefix[..prefix.len().min(BECH32_HASH_PART_LEN)];

        let hrp_len = prefix.len().min(BECH32_PREFIX.len());
        if prefix[..hrp_len] != BECH32_PREFIX[..hrp_len] {
            return None;
        }

        // Every character sets 5 bits of the hash.
        let mut mask = [0u8; 20];
        let mut bits = [0u8; 20];
        for (i, character) in prefix[hrp_len..].iter().enumerate() {
            let value = BECH32_CHARSET.iter().position(|c| c == character)?;
            for bit in 0..5 {
                let position = i * 5 + bit;
                mask[position / 8] |= 0x80 >> (position % 8);
                if value & (0x10 >> bit) != 0 {
                    bits[position / 8] |= 0x80 >> (position % 8);
                }
            }
        }

        let split = |bytes: [u8; 20]| {
            let head = u128::from_be_bytes(bytes[..16].try_into().unwrap());
            let tail = u32::from_be_bytes(bytes[16..].try_into().unwrap());
            (head, tail)
        };
        Some(Self { mask: split(mask), bits: split(bits) })
    }
}

/// Adds all the ways to write a prefix in Base58 to `variants`, which is more
/// than one if upper and lowercase don't matter. Returns false if there are
/// too many of them.
fn base58_variants(prefix: &[u8], is_case_sensitive: bool, variants: &mut Vec<Vec<u8>>) -> bool {
    let start = variants.len();
    variants.push(Vec::with_capacity(prefix.len()));

    for character in prefix {
        let mut options = vec![*character];
        if !is_case_sensitive {
            options = vec![character.to_ascii_lowercase(), character.to_ascii_uppercase()];
            options.dedup();
        }
        options.retain(|option| BASE58_CHARSET.contains(option));

        // With no options left this removes all the variants, as there are no
        // addresses starting with the prefix.
        let unfinished = variants.split_off(start);
        for variant in &unfinished {
            for option in &options {
                let mut variant = variant.clone();
                variant.push(*option);
                variants.push(variant);
            }
        }
        if variants.len() > BASE58_MAX_VARIANTS {
            return false;
        }
    }
    true
}

/// Adds the ranges of public key hashes that have all the addresses starting
/// with a (case sensitive) prefix to `ranges`.
fn base58_ranges(prefix: &[u8], ranges: &mut Vec<Base58Range>) {
    // Every leading '1' of an address is a leading zero byte of the payload,
    // the rest of the address is the rest of the payload as a number.
    let zeros = prefix.iter().take_while(|character| **character == b'1').count();
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
        ranges.push(Base58Range {
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
    // digits that could follow them.
    for len in digits.len()..=BASE58_MAX_ADDRESS_LEN {
        let number = |fill: u8| {
            let mut number = [0u8; BASE58_PAYLOAD_LEN];
            let fill = std::iter::repeat(fill).take(len - digits.len());
            for digit in digits.iter().copied().chain(fill) {
                let mut carry = u32::from(digit);
                for byte in number.iter_mut().rev() {
                    carry += u32::from(*byte) * 58;
                    *byte = carry as u8;
                    carry >>= 8;
                }
                if carry != 0 {
                    return None;
                }
            }
            Some(number)
        };

        // Too large numbers have no first, too small ones have a last that
        // is too small.
        let Some(first) = number(0) else { break };
        let last = number(57).unwrap_or(largest);
        if first > largest || last < smallest {
            continue;
        }
        add_range(first.max(smallest), last.min(largest));
    }
}

fn random_secret_key() -> SecretKey {
    loop {
        // Not every 32 bytes are a valid secret key, although practically all are.
        if let Ok(secret_key) = SecretKey::from_slice(&get_random_bytes()) {
            return secret_key;
        }
    }
}

fn get_random_bytes() -> [u8; secp256k1::constants::SECRET_KEY_SIZE] {
    let mut buf = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
    getrandom::fill(&mut buf).expect("Failed to create random bytes");
    buf
}
