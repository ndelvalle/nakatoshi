use std::sync::OnceLock;

use bitcoin::hashes::{Hash, HashEngine, hash160};
use bitcoin::secp256k1;
use bitcoin::secp256k1::{Scalar, Secp256k1, SecretKey, Signing, Verification};
use bitcoin::taproot::TapTweakHash;
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, PublicKey};
use k256::FieldBytes;
use k256::elliptic_curve::hazmat::FieldArithmetic;

// The field of secp256k1, which k256 only exposes through this trait.
type FieldElement = <k256::Secp256k1 as FieldArithmetic>::FieldElement;

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_PREFIX: &[u8; 4] = b"bc1q";
// "bc1q" followed by the 32 characters that encode the 20 byte hash.
const BECH32_HASH_PART_LEN: usize = 36;

const TAPROOT_PREFIX: &[u8; 4] = b"bc1p";
// "bc1p" followed by the 52 characters that encode the 32 byte output key.
const TAPROOT_KEY_PART_LEN: usize = 56;

const BASE58_CHARSET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
// Version byte, 20 byte hash and 4 byte checksum.
const BASE58_PAYLOAD_LEN: usize = 25;
const BASE58_MAX_ADDRESS_LEN: usize = 35;
// Every upper/lowercase variant of a prefix has ranges of its own to match,
// which take about 50 bytes. This is how many variants all the prefixes can
// have, to keep that within 500 megabytes.
pub const BASE58_MAX_VARIANTS: usize = 1 << 23;

// A batch has a center key, and this many keys on both sides of it.
const HALF_BATCH_SIZE: usize = 1024;
const BATCH_SIZE: usize = 2 * HALF_BATCH_SIZE + 1;

// The tweak of a Taproot address is split up in windows of this many bits.
const TWEAK_WINDOW_BITS: usize = 13;
// The number of values a window can have.
const TWEAK_WINDOW_SIZE: usize = 1 << TWEAK_WINDOW_BITS;
const TWEAK_WINDOWS: usize = 256usize.div_ceil(TWEAK_WINDOW_BITS);

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum AddressType {
    // Base58 addresses, starting with 1.
    Legacy,
    // Starting with bc1q.
    Bech32,
    // Starting with bc1p.
    Taproot,
}

pub struct BitcoinAddress {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub address: Address,
}

impl BitcoinAddress {
    #[allow(dead_code)]
    pub fn new(
        secp: &Secp256k1<impl Signing + Verification>,
        is_compressed: bool,
        address_type: AddressType,
    ) -> Self {
        Self::from_secret_key(secp, random_secret_key(), is_compressed, address_type)
    }

    pub fn from_secret_key(
        secp: &Secp256k1<impl Signing + Verification>,
        secret_key: SecretKey,
        is_compressed: bool,
        address_type: AddressType,
    ) -> Self {
        let private_key = PrivateKey {
            compressed: is_compressed,
            network: NetworkKind::Main,
            inner: secret_key,
        };

        let public_key = PublicKey::from_private_key(secp, &private_key);

        let address: Address = match address_type {
            AddressType::Legacy => Address::p2pkh(public_key, Network::Bitcoin),
            AddressType::Bech32 => {
                let compressed = CompressedPublicKey::try_from(public_key)
                    .expect("Failed to create Bitcoin bech32 address");
                Address::p2wpkh(&compressed, Network::Bitcoin)
            }
            AddressType::Taproot => {
                // The address can only be spent with the key, there are no scripts in it.
                let (internal_key, _) = public_key.inner.x_only_public_key();
                Address::p2tr(secp, internal_key, None, Network::Bitcoin)
            }
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

/// A point on the curve. Both coordinates are normalized, the ones that come
/// out of `add_points` only weakly.
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
    let bytes: [u8; 32] = bytes
        .try_into()
        .expect("Failed to create Bitcoin public key");
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

/// Multiples of G that add up to any tweak times G, shared by all the threads.
///
/// A tweak is split up in windows of `TWEAK_WINDOW_BITS` bits, and for every
/// window there is a multiple for each of the values it can have. That makes
/// a tweak times G the sum of one multiple per window.
struct TweakMultiples {
    // The multiples of the first window (the lowest bits of the tweak),
    // followed by those of the next ones.
    multiples: Vec<Point>,
}

impl TweakMultiples {
    fn get(secp: &Secp256k1<impl Signing>) -> &'static Self {
        static MULTIPLES: OnceLock<TweakMultiples> = OnceLock::new();

        MULTIPLES.get_or_init(|| {
            let mut multiples = Vec::with_capacity(TWEAK_WINDOWS * TWEAK_WINDOW_SIZE);
            let mut products = Vec::new();
            // The value 1 of every window, times G.
            let mut ones = Vec::with_capacity(TWEAK_WINDOWS);

            for window in 0..TWEAK_WINDOWS {
                let bit = window * TWEAK_WINDOW_BITS;
                let mut one = [0u8; 32];
                one[31 - bit / 8] = 1 << (bit % 8);
                let one = SecretKey::from_slice(&one).expect("Failed to create Bitcoin secret key");
                let one = secp256k1::PublicKey::from_secret_key(secp, &one);
                let two = one
                    .combine(&one)
                    .expect("Failed to create Bitcoin public key");

                // There is no point to add for a value of zero, so these are
                // the multiples for the values plus one.
                let start = multiples.len();
                multiples.push(Point::from_public_key(&one));
                multiples.push(Point::from_public_key(&two));
                while multiples.len() - start < TWEAK_WINDOW_SIZE {
                    // Adding the last multiple to the ones before it gives
                    // the ones that follow it.
                    let len = multiples.len() - start;
                    let last = multiples[start + len - 1];
                    let more = (len - 1).min(TWEAK_WINDOW_SIZE - len);
                    multiples.extend_from_within(start..start + more);
                    let is_added =
                        add_points(&mut multiples[start + len..], |_| &last, &mut products);
                    assert!(is_added, "Failed to create Bitcoin public key");
                }
                ones.push(one);
            }

            // That is a one too many for every window, the multiples of the
            // first window make up for all of them.
            let ones: Vec<&secp256k1::PublicKey> = ones.iter().collect();
            let ones = secp256k1::PublicKey::combine_keys(&ones)
                .expect("Failed to create Bitcoin public key");
            let mut minus_ones = Point::from_public_key(&ones);
            minus_ones.y = minus_ones.y.negate(1).normalize();
            let first_window = &mut multiples[..TWEAK_WINDOW_SIZE];
            let is_added = add_points(first_window, |_| &minus_ones, &mut products);
            assert!(is_added, "Failed to create Bitcoin public key");

            Self { multiples }
        })
    }
}

/// Adds another point to every one of the points, `other` gives the point to
/// add by index. All the divisions this takes are replaced by a single one
/// (and some multiplications) using Montgomery's trick.
///
/// Returns false if one of the points is the same as (or the inverse of) the
/// point to add to it, the points are left as they are in that case.
///
/// The coordinates of the sums are only weakly normalized, as that is all it
/// takes to add to them again.
fn add_points<'a>(
    points: &mut [Point],
    other: impl Fn(usize) -> &'a Point,
    products: &mut Vec<FieldElement>,
) -> bool {
    // What we have to divide by for every point, as the product of all of
    // them before the point.
    products.clear();
    let mut product = FieldElement::ONE;
    for (i, point) in points.iter().enumerate() {
        products.push(product);
        product = product.mul(&(other(i).x + point.x.negate(1)));
    }
    let Some(mut inverse) = Option::<FieldElement>::from(product.normalize().invert()) else {
        return false;
    };

    for (i, point) in points.iter_mut().enumerate().rev() {
        let other = other(i);
        let delta_inverse = inverse.mul(&products[i]);
        inverse = inverse.mul(&(other.x + point.x.negate(1)));

        let slope = (other.y + point.y.negate(1)).mul(&delta_inverse);
        let x = (slope.square() + (point.x + other.x).negate(2)).normalize_weak();
        let y = (slope.mul(&(point.x + x.negate(1))) + point.y.negate(1)).normalize_weak();
        *point = Point { x, y };
    }
    true
}

/// The output keys of a batch, these are what Taproot addresses encode.
///
/// An output key is the public key plus a tweak times G. The tweak is a hash
/// of the public key, so there is no cheap way to get from the output key of
/// one key to that of the next one. Every one of them takes adding a point
/// per window of the tweak, which is why Taproot addresses are a lot slower
/// than the other ones.
struct OutputKeys {
    multiples: &'static TweakMultiples,
    // The public keys of the batch, that are turned into the output keys by
    // adding the tweaks to them one window at a time.
    points: Vec<Point>,
    // For every tweak, which of the multiples to add for each of the windows.
    tweaks: Vec<[u32; TWEAK_WINDOWS]>,
    // Scratch space for the divisions.
    products: Vec<FieldElement>,
}

impl OutputKeys {
    fn new(secp: &Secp256k1<impl Signing>) -> Self {
        Self {
            multiples: TweakMultiples::get(secp),
            points: vec![
                Point {
                    x: FieldElement::ZERO,
                    y: FieldElement::ZERO
                };
                BATCH_SIZE
            ],
            tweaks: vec![[0u32; TWEAK_WINDOWS]; BATCH_SIZE],
            products: Vec::with_capacity(BATCH_SIZE),
        }
    }

    /// Calculate the output keys of a batch of public keys, `x` followed by
    /// `y`. Returns false in the practically impossible case that this can't
    /// be done for one of them.
    fn calculate(&mut self, public_keys: &[[u8; 64]]) -> bool {
        let keys = public_keys
            .iter()
            .zip(&mut self.points)
            .zip(&mut self.tweaks);
        for ((public_key, point), tweak) in keys {
            // Taproot only uses the `x` of a public key, the `y` is always
            // the even one.
            let x = field_element(&public_key[..32]);
            let mut y = field_element(&public_key[32..]);
            if public_key[63] & 1 == 1 {
                y = y.negate(1).normalize();
            }
            *point = Point { x, y };

            // The address can only be spent with the key, so the tweak is
            // the hash of nothing but the key.
            let mut engine = TapTweakHash::engine();
            engine.input(&public_key[..32]);
            let hash = TapTweakHash::from_engine(engine).to_byte_array();

            let mut high = u128::from_be_bytes(hash[..16].try_into().unwrap());
            let mut low = u128::from_be_bytes(hash[16..].try_into().unwrap());
            for (window, multiple) in tweak.iter_mut().enumerate() {
                let value = low as usize % TWEAK_WINDOW_SIZE;
                *multiple = (window * TWEAK_WINDOW_SIZE + value) as u32;
                low = low >> TWEAK_WINDOW_BITS | high << (128 - TWEAK_WINDOW_BITS);
                high >>= TWEAK_WINDOW_BITS;
            }
        }

        let multiples = &self.multiples.multiples;
        let tweaks = &self.tweaks;
        (0..TWEAK_WINDOWS).all(|window| {
            let multiple = |i: usize| &multiples[tweaks[i][window] as usize];
            add_points(&mut self.points, multiple, &mut self.products)
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
///   keys. Not for Taproot addresses though, as those don't look at the sign
///   of `y`: both keys have the same address.
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
    // for uncompressed keys and Taproot addresses, it is not needed for the
    // hash of a compressed key.
    points: Vec<[u8; 64]>,
    // Scratch space for the divisions.
    deltas: Vec<FieldElement>,
    products: Vec<FieldElement>,
    // The output keys of the current batch, only there for Taproot addresses.
    output_keys: Option<OutputKeys>,
}

impl KeyWalker {
    pub fn new(
        secp: &Secp256k1<impl Signing>,
        is_compressed: bool,
        address_type: AddressType,
    ) -> Self {
        let is_taproot = address_type == AddressType::Taproot;
        let mut walker = Self {
            is_compressed,
            multiples: GeneratorMultiples::get(secp),
            base: random_secret_key(),
            center_offset: 0,
            next_center: Point {
                x: FieldElement::ZERO,
                y: FieldElement::ZERO,
            },
            next_center_offset: 0,
            points: vec![[0u8; 64]; BATCH_SIZE],
            deltas: vec![FieldElement::ZERO; HALF_BATCH_SIZE + 1],
            products: vec![FieldElement::ZERO; HALF_BATCH_SIZE + 1],
            output_keys: is_taproot.then(|| OutputKeys::new(secp)),
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
        let has_y = !self.is_compressed || self.output_keys.is_some();
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
            if has_y {
                let y = (slope.mul(&(center.x + x.negate(1))) + neg_center_y).normalize();
                point[32..].copy_from_slice(&y.to_bytes());
            }

            // The center minus the multiple.
            let slope = (multiple.y + center.y).negate(2).mul(&delta_inverse);
            let x = (slope.square() + neg_x_sum).normalize();
            let point = &mut self.points[2 + 2 * i];
            point[..32].copy_from_slice(&x.to_bytes());
            if has_y {
                let y = (slope.mul(&(center.x + x.negate(1))) + neg_center_y).normalize();
                point[32..].copy_from_slice(&y.to_bytes());
            }
        }

        self.points[0][..32].copy_from_slice(&center.x.to_bytes());
        self.points[0][32..].copy_from_slice(&center.y.to_bytes());

        if let Some(output_keys) = &mut self.output_keys
            && !output_keys.calculate(&self.points)
        {
            return false;
        }

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

    /// The output key of a point in the current batch, this is what a Taproot
    /// address encodes. It is the same one for both secret keys of the point.
    pub fn output_key(&self, index: usize) -> [u8; 32] {
        let output_keys = self
            .output_keys
            .as_ref()
            .expect("Failed to create Bitcoin output key");
        // This is the only place that needs it fully normalized.
        output_keys.points[index].x.normalize().to_bytes().into()
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

/// Matches prefixes against a public key hash (or the output key for Taproot
/// addresses), without creating an address.
///
/// It might match a little too much, so a match has to be confirmed with
/// `BitcoinAddress::starts_with_any`.
pub enum PrefixMatcher {
    Bech32(Vec<Bech32Prefix>),
    Taproot(Vec<TaprootPrefix>),
    Base58(Vec<Base58Range>),
}

/// The prefixes have more than `BASE58_MAX_VARIANTS` upper/lowercase variants.
#[derive(Debug)]
pub struct TooManyVariants;

/// The bits of a public key hash that are set by a Bech32 prefix.
pub struct Bech32Prefix {
    // The first 16 bytes and the last 4 bytes of the hash.
    mask: (u128, u32),
    bits: (u128, u32),
}

/// The bits of an output key that are set by a Taproot prefix.
pub struct TaprootPrefix {
    // The first 16 bytes and the last 16 bytes of the key.
    mask: (u128, u128),
    bits: (u128, u128),
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
    pub fn new(
        prefixes: &[String],
        is_case_sensitive: bool,
        address_type: AddressType,
    ) -> Result<Self, TooManyVariants> {
        match address_type {
            AddressType::Legacy => {}
            AddressType::Bech32 => {
                let prefixes = prefixes
                    .iter()
                    .filter_map(|prefix| Bech32Prefix::new(prefix));
                return Ok(Self::Bech32(prefixes.collect()));
            }
            AddressType::Taproot => {
                let prefixes = prefixes
                    .iter()
                    .filter_map(|prefix| TaprootPrefix::new(prefix));
                return Ok(Self::Taproot(prefixes.collect()));
            }
        }

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

        let mut ranges = Vec::new();
        for variants in variants {
            variants.add_ranges(&mut ranges);
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
        Ok(Self::Base58(ranges))
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
            // These have no public key hash in them.
            Self::Taproot(_) => false,
            Self::Base58(ranges) => {
                let index = ranges.partition_point(|range| range.first <= *pubkey_hash);
                index > 0 && *pubkey_hash <= ranges[index - 1].last
            }
        }
    }

    /// Like `matches`, for the output key of a Taproot address.
    pub fn matches_output_key(&self, output_key: &[u8; 32]) -> bool {
        let Self::Taproot(prefixes) = self else {
            return false;
        };
        let head = u128::from_be_bytes(output_key[..16].try_into().unwrap());
        let tail = u128::from_be_bytes(output_key[16..].try_into().unwrap());
        prefixes.iter().any(|prefix| {
            head & prefix.mask.0 == prefix.bits.0 && tail & prefix.mask.1 == prefix.bits.1
        })
    }

    /// Returns true if there is no address that starts with any of the
    /// prefixes.
    pub fn is_empty(&self) -> bool {
        match self {
            Self::Bech32(prefixes) => prefixes.is_empty(),
            Self::Taproot(prefixes) => prefixes.is_empty(),
            Self::Base58(ranges) => ranges.is_empty(),
        }
    }
}

impl Bech32Prefix {
    /// Returns nothing if there are no addresses starting with the prefix.
    fn new(prefix: &str) -> Option<Self> {
        let (mask, bits) = bech32_bits::<20>(prefix, BECH32_PREFIX, BECH32_HASH_PART_LEN)?;

        let split = |bytes: [u8; 20]| {
            let head = u128::from_be_bytes(bytes[..16].try_into().unwrap());
            let tail = u32::from_be_bytes(bytes[16..].try_into().unwrap());
            (head, tail)
        };
        Some(Self {
            mask: split(mask),
            bits: split(bits),
        })
    }
}

impl TaprootPrefix {
    /// Returns nothing if there are no addresses starting with the prefix.
    fn new(prefix: &str) -> Option<Self> {
        let (mask, bits) = bech32_bits::<32>(prefix, TAPROOT_PREFIX, TAPROOT_KEY_PART_LEN)?;

        let split = |bytes: [u8; 32]| {
            let head = u128::from_be_bytes(bytes[..16].try_into().unwrap());
            let tail = u128::from_be_bytes(bytes[16..].try_into().unwrap());
            (head, tail)
        };
        Some(Self {
            mask: split(mask),
            bits: split(bits),
        })
    }
}

/// The bits that are set by a Bech32 prefix in the `N` bytes that an address
/// encodes, as a mask and the value of the bits in it. `start` is what all the
/// addresses start with, and `len` how long they are without the checksum.
///
/// Returns nothing if there are no addresses starting with the prefix.
fn bech32_bits<const N: usize>(
    prefix: &str,
    start: &[u8; 4],
    len: usize,
) -> Option<([u8; N], [u8; N])> {
    let prefix = prefix.to_lowercase().into_bytes();
    // The checksum of a Bech32 address is not looked at here.
    let prefix = &prefix[..prefix.len().min(len)];

    let start_len = prefix.len().min(start.len());
    if prefix[..start_len] != start[..start_len] {
        return None;
    }

    // Every character sets 5 bits.
    let mut mask = [0u8; N];
    let mut bits = [0u8; N];
    for (i, character) in prefix[start_len..].iter().enumerate() {
        let value = BECH32_CHARSET.iter().position(|c| c == character)?;
        for bit in 0..5 {
            let position = i * 5 + bit;
            let is_set = value & (0x10 >> bit) != 0;
            if position >= N * 8 {
                // The last character has some bits left, they are always zero.
                if is_set {
                    return None;
                }
                continue;
            }
            mask[position / 8] |= 0x80 >> (position % 8);
            if is_set {
                bits[position / 8] |= 0x80 >> (position % 8);
            }
        }
    }
    Some((mask, bits))
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
    fn add_ranges(mut self, ranges: &mut Vec<Base58Range>) {
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
fn base58_variant_ranges(prefix: &[u8], ranges: &mut Vec<Base58Range>) {
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
