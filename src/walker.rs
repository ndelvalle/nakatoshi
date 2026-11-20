use std::sync::OnceLock;

use bitcoin::hashes::{Hash, HashEngine, hash160};
use bitcoin::secp256k1;
use bitcoin::secp256k1::{Scalar, Secp256k1, SecretKey, Signing};
use bitcoin::taproot::TapTweakHash;
use k256::FieldBytes;
use k256::elliptic_curve::hazmat::FieldArithmetic;

use crate::address::{AddressType, random_secret_key};

// The field of secp256k1, which k256 only exposes through this trait.
type FieldElement = <k256::Secp256k1 as FieldArithmetic>::FieldElement;

// A batch has a center key, and this many keys on both sides of it.
const HALF_BATCH_SIZE: usize = 1024;
const BATCH_SIZE: usize = 2 * HALF_BATCH_SIZE + 1;

// The tweak of a Taproot address is split up in windows of this many bits.
const TWEAK_WINDOW_BITS: usize = 13;
// The number of values a window can have.
const TWEAK_WINDOW_SIZE: usize = 1 << TWEAK_WINDOW_BITS;
const TWEAK_WINDOWS: usize = 256usize.div_ceil(TWEAK_WINDOW_BITS);

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
    // What is added to the center of a batch for the other points of it,
    // which is G, minus G, 2G, minus 2G and so on. The last one is
    // `BATCH_SIZE` times G, for the center of the next batch.
    offsets: Vec<Point>,
}

impl GeneratorMultiples {
    fn get(secp: &Secp256k1<impl Signing>) -> &'static Self {
        static MULTIPLES: OnceLock<GeneratorMultiples> = OnceLock::new();

        MULTIPLES.get_or_init(|| {
            let multiple = |factor: usize| {
                let mut secret_key = [0u8; 32];
                secret_key[24..].copy_from_slice(&(factor as u64).to_be_bytes());
                let secret_key = SecretKey::from_slice(&secret_key)
                    .expect("Failed to create Bitcoin secret key");
                Point::from_public_key(&secp256k1::PublicKey::from_secret_key(secp, &secret_key))
            };

            let mut offsets = Vec::with_capacity(BATCH_SIZE);
            for factor in 1..=HALF_BATCH_SIZE {
                let point = multiple(factor);
                offsets.push(point);
                offsets.push(Point {
                    x: point.x,
                    y: point.y.negate(1).normalize(),
                });
            }
            offsets.push(multiple(BATCH_SIZE));
            Self { offsets }
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
    // The points of the current batch, `x` followed by `y`.
    points: Vec<[u8; 64]>,
    // Scratch space for adding the offsets to the center.
    sums: Vec<Point>,
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
        let zero = Point {
            x: FieldElement::ZERO,
            y: FieldElement::ZERO,
        };
        let mut walker = Self {
            is_compressed,
            multiples: GeneratorMultiples::get(secp),
            base: random_secret_key(),
            center_offset: 0,
            next_center: zero,
            next_center_offset: 0,
            points: vec![[0u8; 64]; BATCH_SIZE],
            sums: vec![zero; BATCH_SIZE],
            products: Vec::with_capacity(BATCH_SIZE),
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
        let center = self.next_center;
        let offsets = &self.multiples.offsets;
        self.sums.fill(center);
        if !add_points(&mut self.sums, |i| &offsets[i], &mut self.products) {
            // One of the points is the same as (or the inverse of) the center.
            return false;
        }

        // The last sum is not a point of this batch, it is the next center.
        let points = std::iter::once(&center).chain(&self.sums);
        for (bytes, point) in self.points.iter_mut().zip(points) {
            bytes[..32].copy_from_slice(&point.x.normalize().to_bytes());
            bytes[32..].copy_from_slice(&point.y.normalize().to_bytes());
        }

        if let Some(output_keys) = &mut self.output_keys
            && !output_keys.calculate(&self.points)
        {
            return false;
        }

        let next_center = self.sums[BATCH_SIZE - 1];
        self.center_offset = self.next_center_offset;
        self.next_center = Point {
            x: next_center.x.normalize(),
            y: next_center.y.normalize(),
        };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::address::BitcoinAddress;

    #[test]
    fn walked_keys_match_their_secret_key() {
        let secp = Secp256k1::new();

        for is_compressed in [true, false] {
            let mut keys = KeyWalker::new(&secp, is_compressed, AddressType::Legacy);
            let mut seen = std::collections::HashSet::new();

            for batch in 0..6 {
                if batch == 3 {
                    keys.restart(&secp);
                }
                let batch_len = keys.next_batch(&secp);
                for index in 0..batch_len {
                    let mut expected: Vec<[u8; 20]> = keys
                        .secret_keys(index)
                        .into_iter()
                        .map(|secret_key| {
                            let address_type = AddressType::Legacy;
                            BitcoinAddress::from_secret_key(
                                &secp,
                                secret_key,
                                is_compressed,
                                address_type,
                            )
                            .public_key
                            .pubkey_hash()
                            .to_byte_array()
                        })
                        .collect();
                    let mut hashes = keys.pubkey_hashes(index).to_vec();
                    expected.sort();
                    hashes.sort();
                    assert_eq!(hashes, expected);
                    // No key is tried twice.
                    assert!(hashes.into_iter().all(|hash| seen.insert(hash)));
                }
            }
        }
    }

    #[test]
    fn walked_output_keys_match_their_secret_key() {
        let secp = Secp256k1::new();
        let mut keys = KeyWalker::new(&secp, true, AddressType::Taproot);
        let mut seen = std::collections::HashSet::new();

        for batch in 0..3 {
            if batch == 2 {
                keys.restart(&secp);
            }
            let batch_len = keys.next_batch(&secp);
            for index in 0..batch_len {
                let output_key = keys.output_key(index);
                // Both secret keys have the same address.
                for secret_key in keys.secret_keys(index) {
                    let address_type = AddressType::Taproot;
                    let address =
                        BitcoinAddress::from_secret_key(&secp, secret_key, true, address_type);
                    let program = address.address.witness_program().unwrap();
                    assert_eq!(program.program().as_bytes(), output_key);
                }
                // No key is tried twice.
                assert!(seen.insert(output_key));
            }
        }
    }
}
