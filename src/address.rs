use bitcoin::hashes::{hash160, Hash};
use bitcoin::secp256k1;
use bitcoin::secp256k1::{Scalar, Secp256k1, SecretKey, Signing};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, PublicKey};

const BECH32_CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32_PREFIX: &[u8; 4] = b"bc1q";
// "bc1q" followed by the 32 characters that encode the 20 byte hash.
const BECH32_HASH_PART_LEN: usize = 36;

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

/// Walks over consecutive keys, starting at a random one.
///
/// Deriving a public key from a secret key is by far the most expensive step
/// of generating an address. Adding the generator point to a public key gives
/// the public key of the next secret key and is a lot cheaper, so only the
/// starting point is derived the expensive way.
pub struct KeyWalker {
    base: SecretKey,
    offset: u64,
    point: secp256k1::PublicKey,
    generator: secp256k1::PublicKey,
}

impl KeyWalker {
    pub fn new(secp: &Secp256k1<impl Signing>) -> Self {
        let one = SecretKey::from_slice(&secp256k1::constants::ONE)
            .expect("Failed to create Bitcoin secret key");
        let base = random_secret_key();

        Self {
            base,
            offset: 0,
            point: secp256k1::PublicKey::from_secret_key(secp, &base),
            generator: secp256k1::PublicKey::from_secret_key(secp, &one),
        }
    }

    /// Move on to the next key.
    pub fn advance(&mut self, secp: &Secp256k1<impl Signing>) {
        match self.point.combine(&self.generator) {
            Ok(point) if self.offset < u64::MAX => {
                self.point = point;
                self.offset += 1;
            }
            // Practically unreachable, just start over somewhere else.
            _ => *self = Self::new(secp),
        }
    }

    /// The hash160 of the current public key, this is what addresses encode.
    pub fn pubkey_hash(&self, is_compressed: bool) -> [u8; 20] {
        if is_compressed {
            hash160::Hash::hash(&self.point.serialize()).to_byte_array()
        } else {
            hash160::Hash::hash(&self.point.serialize_uncompressed()).to_byte_array()
        }
    }

    /// The secret key of the current public key.
    pub fn secret_key(&self) -> SecretKey {
        let mut tweak = [0u8; 32];
        tweak[24..].copy_from_slice(&self.offset.to_be_bytes());
        let tweak = Scalar::from_be_bytes(tweak).expect("Failed to create Bitcoin secret key");
        self.base
            .add_tweak(&tweak)
            .expect("Failed to create Bitcoin secret key")
    }
}

/// Matches prefixes against a public key hash, without creating an address.
///
/// It might match a little too much (see `matches`), so a match has to be
/// confirmed with `BitcoinAddress::starts_with_any`.
pub struct PrefixMatcher {
    prefixes: Vec<Vec<u8>>,
    is_case_sensitive: bool,
    is_bech32: bool,
}

impl PrefixMatcher {
    pub fn new(prefixes: &[String], is_case_sensitive: bool, is_bech32: bool) -> Self {
        let prefixes = prefixes
            .iter()
            .map(|prefix| {
                let mut prefix = if is_case_sensitive {
                    prefix.clone().into_bytes()
                } else {
                    prefix.to_lowercase().into_bytes()
                };
                // The checksum of a Bech32 address is not looked at here.
                if is_bech32 {
                    prefix.truncate(BECH32_HASH_PART_LEN);
                }
                prefix
            })
            .collect();

        Self {
            prefixes,
            is_case_sensitive,
            is_bech32,
        }
    }

    pub fn matches(&self, pubkey_hash: &[u8; 20]) -> bool {
        if self.is_bech32 {
            let address = bech32_hash_part(pubkey_hash);
            self.starts_with_any(&address)
        } else {
            let mut payload = [0u8; 21];
            payload[1..].copy_from_slice(pubkey_hash);
            let mut address = bitcoin::base58::encode_check(&payload).into_bytes();
            if !self.is_case_sensitive {
                address.make_ascii_lowercase();
            }
            self.starts_with_any(&address)
        }
    }

    fn starts_with_any(&self, address: &[u8]) -> bool {
        self.prefixes.iter().any(|prefix| address.starts_with(prefix))
    }
}

/// The start of the Bech32 address of a public key hash, without the checksum.
fn bech32_hash_part(pubkey_hash: &[u8; 20]) -> [u8; BECH32_HASH_PART_LEN] {
    let mut address = [0u8; BECH32_HASH_PART_LEN];
    address[..BECH32_PREFIX.len()].copy_from_slice(BECH32_PREFIX);

    let mut len = BECH32_PREFIX.len();
    let mut acc = 0u32;
    let mut bits = 0;
    for byte in pubkey_hash {
        acc = (acc << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            address[len] = BECH32_CHARSET[((acc >> bits) & 31) as usize];
            len += 1;
        }
    }
    address
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
