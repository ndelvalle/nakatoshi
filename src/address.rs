use bitcoin::network::constants::Network;
use bitcoin::secp256k1;
use bitcoin::secp256k1::{Secp256k1, SecretKey, Signing};
use bitcoin::util::address::Address;
use bitcoin::util::key::{PrivateKey, PublicKey};

pub struct BitcoinAddress {
    pub private_key: PrivateKey,
    pub public_key: PublicKey,
    pub address: Address,
}

impl BitcoinAddress {
    pub fn new(secp: &Secp256k1<impl Signing>, is_compressed: bool, is_bech32: bool) -> Self {
        let random_bytes = get_random_bytes();
        let secret_key =
            SecretKey::from_slice(&random_bytes).expect("Failed to create Bitcoin secret key");

        let private_key = PrivateKey {
            compressed: is_compressed,
            network: Network::Bitcoin,
            inner: secret_key,
        };

        let public_key = PublicKey::from_private_key(secp, &private_key);

        let address: Address = if is_bech32 {
            Address::p2wpkh(&public_key, Network::Bitcoin)
                .expect("Failed to create Bitcoin bech32 address")
        } else {
            Address::p2pkh(&public_key, Network::Bitcoin)
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

fn get_random_bytes() -> [u8; secp256k1::constants::SECRET_KEY_SIZE] {
    let mut buf = [0u8; secp256k1::constants::SECRET_KEY_SIZE];
    getrandom::getrandom(&mut buf).expect("Failed to create random bytes");
    buf
}
