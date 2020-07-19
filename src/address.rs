use bitcoin::network::constants::Network;
use bitcoin::util;
use secp256k1::constants;
use secp256k1::key::SecretKey;
use secp256k1::{Secp256k1, Signing};


fn get_random_buf() -> [u8; constants::SECRET_KEY_SIZE] {
    let mut buf = [0u8; constants::SECRET_KEY_SIZE];
    getrandom::getrandom(&mut buf).expect("Failed to create random bytes");
    buf
}

pub struct Couple {
    pub uncompressed: Address,
    pub compressed: Address,
}

impl Couple {
    pub fn new(secp: &Secp256k1<impl Signing>, is_bech32: bool) -> Couple {
        let random_buf = get_random_buf();
        let uncompressed = Address::new(secp, &random_buf, false, is_bech32);
        let compressed = Address::new(secp, &random_buf, true, is_bech32);

        Couple {
            uncompressed,
            compressed,
        }
    }

    pub fn starts_with_any(&self, addresses: &[String], is_case_sensitive: bool) -> bool {
        for address in addresses {
            if self.starts_with(address, is_case_sensitive) {
                return true;
            }
        }
        false
    }

    pub fn starts_with(&self, starts_with: &str, is_case_sensitive: bool) -> bool {
        self.uncompressed
            .starts_with(starts_with, is_case_sensitive)
            || self.compressed.starts_with(starts_with, is_case_sensitive)
    }
}

pub struct Address {
    pub private_key: util::key::PrivateKey,
    pub public_key: util::key::PublicKey,
    pub address: util::address::Address,
}

impl Address {
    pub fn new(
        secp: &Secp256k1<impl Signing>,
        random_bytes: &[u8],
        compressed: bool,
        is_bech32: bool,
    ) -> Address {
        let secret_key = SecretKey::from_slice(random_bytes)
            .expect("Failed to create secret key from random bytes");

        let private_key = util::key::PrivateKey {
            compressed,
            network: Network::Bitcoin,
            key: secret_key,
        };

        let public_key = util::key::PublicKey::from_private_key(&secp, &private_key);

        let address: util::address::Address = if is_bech32 {
            util::address::Address::p2wpkh(&public_key, Network::Bitcoin)
        } else {
            util::address::Address::p2pkh(&public_key, Network::Bitcoin)
        };

        Address {
            private_key,
            public_key,
            address,
        }
    }

    pub fn starts_with(&self, starts_with: &str, is_case_sensitive: bool) -> bool {
        if is_case_sensitive {
            self.address.to_string().starts_with(starts_with)
        } else {
            self.address
                .to_string()
                .to_lowercase()
                .starts_with(starts_with.to_lowercase().as_str())
        }
    }
}
