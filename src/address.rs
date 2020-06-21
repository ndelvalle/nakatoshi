use bitcoin::network::constants::Network;
use bitcoin::util;
use secp256k1::constants;
use secp256k1::key::SecretKey;
use secp256k1::{Secp256k1, Signing};

fn get_random_buf() -> [u8; constants::SECRET_KEY_SIZE] {
    let mut buf = [0u8; constants::SECRET_KEY_SIZE];
    getrandom::getrandom(&mut buf).expect("Error creating random bytes");
    buf
}

pub struct Couple {
    pub uncompressed: Address,
    pub compressed: Address,
}

impl Couple {
    pub fn new(secp: &Secp256k1<impl Signing>, bech: bool) -> Couple {
        let random_buf = get_random_buf();
        let uncompressed = Address::new(secp, &random_buf, false, bech);
        let compressed = Address::new(secp, &random_buf, true, bech);

        Couple {
            uncompressed,
            compressed,
        }
    }

    pub fn starts_with_any(&self, addresses: &[String], case_sensitive: bool) -> bool {
        for address in addresses.iter() {
            if self.starts_with(address, case_sensitive) {
                return true;
            }
        }
        false
    }

    pub fn starts_with(&self, starts_with: &str, case_sensitive: bool) -> bool {
        self.uncompressed.starts_with(starts_with, case_sensitive)
            || self.compressed.starts_with(starts_with, case_sensitive)
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
        data: &[u8],
        compressed: bool,
        bech: bool,
    ) -> Address {
        let key = match SecretKey::from_slice(data) {
            Ok(sk) => sk,
            Err(err) => panic!(
                "Error creating secret key from random bytes {:?}",
                err.to_string()
            ),
        };

        let private_key = util::key::PrivateKey {
            compressed,
            network: Network::Bitcoin,
            key,
        };

        let public_key = util::key::PublicKey::from_private_key(&secp, &private_key);
        let address: util::address::Address = if bech {
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

    pub fn starts_with(&self, starts_with: &str, case_sensitive: bool) -> bool {
        if case_sensitive {
            self.address.to_string().starts_with(starts_with)
        } else {
            self.address
                .to_string()
                .to_lowercase()
                .starts_with(starts_with)
        }
    }
}
