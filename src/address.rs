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

pub struct Address {
    pub private_key: util::key::PrivateKey,
    pub public_key: util::key::PublicKey,
    pub address: util::address::Address,
}

impl Address {
    pub fn new(secp: &Secp256k1<impl Signing>) -> Address {
        let random_buf = get_random_buf();
        let secret_key = match SecretKey::from_slice(&random_buf) {
            Ok(sk) => sk,
            Err(err) => panic!(
                "Error creating secret key from random bytes {:?}",
                err.to_string()
            ),
        };

        let priv_key = util::key::PrivateKey {
            compressed: true,
            network: Network::Bitcoin,
            key: secret_key,
        };
        let pub_key = util::key::PublicKey::from_private_key(&secp, &priv_key);
        let address = util::address::Address::p2pkh(&pub_key, Network::Bitcoin);

        Address {
            private_key: priv_key,
            public_key: pub_key,
            address,
        }
    }

    pub fn starts_with(&self, starts_with: &str, case_sensitive: bool) -> bool {
        if case_sensitive {
            self.address.to_string().starts_with(starts_with)
        } else {
            self.address.to_string().to_lowercase().starts_with(starts_with)
        }
    }
}
