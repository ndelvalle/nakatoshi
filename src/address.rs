use secp256k1::rand::thread_rng;
use secp256k1::{Secp256k1, Signing};

use bitcoin::network::constants::Network;
use bitcoin::util;

pub struct Address {
    pub private_key: util::key::PrivateKey,
    pub public_key: util::key::PublicKey,
    pub address: util::address::Address,
}

impl Address {
    pub fn new(secp: &Secp256k1<impl Signing>) -> Address {
        let keypair = secp.generate_keypair(&mut thread_rng());
        let private_key = util::key::PrivateKey {
            compressed: true,
            network: Network::Bitcoin,
            key: keypair.0,
        };
        let public_key = util::key::PublicKey::from_private_key(&secp, &private_key);
        let address = util::address::Address::p2pkh(&public_key, Network::Bitcoin);

        Address {
            private_key,
            public_key,
            address,
        }
    }

    pub fn starts_with(&self, starts_with: &str) -> bool {
        self.address.to_string().starts_with(starts_with)
    }
}
