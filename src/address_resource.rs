use secp256k1::Secp256k1;
use secp256k1::rand::thread_rng;

use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::key;

pub struct AddressResource {
    pub private_key: key::PrivateKey,
    pub public_key: key::PublicKey,
    pub address: Address,
}

impl AddressResource {
    pub fn new() -> AddressResource {
        let secp = Secp256k1::new();
        let keypair = secp.generate_keypair(&mut thread_rng());
        let private_key = key::PrivateKey {
            compressed: true,
            network: Network::Bitcoin,
            key: keypair.0,
        };
        let public_key = key::PublicKey::from_private_key(&secp, &private_key);
        let address = Address::p2pkh(&public_key, Network::Bitcoin);

        AddressResource { private_key, public_key, address }
    }

    pub fn address_starts_with (&self, starts_with: &str) -> bool {
        self.address.to_string().starts_with(starts_with)
    }
}