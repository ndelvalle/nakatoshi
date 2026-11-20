use bitcoin::secp256k1;
use bitcoin::secp256k1::{Secp256k1, SecretKey, Signing, Verification};
use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, PublicKey};

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
    #[cfg(test)]
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

pub fn random_secret_key() -> SecretKey {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_compressed_bitcoin_public_key() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Legacy;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);

        let actual = bitcoin_address.public_key.to_string().len();
        let expected = 66;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_uncompressed_bitcoin_public_key() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Legacy;
        let is_compressed = false;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);

        let actual = bitcoin_address.public_key.to_string().len();
        let expected = 130;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bech32_address() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Bech32;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);
        let address = bitcoin_address.address.to_string();

        assert!(address.starts_with("bc1q"));
    }

    #[test]
    fn create_taproot_address() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Taproot;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);
        let address = bitcoin_address.address.to_string();

        assert!(address.starts_with("bc1p"));
        assert_eq!(address.len(), 62);
    }

    #[test]
    fn create_bitcoin_private_key() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Legacy;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);

        let actual = bitcoin_address.private_key.to_string().len();
        let expected = 52;

        assert_eq!(actual, expected);
    }

    #[test]
    fn create_bitcoin_address() {
        let secp = Secp256k1::new();
        let address_type = AddressType::Legacy;
        let is_compressed = true;
        let bitcoin_address = BitcoinAddress::new(&secp, is_compressed, address_type);

        let actual = bitcoin_address.address.to_string().len();
        let expected = 34;

        assert_eq!(actual, expected);
    }

    // The addresses of a key that is published with them.
    fn assert_addresses(private_key: &str, expected: [(AddressType, &str); 3]) {
        let secp = Secp256k1::new();
        let private_key = PrivateKey::from_wif(private_key).unwrap();
        for (address_type, expected) in expected {
            let address = BitcoinAddress::from_secret_key(
                &secp,
                private_key.inner,
                private_key.compressed,
                address_type,
            );
            assert_eq!(address.address.to_string(), expected);
            assert_eq!(address.private_key, private_key);
        }
    }

    #[test]
    fn addresses_of_the_secret_key_one() {
        assert_addresses(
            "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoWn",
            [
                (AddressType::Legacy, "1BgGZ9tcN4rm9KBzDn7KprQz87SZ26SAMH"),
                (
                    AddressType::Bech32,
                    "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4",
                ),
                (
                    AddressType::Taproot,
                    "bc1pmfr3p9j00pfxjh0zmgp99y8zftmd3s5pmedqhyptwy6lm87hf5sspknck9",
                ),
            ],
        );

        let secp = Secp256k1::new();
        let private_key =
            PrivateKey::from_wif("5HpHagT65TZzG1PH3CSu63k8DbpvD8s5ip4nEB3kEsreAnchuDf").unwrap();
        let address_type = AddressType::Legacy;
        let address =
            BitcoinAddress::from_secret_key(&secp, private_key.inner, false, address_type);
        assert_eq!(
            address.address.to_string(),
            "1EHNa6Q4Jz2uvNExL497mE43ikXhwF6kZm"
        );
    }

    #[test]
    fn addresses_of_the_bip_86_test_vector() {
        // The first receiving address of the test vectors of BIP 86.
        assert_addresses(
            "KyRv5iFPHG7iB5E4CqvMzH3WFJVhbfYK4VY7XAedd9Ys69mEsPLQ",
            [
                (AddressType::Legacy, "1NsJS4DAHLcegD63trZurmkLm23TRAujXd"),
                (
                    AddressType::Bech32,
                    "bc1qalwlmdxd2ggue4290ekzxl9tetg56neexr6amw",
                ),
                (
                    AddressType::Taproot,
                    "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
                ),
            ],
        );
    }
}
