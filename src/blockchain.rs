use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use super::Hash;
use crate::credential::{Credential, Issuer, SignedCredential};

/// Custom serialization for Hash
mod hash_serde {
    use super::Hash;
    use hex::{decode, encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(hash: &Hash, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&encode(hash))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Hash, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s: &str = Deserialize::deserialize(deserializer)?;
        let bytes = decode(s).map_err(serde::de::Error::custom)?;
        if bytes.len() != 64 {
            return Err(serde::de::Error::custom("Hash must be 64 bytes"));
        }
        let mut array = [0u8; 64];
        array.copy_from_slice(&bytes);
        Ok(array)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Block {
    timestamp: DateTime<Utc>,
    new_credentials: Vec<SignedCredential>,
    revoked_credentials: Vec<SignedCredential>,
    #[serde(with = "hash_serde")]
    previous_hash: Hash,
    signer: Issuer,
    #[serde(with = "hash_serde")]
    hash: Hash,
    #[serde(with = "hash_serde")]
    signature: Hash,
}

impl Block {
    #[must_use]
    pub fn new(signer: Issuer) -> Self {
        Self {
            timestamp: Utc::now(),
            new_credentials: Vec::new(),
            revoked_credentials: Vec::new(),
            previous_hash: [0; 64],
            signer,
            hash: [0; 64],
            signature: [0; 64],
        }
    }

    pub fn add_credential(&mut self, signed_credential: SignedCredential, revoking: bool) {
        if revoking {
            self.revoked_credentials.push(signed_credential);
        } else {
            self.new_credentials.push(signed_credential);
        }
    }

    pub fn finalize(&mut self, previous_hash: Hash, signing: &SigningKey) {
        self.timestamp = Utc::now();
        self.previous_hash = previous_hash;
        let mut hasher = Sha512::new();
        hasher.update(self.timestamp.to_string());
        self.new_credentials
            .iter()
            .chain(self.revoked_credentials.iter())
            .for_each(|c| c.hash_credential(&mut hasher));
        hasher.update(self.previous_hash);
        self.signer.hash(&mut hasher);
        self.hash = hasher.finalize().into();
        self.signature = signing.sign(&self.hash).to_bytes();
    }

    fn find(&self, new_hash: Hash, revoking_hash: Hash, verifying: &VerifyingKey) -> (bool, bool) {
        let new = self
            .new_credentials
            .iter()
            .find(|s| s.credential == new_hash)
            .is_some_and(|c| c.verify(verifying));
        let revoked = self
            .revoked_credentials
            .iter()
            .find(|s| s.credential == revoking_hash)
            .is_some_and(|c| c.verify(verifying));
        (new, revoked)
    }

    pub fn print_json(&self) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => println!("Block:\n{}\n", json),
            Err(e) => eprintln!("Error serializing block to JSON: {}", e),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Blockchain {
    chain: Vec<Block>,
}

impl Default for Blockchain {
    fn default() -> Self {
        Self::new()
    }
}

impl Blockchain {
    #[must_use]
    pub fn new() -> Self {
        Self { chain: Vec::new() }
    }

    pub fn add_block(&mut self, mut block: Block, signing: &SigningKey) {
        block.finalize(self.chain.last().map_or([0; 64], |b| b.hash), signing);
        self.chain.push(block);
    }

    #[must_use]
    pub fn check_credential(&self, credential: &Credential) -> bool {
        let new_hash = credential.hash(false);
        let revoking_hash = credential.hash(true);
        let mut found = false;
        for b in &self.chain {
            let (f, r) = b.find(new_hash, revoking_hash, &credential.issuer.verifying);
            if r {
                return false;
            }
            found |= f;
        }
        found
    }

    pub fn print_json(&self) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => println!("Blockchain:\n{}\n", json),
            Err(e) => eprintln!("Error serializing blockchain to JSON: {}", e),
        }
    }
}
