#![warn(clippy::pedantic)]

use chrono::{DateTime, NaiveDate, Utc};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier};
use serde::ser::Serializer;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

#[derive(Debug, Serialize, Deserialize)]
struct Attribute {
    issuer_id: u32,
    issuer_name: String,
    subject_id: u32,
    subject_name: String,
    name: String,
    id: u32,
    from: NaiveDate,
    to: NaiveDate,
}

impl Attribute {
    fn hash(&self) -> Hash {
        let mut hasher = Sha512::new();
        hasher.update(self.issuer_id.to_be_bytes());
        hasher.update(&self.issuer_name);
        hasher.update(self.subject_id.to_be_bytes());
        hasher.update(&self.subject_name);
        hasher.update(&self.name);
        hasher.update(self.id.to_be_bytes());
        hasher.update(self.from.format("%Y-%m-%d").to_string());
        hasher.update(self.to.format("%Y-%m-%d").to_string());
        Hash(hasher.finalize().try_into().unwrap())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
struct Hash(#[serde(serialize_with = "as_hex")] [u8; 64]);

impl Default for Hash {
    fn default() -> Self { Self([0; 64]) }
}

impl AsRef<[u8]> for Hash {
    fn as_ref(&self) -> &[u8] { &self.0 }
}

#[derive(Debug, Serialize)]
struct Block {
    timestamp: DateTime<Utc>,
    attribute_hashes: Vec<Hash>,
    previous_hash: Hash,
    hash: Hash,
    signature: Hash,
}

impl Default for Block {
    fn default() -> Self {
        Self {
            timestamp: Utc::now(),
            attribute_hashes: Vec::new(),
            previous_hash: Hash::default(),
            hash: Hash::default(),
            signature: Hash::default(),
        }
    }
}

impl Block {
    fn add_attribute(&mut self, attribute: &Attribute) {
        self.attribute_hashes.push(attribute.hash());
    }

    fn finalize(&mut self, previous_hash: Hash) {
        self.timestamp = Utc::now();
        self.previous_hash = previous_hash;
        let mut hasher = Sha512::new();
        hasher.update(self.timestamp.to_string());
        for h in &self.attribute_hashes {
            hasher.update(h);
        }
        hasher.update(&self.previous_hash);
        self.hash = Hash(hasher.finalize().try_into().unwrap());
    }

    fn sign(&mut self, signer: &impl Signer<Signature>) {
        self.signature = Hash(signer.sign(&self.hash.0).to_bytes());
    }
}

// Helper function for hex serialization
fn as_hex<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where S: Serializer {
    serializer.serialize_str(&hex::encode(bytes))
}

#[derive(Debug, Serialize)]
struct Blockchain {
    chain: Vec<Block>,
}

impl Blockchain {
    fn new() -> Self {
        let mut genesis = Block::default();
        genesis.finalize(Hash::default());
        Self { chain: vec![genesis] }
    }

    fn add_block(&mut self, mut block: Block, signer: &impl Signer<Signature>) {
        block.finalize(self.chain.last().unwrap().previous_hash.clone());
        block.sign(signer);
        self.chain.push(block);
    }

    fn check_certificate(&self, attribute: &Attribute, verifier: &impl Verifier<Signature>) -> bool {
        let hash = attribute.hash();
        let Some(block) = self.chain.iter().find(|b| b.attribute_hashes.contains(&hash)) else {
            return false;
        };
        verifier.verify(&block.hash.0, &Signature::from_bytes(&block.signature.0)).is_ok()
    }
}

fn main() {
    let mut blockchain = Blockchain::new();
    let mut new_block = Block::default();
    let attribute = Attribute {
        issuer_id: 0,
        issuer_name: String::new(),
        subject_id: 0,
        subject_name: String::new(),
        name: String::new(),
        id: 0,
        from: NaiveDate::default(),
        to: NaiveDate::default(),
    };
    new_block.add_attribute(&attribute);
    let mut rand = rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut rand);
    let verifier = signing.verifying_key();
    blockchain.add_block(new_block, &signing);
    let result = blockchain.check_certificate(&attribute, &verifier);
    println!("{result}");
}
