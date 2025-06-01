extern crate chrono;

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde::ser::Serializer;
use sha2::{Digest, Sha256};

#[derive(Debug, Serialize)]
struct Transaction {
    sender: String,
    receiver: String,
    amount: f32,
}

#[derive(Debug, Serialize)]
struct Block {
    timestamp: DateTime<Utc>,
    transactions: Vec<Transaction>,
    #[serde(serialize_with = "as_hex")]
    previous_hash: Vec<u8>,
    #[serde(serialize_with = "as_hex")]
    hash: Vec<u8>,
}

// Helper function for hex serialization
fn as_hex<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

#[derive(Debug, Serialize)]
struct Blockchain {
    chain: Vec<Block>,
    difficulty: u32,
}

impl Block {
    fn calculate_hash(&mut self) -> Vec<u8> {
        let mut hasher = Sha256::new();
        let timestamp_bytes: Vec<u8> = self.timestamp.to_string().into_bytes();
        let transaction_bytes: Vec<u8> = format!("{:?}", self.transactions).into_bytes();
        let previous_hash_bytes: Vec<u8> = format!("{:?}", self.previous_hash).into_bytes();

        hasher.update(timestamp_bytes);
        hasher.update(transaction_bytes);
        hasher.update(previous_hash_bytes);

        hasher.finalize().to_vec()
    }

    fn mine_block(&mut self, difficulty: u32) {
        let prefix: Vec<u8> = vec![0u8; difficulty as usize];
        loop {
            self.hash = self.calculate_hash();
            if self.hash.starts_with(&prefix) {
                println!(
                    "\nBlock mined: {}",
                    serde_json::to_string_pretty(&self).expect("Failed to serialize block")
                );

                break;
            }
        }
    }
}

impl Blockchain {
    fn new(difficulty: u32) -> Self {
        let genesis_block: Block = Block {
            timestamp: Utc::now(),
            transactions: vec![],
            previous_hash: vec![0; 32],
            hash: vec![],
        };

        let mut blockchain: Blockchain = Blockchain {
            chain: vec![genesis_block],
            difficulty,
        };

        blockchain.chain[0].mine_block(difficulty);
        blockchain
    }

    fn add_block(&mut self, mut block: Block) {
        let prev_hash = self.chain.last().unwrap().hash.clone();
        block.previous_hash = prev_hash;
        block.mine_block(self.difficulty);
        self.chain.push(block);
    }
}

fn main() {
    let mut blockchain = Blockchain::new(0);

    let transactoin_of_alice = Transaction {
        sender: "Alice".to_string(),
        receiver: "Bob".to_string(),
        amount: 10.0,
    };
    println!(
        "\nTransaction: {} sent {} to {}",
        transactoin_of_alice.sender, transactoin_of_alice.amount, transactoin_of_alice.receiver
    );

    let block1: Block = Block {
        timestamp: Utc::now(),
        transactions: vec![transactoin_of_alice],
        previous_hash: vec![],
        hash: vec![],
    };

    blockchain.add_block(block1);

    println!(
        "{}",
        serde_json::to_string_pretty(&blockchain).expect("Failed to serialize blockchain")
    );
}
