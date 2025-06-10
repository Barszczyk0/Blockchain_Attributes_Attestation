use std::fs;
use std::fs::File;

use chrono::NaiveDate;
use clap::{Args, Parser, Subcommand};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::blockchain::{Block, Blockchain};
use crate::credential::{Attribute, Credential, Issuer, SignedCredential, Subject, ValidDuration};

/// Custom serialization for `SigningKey`
mod signing_key_serde {
    use ed25519_dalek::SigningKey;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(key: &SigningKey, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let hex_string = hex::encode(key.as_bytes());
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<SigningKey, D::Error>
    where D: Deserializer<'de> {
        let hex_str: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str).map_err(de::Error::custom)?;
        let bytes =
            bytes.try_into().map_err(|_| de::Error::custom("Verifying key must be 32 bytes"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }
}

#[derive(Serialize, Deserialize)]
struct BlockFull(Block, #[serde(with = "signing_key_serde")] SigningKey);

type CredentialFull = (Credential, SignedCredential, SignedCredential);

#[derive(Serialize, Deserialize)]
struct IssuerFull(Issuer, #[serde(with = "signing_key_serde")] SigningKey);

fn open_block() -> Result<BlockFull, &'static str> {
    let reader = File::open_buffered("block.json").map_err(|_| "Failed to open block file")?;
    let block: Option<BlockFull> =
        serde_json::from_reader(reader).map_err(|_| "Failed to parse block")?;
    block.ok_or("Block is not initialized")
}

fn save_block(block: &BlockFull) -> Result<(), &'static str> {
    let writer = File::create_buffered("block.json").map_err(|_| "Failed to open block file")?;
    serde_json::to_writer(writer, &block).map_err(|_| "Failed to write block")
}

fn open_blockchain() -> Result<Blockchain, &'static str> {
    let reader =
        File::open_buffered("blockchain.json").map_err(|_| "Failed to open blockchain file")?;
    serde_json::from_reader(reader).map_err(|_| "Failed to parse blockchain")
}

fn save_blockchain(blockchain: &Blockchain) -> Result<(), &'static str> {
    let writer =
        File::create_buffered("blockchain.json").map_err(|_| "Failed to open blockchain file")?;
    serde_json::to_writer(writer, &blockchain).map_err(|_| "Failed to write blockchain")
}

fn open_credentials() -> Result<Vec<CredentialFull>, &'static str> {
    let reader =
        File::open_buffered("credentials.json").map_err(|_| "Failed to open credentials file")?;
    serde_json::from_reader(reader).map_err(|_| "Failed to parse credentials")
}

fn save_credentials(credentials: &[CredentialFull]) -> Result<(), &'static str> {
    let writer =
        File::create_buffered("credentials.json").map_err(|_| "Failed to open credentials file")?;
    serde_json::to_writer(writer, &credentials).map_err(|_| "Failed to write credentials")
}

fn open_issuers() -> Result<Vec<IssuerFull>, &'static str> {
    let reader = File::open_buffered("issuers.json").map_err(|_| "Failed to open issuers file")?;
    serde_json::from_reader(reader)
        .inspect_err(|e| println!("{e}"))
        .map_err(|_| "Failed to parse issuers")
}

fn save_issuers(issuers: &[IssuerFull]) -> Result<(), &'static str> {
    let writer =
        File::create_buffered("issuers.json").map_err(|_| "Failed to open issuers file")?;
    serde_json::to_writer(writer, &issuers).map_err(|_| "Failed to write issuers")
}

fn open_subjects() -> Result<Vec<Subject>, &'static str> {
    let reader =
        File::open_buffered("subjects.json").map_err(|_| "Failed to open subjects file")?;
    serde_json::from_reader(reader).map_err(|_| "Failed to parse subjects")
}

fn save_subjects(subjects: &[Subject]) -> Result<(), &'static str> {
    let writer =
        File::create_buffered("subjects.json").map_err(|_| "Failed to open subjects file")?;
    serde_json::to_writer(writer, &subjects).map_err(|_| "Failed to write subjects")
}

#[derive(Parser)]
#[command()]
pub struct Cli {
    #[command(subcommand)]
    subcommand: Subcommands,
}

impl Cli {
    #[expect(clippy::missing_errors_doc)]
    pub fn run(self) -> Result<(), &'static str> { self.subcommand.run() }
}

#[derive(Subcommand)]
enum Subcommands {
    /// Modify currently created block
    Block {
        #[command(subcommand)]
        subcommand: BlockSubcommands,
    },
    /// Initialize or display blockchain, verify credentials
    Blockchain {
        #[command(subcommand)]
        subcommand: BlockchainSubcommands,
    },
    /// Add or list credentials
    Credentials {
        #[command(subcommand)]
        subcommand: CredentialSubcommands,
    },
    /// Add or list issuers
    Issuers {
        #[command(subcommand)]
        subcommand: IssuerSubcommands,
    },
    /// Add or list subjects
    Subjects {
        #[command(subcommand)]
        subcommand: SubjectSubcommands,
    },
}

impl Subcommands {
    fn run(self) -> Result<(), &'static str> {
        match self {
            Self::Block { subcommand } => subcommand.run(),
            Self::Blockchain { subcommand } => subcommand.run(),
            Self::Credentials { subcommand } => subcommand.run(),
            Self::Issuers { subcommand } => subcommand.run(),
            Self::Subjects { subcommand } => subcommand.run(),
        }
    }
}

#[derive(Subcommand)]
enum BlockSubcommands {
    /// Add a credential to a block
    Add { credential: usize },
    /// Display block
    Display,
    /// Finalize block and add to the blockchain
    Finalize,
    /// Create new block
    New { issuer: usize },
    /// Add a credential to the block's revoking list
    Revoke { credential: usize },
}

impl BlockSubcommands {
    fn run(self) -> Result<(), &'static str> {
        match self {
            Self::Add { credential } => Self::add(credential),
            Self::Display => Self::display(),
            Self::Finalize => Self::finalize(),
            Self::New { issuer } => Self::new(issuer),
            Self::Revoke { credential } => Self::revoke(credential),
        }
    }

    fn add(credential: usize) -> Result<(), &'static str> {
        let mut block = open_block()?;
        let mut credentials = open_credentials()?;
        if credential >= credentials.len() {
            return Err("No credential with given index");
        }
        let signed = credentials.swap_remove(credential).1;
        block.0.add_credential(signed, false);
        println!("Added credential to the block");
        save_block(&block)?;
        Ok(())
    }

    fn display() -> Result<(), &'static str> {
        let block = open_block()?.0;
        println!("{block}");
        Ok(())
    }

    fn finalize() -> Result<(), &'static str> {
        let mut blockchain = open_blockchain()?;
        let block = open_block()?;
        blockchain.add_block(block.0, &block.1);
        fs::write("block.json", "null").map_err(|_| "Failed to open block file")?;
        save_blockchain(&blockchain)?;
        println!("Added block to blockchain");
        Ok(())
    }

    #[expect(clippy::new_ret_no_self)]
    fn new(issuer: usize) -> Result<(), &'static str> {
        let mut issuers = open_issuers()?;
        if issuer >= issuers.len() {
            return Err("No issuer with given index");
        }
        let issuer = issuers.swap_remove(issuer);
        let block = BlockFull(Block::new(issuer.0), issuer.1);
        save_block(&block)?;
        println!("Created a new block with a given issuer");
        Ok(())
    }

    fn revoke(credential: usize) -> Result<(), &'static str> {
        let mut block = open_block()?;
        let mut credentials = open_credentials()?;
        if credential >= credentials.len() {
            return Err("No credential with given index");
        }
        let signed = credentials.swap_remove(credential).2;
        block.0.add_credential(signed, true);
        save_block(&block)?;
        println!("Added credential to the block's revoking list");
        Ok(())
    }
}

#[derive(Subcommand)]
enum BlockchainSubcommands {
    /// Display blockchain
    Display,
    /// Initialize blockchain
    Init,
    /// Verify a credential is valid
    Verify { credential: usize },
}

impl BlockchainSubcommands {
    fn run(self) -> Result<(), &'static str> {
        match self {
            Self::Display => Self::display(),
            Self::Init => Self::init(),
            Self::Verify { credential } => Self::verify(credential),
        }
    }

    fn display() -> Result<(), &'static str> {
        let blockchain = open_blockchain()?;
        println!("{blockchain}");
        Ok(())
    }

    fn init() -> Result<(), &'static str> {
        let blockchain = Blockchain::new();
        let mut writer = File::create_buffered("blockchain.json")
            .map_err(|_| "Failed to create blockchain file")?;
        serde_json::to_writer(&mut writer, &blockchain)
            .map_err(|_| "Failed to write blockchain")?;
        fs::write("block.json", "null").map_err(|_| "Failed to create block file")?;
        fs::write("credentials.json", "[]").map_err(|_| "Failed to create credentials file")?;
        fs::write("issuers.json", "[]").map_err(|_| "Failed to create issuers file")?;
        fs::write("subjects.json", "[]").map_err(|_| "Failed to create subject file")?;
        println!("Initialized new blockchain, created all the files");
        Ok(())
    }

    fn verify(credential: usize) -> Result<(), &'static str> {
        let blockchain = open_blockchain()?;
        let credentials = open_credentials()?;
        let credential = &credentials.get(credential).ok_or("No credential with given index")?.0;
        let result = blockchain.check_credential(credential);
        println!("Result: {result}");
        Ok(())
    }
}

#[derive(Subcommand)]
enum CredentialSubcommands {
    /// Add a new credential
    Add(NewCredentialArgs),
    /// List existing credentials
    List,
}

impl CredentialSubcommands {
    fn run(self) -> Result<(), &'static str> {
        match self {
            CredentialSubcommands::Add(args) => args.run(),
            CredentialSubcommands::List => Self::list(),
        }
    }

    fn list() -> Result<(), &'static str> {
        let credentials = open_credentials()?;
        for (i, c) in credentials.into_iter().enumerate() {
            println!("{i}: {}", c.0);
        }
        Ok(())
    }
}

#[derive(Args)]
struct NewCredentialArgs {
    /// Index of the credential's issuer
    issuer: usize,
    /// Index of the credential's subject
    subject: usize,
    /// Name of the attribute
    name: String,
    /// Value of the attribute
    value: String,
    /// Date from which the attribute is valid
    from: NaiveDate,
    /// Date to which the attribute is valid, indefinite if not provided
    to: Option<NaiveDate>,
}

impl NewCredentialArgs {
    fn run(self) -> Result<(), &'static str> {
        let mut issuers = open_issuers()?;
        if self.issuer >= issuers.len() {
            return Err("No issuer with given index");
        }
        let issuer = issuers.swap_remove(self.issuer);
        let mut subjects = open_subjects()?;
        if self.subject >= subjects.len() {
            return Err("No subject with given index");
        }
        let subject = subjects.swap_remove(self.subject);
        let credential = Credential::new(
            Attribute::new(self.name, self.value),
            issuer.0,
            subject,
            ValidDuration::new(self.from, self.to),
        );
        let signed_regular = credential.sign(&issuer.1, false);
        let signed_revoking = credential.sign(&issuer.1, true);
        let mut credentials = open_credentials()?;
        credentials.push((credential, signed_regular, signed_revoking));
        save_credentials(&credentials)?;
        println!("Created new credential");
        Ok(())
    }
}

#[derive(Subcommand)]
enum IssuerSubcommands {
    /// Add a new issuer
    Add { name: String },
    /// Display existing issuers
    List,
}

impl IssuerSubcommands {
    fn run(self) -> Result<(), &'static str> {
        match self {
            Self::Add { name } => Self::add(name),
            Self::List => Self::list(),
        }
    }

    fn add(name: String) -> Result<(), &'static str> {
        let (issuer, key) = Issuer::new(name);
        let mut issuers = open_issuers()?;
        issuers.push(IssuerFull(issuer, key));
        save_issuers(&issuers)?;
        println!("Created new issuer");
        Ok(())
    }

    fn list() -> Result<(), &'static str> {
        let issuers = open_issuers()?;
        for (i, issuer) in issuers.into_iter().enumerate() {
            println!("{i}: {}", issuer.0);
        }
        Ok(())
    }
}

#[derive(Subcommand)]
enum SubjectSubcommands {
    /// Add a new subject
    Add(NewSubjectArgs),
    /// List existing subjects
    List,
}

impl SubjectSubcommands {
    fn run(self) -> Result<(), &'static str> {
        match self {
            Self::Add(args) => args.run(),
            Self::List => Self::list(),
        }
    }

    fn list() -> Result<(), &'static str> {
        let subjects = open_subjects()?;
        for (i, s) in subjects.into_iter().enumerate() {
            println!("{i}: {s}");
        }
        Ok(())
    }
}

#[derive(Args)]
struct NewSubjectArgs {
    name: String,
    surname: String,
}

impl NewSubjectArgs {
    fn run(self) -> Result<(), &'static str> {
        let subject = Subject::new(self.name, self.surname);
        let mut subjects = open_subjects()?;
        subjects.push(subject);
        save_subjects(&subjects)?;
        println!("Created new subject");
        Ok(())
    }
}
