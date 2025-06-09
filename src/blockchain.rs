use std::fmt;
use std::fmt::{Display, Formatter};

use chrono::{DateTime, Utc};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};

use crate::credential::{Credential, Issuer, SignedCredential};
use crate::hash::Hash;

#[derive(Debug, Serialize, Deserialize)]
pub struct Block {
    timestamp: DateTime<Utc>,
    new_credentials: Vec<SignedCredential>,
    revoked_credentials: Vec<SignedCredential>,
    previous_hash: Hash,
    signer: Issuer,
    hash: Hash,
    signature: Hash,
}

impl Block {
    #[must_use]
    pub fn new(signer: Issuer) -> Self {
        Self {
            timestamp: Utc::now(),
            new_credentials: Vec::new(),
            revoked_credentials: Vec::new(),
            previous_hash: Hash::default(),
            signer,
            hash: Hash::default(),
            signature: Hash::default(),
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
            .for_each(|c| c.update_hash(&mut hasher));
        hasher.update(self.previous_hash.0);
        self.signer.update_hash(&mut hasher);
        self.hash = hasher.finalize().into();
        self.signature = signing.sign(&self.hash.0).into();
    }

    fn find(
        &self, new_hash: &Hash, revoking_hash: &Hash, verifying: &VerifyingKey,
    ) -> (bool, bool) {
        let new = self
            .new_credentials
            .iter()
            .find(|s| &s.credential == new_hash)
            .is_some_and(|c| c.verify(verifying));
        let revoked = self
            .revoked_credentials
            .iter()
            .find(|s| &s.credential == revoking_hash)
            .is_some_and(|c| c.verify(verifying));
        (new, revoked)
    }
}

impl Display for Block {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&serde_json::to_string_pretty(&self).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Blockchain {
    chain: Vec<Block>,
}

impl Default for Blockchain {
    fn default() -> Self { Self::new() }
}

impl Blockchain {
    #[must_use]
    pub fn new() -> Self { Self { chain: Vec::new() } }

    pub fn add_block(&mut self, mut block: Block, signing: &SigningKey) {
        block.finalize(self.chain.last().map_or(Hash::default(), |b| b.hash.clone()), signing);
        self.chain.push(block);
    }

    #[must_use]
    pub fn check_credential(&self, credential: &Credential) -> bool {
        let new_hash = credential.hash(false);
        let revoking_hash = credential.hash(true);
        let mut found = false;
        for b in &self.chain {
            let (f, r) = b.find(&new_hash, &revoking_hash, &credential.issuer.verifying);
            if r {
                return false;
            }
            found |= f;
        }
        found
    }
}

impl Display for Blockchain {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&serde_json::to_string_pretty(&self).unwrap())
    }
}
