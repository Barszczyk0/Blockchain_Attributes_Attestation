use chrono::NaiveDate;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use uuid::Uuid;

use super::Hash;

/// Custom serialization for VerifyingKey
mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use hex::{decode, encode};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_string = encode(key.as_bytes());
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: &str = Deserialize::deserialize(deserializer)?;
        let bytes = decode(hex_str).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("VerifyingKey must be 32 bytes"));
        }
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        VerifyingKey::from_bytes(&array).map_err(serde::de::Error::custom)
    }
}

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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Issuer {
    pub uuid: Uuid,
    pub name: String,
    #[serde(with = "verifying_key_serde")]
    pub verifying: VerifyingKey,
}

impl Issuer {
    #[must_use]
    pub fn new(name: String) -> (Self, SigningKey) {
        let signing = SigningKey::generate(&mut rand::thread_rng());
        let verifying = signing.verifying_key();
        let uuid = Uuid::new_v4();
        let issuer = Self {
            uuid,
            name,
            verifying,
        };
        (issuer, signing)
    }

    pub fn hash(&self, hasher: &mut impl Digest) {
        hasher.update(self.uuid);
        hasher.update(&self.name);
        hasher.update(self.verifying);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Subject {
    pub uuid: Uuid,
    pub name: String,
    pub surname: String,
}

impl Subject {
    #[must_use]
    pub fn new(name: String, surname: String) -> Self {
        let uuid = Uuid::new_v4();
        Self {
            uuid,
            name,
            surname,
        }
    }

    fn hash(&self, hasher: &mut impl Digest) {
        hasher.update(self.uuid);
        hasher.update(&self.name);
        hasher.update(&self.surname);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ValidDuration {
    pub from: NaiveDate,
    pub to: Option<NaiveDate>,
}

impl ValidDuration {
    #[must_use]
    pub fn new(from: NaiveDate, to: Option<NaiveDate>) -> Self {
        Self { from, to }
    }

    fn hash(&self, hasher: &mut impl Digest) {
        hasher.update(self.from.format("%Y-%m-%d").to_string());
        if let Some(to) = &self.to {
            hasher.update(to.format("%Y-%m-%d").to_string());
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Attribute {
    pub name: String,
    pub value: String,
    pub description: String,
}

impl Attribute {
    #[must_use]
    pub fn new(name: String, value: String, description: String) -> Self {
        Self {
            name,
            value,
            description,
        }
    }

    fn hash(&self, hasher: &mut impl Digest) {
        hasher.update(&self.name);
        hasher.update(&self.value);
        hasher.update(&self.description);
    }
}

#[derive(Debug, Serialize)]
pub struct Credential {
    pub uuid: Uuid,
    pub attribute: Attribute,
    pub issuer: Issuer,
    pub subject: Subject,
    pub valid_duration: ValidDuration,
}

impl Credential {
    #[must_use]
    pub fn new(
        attribute: Attribute,
        issuer: Issuer,
        subject: Subject,
        valid_duration: ValidDuration,
    ) -> Self {
        let uuid = Uuid::new_v4();
        Self {
            uuid,
            attribute,
            issuer,
            subject,
            valid_duration,
        }
    }

    #[must_use]
    pub fn hash(&self, revoking: bool) -> Hash {
        let mut hasher = Sha512::new();
        hasher.update(self.uuid);
        self.attribute.hash(&mut hasher);
        self.issuer.hash(&mut hasher);
        self.subject.hash(&mut hasher);
        self.valid_duration.hash(&mut hasher);
        if revoking {
            hasher.update("revoking");
        }
        hasher.finalize().into()
    }

    pub fn sign(&mut self, signer: &impl Signer<Signature>, revoking: bool) -> SignedCredential {
        let hash = self.hash(revoking);
        let signature = signer.sign(&hash).into();
        SignedCredential::new(hash, signature)
    }

    pub fn print_json(&self) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => println!("Credential:\n{}\n", json),
            Err(e) => eprintln!("Error serializing credential to JSON: {}", e),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedCredential {
    #[serde(with = "hash_serde")]
    pub credential: Hash,
    #[serde(with = "hash_serde")]
    pub signature: Hash,
}

impl SignedCredential {
    #[must_use]
    pub fn new(credential: Hash, signature: Hash) -> Self {
        Self {
            credential,
            signature,
        }
    }

    #[must_use]
    pub fn verify(&self, verifying: &VerifyingKey) -> bool {
        verifying
            .verify(&self.credential, &Signature::from_bytes(&self.signature))
            .is_ok()
    }

    pub fn hash_credential(&self, hasher: &mut impl Digest) {
        hasher.update(self.credential);
        hasher.update(self.signature);
    }
}
