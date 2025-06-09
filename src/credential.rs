use std::fmt;
use std::fmt::{Display, Formatter};

use chrono::NaiveDate;
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha512};
use uuid::Uuid;

use crate::hash::Hash;

/// Custom serialization for `VerifyingKey`
mod verifying_key_serde {
    use ed25519_dalek::VerifyingKey;
    use serde::{Deserialize, Deserializer, Serializer, de};

    pub fn serialize<S>(key: &VerifyingKey, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        let hex_string = hex::encode(key.as_bytes());
        serializer.serialize_str(&hex_string)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
    where D: Deserializer<'de> {
        let hex_str: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(hex_str).map_err(de::Error::custom)?;
        let bytes =
            bytes.try_into().map_err(|_| de::Error::custom("Verifying key must be 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes).map_err(de::Error::custom)
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
        let issuer = Self { uuid, name, verifying };
        (issuer, signing)
    }

    pub fn update_hash(&self, hasher: &mut impl Digest) {
        hasher.update(self.uuid);
        hasher.update(&self.name);
        hasher.update(self.verifying);
    }
}

impl Display for Issuer {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&serde_json::to_string_pretty(self).unwrap())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subject {
    pub uuid: Uuid,
    pub name: String,
    pub surname: String,
}

impl Subject {
    #[must_use]
    pub fn new(name: String, surname: String) -> Self {
        let uuid = Uuid::new_v4();
        Self { uuid, name, surname }
    }

    fn hash(&self, hasher: &mut impl Digest) {
        hasher.update(self.uuid);
        hasher.update(&self.name);
        hasher.update(&self.surname);
    }
}

impl Display for Subject {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&serde_json::to_string_pretty(self).unwrap())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidDuration {
    pub from: NaiveDate,
    pub to: Option<NaiveDate>,
}

impl ValidDuration {
    #[must_use]
    pub fn new(from: NaiveDate, to: Option<NaiveDate>) -> Self { Self { from, to } }

    fn hash(&self, hasher: &mut impl Digest) {
        hasher.update(self.from.format("%Y-%m-%d").to_string());
        if let Some(to) = &self.to {
            hasher.update(to.format("%Y-%m-%d").to_string());
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attribute {
    pub name: String,
    pub value: String,
}

impl Attribute {
    #[must_use]
    pub fn new(name: String, value: String) -> Self { Self { name, value } }

    fn hash(&self, hasher: &mut impl Digest) {
        hasher.update(&self.name);
        hasher.update(&self.value);
    }
}

#[derive(Debug, Serialize, Deserialize)]
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
        attribute: Attribute, issuer: Issuer, subject: Subject, valid_duration: ValidDuration,
    ) -> Self {
        let uuid = Uuid::new_v4();
        Self { uuid, attribute, issuer, subject, valid_duration }
    }

    #[must_use]
    pub fn hash(&self, revoking: bool) -> Hash {
        let mut hasher = Sha512::new();
        hasher.update(self.uuid);
        self.attribute.hash(&mut hasher);
        self.issuer.update_hash(&mut hasher);
        self.subject.hash(&mut hasher);
        self.valid_duration.hash(&mut hasher);
        if revoking {
            hasher.update("revoking");
        }
        hasher.finalize().into()
    }

    #[must_use]
    pub fn sign(&self, signer: &SigningKey, revoking: bool) -> SignedCredential {
        let hash = self.hash(revoking);
        let signature = signer.sign(&hash.0).into();
        SignedCredential::new(hash, signature)
    }
}

impl Display for Credential {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&serde_json::to_string_pretty(self).unwrap())
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedCredential {
    pub credential: Hash,
    pub signature: Hash,
}

impl SignedCredential {
    #[must_use]
    pub fn new(credential: Hash, signature: Hash) -> Self { Self { credential, signature } }

    #[must_use]
    pub fn verify(&self, verifying: &VerifyingKey) -> bool {
        verifying.verify(&self.credential.0, &Signature::from_bytes(&self.signature.0)).is_ok()
    }

    pub fn update_hash(&self, hasher: &mut impl Digest) {
        hasher.update(self.credential.0);
        hasher.update(self.signature.0);
    }
}
