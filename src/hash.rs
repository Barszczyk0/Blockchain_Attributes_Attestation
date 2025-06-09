use ed25519_dalek::Signature;
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};
use sha2::Sha512;
use sha2::digest::Output;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hash(pub [u8; 64]);

impl Default for Hash {
    fn default() -> Self { Self([0; 64]) }
}

impl From<Signature> for Hash {
    fn from(value: Signature) -> Self { Self(value.to_bytes()) }
}

impl From<Output<Sha512>> for Hash {
    fn from(value: Output<Sha512>) -> Self { Self(value.into()) }
}

impl Serialize for Hash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer {
        serializer.serialize_str(&hex::encode(self.0))
    }
}

impl<'de> Deserialize<'de> for Hash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer<'de> {
        let s: String = Deserialize::deserialize(deserializer)?;
        let bytes = hex::decode(s).map_err(de::Error::custom)?;
        let bytes =
            bytes.try_into().map_err(|_| de::Error::custom("Verifying key must be 32 bytes"))?;
        Ok(Self(bytes))
    }
}
