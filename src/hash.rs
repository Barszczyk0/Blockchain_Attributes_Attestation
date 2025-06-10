use ed25519_dalek::Signature;
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
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

#[cfg(test)]
mod tests {
    use ed25519_dalek::{Signer, SigningKey};
    use hex;
    use sha2::{Digest, Sha512};

    use crate::hash::Hash;

    #[test]
    fn test_hash_default_is_zero() {
        let hash = Hash::default();
        assert_eq!(hash.0, [0u8; 64]);
    }

    #[test]
    fn test_hash_from_sha512_output() {
        let mut hasher = Sha512::new();
        hasher.update(b"test data");
        let output = hasher.finalize();
        let hash = Hash::from(output);
        assert_eq!(hash.0, output[..]);
    }

    #[test]
    fn test_hash_from_signature() {
        let key = SigningKey::generate(&mut rand::thread_rng());
        let message = b"hello world";
        let signature = key.sign(message);
        let hash = Hash::from(signature);
        assert_eq!(hash.0, signature.to_bytes());
    }

    #[test]
    fn test_hash_serialization() {
        let original = Hash([1u8; 64]);
        let json = serde_json::to_string(&original).unwrap();
        let expected = format!("\"{}\"", hex::encode([1u8; 64]));
        assert_eq!(json, expected);
    }

    #[test]
    fn test_hash_deserialization() {
        let bytes = [2u8; 64];
        let hex_string = hex::encode(bytes);
        let json = format!("\"{}\"", hex_string);
        let deserialized: Hash = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.0, bytes);
    }

    #[test]
    fn test_hash_deserialization_invalid_length() {
        let short_hex = "\"deadbeef\""; // Too short for 64 bytes
        let result: Result<Hash, _> = serde_json::from_str(short_hex);
        assert!(result.is_err());
    }
}
