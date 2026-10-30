//! Строгая проверка подписанных метаданных выпусков r2o и архивов выпуска.

pub mod config;

use base64::Engine as _;
use ring::signature::{ED25519, UnparsedPublicKey};
use serde::de::{MapAccess, Visitor};
use serde::{Deserialize, Deserializer};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::io::{self, Read};

pub const MANIFEST_MAX_BYTES: usize = 64 * 1024;
pub const SIGNATURE_BYTES: usize = 64;
pub const PUBLIC_KEY_BYTES: usize = 32;
const DER_ED25519_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseManifest {
    pub release_id: String,
    pub version: String,
    pub notes: String,
    pub assets: BTreeMap<String, ReleaseAsset>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReleaseAsset {
    pub sha256: String,
}

#[derive(Debug)]
pub enum VerifyError {
    Io(io::Error),
    ManifestTooLarge,
    InvalidManifest(String),
    InvalidSignature,
    InvalidPublicKey,
    UnknownArchitecture(String),
    InvalidDigest,
    ArchiveDigestMismatch { expected: String, actual: String },
}

impl fmt::Display for VerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(f, "I/O error: {error}"),
            Self::ManifestTooLarge => {
                write!(f, "release manifest exceeds {MANIFEST_MAX_BYTES} bytes")
            }
            Self::InvalidManifest(reason) => write!(f, "invalid release manifest: {reason}"),
            Self::InvalidSignature => write!(f, "release manifest signature does not match"),
            Self::InvalidPublicKey => write!(
                f,
                "expected a 32-byte Ed25519 public key, hex key, or Ed25519 PEM"
            ),
            Self::UnknownArchitecture(arch) => {
                write!(f, "release has no asset for architecture {arch:?}")
            }
            Self::InvalidDigest => write!(f, "release asset must have a lowercase SHA-256 digest"),
            Self::ArchiveDigestMismatch { expected, actual } => {
                write!(
                    f,
                    "archive SHA-256 mismatch: expected {expected}, got {actual}"
                )
            }
        }
    }
}

impl std::error::Error for VerifyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<io::Error> for VerifyError {
    fn from(value: io::Error) -> Self {
        Self::Io(value)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawManifest {
    release_id: String,
    version: String,
    notes: String,
    assets: UniqueAssets,
}

struct UniqueAssets(BTreeMap<String, RawAsset>);

impl<'de> Deserialize<'de> for UniqueAssets {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct UniqueAssetsVisitor;

        impl<'de> Visitor<'de> for UniqueAssetsVisitor {
            type Value = UniqueAssets;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("an object with unique architecture keys")
            }

            fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
            where
                M: MapAccess<'de>,
            {
                let mut assets = BTreeMap::new();
                while let Some((architecture, asset)) = map.next_entry::<String, RawAsset>()? {
                    if assets.insert(architecture, asset).is_some() {
                        return Err(serde::de::Error::custom("duplicate architecture key"));
                    }
                }
                Ok(UniqueAssets(assets))
            }
        }

        deserializer.deserialize_map(UniqueAssetsVisitor)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAsset {
    sha256: String,
}

/// Сначала проверить точные байты манифеста, затем разобрать их. Производные
/// структуры отклоняют повторяющиеся поля, а `deny_unknown_fields` фиксирует
/// состав подписанной схемы.
pub fn verify_manifest(
    manifest_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<ReleaseManifest, VerifyError> {
    if manifest_bytes.len() > MANIFEST_MAX_BYTES {
        return Err(VerifyError::ManifestTooLarge);
    }
    if signature.len() != SIGNATURE_BYTES {
        return Err(VerifyError::InvalidSignature);
    }
    let key = decode_public_key(public_key)?;
    UnparsedPublicKey::new(&ED25519, key)
        .verify(manifest_bytes, signature)
        .map_err(|_| VerifyError::InvalidSignature)?;

    let raw: RawManifest = serde_json::from_slice(manifest_bytes)
        .map_err(|error| VerifyError::InvalidManifest(error.to_string()))?;
    validate_token(&raw.release_id, "release_id", 128)?;
    if raw.version.is_empty() || raw.version.len() > 128 || raw.version.contains('\0') {
        return Err(VerifyError::InvalidManifest("invalid version".into()));
    }
    if raw.notes.len() > 4096 || raw.notes.contains('\0') {
        return Err(VerifyError::InvalidManifest(
            "notes exceed 4096 bytes or contain NUL".into(),
        ));
    }
    if raw.assets.0.is_empty() || raw.assets.0.len() > 64 {
        return Err(VerifyError::InvalidManifest(
            "assets must contain 1 to 64 architectures".into(),
        ));
    }

    let mut assets = BTreeMap::new();
    for (arch, asset) in raw.assets.0 {
        validate_token(&arch, "architecture", 32)?;
        if asset.sha256.len() != 64
            || !asset
                .sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(VerifyError::InvalidDigest);
        }
        assets.insert(
            arch,
            ReleaseAsset {
                sha256: asset.sha256,
            },
        );
    }

    Ok(ReleaseManifest {
        release_id: raw.release_id,
        version: raw.version,
        notes: raw.notes,
        assets,
    })
}

/// Вычислить хеш архива потоком и сравнить его с подписанным значением.
pub fn verify_archive<R: Read>(reader: &mut R, expected: &str) -> Result<String, VerifyError> {
    if expected.len() != 64
        || !expected
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(VerifyError::InvalidDigest);
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 32 * 1024];
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    let actual = to_hex(&hasher.finalize());
    if actual != expected {
        return Err(VerifyError::ArchiveDigestMismatch {
            expected: expected.to_owned(),
            actual,
        });
    }
    Ok(actual)
}

pub fn verify_release_archive<R: Read>(
    manifest_bytes: &[u8],
    signature: &[u8],
    public_key: &[u8],
    architecture: &str,
    archive: &mut R,
) -> Result<(ReleaseManifest, String), VerifyError> {
    let manifest = verify_manifest(manifest_bytes, signature, public_key)?;
    let asset = manifest
        .assets
        .get(architecture)
        .ok_or_else(|| VerifyError::UnknownArchitecture(architecture.to_owned()))?;
    let digest = verify_archive(archive, &asset.sha256)?;
    Ok((manifest, digest))
}

mod install;
mod update;

pub use install::{
    InstallError, InstallSlots, activate_bundle, active_component_path, install_archive,
    read_install_architecture, read_install_slots, rollback,
};
pub use update::{
    UpdateError, check_update, install_update, install_update_auto, mark_bad_previous_release,
    set_auto_update,
};

/// Принять сырые байты Ed25519, 64 шестнадцатеричных символа или PEM Ed25519 SPKI.
pub fn decode_public_key(encoded: &[u8]) -> Result<[u8; PUBLIC_KEY_BYTES], VerifyError> {
    if encoded.len() == PUBLIC_KEY_BYTES {
        return encoded
            .try_into()
            .map_err(|_| VerifyError::InvalidPublicKey);
    }
    let trimmed = trim_ascii(encoded);
    if trimmed.len() == PUBLIC_KEY_BYTES * 2 && trimmed.iter().all(u8::is_ascii_hexdigit) {
        let mut key = [0; PUBLIC_KEY_BYTES];
        let (pairs, _) = trimmed.as_chunks::<2>();
        for (index, pair) in pairs.iter().enumerate() {
            key[index] = (hex_nibble(pair[0])? << 4) | hex_nibble(pair[1])?;
        }
        return Ok(key);
    }

    let pem = std::str::from_utf8(trimmed).map_err(|_| VerifyError::InvalidPublicKey)?;
    let body = pem
        .strip_prefix("-----BEGIN PUBLIC KEY-----")
        .and_then(|value| value.strip_suffix("-----END PUBLIC KEY-----"))
        .ok_or(VerifyError::InvalidPublicKey)?;
    let body: String = body
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let der = base64::engine::general_purpose::STANDARD
        .decode(body)
        .map_err(|_| VerifyError::InvalidPublicKey)?;
    if der.len() != DER_ED25519_PREFIX.len() + PUBLIC_KEY_BYTES
        || der[..DER_ED25519_PREFIX.len()] != DER_ED25519_PREFIX
    {
        return Err(VerifyError::InvalidPublicKey);
    }
    der[DER_ED25519_PREFIX.len()..]
        .try_into()
        .map_err(|_| VerifyError::InvalidPublicKey)
}

fn validate_token(value: &str, name: &str, max_len: usize) -> Result<(), VerifyError> {
    if value.is_empty()
        || value.len() > max_len
        || !value.as_bytes()[0].is_ascii_alphanumeric()
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        return Err(VerifyError::InvalidManifest(format!("invalid {name}")));
    }
    Ok(())
}

fn trim_ascii(mut input: &[u8]) -> &[u8] {
    while input.first().is_some_and(u8::is_ascii_whitespace) {
        input = &input[1..];
    }
    while input.last().is_some_and(u8::is_ascii_whitespace) {
        input = &input[..input.len() - 1];
    }
    input
}

fn hex_nibble(byte: u8) -> Result<u8, VerifyError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(VerifyError::InvalidPublicKey),
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair};
    use std::io::Cursor;

    fn signed_manifest(archive: &[u8]) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap();
        let digest = to_hex(&Sha256::digest(archive));
        let manifest = format!(
            r#"{{"release_id":"r2o-20261018","version":"0.1.0","notes":"test","assets":{{"mipsel":{{"sha256":"{digest}"}}}}}}"#
        )
        .into_bytes();
        let signature = key_pair.sign(&manifest).as_ref().to_vec();
        let public_key = key_pair.public_key().as_ref().to_vec();
        (manifest, signature, public_key)
    }

    #[test]
    fn verifies_signed_manifest_and_archive() {
        let archive = b"release archive";
        let (manifest_bytes, signature, public_key) = signed_manifest(archive);
        let (manifest, digest) = verify_release_archive(
            &manifest_bytes,
            &signature,
            &public_key,
            "mipsel",
            &mut Cursor::new(archive),
        )
        .unwrap();
        assert_eq!(manifest.release_id, "r2o-20261018");
        assert_eq!(digest, to_hex(&Sha256::digest(archive)));
    }

    #[test]
    fn rejects_signature_or_archive_tampering() {
        let archive = b"release archive";
        let (manifest, mut signature, public_key) = signed_manifest(archive);
        signature[0] ^= 1;
        assert!(matches!(
            verify_manifest(&manifest, &signature, &public_key),
            Err(VerifyError::InvalidSignature)
        ));

        let (manifest, signature, public_key) = signed_manifest(archive);
        assert!(matches!(
            verify_release_archive(
                &manifest,
                &signature,
                &public_key,
                "mipsel",
                &mut Cursor::new(b"modified archive"),
            ),
            Err(VerifyError::ArchiveDigestMismatch { .. })
        ));
    }

    #[test]
    fn rejects_duplicate_unknown_and_unsafe_fields() {
        let key_pair = test_key_pair();
        let duplicate = br#"{"release_id":"r2o-good","release_id":"r2o-other","version":"1","notes":"","assets":{"x":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#;
        let duplicate_signature = key_pair.sign(duplicate).as_ref().to_vec();
        assert!(matches!(
            verify_manifest(
                duplicate,
                &duplicate_signature,
                key_pair.public_key().as_ref()
            ),
            Err(VerifyError::InvalidManifest(_))
        ));

        let unsafe_path = br#"{"release_id":"../bad","version":"1","notes":"","assets":{"x":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#;
        let unsafe_signature = key_pair.sign(unsafe_path).as_ref().to_vec();
        assert!(matches!(
            verify_manifest(
                unsafe_path,
                &unsafe_signature,
                key_pair.public_key().as_ref()
            ),
            Err(VerifyError::InvalidManifest(_))
        ));

        let unknown = br#"{"release_id":"r2o-good","version":"1","notes":"","extra":true,"assets":{"x":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}}"#;
        let unknown_signature = key_pair.sign(unknown).as_ref().to_vec();
        assert!(matches!(
            verify_manifest(unknown, &unknown_signature, key_pair.public_key().as_ref()),
            Err(VerifyError::InvalidManifest(_))
        ));

        let duplicate_architecture = br#"{"release_id":"r2o-good","version":"1","notes":"","assets":{"mipsel":{"sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},"mipsel":{"sha256":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}}"#;
        let duplicate_arch_signature = key_pair.sign(duplicate_architecture).as_ref().to_vec();
        assert!(matches!(
            verify_manifest(
                duplicate_architecture,
                &duplicate_arch_signature,
                key_pair.public_key().as_ref()
            ),
            Err(VerifyError::InvalidManifest(_))
        ));
    }

    #[test]
    fn parses_hex_and_pem_keys() {
        let (_, _, public_key) = signed_manifest(b"x");
        let hex = to_hex(&public_key);
        assert_eq!(
            decode_public_key(hex.as_bytes()).unwrap().as_slice(),
            public_key
        );
        let mut der = DER_ED25519_PREFIX.to_vec();
        der.extend_from_slice(&public_key);
        let pem = format!(
            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        );
        assert_eq!(
            decode_public_key(pem.as_bytes()).unwrap().as_slice(),
            public_key
        );
    }

    fn test_key_pair() -> Ed25519KeyPair {
        let rng = SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).unwrap();
        Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).unwrap()
    }
}
