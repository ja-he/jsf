use anyhow::Context;
use serde::{Deserialize, Serialize};

pub type Base64Url = String;

/// Base64URL-encoded [RFC4648] binary data.
pub type DataTypeBinaryData = Base64Url;

/// Base64URL-encoded positive integer with arbitrary precision. Note that the value must not contain leading zero-valued bytes.
pub type DataTypeCrypto = Base64Url;

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Signature {
    Core {
        algorithm: SignatureAlgorithm,
        #[serde(rename = "publicKey")]
        public_key: PublicKey,
        value: Base64Url,
    },
}

pub type PublicKey = Key;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Key {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(flatten)]
    pub inner_key: KeyInner,
}

/// Key type indicator. Currently the following types are recognized:
///
///  - EC     See: [Additional EC Properties](https://cyberphone.github.io/doc/security/jsf.html#Additional_EC_Properties)
///  - OKP    See: [Additional OKP Properties](https://cyberphone.github.io/doc/security/jsf.html#Additional_OKP_Properties)
///  - RSA    See: [Additional RSA Properties](https://cyberphone.github.io/doc/security/jsf.html#Additional_RSA_Properties)
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
#[serde(tag = "kty")]
pub enum KeyInner {
    /// Elliptic Curve (EC)
    #[serde(rename = "EC")]
    EllipticCurve {
        /// EC curve name.
        #[serde(rename = "crv")]
        curve: EcCurveName,

        /// EC curve point X.
        /// The length of this field must be the full size of a coordinate for the curve specified in the "crv" parameter.
        /// For example, if the value of "crv" is "P-521", the decoded argument must be 66 bytes.
        x: DataTypeBinaryData,

        /// EC curve point Y.
        /// The length of this field must be the full size of a coordinate for the curve specified in the "crv" parameter.
        /// For example, if the value of "crv" is "P-256", the decoded argument must be 32 bytes.
        y: DataTypeBinaryData,

        #[serde(skip_serializing_if = "Option::is_none")]
        d: Option<DataTypeBinaryData>,
    },

    /// Octet Key Pair (OKP)
    #[serde(rename = "OKP")]
    OctetKeyPair {
        /// EdDSA curve name.
        #[serde(rename = "crv")]
        curve: EdDsaCurveName,

        /// EdDSA curve point X.
        /// The length of this field must be the full size of a coordinate for the curve specified in the "crv" parameter.
        /// For example, if the value of "crv" is "Ed25519", the decoded argument must be 32 bytes.
        x: DataTypeBinaryData,
    },

    /// RSA
    Rsa {
        /// RSA modulus. (aka `n`)
        #[serde(rename = "n")]
        modulus: DataTypeCrypto,

        /// RSA exponent. (aka `e`)
        #[serde(rename = "e")]
        exponent: DataTypeCrypto,
    },
}

impl TryFrom<p256::PublicKey> for PublicKey {
    type Error = anyhow::Error;
    fn try_from(value: p256::PublicKey) -> anyhow::Result<Self> {
        let jwk_str = value.to_jwk_string();
        let jwk: PublicKey = serde_json::from_str(&jwk_str)
            .with_context(|| "failed to parse JWK created from value")?;
        Ok(jwk)
    }
}

/// EC curve name. The currently recognized EC curves include:
///
///  - P-256
///  - P-384
///  - P-521
///
/// Note: If proprietary curve names are added, they must be expressed as URIs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum EcCurveName {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
}

/// EdDSA curve name. The currently recognized EdDSA curves include:
///
///  - Ed25519
///  - Ed448
///
/// Note: If proprietary curve names are added, they must be expressed as URIs.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub enum EdDsaCurveName {
    Ed25519,
    Ed448,
}

/// Signature algorithm. The currently recognized JWA [RFC7518] and RFC8037 [RFC8037] asymmetric key algorithms include:
///
///  - RS256
///  - RS384
///  - RS512
///  - PS256
///  - PS384
///  - PS512
///  - ES256
///  - ES384
///  - ES512
///  - Ed25519
///  - Ed448
///
/// Note: Unlike RFC8037 [RFC8037] JSF requires explicit Ed* algorithm names instead of "EdDSA".
/// The currently recognized JWA [RFC7518] symmetric key algorithms include:
///
///  - HS256
///  - HS384
///  - HS512
///
/// Note: If proprietary signature algorithms are added, they must be expressed as URIs.
/// JWS counterpart: "alg".
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum SignatureAlgorithm {
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    ES256,
    ES384,
    ES512,
    Ed25519,
    Ed448,
    HS256,
    HS384,
    HS512,
}

impl std::fmt::Display for SignatureAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SignatureAlgorithm::RS256 => write!(f, "RS256"),
            SignatureAlgorithm::RS384 => write!(f, "RS384"),
            SignatureAlgorithm::RS512 => write!(f, "RS512"),
            SignatureAlgorithm::PS256 => write!(f, "PS256"),
            SignatureAlgorithm::PS384 => write!(f, "PS384"),
            SignatureAlgorithm::PS512 => write!(f, "PS512"),
            SignatureAlgorithm::ES256 => write!(f, "ES256"),
            SignatureAlgorithm::ES384 => write!(f, "ES384"),
            SignatureAlgorithm::ES512 => write!(f, "ES512"),
            SignatureAlgorithm::Ed25519 => write!(f, "Ed25519"),
            SignatureAlgorithm::Ed448 => write!(f, "Ed448"),
            SignatureAlgorithm::HS256 => write!(f, "HS256"),
            SignatureAlgorithm::HS384 => write!(f, "HS384"),
            SignatureAlgorithm::HS512 => write!(f, "HS512"),
        }
    }
}

impl std::fmt::Display for EcCurveName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EcCurveName::P256 => write!(f, "P-256"),
            EcCurveName::P384 => write!(f, "P-384"),
            EcCurveName::P521 => write!(f, "P-521"),
        }
    }
}

impl std::fmt::Display for EdDsaCurveName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EdDsaCurveName::Ed25519 => write!(f, "Ed25519"),
            EdDsaCurveName::Ed448 => write!(f, "Ed448"),
        }
    }
}
