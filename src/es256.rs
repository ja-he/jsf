use anyhow::Context;
use anyhow::Result;

use serde::Serialize;

use p256::ecdsa;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::Verifier;

use crate::data;

pub fn sign(bytes: Vec<u8>, key: &PrivateKey) -> Result<Vec<u8>> {
    let signing_key: p256::ecdsa::SigningKey = p256::SecretKey::from_jwk_str(
        &get_simplified_ec_key_jwk_str(key)
            .with_context(|| "unable to get simplified EC key as JWK string")?,
    )
    .with_context(|| "failed to parse private key")?
    .into();
    let signature: p256::ecdsa::Signature = signing_key.sign(&bytes);
    let verifying_key = ecdsa::VerifyingKey::from(signing_key);
    if let Err(e) = verifying_key.verify(&bytes, &signature) {
        return Err(anyhow::anyhow!(
            "could not verify signature right after creation {e:?}"
        ));
    }
    Ok(signature.to_vec())
}

pub fn get_public_key(k: &PrivateKey) -> Result<data::PublicKey> {
    let s = get_simplified_ec_key_jwk_str(k)
        .with_context(|| "unable to get simplified EC key as JWK string")?;
    let private_key =
        p256::SecretKey::from_jwk_str(&s).with_context(|| "failed to parse private key")?;
    let p256_public_key = private_key.public_key();

    let mut pk = data::PublicKey::try_from(p256_public_key)
        .with_context(|| "failed to convert public key")?;
    pk.kid = k.kid.clone();

    Ok(pk)
}

fn get_simplified_ec_key_jwk_str(key: &PrivateKey) -> Result<String> {
    let simplified_ec_key_jwk_str = {
        let serde_json::Value::Object(mut m) = serde_json::to_value(PrivateKey {
            kid: key.kid.clone(),
            kty: key.kty.clone(),
            crv: key.crv.clone(),
            x: key.x.clone(),
            y: key.y.clone(),
            d: key.d.clone(),
        })
        .with_context(|| "could not serialize private key (internal processing)")?
        else {
            return Err(anyhow::anyhow!(
                "did not find a key object (but some other JSON type)",
            ));
        };
        tracing::debug!("got map {:?}", m);
        if key.kid.is_some() {
            m.remove("kid");
        }
        tracing::debug!("have map w/o kid {:?}", m);
        serde_json::to_string(&serde_json::Value::Object(m))
            .with_context(|| "could not serialize simplified private key")?
    };
    Ok(simplified_ec_key_jwk_str)
}

#[derive(Serialize)]
pub struct PrivateKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    pub kty: KtyEC,
    pub crv: CurveP256,

    pub x: data::DataTypeBinaryData,
    pub y: data::DataTypeBinaryData,
    pub d: data::DataTypeBinaryData,
}

impl TryFrom<data::Key> for PrivateKey {
    type Error = anyhow::Error;

    fn try_from(value: data::Key) -> std::result::Result<Self, Self::Error> {
        let (curve, x, y, d) = match value.inner_key {
            data::KeyInner::EllipticCurve {
                curve: data::EcCurveName::P256,
                x,
                y,
                d,
            } => (
                CurveP256::P256,
                x,
                y,
                d.with_context(|| {
                    "The key must provide the parameter 'd' to construct a private key from it."
                })?,
            ),
            data::KeyInner::EllipticCurve { curve, .. } => {
                return Err(anyhow::format_err!(
                    "cannot use a curve of type {curve:?} instead of P256"
                ));
            }
            data::KeyInner::OctetKeyPair { .. } => {
                return Err(anyhow::format_err!("Unable to construct from OKP key."))
            }
            data::KeyInner::Rsa { .. } => {
                return Err(anyhow::format_err!("Unable to construct from RSA key."))
            }
        };

        Ok(PrivateKey {
            kid: value.kid,
            kty: KtyEC::EllipticCurve,
            crv: curve,
            x,
            y,
            d,
        })
    }
}

#[derive(Serialize, Clone, PartialEq, Debug)]
pub enum KtyEC {
    #[serde(rename = "EC")]
    EllipticCurve,
}
#[derive(Serialize, Clone, PartialEq, Debug)]
pub enum CurveP256 {
    #[serde(rename = "P-256")]
    P256,
}

#[derive(Serialize, Debug)]
pub struct PublicKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    pub kty: KtyEC,

    pub crv: CurveP256,

    pub x: data::DataTypeBinaryData,
    pub y: data::DataTypeBinaryData,
}

impl TryFrom<data::Key> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: data::Key) -> std::result::Result<Self, Self::Error> {
        let (curve, x, y) = match value.inner_key {
            data::KeyInner::EllipticCurve {
                curve: data::EcCurveName::P256,
                x,
                y,
                d: None,
            } => (CurveP256::P256, x, y),
            data::KeyInner::EllipticCurve {
                curve: data::EcCurveName::P256,
                d: Some(_),
                ..
            } => {
                return Err(anyhow::format_err!(
                    "refusing to use a key that has secret param 'd' to construct public key"
                ));
            }
            data::KeyInner::EllipticCurve { curve, .. } => {
                return Err(anyhow::format_err!(
                    "cannot use a curve of type {curve:?} instead of P256"
                ));
            }
            data::KeyInner::OctetKeyPair { .. } => {
                return Err(anyhow::format_err!("Unable to construct from OKP key."))
            }
            data::KeyInner::Rsa { .. } => {
                return Err(anyhow::format_err!("Unable to construct from RSA key."))
            }
        };

        Ok(PublicKey {
            kid: value.kid,
            kty: KtyEC::EllipticCurve,
            crv: curve,
            x,
            y,
        })
    }
}

#[tracing::instrument]
pub fn verify_signature(
    signed_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
    public_key: PublicKey,
) -> Result<bool> {
    let jwk_str =
        serde_json::to_string(&public_key).with_context(|| "Failed to serialize public key")?;

    let pk: p256::PublicKey = {
        let key: data::Key = serde_json::from_str(&jwk_str)
            .with_context(|| format!("could not parse private key '{jwk_str}'"))?;

        let kid = key.kid.clone();
        let simplified_str = {
            let serde_json::Value::Object(mut m) = serde_json::to_value(key)
                .with_context(|| "could not serialize key (internal processing)")?
            else {
                return Err(anyhow::anyhow!(
                    "did not find a key object (but some other JSON type)",
                ));
            };
            tracing::debug!("got map {:?}", m);
            if kid.is_some() {
                m.remove("kid");
            }
            tracing::debug!("have map w/o kid {:?}", m);
            serde_json::to_string(&serde_json::Value::Object(m))
                .with_context(|| "could not serialize simplified key")?
        };

        p256::PublicKey::from_jwk_str(&simplified_str)
            .with_context(|| "Failed to parse public key")?
    };

    let verify_key = p256::ecdsa::VerifyingKey::from(&pk);

    let sig = p256::ecdsa::Signature::from_slice(&signature_bytes)
        .with_context(|| "Failed to parse signature")?;
    tracing::debug!("parsed signature: {sig}");

    match verify_key.verify(&signed_bytes, &sig) {
        Ok(()) => Ok(true),
        Err(_) => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_pubkey() {
        let k_prv = PrivateKey {
            kty: KtyEC::EllipticCurve,
            crv: CurveP256::P256,
            x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4".to_string(),
            y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM".to_string(),
            d: "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE".to_string(),
            kid: Some("fo0.bar".to_string()),
        };
        let _k_pub = get_public_key(&k_prv).unwrap();
    }
}
