use anyhow::Context;
use p256::ecdsa;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::signature::Verifier;
use serde::{Deserialize, Serialize};

use base64::prelude::*;

type Base64Url = String;

#[derive(Serialize, Deserialize, Debug)]
#[serde(untagged)]
pub enum Signature {
    Core {
        algorithm: JwkAlgorithm,
        #[serde(rename = "publicKey")]
        public_key: PublicKey,
        value: Base64Url,
    },
}

#[derive(Serialize, Deserialize, Debug)]
#[serde(tag = "kty")]
pub enum PublicKey {
    #[serde(rename = "EC")]
    EC {
        #[serde(rename = "crv")]
        curve: EllipticCurve,
        x: Base64Url,
        y: Base64Url,
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

#[derive(Serialize, Deserialize, Debug)]
pub enum EllipticCurve {
    #[serde(rename = "P-256")]
    P256,
    // TODO
}

#[derive(Serialize, Deserialize, Debug)]
pub enum JwkAlgorithm {
    ES256,
    // TODO
}

impl std::fmt::Display for JwkAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            JwkAlgorithm::ES256 => write!(f, "ES256"),
        }
    }
}

impl std::fmt::Display for EllipticCurve {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EllipticCurve::P256 => write!(f, "P-256"),
        }
    }
}

pub fn sign_json_object_str(
    input: &str,
    signature_object_key: &str,
    algorithm: JwkAlgorithm,
    private_key_jwk_str: &str,
) -> anyhow::Result<String> {
    let input_value: serde_json::Value =
        serde_json::from_str(input).with_context(|| "failed to parse input")?;

    let serde_json::Value::Object(mut v) = input_value else {
        return Err(anyhow::anyhow!("Expected object"));
    };

    let private_key = p256::SecretKey::from_jwk_str(private_key_jwk_str)
        .with_context(|| "Failed to parse private key")?;
    let partial_signature_object = {
        let p256_public_key = private_key.public_key();
        let public_key =
            PublicKey::try_from(p256_public_key).with_context(|| "failed to convert public key")?;
        match (&algorithm, &public_key) {
            (JwkAlgorithm::ES256, PublicKey::EC { .. }) => {}
            _ => {
                return Err(anyhow::anyhow!(
                    "unsupported combination of algorithm and public key type"
                ))
            }
        }
        let s = Signature::Core {
            algorithm,
            public_key,
            value: "".to_string(), // this is about to be removed before later being added again
        };
        let s_value = serde_json::to_value(&s).with_context(|| "failed to serialize signature")?;
        let serde_json::Value::Object(mut s_object) = s_value else {
            return Err(anyhow::anyhow!("expected object"));
        };
        s_object.remove("value");
        serde_json::Value::Object(s_object)
    };
    let insert_result = v.insert(
        signature_object_key.to_string(),
        partial_signature_object.clone(),
    );
    if insert_result.is_some() {
        return Err(anyhow::anyhow!(
            "failed to insert signature object (signature already present?)"
        ));
    }

    let s = serde_json::to_string(&v).with_context(|| "failed to serialize example")?;

    let signing_key: p256::ecdsa::SigningKey = private_key.into();
    let signature: p256::ecdsa::Signature = signing_key.sign(s.as_bytes());
    let signature_bytes = signature.to_bytes();

    let verifying_key = ecdsa::VerifyingKey::from(signing_key);
    if let Err(e) = verifying_key.verify(s.as_bytes(), &signature) {
        return Err(anyhow::anyhow!(
            "could not verify signature right after creation {e:?}"
        ));
    }

    let sig_value_b64url = BASE64_URL_SAFE_NO_PAD.encode(signature_bytes);

    let serde_json::Value::Object(mut signature) = partial_signature_object else {
        return Err(anyhow::anyhow!("expected object"));
    };
    let insert_result = signature.insert(
        "value".to_string(),
        serde_json::Value::String(sig_value_b64url),
    );
    if insert_result.is_some() {
        return Err(anyhow::anyhow!(
            "failed to insert signature value (already present?)"
        ));
    }
    let insert_result = v.insert(
        signature_object_key.to_string(),
        serde_json::Value::Object(signature),
    );
    if insert_result.is_none() {
        return Err(anyhow::anyhow!(
            "failed to insert signature object (partial signature was missing?)"
        ));
    }

    let signed_object = serde_json::Value::Object(v);

    let signed_object_str = serde_json::to_string(&signed_object)
        .with_context(|| "failed to serialize signed object")?;

    Ok(signed_object_str)
}

#[tracing::instrument(skip(input, signature_object_key))]
pub fn verify_json_object_str(input: &str, signature_object_key: &str) -> anyhow::Result<bool> {
    let input_value: serde_json::Value =
        serde_json::from_str(input).with_context(|| "Failed to parse input")?;

    let serde_json::Value::Object(mut v) = input_value else {
        return Err(anyhow::anyhow!("Expected object"));
    };

    let jsf_signature: Signature = {
        if let Some(signature_value) = v.get_mut(signature_object_key) {
            match signature_value {
                serde_json::Value::Object(signature_obj) => {
                    let signature: Signature =
                        serde_json::from_value(serde_json::Value::Object(signature_obj.clone()))
                            .with_context(|| "Failed to parse signature")?;
                    if signature_obj.remove("value").is_none() {
                        return Err(anyhow::anyhow!(
                            "Expected signature value but removing did nothing"
                        ));
                    }
                    signature
                }
                _ => {
                    return Err(anyhow::anyhow!("Expected string"));
                }
            }
        } else {
            return Err(anyhow::anyhow!("Expected signature"));
        }
    };

    let s = serde_json::to_string(&v).with_context(|| "Failed to serialize example")?;
    tracing::trace!(s, "serialized JSON object");

    match jsf_signature {
        Signature::Core {
            algorithm,
            public_key,
            value,
        } => {
            let jwk_str = serde_json::to_string(&public_key)
                .with_context(|| "Failed to serialize public key")?;
            tracing::debug!("Algorithm: {algorithm}");

            let pk = p256::PublicKey::from_jwk_str(&jwk_str)
                .with_context(|| "Failed to parse public key")?;
            let verify_key = p256::ecdsa::VerifyingKey::from(&pk);

            let sig_value_b64url = &value;
            let sig_vec = BASE64_URL_SAFE_NO_PAD.decode(sig_value_b64url)?;

            let sig = ecdsa::Signature::from_slice(&sig_vec)
                .with_context(|| "Failed to parse signature")?;
            tracing::debug!("parsed signature: {sig}");

            match verify_key.verify(s.as_bytes(), &sig) {
                Ok(()) => Ok(true),
                Err(_) => Ok(false),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sign_and_verify() {
        let input = r#"{"key": "value"}"#;
        let signature_object_key = "signature";
        let algorithm = JwkAlgorithm::ES256;
        let private_key_jwk_str = r#"
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
        }"#;

        let signed_object =
            sign_json_object_str(input, signature_object_key, algorithm, private_key_jwk_str)
                .unwrap();
        println!("have signed object: {signed_object}");

        let good = verify_json_object_str(&signed_object, signature_object_key).unwrap();
        assert!(good, "Signature verification failed");
    }

    #[test]
    fn test_verify_good_signature() {
        let input = r#"{"key":"value","signature":{"algorithm":"ES256","publicKey":{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},"value":"rcwOXiwYpd_BBrFE0BSGYjV3HBzeqeuTAIar8zVVw-Ir0fI8q8JzryU72l0_AZFiu5-hpfcVmBHs6pHFJqL6KA"}}"#;
        let signature_object_key = "signature";

        let good = verify_json_object_str(input, signature_object_key).unwrap();
        assert!(good, "Good signature not correctly verified");
    }

    #[test]
    fn test_verify_bad_signature() {
        let input = r#"{"key":"value","signature":{"algorithm":"ES256","publicKey":{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},"value":"ffffffffff_BBrFE0BSGYjV3HBzeqeuTAIar8zVVw-Ir0fI8q8JzryU72l0_AZFiu5-hpfcVmBHs6pHFJqL6KA"}}"#;
        let signature_object_key = "signature";

        let good = verify_json_object_str(input, signature_object_key).unwrap();
        assert!(
            !good,
            "bad signature not correctly identified as bad in verification"
        );
    }
}
