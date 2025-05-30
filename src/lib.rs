use anyhow::Context;

mod data;
mod es256;
mod es384;

use base64::prelude::*;

#[derive(Debug)]
pub struct SignatureCreationOptions {
    pub include_key_id: bool,
    pub include_public_key: KeyInclusionOptions,
    pub excludes: Vec<String>,
}
#[derive(Debug)]
pub enum KeyInclusionOptions {
    Omit,
    Include { include_kid: bool },
}

#[tracing::instrument(skip(
    input,
    private_key,
    signature_object_key,
    algorithm,
    signature_options
))]
pub fn sign_serde_json_object(
    input: serde_json::Value,
    signature_object_key: &str,
    algorithm: data::SignatureAlgorithm,
    private_key: data::Key,
    signature_options: SignatureCreationOptions,
) -> anyhow::Result<serde_json::Value> {
    let serde_json::Value::Object(mut v) = input else {
        return Err(anyhow::anyhow!("expected object but got {input:?}"));
    };

    // 1. get the public key from the private (key type)
    let public_key = match &private_key.inner_key {
        data::KeyInner::EllipticCurve { .. } => {
            es256::get_public_key(&private_key.clone().try_into().with_context(|| "")?)
                .with_context(|| "unable to get public key from given private key")?
        }

        data::KeyInner::OctetKeyPair { .. } => todo!("unimplemented"),

        data::KeyInner::Rsa { .. } => todo!("unimplemented"),
    };
    let maybe_public_key = {
        match signature_options.include_public_key {
            KeyInclusionOptions::Omit => None,
            KeyInclusionOptions::Include { include_kid } => {
                if include_kid {
                    if public_key.kid.is_none() {
                        return Err(anyhow::format_err!("unable to include kid in public key object as the private key specifies no kid"));
                    }
                    Some(public_key.clone())
                } else {
                    let mut pk_for_sig = public_key.clone();
                    pk_for_sig.kid = None;
                    Some(pk_for_sig)
                }
            }
        }
    };

    let maybe_key_id = match (signature_options.include_key_id, &public_key.kid) {
        (true, Some(key_id)) => Some(key_id.clone()),
        (false, _) => None,
        (true, None) => {
            return Err(anyhow::format_err!(
                "unable to include key ID (as instructed) since no key ID is available"
            ))
        }
    };

    // 2. construct the (unsigned) signature object (public key, algorithm)
    let partial_signature_object = {
        let s = data::Signature {
            excludes: signature_options.excludes.clone(),
            inner: data::InnerSignature::Core {
                algorithm,
                key_id: maybe_key_id,
                public_key: maybe_public_key,
                value: "".to_string(), // this is about to be removed before later being added again
            },
        };
        let s_value = serde_json::to_value(&s).with_context(|| "failed to serialize signature")?;
        let serde_json::Value::Object(mut s_object) = s_value else {
            return Err(anyhow::anyhow!("expected object"));
        };
        s_object.remove("value");
        serde_json::Value::Object(s_object)
    };

    // 3. insert signature object into input json object (--)
    let insert_result = v.insert(
        signature_object_key.to_string(),
        partial_signature_object.clone(),
    );
    if insert_result.is_some() {
        return Err(anyhow::anyhow!(
            "failed to insert signature object (signature already present?)"
        ));
    }

    // 3a. apply excludes
    for exclude_key in &signature_options.excludes {
        v.remove(exclude_key);
    }

    // 4. create a canonical serialization (JCS)
    let signed_object_canonically_serialized = serde_json::to_vec(&v).with_context(|| {
        "failed to serialize input with added partial signature (should not happen?)"
    })?;

    // 5. sign bytes with key (input, algorithm, private key)
    let signature_bytes = sign(signed_object_canonically_serialized, private_key)
        .with_context(|| "unable to sign")?;

    // 6. insert signature value into signed object
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

    // 7. that's it
    Ok(signed_object)
}

#[tracing::instrument(skip(
    input,
    signature_object_key,
    algorithm,
    private_key_jwk_str,
    signature_options
))]
pub fn sign_json_object_str(
    input: &str,
    signature_object_key: &str,
    algorithm: data::SignatureAlgorithm,
    private_key_jwk_str: &str,
    signature_options: SignatureCreationOptions,
) -> anyhow::Result<String> {
    let input_value: serde_json::Value =
        serde_json::from_str(input).with_context(|| "failed to parse input")?;

    let private_key_jwk: data::Key = serde_json::from_str(private_key_jwk_str)
        .with_context(|| format!("could not parse private key '{private_key_jwk_str}'"))?;

    let signed_object = sign_serde_json_object(
        input_value,
        signature_object_key,
        algorithm,
        private_key_jwk,
        signature_options,
    )
    .with_context(|| "unable to sign serde_json value")?;

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

    let jsf_signature: data::Signature = {
        if let Some(signature_value) = v.get_mut(signature_object_key) {
            match signature_value {
                serde_json::Value::Object(signature_obj) => {
                    let signature: data::Signature =
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
    for exclude_key in &jsf_signature.excludes {
        let remove_result = v.remove(exclude_key);
        match remove_result {
            Some(val) => tracing::debug!("removed property '{exclude_key}'({val:?})."),
            None => tracing::debug!("tried to remove property '{exclude_key}' but not found."),
        }
    }

    let signed_bytes = serde_json::to_vec(&v).with_context(|| "Failed to serialize example")?;

    match jsf_signature.inner {
        data::InnerSignature::Core {
            algorithm,
            key_id: _,
            public_key: Some(public_key),
            value,
        } => match (&algorithm, &public_key.inner_key) {
            (data::SignatureAlgorithm::ES256, data::KeyInner::EllipticCurve { .. }) => {
                let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(value)?;
                let p256_key: es256::PublicKey = public_key
                    .try_into()
                    .with_context(|| "unable to use public key as P256 key")?;
                es256::verify_signature(signed_bytes, signature_bytes, p256_key)
            }

            (data::SignatureAlgorithm::ES256, _non_ec_key) => {
                Err(anyhow::format_err!("invalid (non-EC) key given for ES256"))
            }

            (data::SignatureAlgorithm::ES384, data::KeyInner::EllipticCurve { .. }) => {
                let signature_bytes = BASE64_URL_SAFE_NO_PAD.decode(value)?;
                let p384_key: es384::PublicKey = public_key
                    .try_into()
                    .with_context(|| "unable to use public key as P384 key")?;
                es384::verify_signature(signed_bytes, signature_bytes, p384_key)
            }

            (other_algorithm, _) => todo!("currently no support for {other_algorithm:?}"),
        },
        data::InnerSignature::Core {
            algorithm: _,
            key_id: _,
            public_key: None,
            value: _,
        } => {
            // TODO: this is kind of an API question that I do not want to tackle right now.
            todo!("Have to figure out how to deal with only having Key ID and no actual key info.")
        }
    }
}

fn sign(bytes: Vec<u8>, private_key: data::Key) -> anyhow::Result<Vec<u8>> {
    match private_key.inner_key {
        data::KeyInner::EllipticCurve { .. } => es256::sign(
            bytes,
            &private_key
                .try_into()
                .with_context(|| "unable to convert private key into EC key")?,
        ),
        data::KeyInner::OctetKeyPair { .. } => todo!(),
        data::KeyInner::Rsa { .. } => todo!(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // TODO: maybe drop this?
    const DEFAULT_SIGNATURE_CREATION_OPTIONS: SignatureCreationOptions = SignatureCreationOptions {
        include_key_id: false,
        include_public_key: KeyInclusionOptions::Include { include_kid: false },
        excludes: vec![],
    };

    #[test]
    fn test_sign_and_verify_str() {
        let input = r#"{"key": "value"}"#;
        let signature_object_key = "signature";
        let algorithm = data::SignatureAlgorithm::ES256;
        let private_key_jwk_str = r#"
        {
            "kty": "EC",
            "crv": "P-256",
            "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
            "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
            "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
        }"#;

        let signed_object = sign_json_object_str(
            input,
            signature_object_key,
            algorithm,
            private_key_jwk_str,
            DEFAULT_SIGNATURE_CREATION_OPTIONS,
        )
        .unwrap();
        println!("have signed object: {signed_object}");

        let good = verify_json_object_str(&signed_object, signature_object_key).unwrap();
        assert!(good, "Signature verification failed");
    }

    #[test]
    fn test_sign_and_verify_obj() {
        let input = serde_json::json!({"key": "value"});
        let signature_object_key = "signature";
        let algorithm = data::SignatureAlgorithm::ES256;
        let private_key: data::Key = serde_json::from_str(
            r#"{
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                  "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
                }"#,
        )
        .unwrap();

        let signed_object = sign_serde_json_object(
            input,
            signature_object_key,
            algorithm,
            private_key,
            DEFAULT_SIGNATURE_CREATION_OPTIONS,
        )
        .unwrap();
        println!("have signed object: {signed_object}");

        // let good = verify_json_object_str(&signed_object, signature_object_key).unwrap();
        // assert!(good, "Signature verification failed");
    }

    #[test]
    fn test_sign_and_verify_with_excludes() {
        let input = serde_json::json!({"key": "value", "key2": 42});
        let signature_object_key = "signature";
        let algorithm = data::SignatureAlgorithm::ES256;
        let private_key: data::Key = serde_json::from_str(
            r#"{
                  "kty": "EC",
                  "crv": "P-256",
                  "x": "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                  "y": "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                  "d": "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE"
                }"#,
        )
        .unwrap();

        let signed_object = sign_serde_json_object(
            input,
            signature_object_key,
            algorithm,
            private_key,
            SignatureCreationOptions {
                include_key_id: false,
                include_public_key: KeyInclusionOptions::Include { include_kid: false },
                excludes: vec!["key2".to_string()],
            },
        )
        .unwrap();
        println!("have signed object: {signed_object}");

        let good =
            verify_json_object_str(&signed_object.to_string(), signature_object_key).unwrap();
        assert!(good, "Signature verification failed");

        let mut signed_object_with_altered_excluded_property = signed_object.clone();
        signed_object_with_altered_excluded_property["key2"] = serde_json::json!(43);
        let good = verify_json_object_str(
            &signed_object_with_altered_excluded_property.to_string(),
            signature_object_key,
        )
        .unwrap();
        assert!(good, "Signature verification of altered object failed");
    }

    #[test]
    fn test_verify_good_signature() {
        let input = r#"{"key":"value","signature":{"algorithm":"ES256","publicKey":{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},"value":"rcwOXiwYpd_BBrFE0BSGYjV3HBzeqeuTAIar8zVVw-Ir0fI8q8JzryU72l0_AZFiu5-hpfcVmBHs6pHFJqL6KA"}}"#;
        let signature_object_key = "signature";

        let good = verify_json_object_str(input, signature_object_key).unwrap();
        assert!(good, "Good signature not correctly verified");
    }

    #[test]
    fn test_recreate_good_signature() {
        // this key from the JWK spec (rfc7517)
        let private_key_json_bytes = r#"{"kty":"EC",
                                         "crv":"P-256",
                                         "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
                                         "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
                                         "d":"870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
                                         "use":"enc",
                                         "kid":"1"}"#;
        let obj = r#"{"key":"value"}"#;
        let signature_object_key = "signature";

        let signature = sign_json_object_str(
            obj,
            signature_object_key,
            data::SignatureAlgorithm::ES256,
            private_key_json_bytes,
            SignatureCreationOptions {
                include_key_id: false,
                include_public_key: KeyInclusionOptions::Include { include_kid: false },
                excludes: vec![],
            },
        )
        .expect("could not sign");

        let expected_result = r#"{"key":"value","signature":{"algorithm":"ES256","publicKey":{"crv":"P-256","kty":"EC","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"},"value":"rcwOXiwYpd_BBrFE0BSGYjV3HBzeqeuTAIar8zVVw-Ir0fI8q8JzryU72l0_AZFiu5-hpfcVmBHs6pHFJqL6KA"}}"#;
        assert_eq!(signature, expected_result);
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

    #[cfg(test)]
    mod spec_test_vectors {
        use lazy_static::lazy_static;
        use std::collections::HashMap;

        use crate::verify_json_object_str;

        lazy_static! {
            static ref TEST_VECTORS: HashMap<&'static str, &'static str> = {
                let mut map = HashMap::new();
                map.insert(
                    "p256privatekey.jwk",
                    include_str!("../test_vectors/spec/p256privatekey.jwk"),
                );
                map.insert(
                    "p256#es256@kid.json",
                    include_str!("../test_vectors/spec/p256_es256_kid.json"),
                );
                map.insert(
                    "p256#es256@name-jwk.json",
                    include_str!("../test_vectors/spec/p256_es256_name-jwk.json"),
                );
                map.insert(
                    "p256#es256@exts-jwk.json",
                    include_str!("../test_vectors/spec/p256_es256_exts-jwk.json"),
                );
                map.insert(
                    "p256#es256@excl-jwk.json",
                    include_str!("../test_vectors/spec/p256_es256_excl-jwk.json"),
                );
                map.insert(
                    "p384privatekey.jwk",
                    include_str!("../test_vectors/spec/p384privatekey.jwk"),
                );
                map.insert(
                    "p384#es384@jwk.json",
                    include_str!("../test_vectors/spec/p384_es384_jwk.json"),
                );
                map
            };
        }

        // #[test]
        // fn test_p256_es256_kid_json_validate_signature() {
        //     let object = TEST_VECTORS["p256#es256@kid.json"];
        //     assert!(verify_json_object_str(object, "signature")
        //         .expect("unable to verify valid signature from spec test vector"));
        // }

        #[test]
        fn test_p256_es256_name_jwk_json_validate_signature() {
            let object = TEST_VECTORS["p256#es256@name-jwk.json"];
            assert!(verify_json_object_str(object, "authorizationSignature")
                .expect("unable to verify valid signature from spec test vector"));
        }

        #[test]
        fn test_p256_es256_exts_jwk_json_validate_signature() {
            let object = TEST_VECTORS["p256#es256@exts-jwk.json"];
            assert!(verify_json_object_str(object, "signature")
                .expect("unable to verify valid signature from spec test vector"));
        }

        // #[test]
        // fn test_p256_es256_excl_jwk_json_validate_signature() {
        //     let object = TEST_VECTORS["p256#es256@excl-jwk.json"];
        //     assert!(verify_json_object_str(object, "signature")
        //         .expect("unable to verify valid signature from spec test vector"));
        // }

        // #[test]
        // fn test_p384_es384_jwk_json_validate_signature() {
        //     let object = TEST_VECTORS["p384#es384@jwk.json"];
        //     assert!(verify_json_object_str(object, "signature")
        //         .expect("unable to verify valid signature from spec test vector"));
        // }
    }
}
