use anyhow::Result;
use serde::Serialize;

use crate::data;

#[derive(Serialize, Clone, PartialEq)]
pub enum KtyEC {
    #[serde(rename = "EC")]
    EllipticCurve,
}
#[derive(Serialize, Clone, PartialEq)]
pub enum CurveP384 {
    #[serde(rename = "P-384")]
    P384,
}

#[derive(Serialize)]
pub struct PublicKey {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,

    pub kty: KtyEC,

    pub crv: CurveP384,

    pub x: data::DataTypeBinaryData,
    pub y: data::DataTypeBinaryData,
}

impl TryFrom<data::Key> for PublicKey {
    type Error = anyhow::Error;

    fn try_from(value: data::Key) -> std::result::Result<Self, Self::Error> {
        let (curve, x, y) = match value.inner_key {
            data::KeyInner::EllipticCurve {
                curve: data::EcCurveName::P384,
                x,
                y,
                d: None,
            } => (CurveP384::P384, x, y),
            data::KeyInner::EllipticCurve {
                curve: data::EcCurveName::P384,
                d: Some(_),
                ..
            } => {
                return Err(anyhow::format_err!(
                    "refusing to use a key that has secret param 'd' to construct public key"
                ));
            }
            data::KeyInner::EllipticCurve { curve, .. } => {
                return Err(anyhow::format_err!(
                    "cannot use a curve of type {curve:?} instead of P384"
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

pub fn verify_signature(
    signed_bytes: Vec<u8>,
    signature_bytes: Vec<u8>,
    public_key: PublicKey,
) -> Result<bool> {
    todo!()
}
