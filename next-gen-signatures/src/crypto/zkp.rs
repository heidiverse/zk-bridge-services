use std::{collections::HashMap, fmt::Write, io::Cursor, str::FromStr};

use anyhow::Context;
use ark_ff::{BigInteger, PrimeField};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use base64::{
    prelude::{BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD},
    Engine,
};
use chrono::DateTime;
use json_ld::{rdf_types::generator, syntax::Parse, JsonLdProcessor, RemoteDocument};
use num_bigint::BigUint;
use rand_core::RngCore;
pub use rdf_util::Value as RdfValue;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value as JsonValue};
use static_iref::iri;
pub use zkp_util::vc::requirements::{DiscloseRequirement, ProofRequirement};
use zkp_util::{
    device_binding::{DeviceBindingPresentationSigma, SecpAffine, SecpFq, SecpFr},
    vc::{
        presentation::VerifiablePresentationSigma,
        requirements::{DeviceBindingRequirement, DeviceBindingVerificationParams},
        VerifiableCredential,
    },
    EcdsaSignature,
};

pub fn serialize_public_key_uncompressed(pubkey: &SecpAffine) -> Vec<u8> {
    // Serialize X and Y coordinates (32 bytes each)
    let x_bytes = pubkey.x.into_bigint().to_bytes_be();
    let y_bytes = pubkey.y.into_bigint().to_bytes_be();

    // Concatenate into [0x04, X, Y]
    let mut serialized = vec![0x04];
    serialized.extend(x_bytes);
    serialized.extend(y_bytes);

    serialized
}

pub fn deserialize_public_key_uncompressed(bytes: &[u8]) -> anyhow::Result<SecpAffine> {
    anyhow::ensure!(bytes.len() == 65, "Invalid public key length");
    anyhow::ensure!(
        bytes[0] == 0x04,
        "Invalid uncompressed SEC1 format (missing 0x04 prefix)"
    );

    // Extract X and Y coordinates
    let x_bytes: [u8; 32] = bytes[1..33]
        .try_into()
        .context("Failed to extract X coordinate")?;
    let y_bytes: [u8; 32] = bytes[33..65]
        .try_into()
        .context("Failed to extract Y coordinate")?;

    // Convert bytes to field elements
    let x = SecpFq::from(BigUint::from_bytes_be(&x_bytes));
    let y = SecpFq::from(BigUint::from_bytes_be(&y_bytes));

    // Create an affine point
    Ok(SecpAffine::new_unchecked(x, y))
}

fn pad_vec_front(vec: &mut Vec<u8>, target_len: usize) {
    // If the vector is shorter than the target length, pad with zeros at the front
    let padding_needed = target_len.saturating_sub(vec.len());

    // Insert `0`s at the beginning of the vector
    vec.splice(0..0, vec![0; padding_needed]);
}

pub fn serialize_signature(signature: &EcdsaSignature) -> Vec<u8> {
    let mut rand_x_coord = signature.rand_x_coord.into_bigint().to_bytes_be();
    let mut response = signature.response.into_bigint().to_bytes_be();

    pad_vec_front(&mut rand_x_coord, 32);
    pad_vec_front(&mut response, 32);

    let mut result = rand_x_coord;
    result.extend_from_slice(&response);
    result
}

pub fn deserialize_signature(serialized: &[u8]) -> anyhow::Result<EcdsaSignature> {
    anyhow::ensure!(
        serialized.len() == 64,
        "Invalid serialized length, expected 64 bytes."
    );

    // Extract the two 32-byte components from the serialized data
    let (rand_x_coord_bytes, response_bytes) = serialized.split_at(32);

    // Convert the byte slices back to BigInt
    let rand_x_coord = SecpFr::from(BigUint::from_bytes_be(rand_x_coord_bytes));
    let response = SecpFr::from(BigUint::from_bytes_be(response_bytes));

    // Create and return the EcdsaSignature struct
    Ok(EcdsaSignature {
        rand_x_coord,
        response,
    })
}

pub use zkp_util::keypair::generate_keypair;

async fn parse_json_ld(data: &str) -> anyhow::Result<RdfValue> {
    let doc = RemoteDocument::new(None, None, json_ld::syntax::Value::parse_str(data)?.0);

    let mut loader = json_ld::FsLoader::default();
    loader.mount(iri!("https://www.w3.org/").to_owned(), "jsonld");
    loader.mount(iri!("https://w3id.org/").to_owned(), "jsonld");
    loader.mount(iri!("http://schema.org/").to_owned(), "jsonld");

    let mut generator = generator::Blank::new_with_prefix("b".to_string());
    let mut rdf = doc.to_rdf(&mut generator, &loader).await?;

    let rdf = rdf.cloned_quads().fold(String::new(), |mut output, q| {
        let _ = writeln!(output, "{q} .");
        output
    });

    rdf_util::from_str(rdf).map_err(|e| e.into())
}

#[allow(clippy::too_many_arguments)]
pub async fn issue<R: RngCore>(
    rng: &mut R,
    claims: JsonValue,
    issuer_pk: &str,
    issuer_sk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
    issuance_date: Option<&str>,
    created_date: Option<&str>,
    expiration_date: Option<&str>,
    device_binding: Option<(String, String)>,
    vc_type: Option<&str>,
) -> anyhow::Result<String> {
    let claims = parse_json_ld(&claims.to_string()).await?;

    let issuance_date = issuance_date.map(DateTime::from_str).transpose()?;
    let created_date = created_date.map(DateTime::from_str).transpose()?;
    let expiration_date = expiration_date.map(DateTime::from_str).transpose()?;

    // Change bases
    let device_binding = if let Some((x, y)) = device_binding {
        let x = SecpFq::from(BigUint::from_bytes_be(&BASE64_STANDARD.decode(x)?));
        let y = SecpFq::from(BigUint::from_bytes_be(&BASE64_STANDARD.decode(y)?));

        let x = zkp_util::device_binding::change_field(&x);
        let y = zkp_util::device_binding::change_field(&y);

        let x = BASE64_STANDARD.encode(x.into_bigint().to_bytes_be());
        let y = BASE64_STANDARD.encode(y.into_bigint().to_bytes_be());

        Some((x, y))
    } else {
        None
    };

    let vc = zkp_util::vc::issuance::issue(
        rng,
        claims,
        issuer_pk,
        issuer_sk,
        issuer_id,
        issuer_key_id,
        issuance_date,
        created_date,
        expiration_date,
        device_binding,
        vc_type,
    )?;

    let credential = BASE64_URL_SAFE_NO_PAD.encode(
        json!({
            "document": BASE64_URL_SAFE_NO_PAD.encode(vc.document.to_string()),
            "proof": BASE64_URL_SAFE_NO_PAD.encode(vc.proof.to_string())
        })
        .to_string(),
    );

    Ok(credential)
}

pub use zkp_util::circuits::generate_circuits;

#[derive(Debug, Serialize, Deserialize)]
pub struct DBRequirement {
    #[serde(with = "crate::encoding::base64url")]
    pub public_key: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub message: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub message_signature: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub comm_key_secp_label: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub comm_key_tom_label: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub comm_key_bls_label: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub bpp_setup_label: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn present<R: RngCore>(
    rng: &mut R,
    vc: String,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DBRequirement>,
    proving_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<String> {
    let vc = {
        let json = serde_json::from_str::<JsonValue>(&String::from_utf8(
            BASE64_URL_SAFE_NO_PAD.decode(&vc)?,
        )?)?;

        let document = rdf_util::from_str(String::from_utf8(
            BASE64_URL_SAFE_NO_PAD.decode(json["document"].as_str().unwrap())?,
        )?)?;

        let proof = rdf_util::from_str(String::from_utf8(
            BASE64_URL_SAFE_NO_PAD.decode(json["proof"].as_str().unwrap())?,
        )?)?;

        VerifiableCredential {
            document: document.to_graph(None),
            proof: proof.to_graph(None),
        }
    };

    let device_binding = if let Some(db) = device_binding {
        let public_key = deserialize_public_key_uncompressed(&db.public_key)?;
        let message = SecpFr::from(BigUint::from_bytes_be(&db.message));
        let message_signature = deserialize_signature(&db.message_signature)?;

        let valid = message_signature.verify_prehashed(message, public_key);
        assert!(valid, "invalid sig");

        Some(DeviceBindingRequirement {
            public_key,
            message,
            message_signature,
            comm_key_secp_label: db.comm_key_secp_label,
            comm_key_tom_label: db.comm_key_tom_label,
            comm_key_bls_label: db.comm_key_bls_label,
            bpp_setup_label: db.bpp_setup_label,
        })
    } else {
        None
    };

    let vp = zkp_util::vc::presentation::present(
        rng,
        vc,
        requirements,
        device_binding,
        proving_keys,
        issuer_pk,
        issuer_id,
        issuer_key_id,
    )?;

    let db = if let Some(db) = vp.device_binding {
        let mut bytes = Vec::<u8>::new();
        db.serialize_compressed(&mut bytes)?;
        Some(BASE64_URL_SAFE_NO_PAD.encode(bytes))
    } else {
        None
    };

    let token = BASE64_URL_SAFE_NO_PAD.encode(
        json!({
            "proof": BASE64_URL_SAFE_NO_PAD.encode(vp.proof.dataset().to_string()),
            "device_binding": db
        })
        .to_string(),
    );

    Ok(token)
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DBVerificationParams {
    #[serde(with = "crate::encoding::base64url")]
    pub message: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub comm_key_secp_label: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub comm_key_tom_label: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub comm_key_bls_label: Vec<u8>,

    #[serde(with = "crate::encoding::base64url")]
    pub bpp_setup_label: Vec<u8>,
}

#[allow(clippy::too_many_arguments)]
pub fn verify<R: RngCore>(
    rng: &mut R,
    presentation: String,
    requirements: &Vec<ProofRequirement>,
    device_binding: Option<DBVerificationParams>,
    verifying_keys: &HashMap<String, String>,
    issuer_pk: &str,
    issuer_id: &str,
    issuer_key_id: &str,
) -> anyhow::Result<JsonValue> {
    let presentation = {
        let json = serde_json::from_str::<JsonValue>(&String::from_utf8(
            BASE64_URL_SAFE_NO_PAD.decode(presentation)?,
        )?)?;

        let proof = rdf_util::MultiGraph::from_str(&String::from_utf8(
            BASE64_URL_SAFE_NO_PAD
                .decode(json["proof"].as_str().context("No proof value found!")?)?,
        )?)?;

        let device_binding = if let Some(db) = json.get("device_binding") {
            let bytes = BASE64_URL_SAFE_NO_PAD
                .decode(db.as_str().context("Invalid device_binding found!")?)?;
            Some(DeviceBindingPresentationSigma::deserialize_compressed(
                Cursor::new(bytes),
            )?)
        } else {
            None
        };

        VerifiablePresentationSigma {
            proof,
            device_binding,
        }
    };

    let device_binding = if let Some(db) = device_binding {
        Some(DeviceBindingVerificationParams {
            message: SecpFr::from(BigUint::from_bytes_be(&db.message)),
            comm_key_secp_label: db.comm_key_secp_label,
            comm_key_tom_label: db.comm_key_tom_label,
            comm_key_bls_label: db.comm_key_bls_label,
            bpp_setup_label: db.bpp_setup_label,
        })
    } else {
        None
    };

    zkp_util::vc::verification::verify(
        rng,
        presentation,
        requirements,
        device_binding,
        verifying_keys,
        issuer_pk,
        issuer_id,
        issuer_key_id,
        1,
    )
}

#[cfg(test)]
mod tests {
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, PrimeField};
    use ark_std::UniformRand;
    use base64::{prelude::BASE64_STANDARD, Engine};
    use rand_core::OsRng;
    use serde_json::json;
    use zkp_util::{
        circuits,
        device_binding::SecpFr,
        vc::requirements::{DiscloseRequirement, ProofRequirement},
        EcdsaSignature, SECP_GEN,
    };

    use crate::crypto::zkp::{
        serialize_public_key_uncompressed, serialize_signature, DBRequirement, DBVerificationParams,
    };

    #[tokio::test]
    pub async fn test_roundtrip() {
        let mut rng = OsRng;

        let (issuer_pk, issuer_sk) = super::generate_keypair(&mut rng);
        let (issuer_id, issuer_key_id) = ("did:example:issuer0", "did:example:issuer0#key001");

        let db_sk = SecpFr::rand(&mut rng);
        let db_pk = (SECP_GEN * db_sk).into_affine();

        let device_binding = {
            let x = BASE64_STANDARD.encode(db_pk.x().unwrap().into_bigint().to_bytes_be());
            let y = BASE64_STANDARD.encode(db_pk.y().unwrap().into_bigint().to_bytes_be());

            Some((x, y))
        };

        let vc = super::issue(
            &mut rng,
            json!({
                "https://schema.org/name": "John, Doe",
                "https://schema.org/birthDate": {
                    "@value": "2000-01-01T00:00:00Z",
                    "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                },
                "https://schema.org/dog": {
                    "https://schema.org/name": "Ricky"
                }
            }),
            &issuer_pk,
            &issuer_sk,
            issuer_id,
            issuer_key_id,
            None,
            None,
            None,
            device_binding,
            Some("https://example.org/my-vc-type"),
        )
        .await
        .unwrap();

        let requirements = vec![
            ProofRequirement::Required(DiscloseRequirement {
                key: "https://schema.org/name".into(),
            }),
            ProofRequirement::Circuit {
                id: circuits::LESS_THAN_PUBLIC_ID.to_string(),
                private_var: "a".into(),
                private_key: "https://schema.org/birthDate".into(),
                public_var: "b".into(),
                public_val: rdf_util::Value::Typed(
                    "2001-01-01T00:00:00Z".into(),
                    "http://www.w3.org/2001/XMLSchema#dateTime".into(),
                ),
            },
        ];

        let circuits = super::generate_circuits(&mut rng, &requirements);

        let message = SecpFr::rand(&mut rng);
        let message_signature = EcdsaSignature::new_prehashed(&mut rng, message, db_sk);

        let device_binding = Some(DBRequirement {
            public_key: serialize_public_key_uncompressed(&db_pk),
            message: message.into_bigint().to_bytes_be(),
            message_signature: serialize_signature(&message_signature),
            comm_key_secp_label: b"secp".to_vec(),
            comm_key_tom_label: b"tom".to_vec(),
            comm_key_bls_label: b"bls".to_vec(),
            bpp_setup_label: b"bpp-setup".to_vec(),
        });

        let vp = super::present(
            &mut rng,
            vc,
            &requirements,
            device_binding,
            &circuits.proving_keys,
            &issuer_pk,
            issuer_id,
            issuer_key_id,
        )
        .unwrap();

        let device_binding = Some(DBVerificationParams {
            message: message.into_bigint().to_bytes_be(),
            comm_key_secp_label: b"secp".to_vec(),
            comm_key_tom_label: b"tom".to_vec(),
            comm_key_bls_label: b"bls".to_vec(),
            bpp_setup_label: b"bpp-setup".to_vec(),
        });

        super::verify(
            &mut rng,
            vp,
            &requirements,
            device_binding,
            &circuits.verifying_keys,
            &issuer_pk,
            issuer_id,
            issuer_key_id,
        )
        .unwrap();
    }
}
