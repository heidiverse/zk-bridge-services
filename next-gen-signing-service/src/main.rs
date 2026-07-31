/* Copyright 2025 Ubique Innovation AG

Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
 */

use rocket::{get, launch, routes};

pub mod models;
pub mod routes;

const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(target_arch = "x86_64")]
#[unsafe(no_mangle)]
pub unsafe extern "C" fn __rust_probestack() {}

#[get("/")]
fn index() -> String {
    format!("SPRIND Signing Service v{VERSION}")
}

#[launch]
fn rocket() -> _ {
    rocket::build()
        .mount("/", routes![index])
        .mount(
            "/fips204/44",
            routes![
                routes::fips204::Fips204MlDsa44Provider_gen_keypair,
                routes::fips204::Fips204MlDsa44Provider_sign,
                routes::fips204::Fips204MlDsa44Provider_verify
            ],
        )
        .mount(
            "/fips204/65",
            routes![
                routes::fips204::Fips204MlDsa65Provider_gen_keypair,
                routes::fips204::Fips204MlDsa65Provider_sign,
                routes::fips204::Fips204MlDsa65Provider_verify
            ],
        )
        .mount(
            "/fips204/87",
            routes![
                routes::fips204::Fips204MlDsa87Provider_gen_keypair,
                routes::fips204::Fips204MlDsa87Provider_sign,
                routes::fips204::Fips204MlDsa87Provider_verify
            ],
        )
        .mount(
            "/bbs+/g1/",
            routes![
                routes::bbs_plus::BbsPlusG1Provider_gen_keypair,
                routes::bbs_plus::BbsPlusG1Provider_sign,
                routes::bbs_plus::BbsPlusG1Provider_verify,
                routes::bbs_plus::BbsPlusG1Provider_create_pok_of_sig,
                routes::bbs_plus::BbsPlusG1Provider_verify_pok_of_sig,
            ],
        )
        .mount(
            "/bbs+/g2/",
            routes![
                routes::bbs_plus::BbsPlusG2Provider_gen_keypair,
                routes::bbs_plus::BbsPlusG2Provider_sign,
                routes::bbs_plus::BbsPlusG2Provider_verify,
            ],
        )
        .mount(
            "/zkp/",
            routes![
                routes::zkp::gen_keypair,
                routes::zkp::issue,
                routes::zkp::gen_proving_keys,
                routes::zkp::present,
                routes::zkp::verify
            ],
        )
}

#[cfg(test)]
mod test {
    use crate::{
        models::{
            common::KeyPair,
            zkp::{CircuitKeys, VerifiableCredential, VerifiablePresentation},
        },
        VERSION,
    };

    use super::*;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_ff::{BigInteger, PrimeField};
    use ark_std::UniformRand;
    use next_gen_signatures::{
        crypto::zkp::{serialize_public_key_uncompressed, serialize_signature},
        Engine, BASE64_STANDARD, BASE64_URL_SAFE_NO_PAD,
    };
    use rand_core::OsRng;
    use rocket::local::blocking::Client;
    use rocket::{
        http::{Header, Status},
        uri,
    };
    use serde_json::{json, Value};
    use zkp_util::{device_binding::SecpFr, EcdsaSignature, SECP_GEN};

    macro_rules! test_roundtrip_fips204 {
        ($v:expr) => {
            paste::item! {
                #[test]
                fn [<test_roundtrip_fips204_ $v>]() {
                    let message = BASE64_URL_SAFE_NO_PAD.encode("Hello, World!");

                    let client = Client::tracked(rocket()).expect("valid rocket instance");
                    let response = client
                        .get(format!(
                            "/fips204/{v}/keypair",
                            v = stringify!($v)
                        ))
                        .dispatch();
                    assert_eq!(response.status(), Status::Ok);

                    let keypair = response.into_json::<KeyPair>().unwrap();

                    let response = client
                        .get(format!(
                            "/fips204/{v}/sign?secret_key={sk}&message={msg}",
                            v = stringify!($v),
                            sk = keypair.secret_key,
                            msg = message,
                        ))
                        .dispatch();
                    assert_eq!(response.status(), Status::Ok);

                    let signature = response.into_json::<String>().unwrap();
                    let response = client
                        .get(format!(
                            "/fips204/{v}/verify?public_key={pk}&signature={sig}&message={msg}",
                            v = stringify!($v),
                            pk = keypair.public_key,
                            sig = signature,
                            msg = message,
                        ))
                        .dispatch();

                    assert_eq!(response.status(), Status::Ok);

                    let success = response.into_json::<bool>().unwrap();

                    assert!(success);
                }
            }
        };
    }

    macro_rules! test_roundtrip_bbs_plus {
        ($g:ident) => {
            paste::item! {
                #[test]
                fn [<test_roundtrip_bbs_plus_ $g>]() {
                    let nonce = BASE64_URL_SAFE_NO_PAD.encode("nonce");
                    let message = BASE64_URL_SAFE_NO_PAD.encode("Hello, World!");

                    let client = Client::tracked(rocket()).expect("valid rocket instance");
                    let response = client
                        .get(format!(
                            "/bbs+/{g}/keypair?nonce={n}&message_count={c}",
                            g = stringify!($g),
                            n = nonce,
                            c = 1
                        ))
                        .dispatch();
                    assert_eq!(response.status(), Status::Ok);

                    let keypair = response.into_json::<KeyPair>().unwrap();

                    let response = client
                        .get(format!(
                            "/bbs+/{g}/sign?secret_key={sk}&messages.0={msg}&nonce={n}&message_count={c}",
                            g = stringify!($g),
                            sk = keypair.secret_key,
                            msg = message,
                            n = nonce,
                            c = 1
                        ))
                        .dispatch();
                    assert_eq!(response.status(), Status::Ok);

                    let signature = response.into_json::<String>().unwrap();
                    let response = client
                        .get(format!(
                            "/bbs+/{g}/verify?public_key={pk}&signature={sig}&messages.0={msg}&nonce={n}&message_count={c}",
                            g = stringify!($g),
                            pk = keypair.public_key,
                            sig = signature,
                            msg = message,
                            n = nonce,
                            c = 1
                        ))
                        .dispatch();

                    assert_eq!(response.status(), Status::Ok);

                    let success = response.into_json::<bool>().unwrap();

                    assert!(success);
                }
            }
        };
    }

    #[test]
    fn index_should_contain_version() {
        let client = Client::tracked(rocket()).expect("valid rocket instance");
        let response = client.get(uri!(super::index)).dispatch();
        assert_eq!(response.status(), Status::Ok);
        assert!(response.into_string().unwrap().contains(VERSION));
    }

    test_roundtrip_fips204!(44);
    test_roundtrip_fips204!(65);
    test_roundtrip_fips204!(87);

    test_roundtrip_bbs_plus!(g1);
    test_roundtrip_bbs_plus!(g2);

    #[test]
    fn test_roundtrip_bbs_plus_g1_pok() {
        let nonce = BASE64_URL_SAFE_NO_PAD.encode("nonce");
        let messages = [
            b"message 1",
            b"message 2",
            b"message 3",
            b"message 4",
            b"message 5",
        ]
        .iter()
        .map(|m| BASE64_URL_SAFE_NO_PAD.encode(m))
        .collect::<Vec<_>>();

        let client = Client::tracked(rocket()).unwrap();
        let response = client
            .get(format!(
                "/bbs+/g1/keypair?nonce={n}&message_count={c}",
                n = nonce,
                c = messages.len()
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let keypair = response.into_json::<KeyPair>().unwrap();

        let response = client
            .get(format!(
                "/bbs+/g1/sign?secret_key={sk}&nonce={n}&message_count={c}&messages={msgs}",
                sk = keypair.secret_key,
                n = nonce,
                c = messages.len(),
                msgs = messages.join("&messages=")
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let signature = response.into_json::<String>().unwrap();

        let response = client
            .get(format!(
                "/bbs+/g1/pok/create?signature={signature}&nonce={nonce}&messages={msgs}&revealed_indexes={ri}",
                msgs = messages.join("&messages="),
                ri = ["0", "2", "4"].join("&revealed_indexes=")
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let proof = response.into_json::<String>().unwrap();

        let response = client
            .get(format!(
                "/bbs+/g1/pok/verify?proof={proof}{msgs}&public_key={pk}&nonce={nonce}&message_count={count}",
                msgs = [0usize, 2, 4]
                    .into_iter()
                    .map(|i| format!("&revealed_messages[{i}]={msg}", msg = &messages[i]))
                    .collect::<Vec<_>>().join(""),
                pk = &keypair.public_key,
                count = messages.len()
            ))
            .dispatch();
        assert_eq!(response.status(), Status::Ok);

        let success = response.into_json::<bool>().unwrap();

        assert!(success);
    }

    #[test]
    fn test_roundtrip_zkp() {
        let mut rng = OsRng;

        // device binding
        let db_sk = SecpFr::rand(&mut rng);
        let db_pk = (SECP_GEN * db_sk).into_affine();
        let db_pk_x = BASE64_STANDARD.encode(db_pk.x().unwrap().into_bigint().to_bytes_be());
        let db_pk_y = BASE64_STANDARD.encode(db_pk.y().unwrap().into_bigint().to_bytes_be());

        let client = Client::tracked(rocket()).unwrap();
        let response = client.get("/zkp/keypair").dispatch();
        assert_eq!(response.status(), Status::Ok);

        let issuer = response.into_json::<KeyPair>().unwrap();
        let issuer_id = "did:example:issuer0";
        let issuer_key_id = "did:example:issuer0#bls12_381-g2-pub001";

        let response = client
            .post("/zkp/issue")
            .body(
                json!({
                    "claims": {
                    "@type": "http://schema.org/Person",
                    "@id": "did:example:johndoe",
                    "http://schema.org/name": "John Doe",
                    "http://schema.org/birthDate": {
                        "@value": "1990-01-01T00:00:00Z",
                        "@type": "http://www.w3.org/2001/XMLSchema#dateTime"
                    },
                    "http://schema.org/telephone": "(425) 123-4567",
                    },
                    "issuer_pk": issuer.public_key,
                    "issuer_sk": issuer.secret_key,
                    "issuer_id": issuer_id,
                    "issuer_key_id": issuer_key_id,
                    "issuance_date": "2020-01-01T00:00:00Z",
                    "created_date": "2025-01-01T00:00:00Z",
                    "expiration_date": "2030-01-01T00:00:00Z",
                    "device_binding": [db_pk_x, db_pk_y],
                    "vc_type": "https://example.org/my-vc-type",
                })
                .to_string(),
            )
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);

        let vc = response.into_json::<VerifiableCredential>().unwrap();

        let requirements = json!([
            { "type": "required", "key": "http://schema.org/name" },
            {
                "type": "circuit",
                "circuit_id": "https://zkp-ld.org/circuit/ubique/lessThanPublic",

                "private_var": "a",
                "private_key": "http://schema.org/birthDate",

                "public_var": "b",
                "public_val": [
                    // value
                    "2001-01-01T00:00:00Z",
                    // datatype
                    "http://www.w3.org/2001/XMLSchema#dateTime"
                ],
            }
        ]);

        let response = client
            .post("/zkp/circuit-keys")
            .body(requirements.to_string())
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);

        let circuit_keys = response.into_json::<CircuitKeys>().unwrap();

        let message = SecpFr::rand(&mut rng);
        let message_signature = EcdsaSignature::new_prehashed(&mut rng, message, db_sk);

        let response = client
            .post("/zkp/present")
            .body(
                json!({
                    "verifiable_credential": vc,
                    "requirements": requirements,
                    "device_binding": {
                        "public_key": BASE64_URL_SAFE_NO_PAD.encode(
                            serialize_public_key_uncompressed(&db_pk)),
                        "message": BASE64_URL_SAFE_NO_PAD.encode(
                            message.into_bigint().to_bytes_be()),
                        "message_signature": BASE64_URL_SAFE_NO_PAD
                            .encode(serialize_signature(&message_signature)),
                        "comm_key_secp_label": BASE64_URL_SAFE_NO_PAD.encode(b"secp"),
                        "comm_key_tom_label": BASE64_URL_SAFE_NO_PAD.encode(b"tom"),
                        "comm_key_bls_label": BASE64_URL_SAFE_NO_PAD.encode(b"bls"),
                        "bpp_setup_label": BASE64_URL_SAFE_NO_PAD.encode(b"bpp"),
                    },
                    "proving_keys": circuit_keys.proving_keys,
                    "issuer_pk": issuer.public_key,
                    "issuer_id": issuer_id,
                    "issuer_key_id": issuer_key_id,
                })
                .to_string(),
            )
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);

        let vp = response.into_json::<VerifiablePresentation>().unwrap();

        let response = client
            .post("/zkp/verify")
            .body(
                json!({
                    "presentation": vp,
                    "requirements": requirements,
                    "device_binding": {
                        "message": BASE64_URL_SAFE_NO_PAD.encode(
                            message.into_bigint().to_bytes_be()),
                        "comm_key_secp_label": BASE64_URL_SAFE_NO_PAD.encode(b"secp"),
                        "comm_key_tom_label": BASE64_URL_SAFE_NO_PAD.encode(b"tom"),
                        "comm_key_bls_label": BASE64_URL_SAFE_NO_PAD.encode(b"bls"),
                        "bpp_setup_label": BASE64_URL_SAFE_NO_PAD.encode(b"bpp"),
                    },
                    "verifying_keys": circuit_keys.verifying_keys,
                    "issuer_pk": issuer.public_key,
                    "issuer_id": issuer_id,
                    "issuer_key_id": issuer_key_id,
                })
                .to_string(),
            )
            .header(Header::new("Content-Type", "application/json"))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);

        let disclosed = response.into_json::<Value>().unwrap();

        assert_eq!(disclosed["http://schema.org/name"], "John Doe");
    }
}
