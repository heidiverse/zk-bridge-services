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

use next_gen_signatures::crypto::zkp::{self, DiscloseRequirement, ProofRequirement};
use rand_core::OsRng;
use rocket::{get, post, serde::json::Json};
use serde_json::Value as JsonValue;

use crate::models::{common::KeyPair, zkp::*};

#[get("/keypair")]
pub fn gen_keypair() -> Json<KeyPair> {
    let (pk, sk) = zkp::generate_keypair(&mut OsRng);
    Json(KeyPair {
        public_key: pk,
        secret_key: sk,
    })
}

#[post("/issue", data = "<params>")]
pub async fn issue(
    params: Json<IssuanceParams>,
) -> rocket_errors::anyhow::Result<Json<VerifiableCredential>> {
    let Json(params) = params;

    let vc = zkp::issue(
        &mut OsRng,
        params.claims,
        &params.issuer_pk,
        &params.issuer_sk,
        &params.issuer_id,
        &params.issuer_key_id,
        params.issuance_date.as_deref(),
        params.created_date.as_deref(),
        params.expiration_date.as_deref(),
        params.device_binding,
        params.vc_type.as_deref(),
    )
    .await?;

    Ok(Json(vc))
}

#[post("/circuit-keys", data = "<definition>")]
pub fn gen_proving_keys(definition: Json<Vec<Requirement>>) -> Json<CircuitKeys> {
    let requirements = definition
        .0
        .into_iter()
        .map(|r| match r {
            Requirement::Required { key } => {
                ProofRequirement::Required(DiscloseRequirement { key })
            }
            Requirement::Circuit {
                circuit_id,
                private_var,
                private_key,
                public_var,
                public_val: (pub_value, pub_datatype),
            } => ProofRequirement::Circuit {
                id: circuit_id,
                private_var,
                private_key,
                public_var,
                public_val: zkp::RdfValue::Typed(pub_value, pub_datatype),
            },
        })
        .collect::<Vec<_>>();

    let keys = zkp::generate_circuits(&mut OsRng, &requirements);

    Json(CircuitKeys {
        proving_keys: keys.proving_keys,
        verifying_keys: keys.verifying_keys,
    })
}

#[post("/present", data = "<params>")]
pub fn present(
    params: Json<PresentationParams>,
) -> rocket_errors::anyhow::Result<Json<VerifiablePresentation>> {
    let Json(params) = params;

    let requirements = params
        .requirements
        .into_iter()
        .map(|r| match r {
            Requirement::Required { key } => {
                ProofRequirement::Required(DiscloseRequirement { key })
            }
            Requirement::Circuit {
                circuit_id,
                private_var,
                private_key,
                public_var,
                public_val: (pub_value, pub_datatype),
            } => ProofRequirement::Circuit {
                id: circuit_id,
                private_var,
                private_key,
                public_var,
                public_val: zkp::RdfValue::Typed(pub_value, pub_datatype),
            },
        })
        .collect::<Vec<_>>();

    let device_binding = params.device_binding.map(|db| zkp::DBRequirement {
        public_key: db.public_key,
        message: db.message,
        message_signature: db.message_signature,
        comm_key_secp_label: db.comm_key_secp_label,
        comm_key_tom_label: db.comm_key_tom_label,
        comm_key_bls_label: db.comm_key_bls_label,
        bpp_setup_label: db.bpp_setup_label,
    });

    let vp = zkp::present(
        &mut OsRng,
        params.verifiable_credential,
        &requirements,
        device_binding,
        &params.proving_keys,
        &params.issuer_pk,
        &params.issuer_id,
        &params.issuer_key_id,
    )?;

    Ok(Json(vp))
}

#[post("/verify", data = "<params>")]
pub fn verify(params: Json<VerificationParams>) -> rocket_errors::anyhow::Result<Json<JsonValue>> {
    let Json(params) = params;

    let requirements = params
        .requirements
        .into_iter()
        .map(|r| match r {
            Requirement::Required { key } => {
                ProofRequirement::Required(DiscloseRequirement { key })
            }
            Requirement::Circuit {
                circuit_id,
                private_var,
                private_key,
                public_var,
                public_val: (pub_value, pub_datatype),
            } => ProofRequirement::Circuit {
                id: circuit_id,
                private_var,
                private_key,
                public_var,
                public_val: zkp::RdfValue::Typed(pub_value, pub_datatype),
            },
        })
        .collect::<Vec<_>>();

    let device_binding = params.device_binding.map(|db| zkp::DBVerificationParams {
        message: db.message,
        comm_key_secp_label: db.comm_key_secp_label,
        comm_key_tom_label: db.comm_key_tom_label,
        comm_key_bls_label: db.comm_key_bls_label,
        bpp_setup_label: db.bpp_setup_label,
    });

    let body = zkp::verify(
        &mut OsRng,
        params.presentation,
        &requirements,
        device_binding,
        &params.verifying_keys,
        &params.issuer_pk,
        &params.issuer_id,
        &params.issuer_key_id,
    )?;

    Ok(Json(body))
}
