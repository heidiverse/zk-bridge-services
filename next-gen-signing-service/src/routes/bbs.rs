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

use std::collections::HashMap;
use std::sync::{OnceLock, RwLock};

use next_gen_signatures::crypto::zkp;
use rand_core::OsRng;
use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use serde_json::json;

use crate::models::protocol::{CreateKeyRequest, KeyRef, OperationRequest, OperationResponse};

pub const ALGORITHM: &str = "BBS";
pub const OPERATION: &str = "w3c.bbs-data-integrity-credential-issuance";
pub const PRESENTATION_SETUP_OPERATION: &str = "w3c.bbs-data-integrity-presentation-setup";
const COMPLETED: &str = "COMPLETED";
const SCHEME: &str = "next-gen";

struct BbsKey {
    public_key: String,
    secret_key: String,
}

static KEYS: OnceLock<RwLock<HashMap<String, BbsKey>>> = OnceLock::new();

fn keys() -> &'static RwLock<HashMap<String, BbsKey>> {
    KEYS.get_or_init(|| RwLock::new(HashMap::new()))
}

pub fn operations() -> Vec<String> {
    vec![
        OPERATION.to_string(),
        PRESENTATION_SETUP_OPERATION.to_string(),
    ]
}

pub fn keyless_operations() -> Vec<String> {
    vec![PRESENTATION_SETUP_OPERATION.to_string()]
}

pub fn supports(operation: &str) -> bool {
    operation == OPERATION || operation == PRESENTATION_SETUP_OPERATION
}

pub fn supports_keyless(operation: &str) -> bool {
    operation == PRESENTATION_SETUP_OPERATION
}

pub fn resolve(uri: String) -> Result<Json<KeyRef>, Status> {
    let key_id = key_id(&uri).ok_or(Status::NotFound)?;
    let store = keys().read().map_err(|_| Status::InternalServerError)?;
    let key = store.get(key_id).ok_or(Status::NotFound)?;
    Ok(Json(key_ref(&uri, key)))
}

pub fn create(
    request: Json<CreateKeyRequest>,
) -> rocket_errors::anyhow::Result<Custom<Json<KeyRef>>> {
    if request.algorithm != ALGORITHM {
        return Err(std::io::Error::other(format!(
            "Unsupported protocol algorithm: {}",
            request.algorithm
        ))
        .into());
    }
    let effective_key_id = effective_key_id(request.namespace.as_deref(), &request.key_id)?;
    let uri = key_uri(&effective_key_id)?;
    let mut store = keys()
        .write()
        .map_err(|_| std::io::Error::other("BBS key store is unavailable"))?;
    if store.contains_key(&effective_key_id) {
        return Err(std::io::Error::other(format!("BBS signing key already exists: {uri}")).into());
    }
    let (public_key, secret_key) = zkp::generate_keypair(&mut OsRng);
    let key = BbsKey {
        public_key,
        secret_key,
    };
    let response = key_ref(&uri, &key);
    store.insert(effective_key_id, key);
    Ok(Custom(Status::Created, Json(response)))
}

pub fn delete(uri: String) -> Result<Status, Status> {
    let key_id = key_id(&uri).ok_or(Status::NotFound)?;
    let mut store = keys().write().map_err(|_| Status::InternalServerError)?;
    if store.remove(key_id).is_none() {
        return Err(Status::NotFound);
    }
    Ok(Status::NoContent)
}

pub async fn execute(
    request: OperationRequest,
) -> rocket_errors::anyhow::Result<Json<OperationResponse>> {
    let input = request
        .input
        .as_object()
        .ok_or_else(|| std::io::Error::other("Operation input must be a JSON object"))?;
    let algorithm = text(input, "algorithm")?;
    if algorithm != ALGORITHM {
        return Err(
            std::io::Error::other(format!("Unsupported protocol algorithm: {algorithm}")).into(),
        );
    }
    let claims = input
        .get("claims")
        .cloned()
        .ok_or_else(|| std::io::Error::other("Missing operation input: claims"))?;
    let issuer_id = text(input, "issuerId")?;
    let issuer_key_id = text(input, "issuerKeyId")?;
    let credential_type = input.get("credentialType").and_then(|value| value.as_str());
    let device_binding = match input.get("deviceBinding") {
        None | Some(serde_json::Value::Null) => None,
        Some(value) => {
            let object = value.as_object().ok_or_else(|| {
                std::io::Error::other("deviceBinding must contain x and y coordinates")
            })?;
            let x = object
                .get("x")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| std::io::Error::other("deviceBinding is missing x"))?;
            let y = object
                .get("y")
                .and_then(|value| value.as_str())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| std::io::Error::other("deviceBinding is missing y"))?;
            Some((x.to_string(), y.to_string()))
        }
    };
    let key = {
        let store = keys()
            .read()
            .map_err(|_| std::io::Error::other("BBS key store is unavailable"))?;
        let key_uri = request
            .key_uri
            .as_deref()
            .ok_or_else(|| std::io::Error::other("Missing BBS signing key"))?;
        let key_id =
            key_id(key_uri).ok_or_else(|| std::io::Error::other("Unknown BBS signing key"))?;
        let key = store
            .get(key_id)
            .ok_or_else(|| std::io::Error::other(format!("Unknown BBS signing key: {key_uri}")))?;
        (key.public_key.clone(), key.secret_key.clone())
    };

    let credential = zkp::issue(
        &mut OsRng,
        claims,
        &key.0,
        &key.1,
        &issuer_id,
        &issuer_key_id,
        None,
        None,
        None,
        device_binding,
        credential_type,
    )
    .await?;

    Ok(Json(OperationResponse {
        operation: request.operation,
        status: COMPLETED.to_string(),
        result: Some(json!({ "credential": credential })),
        operation_id: request.operation_id,
        interaction: None,
    }))
}

pub fn execute_keyless(
    request: OperationRequest,
) -> rocket_errors::anyhow::Result<Json<OperationResponse>> {
    let input = request
        .input
        .as_object()
        .ok_or_else(|| std::io::Error::other("Operation input must be a JSON object"))?;
    let requirements = input
        .get("requirements")
        .cloned()
        .ok_or_else(|| std::io::Error::other("Missing operation input: requirements"))?;
    let requirements: Vec<crate::models::zkp::Requirement> = serde_json::from_value(requirements)?;
    let requirements = requirements
        .into_iter()
        .map(|requirement| match requirement {
            crate::models::zkp::Requirement::Required { key } => {
                next_gen_signatures::crypto::zkp::ProofRequirement::Required(
                    next_gen_signatures::crypto::zkp::DiscloseRequirement { key },
                )
            }
            crate::models::zkp::Requirement::Circuit {
                circuit_id,
                private_var,
                private_key,
                public_var,
                public_val: (pub_value, pub_datatype),
            } => next_gen_signatures::crypto::zkp::ProofRequirement::Circuit {
                id: circuit_id,
                private_var,
                private_key,
                public_var,
                public_val: zkp::RdfValue::Typed(pub_value, pub_datatype),
            },
        })
        .collect::<Vec<_>>();
    let keys = zkp::generate_circuits(&mut OsRng, &requirements);

    Ok(Json(OperationResponse {
        operation: request.operation,
        status: COMPLETED.to_string(),
        result: Some(json!({
            "provingKeys": keys.proving_keys,
            "verifyingKeys": keys.verifying_keys,
        })),
        operation_id: request.operation_id,
        interaction: None,
    }))
}

fn text(
    input: &serde_json::Map<String, serde_json::Value>,
    name: &str,
) -> rocket_errors::anyhow::Result<String> {
    input
        .get(name)
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .ok_or_else(|| std::io::Error::other(format!("Missing operation input: {name}")).into())
}

fn key_uri(key_id: &str) -> rocket_errors::anyhow::Result<String> {
    if key_id.is_empty() || key_id.contains(['?', '#']) || key_id.split('/').any(str::is_empty) {
        return Err(std::io::Error::other("BBS key ID must be non-empty and path-safe").into());
    }
    Ok(format!("{SCHEME}://{key_id}"))
}

fn key_id(uri: &str) -> Option<&str> {
    uri.strip_prefix(&format!("{SCHEME}://")).filter(|value| {
        !value.is_empty() && !value.contains(['?', '#']) && !value.split('/').any(str::is_empty)
    })
}

fn effective_key_id(
    namespace: Option<&str>,
    key_id: &str,
) -> rocket_errors::anyhow::Result<String> {
    if key_id.is_empty() || key_id.contains(['?', '#', '/']) {
        return Err(std::io::Error::other("BBS key ID must be non-empty and path-safe").into());
    }
    let Some(namespace) = namespace else {
        return Ok(key_id.to_string());
    };
    if !namespace.starts_with("kc/")
        || namespace.len() != 39
        || !namespace[3..]
            .chars()
            .all(|character| character.is_ascii_hexdigit() || character == '-')
    {
        return Err(std::io::Error::other("Invalid keychain namespace").into());
    }
    Ok(format!("{namespace}/{key_id}"))
}

fn key_ref(uri: &str, key: &BbsKey) -> KeyRef {
    KeyRef {
        uri: uri.to_string(),
        public_key_document: json!({
            "kty": "BBS",
            "crv": "BLS12-381-G2",
            "x": &key.public_key,
            "alg": ALGORITHM,
        }),
        algorithm: ALGORITHM.to_string(),
    }
}
