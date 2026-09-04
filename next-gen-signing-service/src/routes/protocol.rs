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

use rocket::http::Status;
use rocket::response::status::Custom;
use rocket::serde::json::Json;
use rocket::{delete, get, post};

use crate::models::protocol::{
    Capabilities, CreateKeyRequest, Health, KeyRef, OperationRequest, OperationResponse,
};
use crate::routes::bbs;

const SCHEME: &str = "next-gen";

#[get("/capabilities")]
pub fn capabilities() -> Json<Capabilities> {
    Json(Capabilities {
        scheme: SCHEME.to_string(),
        supported_algorithms: vec![bbs::ALGORITHM.to_string()],
        digest_signing_algorithms: vec![],
        supported_operations: bbs::operations(),
        keyless_operations: bbs::keyless_operations(),
        can_create: true,
        can_import: false,
        can_delete: true,
    })
}

#[get("/health")]
pub fn health() -> Json<Health> {
    Json(Health { healthy: true })
}

#[get("/keys?<uri>")]
pub fn resolve(uri: String) -> Result<Json<KeyRef>, Status> {
    bbs::resolve(uri)
}

#[post("/keys", data = "<request>")]
pub fn create(
    request: Json<CreateKeyRequest>,
) -> rocket_errors::anyhow::Result<Custom<Json<KeyRef>>> {
    bbs::create(request)
}

#[delete("/keys?<uri>")]
pub fn delete(uri: String) -> Result<Status, Status> {
    bbs::delete(uri)
}

#[post("/operations", data = "<request>")]
pub async fn execute(
    request: Json<OperationRequest>,
) -> rocket_errors::anyhow::Result<Json<OperationResponse>> {
    let request = request.into_inner();
    if !bbs::supports(&request.operation) {
        return Err(std::io::Error::other(format!(
            "Unsupported protocol operation: {}",
            request.operation
        ))
        .into());
    }
    if bbs::supports_keyless(&request.operation) {
        if request.key_uri.is_some() {
            return Err(
                std::io::Error::other("keyUri must be omitted for a keyless operation").into(),
            );
        }
        return bbs::execute_keyless(request);
    }
    bbs::execute(request).await
}
