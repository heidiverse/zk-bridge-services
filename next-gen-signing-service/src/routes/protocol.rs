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

use crate::auth::{self, SignedBody, SignedRequest};
use crate::models::protocol::{
    Capabilities, CreateKeyRequest, Health, KeyRef, OperationRequest, OperationResponse,
    SigningPurpose,
};
use crate::routes::{bbs, grants};

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
pub fn health(_auth: SignedRequest) -> Json<Health> {
    Json(Health { healthy: true })
}

#[get("/keys?<uri>")]
pub fn resolve(uri: String, auth: SignedRequest) -> Result<Json<KeyRef>, Status> {
    if let Some(client) = auth.0.client() {
        grants::require_any(client, &uri)?;
    }
    bbs::resolve(uri)
}

#[post("/keys", data = "<request>")]
pub fn create(request: SignedBody<CreateKeyRequest>) -> Result<Custom<Json<KeyRef>>, Status> {
    let auth = request.auth;
    auth::require_admin(&auth)?;
    let created = bbs::create(Json(request.body)).map_err(|_| Status::InternalServerError)?;
    if let Some(client) = auth.client() {
        let uri = (created.1).0.uri.clone();
        grants::initialise(&uri, Some(client))?;
        grants::initialise(&grants::key_scope(&uri), Some(client))?;
    }
    Ok(created)
}

#[delete("/keys?<uri>")]
pub fn delete(uri: String, auth: SignedRequest) -> Result<Status, Status> {
    auth::require_admin(&auth.0)?;
    if let Some(client) = auth.0.client() {
        grants::require(client, &uri, SigningPurpose::KeyManagement)?;
    }
    bbs::delete(uri)
}

#[post("/operations", data = "<request>")]
pub async fn execute(
    request: SignedBody<OperationRequest>,
) -> Result<Json<OperationResponse>, Status> {
    let auth = request.auth;
    let request = request.body;
    if !bbs::supports(&request.operation) {
        return Err(Status::NotImplemented);
    }
    if bbs::supports_keyless(&request.operation) {
        if request.key_uri.is_some() {
            return Err(Status::BadRequest);
        }
        if let Some(client) = auth.client() {
            grants::require(
                client,
                &format!("op/{}", request.operation),
                SigningPurpose::Operations,
            )?;
        }
        return bbs::execute_keyless(request).map_err(|_| Status::InternalServerError);
    }
    let key_uri = request.key_uri.as_deref().ok_or(Status::BadRequest)?;
    if let Some(client) = auth.client() {
        grants::require(client, key_uri, SigningPurpose::Operations)?;
    }
    bbs::execute(request)
        .await
        .map_err(|_| Status::InternalServerError)
}
