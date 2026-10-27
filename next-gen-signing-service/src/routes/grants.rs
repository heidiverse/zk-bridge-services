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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{OnceLock, RwLock};

use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, put};

use crate::auth::{self, SignedBody, SignedRequest};
use crate::models::protocol::{GrantRequest, GrantsRequest, SigningPurpose};

// Grant policies share the process-local lifecycle of this service's keys.
static GRANTS: OnceLock<RwLock<BTreeMap<String, Vec<GrantRequest>>>> = OnceLock::new();

fn store() -> &'static RwLock<BTreeMap<String, Vec<GrantRequest>>> {
    GRANTS.get_or_init(|| RwLock::new(BTreeMap::new()))
}

pub fn has_policy(scope: &str) -> Result<bool, Status> {
    Ok(store()
        .read()
        .map_err(|_| Status::InternalServerError)?
        .contains_key(scope))
}

pub fn require_any(client: &str, scope: &str) -> Result<(), Status> {
    let policies = store().read().map_err(|_| Status::InternalServerError)?;
    if policies
        .get(scope)
        .is_some_and(|grants| grants.iter().any(|grant| grant.client == client))
    {
        return Ok(());
    }
    Err(Status::Forbidden)
}

pub fn require(client: &str, scope: &str, purpose: SigningPurpose) -> Result<(), Status> {
    let policies = store().read().map_err(|_| Status::InternalServerError)?;
    if policies.get(scope).is_some_and(|grants| {
        grants
            .iter()
            .any(|grant| grant.client == client && grant.purposes.contains(&purpose))
    }) {
        return Ok(());
    }
    Err(Status::Forbidden)
}

pub fn initialise(scope: &str, creator: Option<&str>) -> Result<(), Status> {
    let Some(creator) = creator else {
        return Ok(());
    };
    let mut policies = store().write().map_err(|_| Status::InternalServerError)?;
    policies.entry(scope.to_string()).or_insert_with(|| {
        vec![GrantRequest {
            client: creator.to_string(),
            purposes: BTreeSet::from([SigningPurpose::KeyManagement]),
        }]
    });
    Ok(())
}

pub fn key_scope(uri: &str) -> String {
    let key_id = uri.split_once("://").map_or(uri, |(_, key_id)| key_id);
    if !key_id.starts_with("kc/") {
        return key_id.to_string();
    }
    let version = key_id["kc/".len()..]
        .find('/')
        .map(|index| index + "kc/".len())
        .unwrap_or(key_id.len());
    key_id[..version].to_string()
}

#[get("/keys/grants?<scope>")]
pub fn list(scope: String, auth: SignedRequest) -> Result<Json<Vec<GrantRequest>>, Status> {
    if scope.trim().is_empty() {
        return Err(Status::BadRequest);
    }
    if let Some(client) = auth.0.client() {
        require_any(client, &scope)?;
    }

    let grants = store()
        .read()
        .map_err(|_| Status::InternalServerError)?
        .get(&scope)
        .cloned()
        .unwrap_or_default();

    Ok(Json(grants))
}

#[get("/keys/grants/scopes")]
pub fn scopes(auth: SignedRequest) -> Result<Json<Vec<String>>, Status> {
    auth::require_admin(&auth.0)?;
    let scopes = store()
        .read()
        .map_err(|_| Status::InternalServerError)?
        .keys()
        .cloned()
        .collect();

    Ok(Json(scopes))
}

#[put("/keys/grants", data = "<request>")]
pub fn replace(request: SignedBody<GrantsRequest>) -> Result<Status, Status> {
    let auth = request.auth;
    let request = request.body;
    if request.scope.trim().is_empty()
        || request
            .grants
            .iter()
            .any(|grant| grant.client.trim().is_empty())
    {
        return Err(Status::BadRequest);
    }
    if let Some(client) = auth.client() {
        if has_policy(&request.scope)? {
            require(client, &request.scope, SigningPurpose::KeyManagement)?;
        } else {
            auth::require_admin(&auth)?;
        }
    }

    store()
        .write()
        .map_err(|_| Status::InternalServerError)?
        .insert(request.scope, request.grants);

    Ok(Status::NoContent)
}
