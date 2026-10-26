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

use std::collections::BTreeMap;
use std::sync::{OnceLock, RwLock};

use rocket::http::Status;
use rocket::serde::json::Json;
use rocket::{get, put};

use crate::models::protocol::{GrantRequest, GrantsRequest};

// Grant policies share the process-local lifecycle of this service's keys.
static GRANTS: OnceLock<RwLock<BTreeMap<String, Vec<GrantRequest>>>> = OnceLock::new();

fn store() -> &'static RwLock<BTreeMap<String, Vec<GrantRequest>>> {
    GRANTS.get_or_init(|| RwLock::new(BTreeMap::new()))
}

#[get("/keys/grants?<scope>")]
pub fn list(scope: String) -> Result<Json<Vec<GrantRequest>>, Status> {
    if scope.trim().is_empty() {
        return Err(Status::BadRequest);
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
pub fn scopes() -> Result<Json<Vec<String>>, Status> {
    let scopes = store()
        .read()
        .map_err(|_| Status::InternalServerError)?
        .keys()
        .cloned()
        .collect();

    Ok(Json(scopes))
}

#[put("/keys/grants", data = "<request>")]
pub fn replace(request: Json<GrantsRequest>) -> Result<Status, Status> {
    let request = request.into_inner();
    if request.scope.trim().is_empty()
        || request
            .grants
            .iter()
            .any(|grant| grant.client.trim().is_empty())
    {
        return Err(Status::BadRequest);
    }

    store()
        .write()
        .map_err(|_| Status::InternalServerError)?
        .insert(request.scope, request.grants);

    Ok(Status::NoContent)
}
