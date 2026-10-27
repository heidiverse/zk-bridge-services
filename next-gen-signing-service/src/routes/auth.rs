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
use rocket::serde::json::Json;
use rocket::{delete, get, post, State};

use crate::auth::{
    self, AddClientRequest, AuthState, ClientResponse, OpenRegistrationRequest,
    OpenRegistrationResponse, RegisterPublicKeyRequest, SignedBody, SignedRequest,
};

#[post("/auth/registrations", data = "<request>")]
pub fn open_registration(
    request: Json<OpenRegistrationRequest>,
    state: &State<AuthState>,
) -> Result<Json<OpenRegistrationResponse>, Status> {
    state.open(request.into_inner()).map(Json)
}

#[post("/auth/registrations/<registration_id>/key", data = "<request>")]
pub fn register_public_key(
    registration_id: &str,
    request: Json<RegisterPublicKeyRequest>,
    state: &State<AuthState>,
) -> Result<Status, Status> {
    state.register(registration_id, request.into_inner())?;
    Ok(Status::NoContent)
}

#[get("/auth/clients")]
pub fn clients(
    _auth: SignedRequest,
    state: &State<AuthState>,
) -> Result<Json<Vec<ClientResponse>>, Status> {
    state.clients().map(Json)
}

#[post("/auth/clients", data = "<request>")]
pub fn add_client(
    request: SignedBody<AddClientRequest>,
    state: &State<AuthState>,
) -> Result<Status, Status> {
    auth::require_admin(&request.auth)?;
    state.add_client(request.body.name, request.body.public_key)?;
    Ok(Status::NoContent)
}

#[delete("/auth/clients?<name>")]
pub fn remove_client(
    name: String,
    auth: SignedRequest,
    state: &State<AuthState>,
) -> Result<Status, Status> {
    auth::require_admin(&auth.0)?;
    state.remove_client(&name)?;
    Ok(Status::NoContent)
}
