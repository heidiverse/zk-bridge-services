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

use rocket::serde;
use serde_json::Value;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct CreateKeyRequest {
    pub key_id: String,
    pub algorithm: String,
    pub namespace: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct KeyRef {
    pub uri: String,
    pub public_key_document: Value,
    pub algorithm: String,
}

#[derive(Debug, serde::Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct Capabilities {
    pub scheme: String,
    pub supported_algorithms: Vec<String>,
    pub digest_signing_algorithms: Vec<String>,
    pub supported_operations: Vec<String>,
    pub keyless_operations: Vec<String>,
    pub can_create: bool,
    pub can_import: bool,
    pub can_delete: bool,
}

#[derive(Debug, serde::Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct Health {
    pub healthy: bool,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct OperationRequest {
    pub operation: String,
    pub operation_id: Option<String>,
    pub key_uri: Option<String>,
    pub input: Value,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct OperationResponse {
    pub operation: String,
    pub status: String,
    pub result: Option<Value>,
    pub operation_id: Option<String>,
    pub interaction: Option<Value>,
}
