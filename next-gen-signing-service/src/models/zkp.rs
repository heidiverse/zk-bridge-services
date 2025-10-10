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

use rocket::serde;
use serde_json::Value as JsonValue;

use crate::models::common::encodings::base64url;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct IssuanceParams {
    /// JSON-LD encoded claims that should be issued
    pub claims: JsonValue,

    /// Multibase encoded public key of the issuer
    pub issuer_pk: String,
    /// Multibase encoded secret key of the issuer
    pub issuer_sk: String,
    /// Issuer identifier
    pub issuer_id: String,
    /// Issuer key identifier
    pub issuer_key_id: String,

    /// ISO-8601 DateTime of when the credential should be valid
    pub issuance_date: Option<String>,
    /// ISO-8061 DateTime of when the credential was created
    pub created_date: Option<String>,
    /// ISO-8061 DateTime of when the credential should expire
    pub expiration_date: Option<String>,

    /// BASE64 encoded x,y coordinates (big endian bytes) of
    /// the device binding public key, on the P256 curve.
    pub device_binding: Option<(String, String)>,

    /// Optional type of the verifiable credential.
    pub vc_type: Option<String>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde", tag = "type")]
pub enum Requirement {
    #[serde(rename = "required")]
    Required { key: String },

    #[serde(rename = "circuit")]
    Circuit {
        /// The id of the circuit to use in the proof.
        circuit_id: String,
        /// The name of the private variable.
        private_var: String,
        /// The key in the claims that points to the
        /// variable the proof should be done with.
        private_key: String,
        /// The name of the public variable.
        public_var: String,
        /// The (value, datatype) of the public variable.
        public_val: (String, String),
    },
}

pub type VerifiableCredential = String;

pub type ProvingKeys = HashMap<String, String>;
pub type VerifyingKeys = HashMap<String, String>;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct CircuitKeys {
    /// Mapping from circuit id to the key used to
    /// prove said circuit.
    pub proving_keys: ProvingKeys,

    /// Mapping from circuit id to the key used to
    /// verify said circuit.
    pub verifying_keys: VerifyingKeys,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct PresentationParams {
    /// The verifiable credential that should be
    /// presented.
    pub verifiable_credential: VerifiableCredential,

    /// The requirements that should be met when
    /// presenting the credential.
    pub requirements: Vec<Requirement>,

    /// Optional device binding that should be presented.
    pub device_binding: Option<DBPresentationParams>,

    /// The keys used to prove the circuits that
    /// will be used in the presentation
    pub proving_keys: ProvingKeys,

    /// Multibase encoded public key of the issuer
    /// that issued the verifiable credential.
    pub issuer_pk: String,
    /// Issuer identifier of the issuer that issued
    /// the verifiable credential.
    pub issuer_id: String,
    /// Issuer key identifier of the key that was
    /// used to issue the verifiable credential.
    pub issuer_key_id: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct DBPresentationParams {
    #[serde(with = "base64url")]
    pub public_key: Vec<u8>,

    #[serde(with = "base64url")]
    pub message: Vec<u8>,

    #[serde(with = "base64url")]
    pub message_signature: Vec<u8>,

    #[serde(with = "base64url")]
    pub comm_key_secp_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub comm_key_tom_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub comm_key_bls_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub bpp_setup_label: Vec<u8>,
}

pub type VerifiablePresentation = String;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct VerificationParams {
    /// The presentation that should be verified.
    pub presentation: VerifiablePresentation,

    /// The requirements that should be met when
    /// verifying the presentation.
    pub requirements: Vec<Requirement>,

    /// Optional device binding that should be checked.
    pub device_binding: Option<DBPVerificationParams>,

    /// The keys used to verify the circuits that
    /// were used in the presentation.
    pub verifying_keys: VerifyingKeys,

    /// Multibase encoded public key of the issuer
    /// that issued the verifiable credential.
    pub issuer_pk: String,
    /// Issuer identifier of the issuer that issued
    /// the verifiable credential.
    pub issuer_id: String,
    /// Issuer key identifier of the key that was
    /// used to issue the verifiable credential.
    pub issuer_key_id: String,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(crate = "rocket::serde")]
pub struct DBPVerificationParams {
    #[serde(with = "base64url")]
    pub message: Vec<u8>,

    #[serde(with = "base64url")]
    pub comm_key_secp_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub comm_key_tom_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub comm_key_bls_label: Vec<u8>,

    #[serde(with = "base64url")]
    pub bpp_setup_label: Vec<u8>,
}
