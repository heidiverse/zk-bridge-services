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

use std::collections::{BTreeMap, HashMap};
use std::env;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use ed25519_dalek::{DigestVerifier, Signature, VerifyingKey};
use hmac::{Hmac, Mac};
use rand_core::{OsRng, RngCore};
use rocket::data::{self, Data, FromData, ToByteUnit};
use rocket::http::Status;
use rocket::request::{self, FromRequest, Request};
use rocket::serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256, Sha512};

use crate::models::protocol::SigningPurpose;

const PROVIDER_SCHEME: &str = "next-gen";
const REGISTRATION_TTL_MS: u64 = 5 * 60 * 1_000;
const TIMESTAMP_WINDOW_MS: u64 = 60_000;
const BODY_LIMIT: u64 = 1_048_576;

#[derive(Clone, Copy, Eq, PartialEq)]
enum AuthMode {
    None,
    Registered,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Acceptance {
    AllowList,
    PlatformAssisted,
}

struct Registration {
    client: String,
    psk: Vec<u8>,
    public_key: Option<Vec<u8>>,
    created_at_ms: u64,
    last_use_ms: Option<u64>,
}

struct AuthData {
    clients: BTreeMap<String, Vec<u8>>,
    registrations: HashMap<String, Registration>,
    signatures: HashMap<String, u64>,
}

pub struct AuthState {
    mode: AuthMode,
    acceptance: Acceptance,
    administrator: String,
    data: Mutex<AuthData>,
}

#[derive(Clone)]
pub struct AuthContext {
    client: Option<String>,
    mode: AuthMode,
    administrator: String,
}

impl AuthContext {
    pub fn client(&self) -> Option<&str> {
        self.client.as_deref()
    }

    pub fn require_admin(&self) -> Result<(), Status> {
        if self.mode == AuthMode::None
            || self.client.as_deref() == Some(self.administrator.as_str())
        {
            return Ok(());
        }
        Err(Status::Forbidden)
    }
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct OpenRegistrationRequest {
    pub provider: String,
    pub client: String,
    pub public_key: String,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct OpenRegistrationResponse {
    pub registration_id: String,
    pub psk: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct RegisterPublicKeyRequest {
    pub public_key: String,
    pub signature: String,
}

#[derive(Deserialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct AddClientRequest {
    pub name: String,
    pub public_key: String,
}

#[derive(Serialize)]
#[serde(crate = "rocket::serde", rename_all = "camelCase")]
pub struct ClientResponse {
    name: String,
    registered: bool,
    last_use: Option<String>,
    public_key: String,
}

pub struct SignedRequest(pub AuthContext);

pub struct SignedBody<T> {
    pub body: T,
    pub auth: AuthContext,
}

impl AuthState {
    pub fn from_env() -> Result<Self, String> {
        let mode = match env::var("SIGNING_AUTH_MODE").as_deref() {
            Ok("registered") => AuthMode::Registered,
            Ok("none") | Err(_) => AuthMode::None,
            Ok(_) => return Err("SIGNING_AUTH_MODE must be 'none' or 'registered'".into()),
        };
        let acceptance =
            match env::var("SIGNING_AUTH_CLIENT_ACCEPTANCE").as_deref() {
                Ok("platform-assisted") => Acceptance::PlatformAssisted,
                Ok("allow-list") | Err(_) => Acceptance::AllowList,
                Ok(_) => return Err(
                    "SIGNING_AUTH_CLIENT_ACCEPTANCE must be 'allow-list' or 'platform-assisted'"
                        .into(),
                ),
            };
        let administrator =
            env::var("SIGNING_AUTH_CLIENT_ADMINISTRATOR").unwrap_or_else(|_| "platform".into());
        let configured: BTreeMap<String, String> = env::var("SIGNING_AUTH_CLIENTS")
            .map(|value| serde_json::from_str(&value).map_err(|error| error.to_string()))
            .unwrap_or_else(|_| Ok(BTreeMap::new()))?;
        let clients = configured
            .into_iter()
            .map(|(name, encoded)| {
                let public_key = STANDARD
                    .decode(encoded)
                    .map_err(|error| format!("Invalid public key for client '{name}': {error}"))?;
                if name.trim().is_empty() || public_key.len() != 32 {
                    return Err(format!("Invalid signing client entry: {name}"));
                }
                Ok((name, public_key))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        if mode == AuthMode::Registered && clients.is_empty() {
            return Err(
                "SIGNING_AUTH_CLIENTS must contain an accepted client in registered mode".into(),
            );
        }

        Ok(Self {
            mode,
            acceptance,
            administrator,
            data: Mutex::new(AuthData {
                clients,
                registrations: HashMap::new(),
                signatures: HashMap::new(),
            }),
        })
    }

    pub fn open(
        &self,
        request: OpenRegistrationRequest,
    ) -> Result<OpenRegistrationResponse, Status> {
        if request.provider != PROVIDER_SCHEME || request.client.trim().is_empty() {
            return Err(Status::BadRequest);
        }
        let public_key = STANDARD
            .decode(request.public_key)
            .map_err(|_| Status::BadRequest)?;
        if public_key.len() != 32 {
            return Err(Status::BadRequest);
        }
        let mut data = self.data.lock().map_err(|_| Status::InternalServerError)?;
        if self.mode == AuthMode::Registered && !Self::accepts(&data, &request.client, &public_key)
        {
            return Err(Status::Forbidden);
        }
        let now = now_ms();
        let cutoff = now.saturating_sub(REGISTRATION_TTL_MS);
        data.registrations
            .retain(|_, item| item.public_key.is_some() || item.created_at_ms >= cutoff);
        if let Some((id, registration)) = data.registrations.iter().find(|(_, item)| {
            item.client == request.client && item.public_key.as_deref() == Some(&public_key)
        }) {
            return Ok(OpenRegistrationResponse {
                registration_id: id.clone(),
                psk: STANDARD.encode(&registration.psk),
            });
        }

        let id = new_id();
        let psk = generate_psk(PROVIDER_SCHEME)?;
        data.registrations.insert(
            id.clone(),
            Registration {
                client: request.client,
                psk: psk.clone(),
                public_key: None,
                created_at_ms: now,
                last_use_ms: None,
            },
        );
        Ok(OpenRegistrationResponse {
            registration_id: id,
            psk: STANDARD.encode(psk),
        })
    }

    pub fn register(&self, id: &str, request: RegisterPublicKeyRequest) -> Result<(), Status> {
        let public_key = STANDARD
            .decode(request.public_key)
            .map_err(|_| Status::BadRequest)?;
        let signature = STANDARD
            .decode(request.signature)
            .map_err(|_| Status::BadRequest)?;
        if public_key.len() != 32 || signature.len() != 64 {
            return Err(Status::BadRequest);
        }

        let (client, psk, existing_key) = {
            let data = self.data.lock().map_err(|_| Status::InternalServerError)?;
            let registration = data.registrations.get(id).ok_or(Status::NotFound)?;
            (
                registration.client.clone(),
                registration.psk.clone(),
                registration.public_key.clone(),
            )
        };
        if let Some(existing_key) = existing_key {
            return if existing_key == public_key {
                Ok(())
            } else {
                Err(Status::Conflict)
            };
        }
        {
            let data = self.data.lock().map_err(|_| Status::InternalServerError)?;
            if self.mode == AuthMode::Registered && !Self::accepts(&data, &client, &public_key) {
                return Err(Status::Forbidden);
            }
        }
        verify_proof(&public_key, &psk, None, &public_key, &signature)
            .map_err(|_| Status::Unauthorized)?;

        let mut data = self.data.lock().map_err(|_| Status::InternalServerError)?;
        let registration = data.registrations.get_mut(id).ok_or(Status::NotFound)?;
        if registration.public_key.is_some() {
            return Err(Status::Conflict);
        }
        registration.public_key = Some(public_key);
        Ok(())
    }

    pub fn authenticate(&self, request: &Request<'_>, body: &[u8]) -> Result<AuthContext, Status> {
        if self.mode == AuthMode::None {
            return Ok(self.context(None));
        }

        let id = request
            .headers()
            .get_one("Signing-Authentication")
            .ok_or(Status::Unauthorized)?;
        let timestamp = request
            .headers()
            .get_one("Signing-Authentication-Timestamp")
            .ok_or(Status::Unauthorized)?;
        let purpose = request
            .headers()
            .get_one("Signing-Authentication-Purpose")
            .ok_or(Status::Unauthorized)?;
        let encoded_signature = request
            .headers()
            .get_one("Signing-Authentication-Signature")
            .ok_or(Status::Unauthorized)?;
        let signature = STANDARD
            .decode(encoded_signature)
            .map_err(|_| Status::Unauthorized)?;
        let timestamp_ms = timestamp.parse::<u64>().map_err(|_| Status::Unauthorized)?;
        if now_ms().abs_diff(timestamp_ms) > TIMESTAMP_WINDOW_MS {
            return Err(Status::Unauthorized);
        }
        SigningPurpose::from_wire(purpose).ok_or(Status::Unauthorized)?;
        let path = request.uri().path().as_str();
        if required_purpose(request.method().as_str(), path)
            .is_some_and(|required| required != purpose)
        {
            return Err(Status::Forbidden);
        }

        let (client, psk, public_key) = {
            let data = self.data.lock().map_err(|_| Status::InternalServerError)?;
            let registration = data.registrations.get(id).ok_or(Status::Unauthorized)?;
            let public_key = registration
                .public_key
                .clone()
                .ok_or(Status::Unauthorized)?;
            if !Self::accepts(&data, &registration.client, &public_key) {
                return Err(Status::Forbidden);
            }
            (
                registration.client.clone(),
                registration.psk.clone(),
                public_key,
            )
        };

        let target = request.uri().to_string();
        let mut canonical = Vec::with_capacity(target.len() + body.len() + 16);
        canonical.extend_from_slice(request.method().as_str().as_bytes());
        canonical.push(b'\n');
        canonical.extend_from_slice(target.as_bytes());
        canonical.push(b'\n');
        canonical.extend_from_slice(body);
        let request_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(&canonical));
        let payload = format!("{timestamp}:{purpose}:{request_hash}");
        let key_id = request.headers().get_one("Signing-Authentication-Key-Id");
        verify_proof(&public_key, &psk, key_id, payload.as_bytes(), &signature)
            .map_err(|_| Status::Unauthorized)?;

        let now = now_ms();
        let mut data = self.data.lock().map_err(|_| Status::InternalServerError)?;
        let cutoff = now.saturating_sub(TIMESTAMP_WINDOW_MS);
        data.signatures.retain(|_, used| *used >= cutoff);
        if data.signatures.contains_key(encoded_signature) {
            return Err(Status::Unauthorized);
        }
        data.signatures
            .insert(encoded_signature.to_string(), timestamp_ms);
        if let Some(registration) = data.registrations.get_mut(id) {
            registration.last_use_ms = Some(now);
        }
        Ok(self.context(Some(client)))
    }

    pub fn clients(&self) -> Result<Vec<ClientResponse>, Status> {
        let data = self.data.lock().map_err(|_| Status::InternalServerError)?;
        Ok(data
            .clients
            .iter()
            .map(|(name, public_key)| {
                let matching: Vec<_> = data
                    .registrations
                    .values()
                    .filter(|registration| {
                        registration.client == *name
                            && registration.public_key.as_deref() == Some(public_key)
                    })
                    .collect();
                let last_use_ms = matching.iter().filter_map(|item| item.last_use_ms).max();
                ClientResponse {
                    name: name.clone(),
                    registered: !matching.is_empty(),
                    last_use: last_use_ms.and_then(format_time),
                    public_key: STANDARD.encode(public_key),
                }
            })
            .collect())
    }

    pub fn add_client(&self, client: String, public_key: String) -> Result<(), Status> {
        if self.mode != AuthMode::Registered || self.acceptance != Acceptance::PlatformAssisted {
            return Err(Status::Forbidden);
        }
        if client.trim().is_empty() {
            return Err(Status::BadRequest);
        }
        let public_key = STANDARD
            .decode(public_key)
            .map_err(|_| Status::BadRequest)?;
        if public_key.len() != 32 {
            return Err(Status::BadRequest);
        }
        let mut data = self.data.lock().map_err(|_| Status::InternalServerError)?;
        data.clients.insert(client, public_key);
        Ok(())
    }

    pub fn remove_client(&self, client: &str) -> Result<(), Status> {
        if self.mode != AuthMode::Registered
            || client.trim().is_empty()
            || client == self.administrator
        {
            return Err(Status::BadRequest);
        }
        let mut data = self.data.lock().map_err(|_| Status::InternalServerError)?;
        data.clients.remove(client).ok_or(Status::NotFound)?;
        data.registrations
            .retain(|_, registration| registration.client != client);
        Ok(())
    }

    fn context(&self, client: Option<String>) -> AuthContext {
        AuthContext {
            client,
            mode: self.mode,
            administrator: self.administrator.clone(),
        }
    }

    fn accepts(data: &AuthData, client: &str, public_key: &[u8]) -> bool {
        data.clients
            .get(client)
            .is_some_and(|accepted| accepted.as_slice() == public_key)
    }
}

#[derive(Debug)]
pub struct GuardError;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for SignedRequest {
    type Error = GuardError;

    async fn from_request(request: &'r Request<'_>) -> request::Outcome<Self, Self::Error> {
        let Some(state) = request.rocket().state::<AuthState>() else {
            return request::Outcome::Error((Status::InternalServerError, GuardError));
        };
        match state.authenticate(request, &[]) {
            Ok(context) => request::Outcome::Success(Self(context)),
            Err(status) => request::Outcome::Error((status, GuardError)),
        }
    }
}

#[rocket::async_trait]
impl<'r, T> FromData<'r> for SignedBody<T>
where
    T: DeserializeOwned + Send + 'r,
{
    type Error = GuardError;

    async fn from_data(request: &'r Request<'_>, data: Data<'r>) -> data::Outcome<'r, Self> {
        let bytes = match data.open(BODY_LIMIT.bytes()).into_bytes().await {
            Ok(bytes) if bytes.is_complete() => bytes.value,
            Ok(_) => return data::Outcome::Error((Status::PayloadTooLarge, GuardError)),
            Err(_) => return data::Outcome::Error((Status::BadRequest, GuardError)),
        };
        let Some(state) = request.rocket().state::<AuthState>() else {
            return data::Outcome::Error((Status::InternalServerError, GuardError));
        };
        let auth = match state.authenticate(request, &bytes) {
            Ok(auth) => auth,
            Err(status) => return data::Outcome::Error((status, GuardError)),
        };
        match serde_json::from_slice(&bytes) {
            Ok(body) => data::Outcome::Success(Self { body, auth }),
            Err(_) => data::Outcome::Error((Status::BadRequest, GuardError)),
        }
    }
}

pub fn require_admin(caller: &AuthContext) -> Result<(), Status> {
    caller.require_admin()
}

fn required_purpose(method: &str, path: &str) -> Option<&'static str> {
    if path == "/v1/operations" && method == "POST" {
        return Some("operations");
    }
    if path == "/v1/auth/clients" && matches!(method, "POST" | "DELETE") {
        return Some("key-management");
    }
    if (path == "/v1/keys" || path.starts_with("/v1/keys/")) && method != "GET" {
        return Some("key-management");
    }
    None
}

fn verify_proof(
    public_key: &[u8],
    psk: &[u8],
    key_id: Option<&str>,
    message: &[u8],
    signature: &[u8],
) -> Result<(), ()> {
    let verifying_key = VerifyingKey::try_from(public_key).map_err(|_| ())?;
    if verifying_key.is_weak() {
        return Err(());
    }
    let signature = Signature::from_slice(signature).map_err(|_| ())?;
    let mut context = Vec::with_capacity(psk.len() + key_id.map_or(0, str::len) + 16);
    context.extend_from_slice(b"PASS");
    context.extend_from_slice(psk);
    if let Some(key_id) = key_id.filter(|value| !value.is_empty()) {
        context.extend_from_slice(b"KEY ID");
        context.extend_from_slice(key_id.as_bytes());
    }
    context.extend_from_slice(b"END");
    let context = verifying_key.with_context(&context).map_err(|_| ())?;
    let mut digest = Sha512::new();
    digest.update(message);
    context.verify_digest(digest, &signature).map_err(|_| ())
}

fn generate_psk(provider: &str) -> Result<Vec<u8>, Status> {
    let mut seed = [0u8; 32];
    OsRng.fill_bytes(&mut seed);
    let mut mac =
        <Hmac<Sha256> as Mac>::new_from_slice(&seed).map_err(|_| Status::InternalServerError)?;
    mac.update(b"PROVIDER");
    mac.update(provider.as_bytes());
    mac.update(b"PSK");
    Ok(mac.finalize().into_bytes().to_vec())
}

fn new_id() -> String {
    let mut bytes = [0u8; 16];
    OsRng.fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn format_time(value: u64) -> Option<String> {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(value as i64)
        .map(|date| date.to_rfc3339())
}
