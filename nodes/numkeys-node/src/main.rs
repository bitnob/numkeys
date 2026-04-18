//! NumKeys HTTP/RPC node for issuing and verifying protocol artifacts.

use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use numkeys_core::{
    attestation::AttestationBuilder, generate_proxy_number, verify_attestation,
    verify_attestation_with_key, ProxyGenerationInput,
};
use numkeys_crypto::{
    generate_hex_nonce, generate_keypair, keypair_from_private, verify_challenge_response,
};
use numkeys_types::{
    Challenge, ChallengeResponse, IssuerInfo, KeyPair, Nonce, PhoneNumber, ProxyNumber, PublicKey,
    VerifiedAttestation,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashSet,
    fs,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tower_http::trace::TraceLayer;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use uuid::Uuid;

#[derive(Debug, Clone)]
struct AppState {
    replay: Arc<Mutex<ReplayTracker>>,
    issuer: Arc<IssuerContext>,
}

impl AppState {
    fn new(issuer: IssuerContext) -> Self {
        Self {
            replay: Arc::new(Mutex::new(ReplayTracker::default())),
            issuer: Arc::new(issuer),
        }
    }
}

#[derive(Debug)]
struct IssuerContext {
    domain: String,
    keypair: KeyPair,
    node_dir: PathBuf,
    private_key_path: PathBuf,
}

#[derive(Debug, Default)]
struct ReplayTracker {
    used_jti: HashSet<String>,
    used_challenge_nonce: HashSet<String>,
    used_response_nonce: HashSet<String>,
}

#[derive(Debug, Deserialize)]
struct CreateChallengeRequest {
    proxy_number: String,
    service_id: String,
    #[serde(default)]
    callback_url: Option<String>,
    #[serde(default)]
    ttl_seconds: Option<u64>,
}

#[derive(Debug, Serialize)]
struct CreateChallengeResponse {
    challenge: Challenge,
}

#[derive(Debug, Deserialize)]
struct IssueAttestationRequest {
    phone_number: String,
    user_pubkey: String,
    scope: String,
}

#[derive(Debug, Serialize)]
struct IssueAttestationResponse {
    proxy_number: String,
    attestation: String,
    issuer: String,
    issuer_public_key: String,
}

#[derive(Debug, Deserialize)]
struct VerifyAttestationRequest {
    attestation_jwt: String,
    #[serde(default)]
    issuer_public_key: Option<String>,
    #[serde(default)]
    max_attestation_age_seconds: Option<i64>,
}

#[derive(Debug, Serialize)]
struct VerifyAttestationResponse {
    valid: bool,
    issuer: String,
    sub: String,
    iat: i64,
    jti: String,
    user_pubkey: String,
}

#[derive(Debug, Deserialize)]
struct VerifyChallengeResponseRequest {
    challenge: Challenge,
    response: ChallengeResponse,
    #[serde(default)]
    issuer_public_key: Option<String>,
    #[serde(default)]
    max_attestation_age_seconds: Option<i64>,
    #[serde(default = "default_true")]
    enforce_single_use: bool,
}

#[derive(Debug, Serialize)]
struct VerifyChallengeResponseResponse {
    valid: bool,
    issuer: String,
    sub: String,
}

#[derive(Debug, Serialize)]
struct StatusResponse {
    ok: bool,
    issuer: String,
    issuer_public_key: String,
    node_dir: String,
    private_key_path: String,
}

fn default_true() -> bool {
    true
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "numkeys_node=debug,tower_http=info".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let bind_address: SocketAddr = std::env::var("BIND_ADDRESS")
        .unwrap_or_else(|_| "127.0.0.1:3200".to_string())
        .parse()?;

    let issuer_context = load_or_init_issuer_context(bind_address)?;
    let app_state = AppState::new(issuer_context);

    let app = Router::new()
        .route("/health", get(health))
        .route("/status", get(status))
        .route("/.well-known/numkeys/pubkey.json", get(issuer_pubkey))
        .route("/create-challenge", post(create_challenge))
        .route("/issue-attestation", post(issue_attestation))
        .route("/verify-attestation", post(verify_attestation_endpoint))
        .route(
            "/verify-challenge-response",
            post(verify_challenge_response_endpoint),
        )
        .layer(TraceLayer::new_for_http())
        .with_state(app_state);

    tracing::info!("NumKeys node listening on {}", bind_address);
    tracing::info!("Endpoints:");
    tracing::info!("  GET    /health");
    tracing::info!("  GET    /status");
    tracing::info!("  GET    /.well-known/numkeys/pubkey.json");
    tracing::info!("  POST   /create-challenge");
    tracing::info!("  POST   /issue-attestation");
    tracing::info!("  POST   /verify-attestation");
    tracing::info!("  POST   /verify-challenge-response");

    let listener = tokio::net::TcpListener::bind(bind_address).await?;
    axum::serve(listener, app).await?;
    Ok(())
}

fn load_or_init_issuer_context(bind_address: SocketAddr) -> anyhow::Result<IssuerContext> {
    let node_dir = resolve_node_dir();
    fs::create_dir_all(node_dir.join("keys"))?;

    let domain = std::env::var("ISSUER_DOMAIN")
        .ok()
        .filter(|d| !d.trim().is_empty())
        .unwrap_or_else(|| format!("localhost:{}", bind_address.port()));

    let private_key_path = std::env::var("PRIVATE_KEY_PATH")
        .ok()
        .map(PathBuf::from)
        .unwrap_or_else(|| node_dir.join("keys").join("private.key"));

    let keypair = load_or_generate_keypair(&private_key_path)?;

    tracing::info!("Issuer domain: {}", domain);
    tracing::info!("Issuer public key: {}", keypair.public.to_base64());
    tracing::info!("Private key path: {}", private_key_path.display());

    Ok(IssuerContext {
        domain,
        keypair,
        node_dir,
        private_key_path,
    })
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({ "ok": true }))
}

async fn status(State(state): State<AppState>) -> Json<StatusResponse> {
    Json(StatusResponse {
        ok: true,
        issuer: state.issuer.domain.clone(),
        issuer_public_key: state.issuer.keypair.public.to_base64(),
        node_dir: state.issuer.node_dir.display().to_string(),
        private_key_path: state.issuer.private_key_path.display().to_string(),
    })
}

async fn issuer_pubkey(
    State(state): State<AppState>,
) -> Result<Json<IssuerInfo>, (StatusCode, Json<serde_json::Value>)> {
    Ok(Json(IssuerInfo {
        public_key: state.issuer.keypair.public.clone(),
        algorithm: "Ed25519".to_string(),
        created_at: Utc::now(),
        key_id: Some("default".to_string()),
        service_info: None,
    }))
}

async fn create_challenge(
    Json(req): Json<CreateChallengeRequest>,
) -> Result<Json<CreateChallengeResponse>, (StatusCode, Json<serde_json::Value>)> {
    let ttl_seconds = req.ttl_seconds.unwrap_or(300);
    if ttl_seconds == 0 || ttl_seconds > 3600 {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_ttl",
            "ttl_seconds must be between 1 and 3600",
        ));
    }

    let proxy_number = ProxyNumber::new(req.proxy_number).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_proxy_number",
            &format!("Invalid proxy number: {}", e),
        )
    })?;

    let challenge = Challenge {
        proxy_number,
        service_id: req.service_id,
        challenge_nonce: Nonce::new(generate_hex_nonce()),
        verification_id: Uuid::new_v4().to_string(),
        expires_at: Utc::now().timestamp_millis() + (ttl_seconds as i64 * 1000),
        callback_url: req.callback_url,
    };

    Ok(Json(CreateChallengeResponse { challenge }))
}

async fn issue_attestation(
    State(state): State<AppState>,
    Json(req): Json<IssueAttestationRequest>,
) -> Result<Json<IssueAttestationResponse>, (StatusCode, Json<serde_json::Value>)> {
    let issuer = state.issuer.as_ref();

    let phone_number = PhoneNumber::new(req.phone_number).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_phone_number",
            &format!("Invalid phone number: {}", e),
        )
    })?;
    let user_pubkey = PublicKey::from_base64(&req.user_pubkey).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "invalid_public_key",
            &format!("Invalid user_pubkey: {}", e),
        )
    })?;

    let generation_nonce = generate_hex_nonce();
    let generation_input = ProxyGenerationInput {
        phone_number: phone_number.to_string(),
        user_pubkey: user_pubkey.to_base64(),
        issuer_domain: issuer.domain.clone(),
        scope: req.scope,
        nonce: generation_nonce.clone(),
    };

    let proxy_number = generate_proxy_number(&generation_input).map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "proxy_generation_failed",
            &format!("Could not generate proxy number: {}", e),
        )
    })?;

    let attestation = AttestationBuilder::new(
        issuer.domain.clone(),
        &issuer.keypair.private,
        phone_number,
        proxy_number.clone(),
        user_pubkey,
    )
    .generation_nonce(generation_nonce)
    .build_jwt()
    .map_err(|e| {
        error_response(
            StatusCode::INTERNAL_SERVER_ERROR,
            "attestation_failed",
            &format!("Failed to issue attestation: {}", e),
        )
    })?;

    Ok(Json(IssueAttestationResponse {
        proxy_number: proxy_number.to_string(),
        attestation,
        issuer: issuer.domain.clone(),
        issuer_public_key: issuer.keypair.public.to_base64(),
    }))
}

async fn verify_attestation_endpoint(
    Json(req): Json<VerifyAttestationRequest>,
) -> Result<Json<VerifyAttestationResponse>, (StatusCode, Json<serde_json::Value>)> {
    let verified = verify_attestation_request(
        &req.attestation_jwt,
        req.issuer_public_key.as_deref(),
        req.max_attestation_age_seconds,
    )
    .await
    .map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "attestation_verification_failed",
            &e,
        )
    })?;

    Ok(Json(VerifyAttestationResponse {
        valid: true,
        issuer: verified.issuer,
        sub: verified.attestation.proxy_number.to_string(),
        iat: verified.attestation.iat.timestamp(),
        jti: verified.attestation.jti,
        user_pubkey: verified.attestation.user_pubkey.to_base64(),
    }))
}

async fn verify_challenge_response_endpoint(
    State(state): State<AppState>,
    Json(req): Json<VerifyChallengeResponseRequest>,
) -> Result<Json<VerifyChallengeResponseResponse>, (StatusCode, Json<serde_json::Value>)> {
    if Utc::now().timestamp_millis() > req.challenge.expires_at {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "challenge_expired",
            "Challenge has expired",
        ));
    }

    if req.response.proxy_number != req.challenge.proxy_number {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "proxy_mismatch",
            "Response proxy number does not match challenge proxy number",
        ));
    }

    if req.response.challenge_response.service_id != req.challenge.service_id
        || req.response.challenge_response.challenge_nonce != req.challenge.challenge_nonce
        || req.response.challenge_response.verification_id != req.challenge.verification_id
    {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "challenge_mismatch",
            "Challenge response payload does not match the challenge",
        ));
    }

    let verified = verify_attestation_request(
        &req.response.attestation_jwt,
        req.issuer_public_key.as_deref(),
        req.max_attestation_age_seconds,
    )
    .await
    .map_err(|e| {
        error_response(
            StatusCode::BAD_REQUEST,
            "attestation_verification_failed",
            &e,
        )
    })?;

    if verified.attestation.proxy_number != req.challenge.proxy_number {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "attested_proxy_mismatch",
            "Attestation proxy does not match challenge proxy",
        ));
    }

    if !verify_challenge_response(
        &verified.attestation.user_pubkey,
        &req.response.challenge_response,
        &req.response.user_signature,
    ) {
        return Err(error_response(
            StatusCode::BAD_REQUEST,
            "invalid_user_signature",
            "Challenge response signature is invalid",
        ));
    }

    if req.enforce_single_use {
        mark_replay_values_used(&state, &verified, &req.response)
            .map_err(|e| error_response(StatusCode::BAD_REQUEST, "replay_detected", &e))?;
    }

    Ok(Json(VerifyChallengeResponseResponse {
        valid: true,
        issuer: verified.issuer,
        sub: verified.attestation.proxy_number.to_string(),
    }))
}

fn mark_replay_values_used(
    state: &AppState,
    verified: &VerifiedAttestation,
    response: &ChallengeResponse,
) -> Result<(), String> {
    let mut replay = state
        .replay
        .lock()
        .map_err(|_| "Replay tracker lock poisoned".to_string())?;

    if replay.used_jti.contains(&verified.attestation.jti) {
        return Err("Attestation jti has already been used".to_string());
    }
    if replay
        .used_challenge_nonce
        .contains(response.challenge_response.challenge_nonce.as_str())
    {
        return Err("Challenge nonce has already been used".to_string());
    }
    if replay
        .used_response_nonce
        .contains(response.challenge_response.response_nonce.as_str())
    {
        return Err("Response nonce has already been used".to_string());
    }

    replay.used_jti.insert(verified.attestation.jti.clone());
    replay.used_challenge_nonce.insert(
        response
            .challenge_response
            .challenge_nonce
            .as_str()
            .to_string(),
    );
    replay.used_response_nonce.insert(
        response
            .challenge_response
            .response_nonce
            .as_str()
            .to_string(),
    );

    Ok(())
}

async fn verify_attestation_request(
    attestation_jwt: &str,
    issuer_public_key: Option<&str>,
    max_attestation_age_seconds: Option<i64>,
) -> Result<VerifiedAttestation, String> {
    let verified = if let Some(pubkey_b64) = issuer_public_key {
        let key = PublicKey::from_base64(pubkey_b64)
            .map_err(|e| format!("Invalid issuer_public_key: {}", e))?;
        verify_attestation_with_key(attestation_jwt, &key)
            .map_err(|e| format!("Attestation verification failed: {}", e))?
    } else {
        verify_attestation(attestation_jwt)
            .await
            .map_err(|e| format!("Attestation verification failed: {}", e))?
    };

    if let Some(max_age) = max_attestation_age_seconds {
        if max_age < 0 {
            return Err("max_attestation_age_seconds must be non-negative".to_string());
        }
        let now = Utc::now().timestamp();
        let iat = verified.attestation.iat.timestamp();
        if iat > now + 300 {
            return Err("Attestation iat is too far in the future".to_string());
        }
        if now - iat > max_age {
            return Err("Attestation is older than max_attestation_age_seconds".to_string());
        }
    }

    Ok(verified)
}

fn error_response(
    status: StatusCode,
    code: &str,
    description: &str,
) -> (StatusCode, Json<serde_json::Value>) {
    (
        status,
        Json(json!({
            "error": code,
            "error_description": description,
        })),
    )
}

fn resolve_node_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("NUMKEYS_NODE_DIR") {
        return PathBuf::from(dir);
    }
    if let Ok(home) = std::env::var("HOME") {
        return Path::new(&home).join(".numkeys").join("node");
    }
    PathBuf::from(".numkeys-node")
}

fn load_or_generate_keypair(private_key_path: &Path) -> anyhow::Result<KeyPair> {
    if private_key_path.exists() {
        let key_data = fs::read_to_string(private_key_path)?;
        let private_key = numkeys_types::PrivateKey::from_base64(key_data.trim())?;
        return Ok(keypair_from_private(&private_key)?);
    }

    let keypair = generate_keypair()?;
    if let Some(parent) = private_key_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(private_key_path, keypair.private.to_base64())?;
    Ok(keypair)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{to_bytes, Body};
    use numkeys_crypto::{generate_keypair, sign_challenge_response};
    use numkeys_types::ChallengeResponsePayload;
    use serde_json::Value;
    use tower::util::ServiceExt;

    async fn response_json(response: axum::response::Response) -> Value {
        let body = to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body bytes");
        serde_json::from_slice(&body).expect("valid json")
    }

    fn test_issuer() -> IssuerContext {
        let private = numkeys_types::PrivateKey::from_bytes([7u8; 32]);
        let keypair = keypair_from_private(&private).unwrap();
        IssuerContext {
            domain: "issuer.example.com".to_string(),
            keypair,
            node_dir: PathBuf::from("/tmp/numkeys-node-test"),
            private_key_path: PathBuf::from("/tmp/numkeys-node-test/private.key"),
        }
    }

    #[tokio::test]
    async fn test_health_and_create_challenge() {
        let issuer = test_issuer();
        let app = Router::new()
            .route("/health", get(health))
            .route("/status", get(status))
            .route("/.well-known/numkeys/pubkey.json", get(issuer_pubkey))
            .route("/create-challenge", post(create_challenge))
            .with_state(AppState::new(issuer));

        let health_res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(health_res.status(), StatusCode::OK);

        let payload = json!({
            "proxy_number": "+1002002040155",
            "service_id": "chat.example.com"
        });
        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/create-challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_pubkey_success() {
        let issuer = test_issuer();
        let app = Router::new()
            .route("/.well-known/numkeys/pubkey.json", get(issuer_pubkey))
            .with_state(AppState::new(issuer));

        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .uri("/.well-known/numkeys/pubkey.json")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_issue_attestation_success() {
        let issuer = test_issuer();
        let app = Router::new()
            .route("/issue-attestation", post(issue_attestation))
            .with_state(AppState::new(issuer));

        let payload = json!({
            "phone_number": "+1234567890",
            "user_pubkey": numkeys_crypto::generate_keypair().unwrap().public.to_base64(),
            "scope": "1"
        });
        let res = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/issue-attestation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(res.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_verify_attestation_success_and_failure() {
        let app = Router::new()
            .route("/issue-attestation", post(issue_attestation))
            .route("/verify-attestation", post(verify_attestation_endpoint))
            .with_state(AppState::new(test_issuer()));

        let user = generate_keypair().unwrap();
        let issue_payload = json!({
            "phone_number": "+1234567890",
            "user_pubkey": user.public.to_base64(),
            "scope": "1"
        });
        let issue_res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/issue-attestation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&issue_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(issue_res.status(), StatusCode::OK);
        let issue_json = response_json(issue_res).await;
        let attestation = issue_json["attestation"].as_str().unwrap();
        let issuer_public_key = issue_json["issuer_public_key"].as_str().unwrap();

        let verify_payload = json!({
            "attestation_jwt": attestation,
            "issuer_public_key": issuer_public_key,
            "max_attestation_age_seconds": 3600
        });
        let verify_res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/verify-attestation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&verify_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_res.status(), StatusCode::OK);
        let verify_json = response_json(verify_res).await;
        assert_eq!(verify_json["valid"], json!(true));

        // Tamper the JWT to force signature verification failure.
        let mut tampered = attestation.to_string();
        let last = tampered.pop().unwrap();
        tampered.push(if last == 'A' { 'B' } else { 'A' });
        let bad_payload = json!({
            "attestation_jwt": tampered,
            "issuer_public_key": issuer_public_key
        });
        let bad_res = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/verify-attestation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&bad_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(bad_res.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn test_verify_challenge_response_and_replay_rejection() {
        let app = Router::new()
            .route("/create-challenge", post(create_challenge))
            .route("/issue-attestation", post(issue_attestation))
            .route(
                "/verify-challenge-response",
                post(verify_challenge_response_endpoint),
            )
            .with_state(AppState::new(test_issuer()));

        let user = generate_keypair().unwrap();
        let issue_payload = json!({
            "phone_number": "+1234567890",
            "user_pubkey": user.public.to_base64(),
            "scope": "1"
        });
        let issue_res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/issue-attestation")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&issue_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(issue_res.status(), StatusCode::OK);
        let issue_json = response_json(issue_res).await;
        let attestation = issue_json["attestation"].as_str().unwrap().to_string();
        let issuer_public_key = issue_json["issuer_public_key"]
            .as_str()
            .unwrap()
            .to_string();
        let proxy_number = issue_json["proxy_number"].as_str().unwrap().to_string();

        let challenge_payload = json!({
            "proxy_number": proxy_number,
            "service_id": "chat.example.com",
            "ttl_seconds": 300
        });
        let challenge_res = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/create-challenge")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&challenge_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(challenge_res.status(), StatusCode::OK);
        let challenge_json = response_json(challenge_res).await;
        let challenge: Challenge =
            serde_json::from_value(challenge_json["challenge"].clone()).unwrap();

        let payload = ChallengeResponsePayload {
            service_id: challenge.service_id.clone(),
            challenge_nonce: challenge.challenge_nonce.clone(),
            response_nonce: Nonce::new("wallet-response-nonce-001"),
            verification_id: challenge.verification_id.clone(),
            timestamp: Utc::now().timestamp_millis(),
        };
        let signature = sign_challenge_response(&user.private, &payload).unwrap();
        let response = ChallengeResponse {
            proxy_number: challenge.proxy_number.clone(),
            attestation_jwt: attestation.clone(),
            challenge_response: payload,
            user_signature: signature,
        };

        let verify_payload = json!({
            "challenge": challenge,
            "response": response,
            "issuer_public_key": issuer_public_key,
            "max_attestation_age_seconds": 3600,
            "enforce_single_use": true
        });

        let verify_res_1 = app
            .clone()
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/verify-challenge-response")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&verify_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_res_1.status(), StatusCode::OK);
        let verify_json_1 = response_json(verify_res_1).await;
        assert_eq!(verify_json_1["valid"], json!(true));

        // Re-send the same request; replay protection must reject it.
        let verify_res_2 = app
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/verify-challenge-response")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&verify_payload).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(verify_res_2.status(), StatusCode::BAD_REQUEST);
        let verify_json_2 = response_json(verify_res_2).await;
        assert_eq!(verify_json_2["error"], json!("replay_detected"));
    }

    #[test]
    fn test_resolve_node_dir_prefers_env() {
        let key = "NUMKEYS_NODE_DIR";
        let prev = std::env::var(key).ok();
        std::env::set_var(key, "/tmp/numkeys-node-dir-test");
        let dir = resolve_node_dir();
        assert_eq!(dir, PathBuf::from("/tmp/numkeys-node-dir-test"));
        if let Some(v) = prev {
            std::env::set_var(key, v);
        } else {
            std::env::remove_var(key);
        }
    }
}
