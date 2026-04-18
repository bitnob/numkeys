use numkeys_core::attestation::claims::Claims;
use numkeys_core::attestation::jwt::decode_jwt;
use numkeys_core::{parse_attestation, validate_attestation};
use numkeys_crypto::verify_challenge_response;
use numkeys_types::{Challenge, ChallengeResponsePayload, PublicKey, Signature};
use serde::Deserialize;

#[derive(Deserialize)]
struct VectorSet {
    attestation: AttestationVectors,
    challenge_response: ChallengeVectors,
}

#[derive(Deserialize)]
struct AttestationVectors {
    issuer_public_key: String,
    wrong_issuer_public_key: String,
    user_public_key: String,
    valid_jwt: String,
    expired_jwt: String,
    tampered_signature_jwt: String,
    proxy_number: String,
}

#[derive(Deserialize)]
struct ChallengeVectors {
    challenge: Challenge,
    payload: ChallengeResponsePayload,
    user_signature: String,
    tampered_user_signature: String,
}

#[test]
fn published_attestation_vectors_verify_as_expected() {
    let fixture: VectorSet = serde_json::from_str(include_str!("fixtures/v1.json")).unwrap();

    let issuer_key = PublicKey::from_base64(&fixture.attestation.issuer_public_key).unwrap();
    let wrong_issuer_key =
        PublicKey::from_base64(&fixture.attestation.wrong_issuer_public_key).unwrap();

    let claims: Claims = decode_jwt(&fixture.attestation.valid_jwt, &issuer_key).unwrap();
    let attestation = claims.to_attestation().unwrap();
    assert_eq!(attestation.iss, "issuer.example.com");
    assert_eq!(
        attestation.proxy_number.as_str(),
        fixture.attestation.proxy_number.as_str()
    );

    let expired = parse_attestation(&fixture.attestation.expired_jwt).unwrap();
    assert!(validate_attestation(&expired).is_ok());

    assert!(decode_jwt::<Claims>(&fixture.attestation.valid_jwt, &wrong_issuer_key).is_err());
    assert!(
        decode_jwt::<Claims>(&fixture.attestation.tampered_signature_jwt, &issuer_key).is_err()
    );
}

#[test]
fn published_challenge_vectors_verify_as_expected() {
    let fixture: VectorSet = serde_json::from_str(include_str!("fixtures/v1.json")).unwrap();
    let user_key = PublicKey::from_base64(&fixture.attestation.user_public_key).unwrap();
    let signature = Signature::from_base64(&fixture.challenge_response.user_signature).unwrap();

    assert_eq!(
        fixture.challenge_response.challenge.service_id,
        fixture.challenge_response.payload.service_id
    );
    assert_eq!(
        fixture.challenge_response.challenge.challenge_nonce,
        fixture.challenge_response.payload.challenge_nonce
    );
    assert_eq!(
        fixture.challenge_response.challenge.verification_id,
        fixture.challenge_response.payload.verification_id
    );

    assert!(verify_challenge_response(
        &user_key,
        &fixture.challenge_response.payload,
        &signature,
    ));
    match Signature::from_base64(&fixture.challenge_response.tampered_user_signature) {
        Ok(tampered) => {
            assert!(!verify_challenge_response(
                &user_key,
                &fixture.challenge_response.payload,
                &tampered,
            ));
        }
        Err(_) => {}
    }
}
