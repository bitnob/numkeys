use assert_cmd::Command;
use predicates::prelude::*;
#[test]
fn test_keygen_json() {
    let mut cmd = Command::cargo_bin("numkeys").unwrap();
    cmd.arg("keygen")
        .assert()
        .success()
        .stdout(predicate::str::contains("private_key"))
        .stdout(predicate::str::contains("public_key"));
}

#[test]
fn test_keygen_base64() {
    let mut cmd = Command::cargo_bin("numkeys").unwrap();
    cmd.args(["keygen", "--format", "base64"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Private key:"))
        .stdout(predicate::str::contains("Public key:"));
}

#[test]
fn test_keygen_hex() {
    let mut cmd = Command::cargo_bin("numkeys").unwrap();
    cmd.args(["keygen", "--format", "hex"])
        .assert()
        .success()
        .stdout(predicate::str::contains("Private key:"))
        .stdout(predicate::str::contains("Public key:"));
}

#[test]
fn test_inspect_jwt() {
    let jwt = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.test.signature";

    let mut cmd = Command::cargo_bin("numkeys").unwrap();
    cmd.args(["inspect", jwt]).assert().failure();
}

#[test]
fn test_help() {
    let mut cmd = Command::cargo_bin("numkeys").unwrap();
    cmd.arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("NumKeys Protocol CLI"));
}

#[test]
fn test_help_uses_numkeys_private_key_env_var() {
    let mut cmd = Command::cargo_bin("numkeys").unwrap();
    cmd.arg("attest")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("NUMKEYS_PRIVATE_KEY"))
        .stdout(predicate::str::contains("Private key file"));
}

#[test]
fn test_keygen_help_uses_numkeys_private_key_env_var() {
    let mut cmd = Command::cargo_bin("numkeys").unwrap();
    cmd.arg("keygen")
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("NUMKEYS_PRIVATE_KEY"))
        .stdout(predicate::str::contains("verification response payloads"));
}

#[test]
fn test_info_uses_current_verification_wording() {
    let mut cmd = Command::cargo_bin("numkeys").unwrap();
    cmd.arg("info")
        .assert()
        .success()
        .stdout(predicate::str::contains("NUMKEYS_PRIVATE_KEY"))
        .stdout(predicate::str::contains(
            "Users sign verification response payloads with their private keys",
        ));
}

#[test]
fn test_version() {
    let mut cmd = Command::cargo_bin("numkeys").unwrap();
    cmd.arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains("numkeys"));
}
