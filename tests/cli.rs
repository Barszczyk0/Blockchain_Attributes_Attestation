use std::error::Error;

use assert_cmd::Command;
use predicates::str::contains;
use tempfile::TempDir;

#[test]
fn test_blockchain_init() -> Result<(), Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let mut cmd = Command::cargo_bin("attributes_attestation")?;

    cmd.current_dir(temp_dir.path())
        .args(["blockchain", "init"])
        .assert()
        .success()
        .stdout(contains("Initialized new blockchain"));

    // Validate files exist
    let expected_files =
        ["blockchain.json", "block.json", "credentials.json", "issuers.json", "subjects.json"];
    for file in expected_files {
        assert!(temp_dir.path().join(file).exists(), "Missing file: {file}");
    }

    Ok(())
}

#[test]
fn test_issuer_add_and_list() -> Result<(), Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path();

    Command::cargo_bin("attributes_attestation")?
        .args(["blockchain", "init"])
        .current_dir(path)
        .assert()
        .success();

    Command::cargo_bin("attributes_attestation")?
        .args(["issuers", "add", "TestIssuer"])  // Changed here
        .current_dir(path)
        .assert()
        .success()
        .stdout(contains("Created new issuer"));

    Command::cargo_bin("attributes_attestation")?
        .args(["issuers", "list"])
        .current_dir(path)
        .assert()
        .success()
        .stdout(contains("TestIssuer"));

    Ok(())
}

#[test]
fn test_subject_add_and_list() -> Result<(), Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path();

    Command::cargo_bin("attributes_attestation")?
        .args(["blockchain", "init"])
        .current_dir(path)
        .assert()
        .success();

    Command::cargo_bin("attributes_attestation")?
        .args(["subjects", "add", "John", "Doe"])  // Changed here
        .current_dir(path)
        .assert()
        .success()
        .stdout(contains("Created new subject"));

    Command::cargo_bin("attributes_attestation")?
        .args(["subjects", "list"])
        .current_dir(path)
        .assert()
        .success()
        .stdout(contains("John"))
        .stdout(contains("Doe"));

    Ok(())
}

#[test]
fn test_credential_add_and_list() -> Result<(), Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path();

    Command::cargo_bin("attributes_attestation")?
        .args(["blockchain", "init"])
        .current_dir(path)
        .assert()
        .success();

    // Add issuer
    Command::cargo_bin("attributes_attestation")?
        .args(["issuers", "add", "IssuerA"])
        .current_dir(path)
        .assert()
        .success();

    // Add subject
    Command::cargo_bin("attributes_attestation")?
        .args(["subjects", "add", "Alice", "Smith"])
        .current_dir(path)
        .assert()
        .success();

    // Add credential with UUIDs
    Command::cargo_bin("attributes_attestation")?
        .args(["credentials", "add", "0", "0", "degree", "PhD", "2024-01-01"])
        .current_dir(path)
        .assert()
        .success()
        .stdout(contains("Created new credential"));

    // List credentials and check presence
    Command::cargo_bin("attributes_attestation")?
        .args(["credentials", "list"])
        .current_dir(path)
        .assert()
        .success()
        .stdout(contains("Alice"))
        .stdout(contains("Smith"))
        .stdout(contains("degree"))
        .stdout(contains("PhD"));

    Ok(())
}

#[test]
fn test_help_command() -> Result<(), Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path();

    Command::cargo_bin("attributes_attestation")?
        .args(["--help"])
        .current_dir(path)
        .assert()
        .success()
        .stdout(contains("Usage"));

    Ok(())
}

#[test]
fn test_invalid_command_fails() -> Result<(), Box<dyn Error>> {
    let temp_dir = TempDir::new()?;
    let path = temp_dir.path();

    Command::cargo_bin("attributes_attestation")?
        .args(["nonexistent", "command"])
        .current_dir(path)
        .assert()
        .failure();

    Ok(())
}
