use std::fs;
use std::path::PathBuf;
use std::process::Command;

use assert_cmd::cargo::cargo_bin_cmd;
use predicates::boolean::PredicateBooleanExt;

fn matrix_fixture() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../testdata/terraform-plan/sensitive_matrix.tfplan.json")
}

fn temp_copy() -> PathBuf {
    let dst = std::env::temp_dir().join(format!(
        "rustmaninoff-sensitive-e2e-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dst).unwrap();
    fs::copy(matrix_fixture(), dst.join("plan.tfplan.json")).unwrap();
    dst
}

const CANARY: &str = "SENSITIVE_CANARY_";

fn run_scan(args: &[&str]) -> assert_cmd::assert::Assert {
    let dir = temp_copy();
    let path = dir.join("plan.tfplan.json");
    let mut cmd = cargo_bin_cmd!("rustmaninoff");
    cmd.arg("scan")
        .arg(&path)
        .arg("--framework")
        .arg("terraform_plan")
        .arg("--check")
        .arg("CKV_AWS_20");
    for arg in args {
        cmd.arg(arg);
    }
    cmd.assert()
}

#[test]
fn e2e_cli_output_has_no_canaries() {
    run_scan(&["--output", "cli", "--show-passed", "--show-unknown"])
        .failure()
        .stdout(predicates::str::contains("CKV_AWS_20"))
        .stdout(predicates::str::contains(CANARY).not());
}

#[test]
fn e2e_json_output_has_no_canaries() {
    run_scan(&["--output", "json", "--show-passed"])
        .failure()
        .stdout(predicates::str::contains(CANARY).not());
}

#[test]
fn e2e_sarif_output_has_no_canaries() {
    run_scan(&["--output", "sarif"])
        .failure()
        .stdout(predicates::str::contains(CANARY).not());
}

#[test]
fn e2e_junit_output_has_no_canaries() {
    run_scan(&["--output", "junit"])
        .failure()
        .stdout(predicates::str::contains(CANARY).not());
}

#[test]
fn e2e_compact_cli_has_no_canaries() {
    run_scan(&["--output", "cli", "--compact"])
        .failure()
        .stdout(predicates::str::contains(CANARY).not());
}

#[test]
fn e2e_stderr_has_no_canaries_on_successful_scan() {
    let dir = temp_copy();
    let path = dir.join("plan.tfplan.json");
    let assert = Command::new(env!("CARGO_BIN_EXE_rustmaninoff"))
        .arg("scan")
        .arg(&path)
        .arg("--framework")
        .arg("terraform_plan")
        .output()
        .expect("run");
    let stderr = String::from_utf8_lossy(&assert.stderr);
    let stdout = String::from_utf8_lossy(&assert.stdout);
    assert!(!stderr.contains(CANARY));
    assert!(!stdout.contains(CANARY));
}
