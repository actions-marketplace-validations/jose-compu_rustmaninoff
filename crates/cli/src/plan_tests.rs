use std::fs;
use std::path::Path;

use rustmaninoff_engine::Status;
use rustmaninoff_ir::Framework;

use crate::{scan, ScanRequest, Severity};

fn fixture_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/terraform-plan")
}

#[test]
fn terraform_plan_fail_and_pass_exit_codes() {
    let root = fixture_root();
    let fail = ScanRequest {
        path: root.join("s3_public_fail.tfplan.json"),
        frameworks: vec![Framework::TerraformPlan],
        checks: vec!["CKV_AWS_20".into()],
        skip_checks: Vec::new(),
        fail_on: Severity::High,
        external_dirs: Vec::new(),
        var_files: Vec::new(),
        show_unknown: false,
        show_passed: false,
        compact: false,
        soft_fail: false,
        outputs: vec!["cli".into()],
        json_file: None,
        sarif_file: None,
        junit_file: None,
        excluded: vec![".git".into()],
    };
    let fail_result = scan(&fail).expect("scan fail plan");
    assert_eq!(fail_result.exit_code, 1);
    assert!(fail_result
        .findings
        .iter()
        .any(|f| f.check_id.as_ref() == "CKV_AWS_20" && f.status == Status::Failed));

    let pass = ScanRequest {
        path: root.join("s3_private_pass.tfplan.json"),
        ..fail
    };
    let pass_result = scan(&pass).expect("scan pass plan");
    assert_eq!(pass_result.exit_code, 0);
}

#[test]
fn plan_and_tf_twin_share_check_id() {
    let root = fixture_root();
    let plan = scan(&ScanRequest {
        path: root.join("s3_public_fail.tfplan.json"),
        frameworks: vec![Framework::TerraformPlan],
        checks: vec!["CKV_AWS_20".into()],
        skip_checks: Vec::new(),
        fail_on: Severity::High,
        external_dirs: Vec::new(),
        var_files: Vec::new(),
        show_unknown: false,
        show_passed: false,
        compact: false,
        soft_fail: false,
        outputs: vec!["cli".into()],
        json_file: None,
        sarif_file: None,
        junit_file: None,
        excluded: vec![".git".into()],
    })
    .expect("plan");
    let tf = scan(&ScanRequest {
        path: root.join("s3_public_fail.tf"),
        frameworks: vec![Framework::Terraform],
        checks: vec!["CKV_AWS_20".into()],
        skip_checks: Vec::new(),
        fail_on: Severity::High,
        external_dirs: Vec::new(),
        var_files: Vec::new(),
        show_unknown: false,
        show_passed: false,
        compact: false,
        soft_fail: false,
        outputs: vec!["cli".into()],
        json_file: None,
        sarif_file: None,
        junit_file: None,
        excluded: vec![".git".into()],
    })
    .expect("tf");
    assert_eq!(
        plan.findings
            .iter()
            .find(|f| f.check_id.as_ref() == "CKV_AWS_20")
            .map(|f| f.status),
        tf.findings
            .iter()
            .find(|f| f.check_id.as_ref() == "CKV_AWS_20")
            .map(|f| f.status)
    );
}

#[test]
fn default_scan_ignores_plan_file() {
    let root = fixture_root();
    let dir = std::env::temp_dir().join(format!(
        "rustmaninoff-plan-only-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    fs::copy(
        root.join("s3_public_fail.tfplan.json"),
        dir.join("s3_public_fail.tfplan.json"),
    )
    .unwrap();
    let result = scan(&ScanRequest {
        path: dir.clone(),
        frameworks: vec![
            Framework::Terraform,
            Framework::CloudFormation,
            Framework::Kubernetes,
            Framework::Docker,
        ],
        checks: vec![],
        skip_checks: Vec::new(),
        fail_on: Severity::High,
        external_dirs: Vec::new(),
        var_files: Vec::new(),
        show_unknown: false,
        show_passed: false,
        compact: false,
        soft_fail: false,
        outputs: vec!["cli".into()],
        json_file: None,
        sarif_file: None,
        junit_file: None,
        excluded: vec![".git".into()],
    })
    .expect("default scan");
    assert_eq!(result.exit_code, 0);
    assert!(result
        .findings
        .iter()
        .all(|f| f.check_id.as_ref() != "CKV_AWS_20"));
    let _ = fs::remove_dir_all(dir);
}
