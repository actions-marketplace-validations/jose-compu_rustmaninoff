use std::fs;
use std::path::Path;

use rustmaninoff_engine::Status;
use rustmaninoff_ir::Framework;
use rustmaninoff_parser_terraform::PlanScope;

use rustmaninoff_report::{
    render_json, render_junit, render_sarif, render_text, RenderOptions, SarifOptions,
};

use crate::{parse_plan_scope, scan, ScanRequest, Severity};

const SECRET_MARKER: &str = "SENSITIVE_CANARY_LEGACY_1";

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
        plan_scope: PlanScope::Changes,
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
        plan_scope: PlanScope::Changes,
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
        plan_scope: PlanScope::Changes,
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
        plan_scope: PlanScope::Changes,
    })
    .expect("default scan");
    assert_eq!(result.exit_code, 0);
    assert!(result
        .findings
        .iter()
        .all(|f| f.check_id.as_ref() != "CKV_AWS_20"));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn sensitive_plan_values_never_appear_in_report_outputs() {
    let root = fixture_root();
    let request = ScanRequest {
        path: root.join("s3_nested_sensitive_fail.tfplan.json"),
        frameworks: vec![Framework::TerraformPlan],
        checks: vec!["CKV_AWS_20".into()],
        skip_checks: Vec::new(),
        fail_on: Severity::High,
        external_dirs: Vec::new(),
        var_files: Vec::new(),
        show_unknown: true,
        show_passed: true,
        compact: false,
        soft_fail: false,
        outputs: vec!["cli".into(), "json".into(), "sarif".into(), "junit".into()],
        json_file: None,
        sarif_file: None,
        junit_file: None,
        excluded: vec![".git".into()],
        plan_scope: PlanScope::Changes,
    };
    let result = scan(&request).expect("scan sensitive plan");
    assert_eq!(result.exit_code, 1);
    let options = RenderOptions {
        show_passed: true,
        show_unknown: true,
        compact: false,
    };
    let cli = render_text(&result.findings, &result.diagnostics, &options);
    let json = render_json(&result.findings, &result.diagnostics);
    let sarif = render_sarif(
        &result.findings,
        &SarifOptions {
            scan_root: Some(&request.path),
        },
    );
    let junit = render_junit(&result.findings, &result.diagnostics);
    for blob in [&cli, &json, &sarif, &junit] {
        assert!(
            !blob.contains(SECRET_MARKER),
            "secret leaked into report output"
        );
    }
}

#[test]
fn plan_scope_changes_skips_unchanged_public_bucket() {
    let dir = std::env::temp_dir().join(format!(
        "rustmaninoff-plan-scope-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let plan = r#"{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.new",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "new",
          "values": { "bucket": "data", "acl": "public-read" }
        },
        {
          "address": "aws_s3_bucket.unchanged",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "unchanged",
          "values": { "bucket": "data", "acl": "public-read" }
        }
      ]
    }
  },
  "resource_changes": [
    {
      "address": "aws_s3_bucket.new",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "new",
      "change": {
        "actions": ["create"],
        "after": { "bucket": "data", "acl": "public-read" }
      }
    },
    {
      "address": "aws_s3_bucket.unchanged",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "unchanged",
      "change": {
        "actions": ["no-op"],
        "after": { "bucket": "data", "acl": "public-read" }
      }
    }
  ]
}"#
    .to_string();
    let path = dir.join("mix.tfplan.json");
    fs::write(&path, plan).unwrap();
    let base = ScanRequest {
        path: path.clone(),
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
        plan_scope: PlanScope::Changes,
    };
    let changes = scan(&base).expect("changes scope");
    assert_eq!(changes.exit_code, 1);
    assert_eq!(
        changes
            .findings
            .iter()
            .filter(|f| f.check_id.as_ref() == "CKV_AWS_20" && f.status == Status::Failed)
            .count(),
        1
    );
    let all = scan(&ScanRequest {
        plan_scope: PlanScope::All,
        ..base.clone()
    })
    .expect("all scope");
    assert_eq!(all.exit_code, 1);
    assert_eq!(
        all.findings
            .iter()
            .filter(|f| f.check_id.as_ref() == "CKV_AWS_20" && f.status == Status::Failed)
            .count(),
        2
    );
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn invalid_plan_scope_is_a_usage_error() {
    assert!(parse_plan_scope("nope").is_err());
}

fn logging_plan_fixture(bucket_after: &str, with_config_ref: bool) -> String {
    let configuration = if with_config_ref {
        r#",
  "configuration": {
    "root_module": {
      "resources": [{
        "address": "aws_s3_bucket_logging.data",
        "mode": "managed",
        "type": "aws_s3_bucket_logging",
        "name": "data",
        "expressions": {
          "bucket": { "references": ["aws_s3_bucket.data.id"] }
        }
      }]
    }
  }"#
    } else {
        ""
    };
    format!(
        r#"{{
  "format_version": "1.2",
  "planned_values": {{ "root_module": {{}} }},
  "resource_changes": [
    {{
      "address": "aws_s3_bucket.data",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "data",
      "change": {{ "actions": ["create"], "after": {{ "bucket": "my-bucket" }} }}
    }},
    {{
      "address": "aws_s3_bucket_logging.data",
      "mode": "managed",
      "type": "aws_s3_bucket_logging",
      "name": "data",
      "change": {{
        "actions": ["create"],
        "after": {{ "bucket": {bucket_after}, "target_bucket": "logs-target" }}
      }}
    }}
  ]{configuration}
}}"#
    )
}

fn scan_logging_plan(path: std::path::PathBuf, checks: Vec<String>) -> crate::ScanResult {
    scan(&ScanRequest {
        path,
        frameworks: vec![Framework::TerraformPlan],
        checks,
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
        plan_scope: PlanScope::Changes,
    })
    .expect("scan plan")
}

#[test]
fn plan_ckv2_s3_logging_graph_checks() {
    let dir = std::env::temp_dir().join(format!(
        "rustmaninoff-plan-ckv2-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let bucket_only = dir.join("bucket_only.tfplan.json");
    let bucket_only_json = r#"{
  "format_version": "1.2",
  "planned_values": { "root_module": {} },
  "resource_changes": [{
    "address": "aws_s3_bucket.data",
    "mode": "managed",
    "type": "aws_s3_bucket",
    "name": "data",
    "change": { "actions": ["create"], "after": { "bucket": "my-bucket" } }
  }]
}"#;
    fs::write(&bucket_only, bucket_only_json).unwrap();
    let fail = scan_logging_plan(
        bucket_only.clone(),
        vec!["CKV2_AWS_S3_BUCKET_LOGGING".into()],
    );
    assert!(
        fail.findings.iter().any(|f| {
            f.check_id.as_ref() == "CKV2_AWS_S3_BUCKET_LOGGING" && f.status == Status::Failed
        }),
        "findings={:?}",
        fail.findings
    );

    let with_ref = dir.join("with_ref.tfplan.json");
    fs::write(&with_ref, logging_plan_fixture(r#""my-bucket""#, true)).unwrap();
    let pass = scan_logging_plan(with_ref, vec!["CKV2_AWS_S3_BUCKET_LOGGING".into()]);
    assert!(
        !pass
            .findings
            .iter()
            .any(|f| f.check_id.as_ref() == "CKV2_AWS_S3_BUCKET_LOGGING"
                && f.status == Status::Failed),
        "findings={:?}",
        pass.findings
    );

    let name_only = dir.join("name_only.tfplan.json");
    fs::write(&name_only, logging_plan_fixture(r#""my-bucket""#, false)).unwrap();
    let still_fail = scan_logging_plan(name_only, vec!["CKV2_AWS_S3_BUCKET_LOGGING".into()]);
    assert!(
        still_fail.findings.iter().any(|f| {
            f.check_id.as_ref() == "CKV2_AWS_S3_BUCKET_LOGGING" && f.status == Status::Failed
        }),
        "findings={:?}",
        still_fail.findings
    );

    let default_fw = scan(&ScanRequest {
        path: bucket_only,
        frameworks: Vec::new(),
        checks: Vec::new(),
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
        plan_scope: PlanScope::Changes,
    })
    .expect("default frameworks");
    assert!(default_fw.findings.is_empty());

    let _ = fs::remove_dir_all(dir);
}
