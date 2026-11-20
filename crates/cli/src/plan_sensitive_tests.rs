//! Terraform plan sensitive-value redaction matrix (issue #78).

use std::fmt::Write as _;
use std::fs;
use std::path::Path;

use rustmaninoff_engine::Status;
use rustmaninoff_ir::{lookup, Framework};
use rustmaninoff_parser_terraform::{parse_plan, PlanScope, SENSITIVE_PLACEHOLDER};
use rustmaninoff_report::{
    render_json, render_junit, render_sarif, render_text, RenderOptions, SarifOptions,
};

use crate::{scan, ScanRequest, Severity};

pub(crate) const CANARY_SUBSTR: &str = "SENSITIVE_CANARY_";

pub(crate) fn fixture_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/terraform-plan")
}

pub(crate) fn matrix_plan() -> std::path::PathBuf {
    fixture_root().join("sensitive_matrix.tfplan.json")
}

pub(crate) fn all_report_blobs(
    findings: &[rustmaninoff_engine::Finding],
    diagnostics: &[rustmaninoff_ir::Diagnostic],
    scan_root: &Path,
) -> Vec<(String, String)> {
    let mut blobs = Vec::new();
    for (name, compact, show_passed, show_unknown) in [
        ("cli_verbose", false, true, true),
        ("cli_compact", true, false, false),
        ("cli_default", false, false, false),
    ] {
        let options = RenderOptions {
            show_passed,
            show_unknown,
            compact,
        };
        blobs.push((
            name.to_string(),
            render_text(findings, diagnostics, &options),
        ));
    }
    blobs.push(("json".into(), render_json(findings, diagnostics)));
    blobs.push((
        "sarif".into(),
        render_sarif(
            findings,
            &SarifOptions {
                scan_root: Some(scan_root),
            },
        ),
    ));
    blobs.push(("junit".into(), render_junit(findings, diagnostics)));
    let mut debug = String::new();
    for finding in findings {
        let _ = write!(debug, "{finding:?}");
    }
    for diagnostic in diagnostics {
        let _ = write!(debug, "{diagnostic:?}");
    }
    blobs.push(("debug_findings".into(), debug));
    blobs
}

fn normalize_golden_paths(blob: &str) -> String {
    let marker = "testdata/terraform-plan/sensitive_matrix.tfplan.json";
    let re = regex::Regex::new(r#"[^\s"]*testdata/terraform-plan/sensitive_matrix\.tfplan\.json"#)
        .expect("regex");
    let blob = re.replace_all(blob, marker).into_owned();
    let root_marker = "file://TESTROOT/testdata/terraform-plan";
    let file_uri = regex::Regex::new(r#"file://[^"]*testdata/terraform-plan"#).expect("regex");
    file_uri.replace_all(&blob, root_marker).into_owned()
}

pub(crate) fn assert_no_canaries(blobs: &[(String, String)]) {
    for (name, blob) in blobs {
        assert!(!blob.contains(CANARY_SUBSTR), "canary leaked into {name}");
    }
}

pub(crate) fn sensitive_scan_request(path: std::path::PathBuf) -> ScanRequest {
    ScanRequest {
        path,
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
    }
}

#[test]
fn matrix_fixture_reports_contain_no_canaries() {
    let result = scan(&sensitive_scan_request(matrix_plan())).expect("scan");
    assert_eq!(result.exit_code, 1);
    assert_no_canaries(&all_report_blobs(
        &result.findings,
        &result.diagnostics,
        &matrix_plan(),
    ));
}

#[test]
fn matrix_failing_check_still_fails_without_canary_leak() {
    let result = scan(&sensitive_scan_request(matrix_plan())).expect("scan");
    let failed = result
        .findings
        .iter()
        .find(|f| f.check_id.as_ref() == "CKV_AWS_20" && f.status == Status::Failed);
    assert!(
        failed.is_some(),
        "expected CKV_AWS_20 failure on public-read"
    );
    assert_no_canaries(&all_report_blobs(
        &result.findings,
        &result.diagnostics,
        &matrix_plan(),
    ));
}

#[test]
fn redaction_does_not_change_fail_on_acl_outcome() {
    let root = fixture_root();
    let with_markers = root.join("s3_public_fail_sensitive_tag.tfplan.json");
    let without_markers = root.join("s3_public_fail.tfplan.json");
    let a = scan(&sensitive_scan_request(with_markers)).expect("with markers");
    let b = scan(&sensitive_scan_request(without_markers)).expect("without markers");
    assert_eq!(a.exit_code, b.exit_code);
    let status = |result: &crate::ScanResult| {
        result
            .findings
            .iter()
            .find(|f| f.check_id.as_ref() == "CKV_AWS_20")
            .map(|f| f.status)
    };
    assert_eq!(status(&a), status(&b));
    assert_eq!(status(&b), Some(Status::Failed));
}

#[test]
fn nonsensitive_attributes_stay_evaluatable() {
    let source = fs::read_to_string(matrix_plan()).expect("read matrix");
    let output = parse_plan(&matrix_plan(), &source);
    let root = output
        .resources
        .iter()
        .find(|r| r.name == "root")
        .expect("root bucket");
    let acl = lookup(&root.attributes, "acl");
    assert_eq!(acl.values[0].as_str(), Some("public-read"));
    let bucket = lookup(&root.attributes, "bucket");
    assert_eq!(bucket.values[0].as_str(), Some("PLAIN_VISIBLE_BUCKET"));
    let plain = lookup(&root.attributes, "tags/plain");
    assert_eq!(plain.values[0].as_str(), Some("PLAIN_VISIBLE_TAG"));
    let secret = lookup(&root.attributes, "tags/secret_top");
    assert_eq!(secret.values[0].as_str(), Some(SENSITIVE_PLACEHOLDER));
}

#[test]
fn parse_output_debug_has_no_canaries_after_redaction() {
    let sensitive_canaries = [
        "SENSITIVE_CANARY_0_FAIL_PATH",
        "SENSITIVE_CANARY_1_TOP_LEVEL",
        "SENSITIVE_CANARY_2_NESTED_MAP",
        "SENSITIVE_CANARY_3_LIST_OBJ_A",
        "SENSITIVE_CANARY_4_LIST_OBJ_B",
        "SENSITIVE_CANARY_5_DEEP_BLOCK",
        "SENSITIVE_CANARY_6_FOREACH_ADDR",
        "SENSITIVE_CANARY_7_CHILD_MODULE",
        "SENSITIVE_CANARY_9_PRIOR_STATE",
    ];
    let source = fs::read_to_string(matrix_plan()).expect("read");
    let output = parse_plan(&matrix_plan(), &source);
    let debug = format!("{output:?}");
    for canary in sensitive_canaries {
        assert!(!debug.contains(canary), "IR debug leaked {canary}");
    }
    assert_no_canaries(&all_report_blobs(&[], &output.diagnostics, &matrix_plan()));
}

#[test]
fn malformed_plan_and_missing_sensitive_values_do_not_panic() {
    let root = fixture_root();
    let bad = r#"{ "format_version": "1.0", "planned_values": { "root_module": {} } }"#;
    let output = parse_plan(&root.join("empty.tfplan.json"), bad);
    assert!(output.resources.is_empty());
    let partial = fs::read_to_string(root.join("s3_public_fail.tfplan.json")).expect("read");
    let output = parse_plan(&root.join("s3_public_fail.tfplan.json"), &partial);
    assert!(!output.resources.is_empty());
    let blobs = all_report_blobs(&[], &output.diagnostics, &matrix_plan());
    assert_no_canaries(&blobs);
}

#[test]
fn golden_cli_json_sarif_junit_snapshots() {
    let result = scan(&sensitive_scan_request(matrix_plan())).expect("scan");
    let root = fixture_root().join("golden");
    let plan = matrix_plan();
    for (name, blob) in all_report_blobs(&result.findings, &result.diagnostics, &plan)
        .into_iter()
        .filter(|(name, _)| matches!(name.as_str(), "cli_default" | "json" | "sarif" | "junit"))
    {
        let golden_path = root.join(format!("sensitive_matrix.{name}.golden"));
        let golden = fs::read_to_string(&golden_path).unwrap_or_else(|err| {
            panic!(
                "missing golden {} (generate with UPDATE_GOLDEN=1): {err}",
                golden_path.display()
            )
        });
        assert_eq!(
            normalize_golden_paths(&golden),
            normalize_golden_paths(&blob),
            "golden mismatch for {name}; set UPDATE_GOLDEN=1 to refresh"
        );
    }
}

#[test]
fn golden_refresh_env_var() {
    if std::env::var("UPDATE_GOLDEN").ok().as_deref() != Some("1") {
        return;
    }
    let result = scan(&sensitive_scan_request(matrix_plan())).expect("scan");
    let root = fixture_root().join("golden");
    fs::create_dir_all(&root).expect("mkdir golden");
    let plan = matrix_plan();
    for (name, blob) in all_report_blobs(&result.findings, &result.diagnostics, &plan)
        .into_iter()
        .filter(|(name, _)| matches!(name.as_str(), "cli_default" | "json" | "sarif" | "junit"))
    {
        fs::write(
            root.join(format!("sensitive_matrix.{name}.golden")),
            normalize_golden_paths(&blob),
        )
        .expect("write golden");
    }
}
