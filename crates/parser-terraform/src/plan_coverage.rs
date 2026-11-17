use std::path::Path;

use rustmaninoff_engine::{evaluate, parse_policy, Status};
use rustmaninoff_ir::ResourceKind;

use super::parse_plan;

fn bucket_plan(acl: &str) -> String {
    format!(
        r#"{{
  "format_version": "1.2",
  "planned_values": {{
    "root_module": {{
      "resources": [{{
        "address": "aws_s3_bucket.bad",
        "mode": "managed",
        "type": "aws_s3_bucket",
        "name": "bad",
        "values": {{ "bucket": "data", "acl": "{acl}" }}
      }}]
    }}
  }},
  "resource_changes": []
}}"#
    )
}

#[test]
fn public_read_plan_fails_ckv_aws_20() {
    let output = parse_plan(Path::new("fail.tfplan.json"), &bucket_plan("public-read"));
    assert!(output.diagnostics.is_empty(), "{:?}", output.diagnostics);
    let policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cli/policies/terraform/CKV_AWS_20.yaml"
    )))
    .expect("policy");
    let findings = evaluate(&output.resources, std::slice::from_ref(&policy));
    assert!(findings.iter().any(|f| f.status == Status::Failed));
}

#[test]
fn private_plan_passes_ckv_aws_20() {
    let output = parse_plan(Path::new("pass.tfplan.json"), &bucket_plan("private"));
    let policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cli/policies/terraform/CKV_AWS_20.yaml"
    )))
    .expect("policy");
    let findings = evaluate(&output.resources, std::slice::from_ref(&policy));
    assert!(findings.iter().any(|f| f.status == Status::Passed));
}

#[test]
fn data_source_uses_data_prefix() {
    let source = r#"{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [{
        "address": "data.aws_ami.ubuntu",
        "mode": "data",
        "type": "aws_ami",
        "name": "ubuntu",
        "values": { "most_recent": true }
      }]
    }
  }
}"#;
    let output = parse_plan(Path::new("data.tfplan.json"), source);
    let data = &output.resources[0];
    assert_eq!(data.kind, ResourceKind::Data);
    assert_eq!(data.resource_type, "data.aws_ami");
}

#[test]
fn child_module_resource_name_is_prefixed() {
    let source = r#"{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "child_modules": [{
        "resources": [{
          "address": "module.child.aws_s3_bucket.logs",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "logs",
          "values": { "acl": "private" }
        }]
      }]
    }
  }
}"#;
    let output = parse_plan(Path::new("module.tfplan.json"), source);
    assert_eq!(output.resources.len(), 1);
    assert_eq!(output.resources[0].name, "module.child.logs");
}

#[test]
fn after_unknown_does_not_fail_on_missing_acl() {
    let source = r#"{
  "format_version": "1.0",
  "planned_values": {
    "root_module": {
      "resources": [{
        "address": "aws_s3_bucket.bad",
        "mode": "managed",
        "type": "aws_s3_bucket",
        "name": "bad",
        "values": { "bucket": "data" }
      }]
    }
  },
  "resource_changes": [{
    "address": "aws_s3_bucket.bad",
    "change": {
      "after": { "bucket": "data" },
      "after_unknown": { "acl": true }
    }
  }]
}"#;
    let output = parse_plan(Path::new("unknown.tfplan.json"), source);
    let acl = rustmaninoff_ir::lookup(&output.resources[0].attributes, "acl");
    assert!(acl.unknown);
    let policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cli/policies/terraform/CKV_AWS_20.yaml"
    )))
    .expect("policy");
    let findings = evaluate(&output.resources, std::slice::from_ref(&policy));
    assert!(!findings.iter().any(|f| f.status == Status::Failed));
}

#[test]
fn delete_only_address_is_not_emitted() {
    let source = r#"{
  "format_version": "1.0",
  "planned_values": { "root_module": {} },
  "resource_changes": [{
    "address": "aws_s3_bucket.old",
    "change": { "actions": ["delete"] }
  }]
}"#;
    let output = parse_plan(Path::new("delete.tfplan.json"), source);
    assert!(output.resources.is_empty());
}

#[test]
fn malformed_json_is_a_diagnostic() {
    let output = parse_plan(Path::new("bad.tfplan.json"), "{not json");
    assert_eq!(output.resources.len(), 0);
    assert_eq!(output.diagnostics.len(), 1);
}
