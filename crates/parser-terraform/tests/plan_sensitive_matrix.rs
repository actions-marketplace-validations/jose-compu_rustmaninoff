use std::path::Path;

use rustmaninoff_engine::{evaluate, parse_policy, Status};
use rustmaninoff_ir::lookup;
use rustmaninoff_parser_terraform::{parse_plan, SENSITIVE_PLACEHOLDER};

const CANARY: &str = "SENSITIVE_CANARY_";

fn assert_ir_canary_free(output: &rustmaninoff_ir::ParseOutput) {
    let debug = format!("{output:?}");
    assert!(!debug.contains(CANARY));
}

#[test]
fn top_level_string_redacted() {
    let secret = format!("{CANARY}TOP");
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{ "resources": [{{
    "address": "aws_ssm_parameter.x",
    "mode": "managed", "type": "aws_ssm_parameter", "name": "x",
    "values": {{ "value": "{secret}" }}
  }}] }}}},
  "resource_changes": [{{
    "address": "aws_ssm_parameter.x",
    "change": {{ "sensitive_values": {{ "value": true }} }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("x.tfplan.json"), &source);
    assert_eq!(
        lookup(&output.resources[0].attributes, "value").values[0].as_str(),
        Some(SENSITIVE_PLACEHOLDER)
    );
    assert_ir_canary_free(&output);
}

#[test]
fn nested_map_and_list_redacted() {
    let secret = format!("{CANARY}NESTED");
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{ "resources": [{{
    "address": "aws_s3_bucket.x",
    "mode": "managed", "type": "aws_s3_bucket", "name": "x",
    "values": {{
      "tags": {{ "s": "{secret}" }},
      "cors_rule": [{{ "allowed_headers": ["{secret}b"] }}]
    }}
  }}] }}}},
  "resource_changes": [{{
    "address": "aws_s3_bucket.x",
    "change": {{
      "sensitive_values": {{
        "tags": {{ "s": true }},
        "cors_rule": [{{ "allowed_headers": [true] }}]
      }}
    }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("x.tfplan.json"), &source);
    assert_eq!(
        lookup(&output.resources[0].attributes, "tags/s").values[0].as_str(),
        Some(SENSITIVE_PLACEHOLDER)
    );
    let hdr = lookup(
        &output.resources[0].attributes,
        "cors_rule[0].allowed_headers[0]",
    );
    assert_eq!(hdr.values[0].as_str(), Some(SENSITIVE_PLACEHOLDER));
    assert_ir_canary_free(&output);
}

#[test]
fn whole_block_marked_true_redacts_entire_attribute() {
    let secret = format!("{CANARY}BLOCK");
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{ "resources": [{{
    "address": "aws_s3_bucket.x",
    "mode": "managed", "type": "aws_s3_bucket", "name": "x",
    "values": {{
      "server_side_encryption_configuration": {{
        "rule": {{ "sse_algorithm": "{secret}" }}
      }}
    }}
  }}] }}}},
  "resource_changes": [{{
    "address": "aws_s3_bucket.x",
    "change": {{ "sensitive_values": {{ "server_side_encryption_configuration": true }} }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("x.tfplan.json"), &source);
    let cfg = lookup(
        &output.resources[0].attributes,
        "server_side_encryption_configuration",
    );
    assert_eq!(cfg.values[0].as_str(), Some(SENSITIVE_PLACEHOLDER));
    assert_ir_canary_free(&output);
}

#[test]
fn before_and_after_sensitive_masks_honored() {
    let secret = format!("{CANARY}BEFORE");
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{ "resources": [{{
    "address": "aws_ssm_parameter.x",
    "mode": "managed", "type": "aws_ssm_parameter", "name": "x",
    "values": {{ "value": "{secret}" }}
  }}] }}}},
  "resource_changes": [{{
    "address": "aws_ssm_parameter.x",
    "change": {{
      "before_sensitive": {{ "value": true }},
      "after_sensitive": {{ "value": true }}
    }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("x.tfplan.json"), &source);
    assert_eq!(
        lookup(&output.resources[0].attributes, "value").values[0].as_str(),
        Some(SENSITIVE_PLACEHOLDER)
    );
    assert_ir_canary_free(&output);
}

#[test]
fn after_unknown_and_sensitive_on_different_paths() {
    let secret = format!("{CANARY}COMBO");
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{ "resources": [{{
    "address": "aws_s3_bucket.x",
    "mode": "managed", "type": "aws_s3_bucket", "name": "x",
    "values": {{ "bucket": "visible", "tags": {{ "s": "{secret}" }} }}
  }}] }}}},
  "resource_changes": [{{
    "address": "aws_s3_bucket.x",
    "change": {{
      "after_unknown": {{ "acl": true }},
      "sensitive_values": {{ "tags": {{ "s": true }} }}
    }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("x.tfplan.json"), &source);
    assert!(lookup(&output.resources[0].attributes, "acl").unknown);
    assert_eq!(
        lookup(&output.resources[0].attributes, "tags/s").values[0].as_str(),
        Some(SENSITIVE_PLACEHOLDER)
    );
    assert_eq!(
        lookup(&output.resources[0].attributes, "bucket").values[0].as_str(),
        Some("visible")
    );
    assert_ir_canary_free(&output);
}

#[test]
fn planned_values_sensitive_values_on_resource_entry() {
    let secret = format!("{CANARY}PLANNED");
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{ "resources": [{{
    "address": "aws_ssm_parameter.x",
    "mode": "managed", "type": "aws_ssm_parameter", "name": "x",
    "values": {{ "value": "{secret}" }},
    "sensitive_values": {{ "value": true }}
  }}] }}}},
  "resource_changes": []
}}"#
    );
    let output = parse_plan(Path::new("x.tfplan.json"), &source);
    assert_ir_canary_free(&output);
}

#[test]
fn prior_state_sensitive_values_merged() {
    let secret = format!("{CANARY}PRIOR");
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{ "resources": [{{
    "address": "aws_ssm_parameter.x",
    "mode": "managed", "type": "aws_ssm_parameter", "name": "x",
    "values": {{ "value": "{secret}" }}
  }}] }}}},
  "prior_state": {{
    "values": {{ "root_module": {{ "resources": [{{
      "address": "aws_ssm_parameter.x",
      "sensitive_values": {{ "value": true }}
    }}] }}}}
  }},
  "resource_changes": []
}}"#
    );
    let output = parse_plan(Path::new("x.tfplan.json"), &source);
    assert_eq!(
        lookup(&output.resources[0].attributes, "value").values[0].as_str(),
        Some(SENSITIVE_PLACEHOLDER)
    );
    assert_ir_canary_free(&output);
}

#[test]
fn child_module_address_redacted() {
    let secret = format!("{CANARY}CHILD");
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{
    "child_modules": [{{
      "resources": [{{
        "address": "module.c.aws_s3_bucket.x",
        "mode": "managed", "type": "aws_s3_bucket", "name": "x",
        "values": {{ "tags": {{ "s": "{secret}" }} }}
      }}]
    }}]
  }}}},
  "resource_changes": [{{
    "address": "module.c.aws_s3_bucket.x",
    "change": {{ "sensitive_values": {{ "tags": {{ "s": true }} }} }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("x.tfplan.json"), &source);
    assert_ir_canary_free(&output);
}

#[test]
fn for_each_instance_address_redacted() {
    let secret = format!("{CANARY}FEACH");
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{ "resources": [{{
    "address": "aws_s3_bucket.item[\"k\"]",
    "mode": "managed", "type": "aws_s3_bucket", "name": "item",
    "values": {{ "bucket": "{secret}" }}
  }}] }}}},
  "resource_changes": [{{
    "address": "aws_s3_bucket.item[\"k\"]",
    "change": {{ "sensitive_values": {{ "bucket": true }} }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("x.tfplan.json"), &source);
    assert_eq!(
        lookup(&output.resources[0].attributes, "bucket").values[0].as_str(),
        Some(SENSITIVE_PLACEHOLDER)
    );
    assert_ir_canary_free(&output);
}

#[test]
fn nonsensitive_fields_unredacted_pass_fail_unchanged() {
    let source = r#"{
  "format_version": "1.0",
  "planned_values": { "root_module": { "resources": [{
    "address": "aws_s3_bucket.bad",
    "mode": "managed", "type": "aws_s3_bucket", "name": "bad",
    "values": { "acl": "public-read", "bucket": "PLAIN_VISIBLE_BUCKET" }
  }] } },
  "resource_changes": [{
    "address": "aws_s3_bucket.bad",
    "change": { "sensitive_values": { "tags": { "x": true } } }
  }]
}"#;
    let output = parse_plan(Path::new("fail.tfplan.json"), source);
    assert_eq!(
        lookup(&output.resources[0].attributes, "acl").values[0].as_str(),
        Some("public-read")
    );
    let policy = parse_policy(include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../cli/policies/terraform/CKV_AWS_20.yaml"
    )))
    .expect("policy");
    let with = evaluate(&output.resources, std::slice::from_ref(&policy));
    let plain = parse_plan(
        Path::new("plain.tfplan.json"),
        r#"{
  "format_version": "1.0",
  "planned_values": { "root_module": { "resources": [{
    "address": "aws_s3_bucket.bad",
    "mode": "managed", "type": "aws_s3_bucket", "name": "bad",
    "values": { "acl": "public-read" }
  }] } }
}"#,
    );
    let without = evaluate(&plain.resources, std::slice::from_ref(&policy));
    assert_eq!(
        with.iter()
            .find(|f| f.status == Status::Failed)
            .map(|f| f.status),
        without
            .iter()
            .find(|f| f.status == Status::Failed)
            .map(|f| f.status)
    );
}

#[test]
fn missing_or_malformed_sensitive_values_fail_safe() {
    let output = parse_plan(Path::new("bad.tfplan.json"), "{");
    assert!(!output.diagnostics.is_empty());
    let output = parse_plan(
        Path::new("ok.tfplan.json"),
        r#"{"format_version":"1.0","planned_values":{"root_module":{}}}"#,
    );
    assert!(output.resources.is_empty());
    let output = parse_plan(
        Path::new("partial.tfplan.json"),
        r#"{
  "format_version": "1.0",
  "planned_values": { "root_module": { "resources": [{
    "address": "aws_s3_bucket.x",
    "mode": "managed", "type": "aws_s3_bucket", "name": "x",
    "values": { "acl": "private" }
  }] } },
  "resource_changes": [{ "address": "aws_s3_bucket.x", "change": {} }]
}"#,
    );
    assert_eq!(output.resources.len(), 1);
}
