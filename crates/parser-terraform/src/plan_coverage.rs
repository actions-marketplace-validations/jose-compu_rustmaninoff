use std::path::Path;

use rustmaninoff_engine::{evaluate, parse_policy, Status};
use rustmaninoff_ir::{EdgeKind, ResourceKind};

use super::plan::{
    parse_plan, parse_plan_with_scope, sensitive_paths_for_test, PlanScope, SENSITIVE_PLACEHOLDER,
};

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

#[test]
fn sensitive_string_attribute_is_redacted() {
    let secret = "SENSITIVE_CANARY_UNIT_ALPHA";
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{
    "root_module": {{
      "resources": [{{
        "address": "aws_ssm_parameter.token",
        "mode": "managed",
        "type": "aws_ssm_parameter",
        "name": "token",
        "values": {{ "value": "{secret}", "type": "String" }}
      }}]
    }}
  }},
  "resource_changes": [{{
    "address": "aws_ssm_parameter.token",
    "change": {{
      "after": {{ "value": "{secret}", "type": "String" }},
      "sensitive_values": {{ "value": true }}
    }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("ssm.tfplan.json"), &source);
    let value = rustmaninoff_ir::lookup(&output.resources[0].attributes, "value");
    assert_eq!(value.values[0].as_str(), Some(SENSITIVE_PLACEHOLDER));
    let raw = format!("{output:?}");
    assert!(!raw.contains(secret));
}

#[test]
fn nested_sensitive_map_and_list_are_redacted() {
    let secret = "SENSITIVE_CANARY_UNIT_BETA";
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{
    "root_module": {{
      "resources": [{{
        "address": "aws_s3_bucket.obj",
        "mode": "managed",
        "type": "aws_s3_bucket",
        "name": "obj",
        "values": {{
          "acl": "private",
          "tags": {{ "token": "{secret}" }},
          "replication_configuration": [{{
            "rules": [{{ "id": "{secret}-rule" }}]
          }}]
        }}
      }}]
    }}
  }},
  "resource_changes": [{{
    "address": "aws_s3_bucket.obj",
    "change": {{
      "sensitive_values": {{
        "tags": {{ "token": true }},
        "replication_configuration": [{{ "rules": [{{ "id": true }}] }}]
      }}
    }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("nested.tfplan.json"), &source);
    let tags = rustmaninoff_ir::lookup(&output.resources[0].attributes, "tags/token");
    assert_eq!(tags.values[0].as_str(), Some(SENSITIVE_PLACEHOLDER));
    let rule = rustmaninoff_ir::lookup(
        &output.resources[0].attributes,
        "replication_configuration.rules.id",
    );
    assert!(rule
        .values
        .iter()
        .all(|value| value.as_str() == Some(SENSITIVE_PLACEHOLDER)));
    let raw = format!("{output:?}");
    assert!(!raw.contains(secret));
}

#[test]
fn collect_nested_cors_markers() {
    let source = r#"{
  "format_version": "1.0",
  "planned_values": { "root_module": {} },
  "resource_changes": [{
    "address": "aws_s3_bucket.x",
    "change": { "sensitive_values": { "cors_rule": [{ "allowed_headers": [true] }] } }
  }]
}"#;
    let plan: serde_json::Value = serde_json::from_str(source).unwrap();
    let flags = sensitive_paths_for_test(&plan);
    assert!(
        flags
            .get("aws_s3_bucket.x")
            .and_then(|paths| paths.get("cors_rule[0].allowed_headers[0]"))
            .copied()
            .unwrap_or(false),
        "flags={flags:?}"
    );
}

#[test]
fn cors_list_sensitive_paths_are_collected() {
    let source = r#"{
  "format_version": "1.0",
  "planned_values": { "root_module": { "resources": [{
    "address": "aws_s3_bucket.x",
    "mode": "managed", "type": "aws_s3_bucket", "name": "x",
    "values": { "cors_rule": [{ "allowed_headers": ["secret"] }] }
  }] } },
  "resource_changes": [{
    "address": "aws_s3_bucket.x",
    "change": { "sensitive_values": { "cors_rule": [{ "allowed_headers": [true] }] } }
  }]
}"#;
    let plan: serde_json::Value = serde_json::from_str(source).unwrap();
    let flags = sensitive_paths_for_test(&plan);
    assert!(
        flags
            .get("aws_s3_bucket.x")
            .and_then(|m| m.get("cors_rule[0].allowed_headers[0]"))
            .copied()
            .unwrap_or(false),
        "flags={flags:?}"
    );
}

#[test]
fn before_sensitive_on_resource_change_is_honored() {
    let secret = "SENSITIVE_CANARY_UNIT_GAMMA";
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{
    "root_module": {{
      "resources": [{{
        "address": "aws_ssm_parameter.old",
        "mode": "managed",
        "type": "aws_ssm_parameter",
        "name": "old",
        "values": {{ "value": "{secret}" }}
      }}]
    }}
  }},
  "resource_changes": [{{
    "address": "aws_ssm_parameter.old",
    "change": {{
      "before_sensitive": {{ "value": true }}
    }}
  }}]
}}"#
    );
    let output = parse_plan(Path::new("before.tfplan.json"), &source);
    assert_eq!(
        rustmaninoff_ir::lookup(&output.resources[0].attributes, "value").values[0].as_str(),
        Some(SENSITIVE_PLACEHOLDER)
    );
}

fn bucket_change_plan(acl: &str, actions: &str) -> String {
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
        "values": {{ "bucket": "data", "acl": "private" }}
      }}]
    }}
  }},
  "resource_changes": [{{
    "address": "aws_s3_bucket.bad",
    "mode": "managed",
    "type": "aws_s3_bucket",
    "name": "bad",
    "change": {{
      "actions": {actions},
      "after": {{ "bucket": "data", "acl": "{acl}" }}
    }}
  }}]
}}"#
    )
}

#[test]
fn changes_scope_emits_only_in_scope_actions() {
    for (actions, expect) in [
        (r#"["create"]"#, true),
        (r#"["update"]"#, true),
        (r#"["delete", "create"]"#, true),
        (r#"["create", "delete"]"#, true),
        (r#"["no-op"]"#, false),
        (r#"["delete"]"#, false),
        (r#"["read"]"#, false),
    ] {
        let source = bucket_change_plan("public-read", actions);
        let output =
            parse_plan_with_scope(Path::new("scope.tfplan.json"), &source, PlanScope::Changes);
        assert_eq!(
            output.resources.len(),
            usize::from(expect),
            "actions={actions}"
        );
    }
}

#[test]
fn changes_scope_uses_after_not_planned_values() {
    let source = r#"{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [{
        "address": "aws_s3_bucket.bad",
        "mode": "managed",
        "type": "aws_s3_bucket",
        "name": "bad",
        "values": { "bucket": "data", "acl": "private" }
      }]
    }
  },
  "resource_changes": [{
    "address": "aws_s3_bucket.bad",
    "mode": "managed",
    "type": "aws_s3_bucket",
    "name": "bad",
    "change": {
      "actions": ["update"],
      "after": { "bucket": "data", "acl": "public-read" }
    }
  }]
}"#;
    let output = parse_plan_with_scope(Path::new("after.tfplan.json"), source, PlanScope::Changes);
    let acl = rustmaninoff_ir::lookup(&output.resources[0].attributes, "acl");
    assert_eq!(acl.values[0].as_str(), Some("public-read"));
}

#[test]
fn changes_scope_empty_resource_changes_is_not_an_error() {
    let source = r#"{ "format_version": "1.0", "planned_values": { "root_module": {} }, "resource_changes": [] }"#;
    let output = parse_plan_with_scope(Path::new("empty.tfplan.json"), source, PlanScope::Changes);
    assert!(output.diagnostics.is_empty());
    assert!(output.resources.is_empty());
}

#[test]
fn changes_scope_child_module_address_is_prefixed() {
    let source = r#"{
  "format_version": "1.0",
  "planned_values": { "root_module": {} },
  "resource_changes": [{
    "address": "module.child.aws_s3_bucket.logs",
    "mode": "managed",
    "type": "aws_s3_bucket",
    "name": "logs",
    "change": {
      "actions": ["create"],
      "after": { "acl": "private" }
    }
  }]
}"#;
    let output = parse_plan_with_scope(Path::new("child.tfplan.json"), source, PlanScope::Changes);
    assert_eq!(output.resources.len(), 1);
    assert_eq!(output.resources[0].name, "module.child.logs");
}

#[test]
fn changes_scope_after_unknown_does_not_fail_ckv() {
    let source = r#"{
  "format_version": "1.0",
  "planned_values": { "root_module": {} },
  "resource_changes": [{
    "address": "aws_s3_bucket.bad",
    "mode": "managed",
    "type": "aws_s3_bucket",
    "name": "bad",
    "change": {
      "actions": ["create"],
      "after": { "bucket": "data" },
      "after_unknown": { "acl": true }
    }
  }]
}"#;
    let output =
        parse_plan_with_scope(Path::new("unknown.tfplan.json"), source, PlanScope::Changes);
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
fn changes_scope_sensitive_after_is_redacted() {
    let secret = "SENSITIVE_CANARY_CHANGES_SCOPE";
    let source = format!(
        r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{}} }},
  "resource_changes": [{{
    "address": "aws_ssm_parameter.token",
    "mode": "managed",
    "type": "aws_ssm_parameter",
    "name": "token",
    "change": {{
      "actions": ["create"],
      "after": {{ "value": "{secret}", "type": "String" }},
      "sensitive_values": {{ "value": true }}
    }}
  }}]
}}"#
    );
    let output = parse_plan_with_scope(Path::new("ssm.tfplan.json"), &source, PlanScope::Changes);
    let value = rustmaninoff_ir::lookup(&output.resources[0].attributes, "value");
    assert_eq!(value.values[0].as_str(), Some(SENSITIVE_PLACEHOLDER));
}

fn s3_logging_changes_plan_without_configuration(bucket_attr: &str) -> String {
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
      "change": {{ "actions": ["create"], "after": {{ "bucket": "data" }} }}
    }},
    {{
      "address": "aws_s3_bucket_logging.data",
      "mode": "managed",
      "type": "aws_s3_bucket_logging",
      "name": "data",
      "change": {{
        "actions": ["create"],
        "after": {{ "bucket": {bucket_attr}, "target_bucket": "logs.example.com" }}
      }}
    }}
  ]
}}"#
    )
}

fn s3_logging_changes_plan(bucket_attr: &str) -> String {
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
      "change": {{ "actions": ["create"], "after": {{ "bucket": "data" }} }}
    }},
    {{
      "address": "aws_s3_bucket_logging.data",
      "mode": "managed",
      "type": "aws_s3_bucket_logging",
      "name": "data",
      "change": {{
        "actions": ["create"],
        "after": {{ "bucket": {bucket_attr}, "target_bucket": "logs.example.com" }}
      }}
    }}
  ],
  "configuration": {{
    "root_module": {{
      "resources": [
        {{
          "address": "aws_s3_bucket.data",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "data",
          "expressions": {{ "bucket": {{ "references": [] }} }}
        }},
        {{
          "address": "aws_s3_bucket_logging.data",
          "mode": "managed",
          "type": "aws_s3_bucket_logging",
          "name": "data",
          "expressions": {{ "bucket": {{ "references": ["aws_s3_bucket.data.id"] }} }}
        }}
      ]
    }}
  }}
}}"#
    )
}

#[test]
fn changes_scope_bucket_address_reference_emits_edge() {
    let source = s3_logging_changes_plan(r#""aws_s3_bucket.data""#);
    let output = parse_plan_with_scope(Path::new("ref.tfplan.json"), &source, PlanScope::Changes);
    assert_eq!(output.edges.len(), 1);
    assert_eq!(output.edges[0].kind, EdgeKind::References);
    assert_eq!(output.edges[0].from.name, "data");
    assert_eq!(output.edges[0].from.resource_type, "aws_s3_bucket_logging");
    assert_eq!(output.edges[0].to.resource_type, "aws_s3_bucket");
}

#[test]
fn changes_scope_non_address_bucket_value_emits_no_edge() {
    for bucket_attr in [r#""data""#, r#""logs.example.com""#] {
        let source = s3_logging_changes_plan_without_configuration(bucket_attr);
        let output =
            parse_plan_with_scope(Path::new("noref.tfplan.json"), &source, PlanScope::Changes);
        assert!(
            output.edges.is_empty(),
            "bucket_attr={bucket_attr} edges={:?}",
            output.edges
        );
    }
}

#[test]
fn changes_scope_configuration_reference_resolves_after_name() {
    let source = s3_logging_changes_plan(r#""my-resolved-bucket-name""#);
    let output =
        parse_plan_with_scope(Path::new("cfgref.tfplan.json"), &source, PlanScope::Changes);
    assert_eq!(output.edges.len(), 1);
    assert_eq!(output.edges[0].kind, EdgeKind::References);
    assert_eq!(output.edges[0].via.as_deref(), Some("bucket"));
}

#[test]
fn changes_scope_depends_on_attribute_and_configuration() {
    let attr_only = r#"{
  "format_version": "1.2",
  "planned_values": { "root_module": {} },
  "resource_changes": [{
    "address": "aws_s3_bucket_logging.data",
    "mode": "managed",
    "type": "aws_s3_bucket_logging",
    "name": "data",
    "change": {
      "actions": ["create"],
      "after": {
        "bucket": "logs",
        "target_bucket": "logs",
        "depends_on": ["aws_s3_bucket.data"]
      }
    }
  }, {
    "address": "aws_s3_bucket.data",
    "mode": "managed",
    "type": "aws_s3_bucket",
    "name": "data",
    "change": { "actions": ["create"], "after": { "bucket": "data" } }
  }]
}"#;
    let output = parse_plan_with_scope(
        Path::new("dep-attr.tfplan.json"),
        attr_only,
        PlanScope::Changes,
    );
    assert!(
        output.edges.iter().any(|e| e.kind == EdgeKind::DependsOn),
        "edges={:?}",
        output.edges
    );

    let config_only = r#"{
  "format_version": "1.2",
  "planned_values": { "root_module": {} },
  "resource_changes": [
    {
      "address": "aws_s3_bucket_logging.data",
      "mode": "managed",
      "type": "aws_s3_bucket_logging",
      "name": "data",
      "change": { "actions": ["create"], "after": { "bucket": "logs", "target_bucket": "logs" } }
    },
    {
      "address": "aws_s3_bucket.data",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "data",
      "change": { "actions": ["create"], "after": { "bucket": "data" } }
    }
  ],
  "configuration": {
    "root_module": {
      "resources": [{
        "address": "aws_s3_bucket_logging.data",
        "mode": "managed",
        "type": "aws_s3_bucket_logging",
        "name": "data",
        "depends_on": ["aws_s3_bucket.data"],
        "expressions": {}
      }]
    }
  }
}"#;
    let output = parse_plan_with_scope(
        Path::new("dep-cfg.tfplan.json"),
        config_only,
        PlanScope::Changes,
    );
    assert!(
        output.edges.iter().any(|e| e.kind == EdgeKind::DependsOn),
        "edges={:?}",
        output.edges
    );
}

#[test]
fn changes_scope_child_module_reference_targets_prefixed_name() {
    let source = r#"{
  "format_version": "1.2",
  "planned_values": { "root_module": {} },
  "resource_changes": [
    {
      "address": "module.child.aws_s3_bucket.data",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "data",
      "change": { "actions": ["create"], "after": { "bucket": "data" } }
    },
    {
      "address": "module.child.aws_s3_bucket_logging.data",
      "mode": "managed",
      "type": "aws_s3_bucket_logging",
      "name": "data",
      "change": {
        "actions": ["create"],
        "after": { "bucket": "module.child.aws_s3_bucket.data.id", "target_bucket": "t" }
      }
    }
  ]
}"#;
    let output = parse_plan_with_scope(
        Path::new("childref.tfplan.json"),
        source,
        PlanScope::Changes,
    );
    assert_eq!(output.edges.len(), 1);
    assert_eq!(output.edges[0].to.name, "module.child.data");
}

#[test]
fn changes_scope_skips_no_op_logging_reference() {
    let source = r#"{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [{
        "address": "aws_s3_bucket_logging.data",
        "mode": "managed",
        "type": "aws_s3_bucket_logging",
        "name": "data",
        "values": { "bucket": "aws_s3_bucket.data", "target_bucket": "t" }
      }]
    }
  },
  "resource_changes": [
    {
      "address": "aws_s3_bucket_logging.data",
      "change": { "actions": ["no-op"], "after": { "bucket": "aws_s3_bucket.data" } }
    },
    {
      "address": "aws_s3_bucket.data",
      "mode": "managed",
      "type": "aws_s3_bucket",
      "name": "data",
      "change": { "actions": ["create"], "after": { "bucket": "data" } }
    }
  ]
}"#;
    let output = parse_plan_with_scope(Path::new("noop.tfplan.json"), source, PlanScope::Changes);
    assert!(output.edges.is_empty());
}

#[test]
fn all_scope_includes_planned_only_logging_reference() {
    let source = r#"{
  "format_version": "1.2",
  "planned_values": {
    "root_module": {
      "resources": [
        {
          "address": "aws_s3_bucket.data",
          "mode": "managed",
          "type": "aws_s3_bucket",
          "name": "data",
          "values": { "bucket": "data" }
        },
        {
          "address": "aws_s3_bucket_logging.data",
          "mode": "managed",
          "type": "aws_s3_bucket_logging",
          "name": "data",
          "values": { "bucket": "aws_s3_bucket.data", "target_bucket": "t" }
        }
      ]
    }
  },
  "resource_changes": [{
    "address": "aws_s3_bucket.data",
    "change": { "actions": ["create"], "after": { "bucket": "data" } }
  }]
}"#;
    let all = parse_plan_with_scope(Path::new("all.tfplan.json"), source, PlanScope::All);
    assert_eq!(all.edges.len(), 1);
    let changes = parse_plan_with_scope(Path::new("all.tfplan.json"), source, PlanScope::Changes);
    assert!(changes.edges.is_empty());
}
