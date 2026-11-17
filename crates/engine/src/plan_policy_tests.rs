use std::path::PathBuf;

use rustmaninoff_ir::{Framework, Resource, ResourceKind, Value};

use super::{evaluate, parse_policy, Status};

#[test]
fn terraform_plan_resource_uses_terraform_policies() {
    let resource = Resource {
        framework: Framework::TerraformPlan,
        kind: ResourceKind::Managed,
        resource_type: "aws_s3_bucket".into(),
        name: "bad".into(),
        attributes: Value::from_json(serde_json::json!({ "acl": "public-read" })),
        file: PathBuf::from("plan.tfplan.json"),
        start_line: 1,
        end_line: 1,
        skips: Vec::new(),
    };
    let policy = parse_policy(
        r#"
metadata:
  id: CKV_AWS_20
  name: acl
  framework: terraform
resource_types: [aws_s3_bucket]
definition:
  cond_type: attribute
  attribute: acl
  operator: not_within
  value: [public-read]
"#,
    )
    .expect("policy");
    let findings = evaluate(
        std::slice::from_ref(&resource),
        std::slice::from_ref(&policy),
    );
    assert!(findings.iter().any(|f| f.status == Status::Failed));
    assert_eq!(findings[0].framework.as_ref(), "terraform_plan");
}
