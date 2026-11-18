use proptest::prelude::*;
use rustmaninoff_parser_terraform::parse_plan;
use rustmaninoff_report::{
    render_json, render_junit, render_sarif, render_text, RenderOptions, SarifOptions,
};

const CANARY: &str = "SENSITIVE_CANARY_PROP_";

fn arb_secret() -> impl Strategy<Value = String> {
    (0usize..6).prop_map(move |n| format!("{CANARY}{n}"))
}

proptest! {
    #[test]
    fn random_leaf_masks_never_appear_in_reports(
        secret in arb_secret(),
        key in prop::sample::select(vec!["alpha", "beta", "gamma"]),
    ) {
        let source = format!(
            r#"{{
  "format_version": "1.0",
  "planned_values": {{ "root_module": {{ "resources": [{{
    "address": "aws_ssm_parameter.x",
    "mode": "managed", "type": "aws_ssm_parameter", "name": "x",
    "values": {{ "{key}": "{secret}", "type": "String" }}
  }}] }}}},
  "resource_changes": [{{
    "address": "aws_ssm_parameter.x",
    "change": {{ "sensitive_values": {{ "{key}": true }} }}
  }}]
}}"#
        );
        let output = parse_plan(std::path::Path::new("fuzz.tfplan.json"), &source);
        let debug = format!("{output:?}");
        prop_assert!(!debug.contains(&secret));
        let options = RenderOptions::default();
        let blobs = [
            render_text(&[], &output.diagnostics, &options),
            render_json(&[], &output.diagnostics),
            render_sarif(&[], &SarifOptions::default()),
            render_junit(&[], &output.diagnostics),
        ];
        for blob in blobs {
            prop_assert!(!blob.contains(&secret));
        }
    }
}
