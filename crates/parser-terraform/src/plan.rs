//! Parse `terraform show -json` plan output.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use rustmaninoff_ir::{
    extract_skip_comments, skips_between, Edge, EdgeKind, Framework, ParseOutput, Resource,
    ResourceKind, ResourceRef, Value,
};

/// Stable placeholder for Terraform-marked sensitive plan attributes.
pub const SENSITIVE_PLACEHOLDER: &str = "(sensitive value)";

/// Which Terraform plan resources to materialize for scanning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlanScope {
    /// Create, update, and replace only. Attributes from `change.after`.
    Changes,
    /// Whole `planned_values` walk. Attributes from `values`.
    All,
}

pub fn parse_plan(path: &Path, source: &str) -> ParseOutput {
    parse_plan_with_scope(path, source, PlanScope::All)
}

pub fn parse_plan_with_scope(path: &Path, source: &str, scope: PlanScope) -> ParseOutput {
    let parsed: serde_json::Value = match serde_json::from_str(source) {
        Ok(value) => value,
        Err(err) => {
            return ParseOutput {
                diagnostics: vec![rustmaninoff_ir::Diagnostic {
                    file: path.to_path_buf(),
                    line: 1,
                    message: err.to_string(),
                }],
                resources: Vec::new(),
                edges: Vec::new(),
            };
        }
    };
    match scope {
        PlanScope::All => parse_plan_all(path, source, &parsed),
        PlanScope::Changes => parse_plan_changes(path, source, &parsed),
    }
}

fn parse_plan_all(path: &Path, source: &str, parsed: &serde_json::Value) -> ParseOutput {
    let Some(root_module) = parsed
        .get("planned_values")
        .and_then(|value| value.get("root_module"))
    else {
        return ParseOutput {
            diagnostics: vec![rustmaninoff_ir::Diagnostic {
                file: path.to_path_buf(),
                line: 1,
                message: "missing planned_values.root_module".to_string(),
            }],
            resources: Vec::new(),
            edges: Vec::new(),
        };
    };
    let unknown_by_address = unknown_keys(parsed);
    let sensitive_by_address = sensitive_keys(parsed);
    let skips = skips_between(&extract_skip_comments(source), 1, usize::MAX);
    let mut output = ParseOutput::default();
    let mut address_map = HashMap::new();
    walk_module(
        path,
        root_module,
        &unknown_by_address,
        &sensitive_by_address,
        &skips,
        &mut output,
        &mut address_map,
    );
    attach_plan_edges(parsed, &mut output, &address_map);
    output
}

fn parse_plan_changes(path: &Path, source: &str, parsed: &serde_json::Value) -> ParseOutput {
    let has_root = parsed
        .get("planned_values")
        .and_then(|value| value.get("root_module"))
        .is_some();
    let changes_key = parsed.get("resource_changes");
    if changes_key.is_none() && !has_root {
        return ParseOutput {
            diagnostics: vec![rustmaninoff_ir::Diagnostic {
                file: path.to_path_buf(),
                line: 1,
                message: "missing planned_values.root_module".to_string(),
            }],
            resources: Vec::new(),
            edges: Vec::new(),
        };
    }
    let Some(changes) = changes_key.and_then(|value| value.as_array()) else {
        return ParseOutput::default();
    };
    if changes.is_empty() {
        return ParseOutput::default();
    }
    let unknown_by_address = unknown_keys(parsed);
    let sensitive_by_address = sensitive_keys(parsed);
    let skips = skips_between(&extract_skip_comments(source), 1, usize::MAX);
    let mut output = ParseOutput::default();
    let mut address_map = HashMap::new();
    for entry in changes {
        emit_resource_change(
            path,
            entry,
            &unknown_by_address,
            &sensitive_by_address,
            &skips,
            &mut output,
            &mut address_map,
        );
    }
    attach_plan_edges(parsed, &mut output, &address_map);
    output
}

fn resource_identity<'a>(
    entry: &'a serde_json::Value,
    address: &'a str,
) -> Option<(&'a str, &'a str, &'a str)> {
    if let (Some(type_name), Some(short_name)) = (
        entry.get("type").and_then(|value| value.as_str()),
        entry.get("name").and_then(|value| value.as_str()),
    ) {
        let mode = entry
            .get("mode")
            .and_then(|value| value.as_str())
            .unwrap_or("managed");
        return Some((mode, type_name, short_name));
    }
    let parts: Vec<&str> = address.split('.').collect();
    if parts.len() >= 3 && parts[0] == "data" {
        return Some(("data", parts[1], parts[2]));
    }
    if parts.len() >= 2 {
        return Some(("managed", parts[parts.len() - 2], parts[parts.len() - 1]));
    }
    None
}

fn change_in_scope(actions: &[serde_json::Value]) -> bool {
    actions
        .iter()
        .any(|action| matches!(action.as_str(), Some("create") | Some("update")))
}

fn emit_resource_change(
    path: &Path,
    entry: &serde_json::Value,
    unknown_by_address: &HashMap<String, BTreeMap<String, bool>>,
    sensitive_by_address: &HashMap<String, BTreeMap<String, bool>>,
    skips: &[rustmaninoff_ir::Skip],
    output: &mut ParseOutput,
    address_map: &mut HashMap<String, ResourceRef>,
) {
    let actions = entry
        .get("change")
        .and_then(|value| value.get("actions"))
        .and_then(|value| value.as_array())
        .map(|items| items.as_slice())
        .unwrap_or(&[]);
    if !change_in_scope(actions) {
        return;
    }
    let address = match entry.get("address").and_then(|value| value.as_str()) {
        Some(value) => value,
        None => return,
    };
    let (mode, type_name, short_name) = match resource_identity(entry, address) {
        Some(value) => value,
        None => return,
    };
    let (kind, resource_type) = match mode {
        "data" => (ResourceKind::Data, format!("data.{type_name}")),
        _ => (ResourceKind::Managed, type_name.to_string()),
    };
    let name = prefixed_name(address, type_name, short_name);
    let after = entry.get("change").and_then(|value| value.get("after"));
    let mut attributes = match after {
        Some(value) if !value.is_null() => json_to_value(value),
        _ => Value::Object(BTreeMap::new()),
    };
    if let Some(flags) = unknown_by_address.get(address) {
        for path in flags.keys() {
            if flags.get(path) == Some(&true) {
                set_unknown_path(&mut attributes, path);
            }
        }
    }
    if let Some(flags) = sensitive_by_address.get(address) {
        for path in flags.keys() {
            if flags.get(path) == Some(&true) {
                set_redacted_path(&mut attributes, path);
            }
        }
    }
    let from = ResourceRef::new(resource_type.clone(), name.clone()).with_file(path.to_path_buf());
    address_map.insert(address.to_string(), from.clone());
    output.resources.push(Resource {
        framework: Framework::TerraformPlan,
        kind,
        resource_type,
        name,
        attributes,
        file: path.to_path_buf(),
        start_line: 1,
        end_line: 1,
        skips: skips.to_vec(),
    });
}

fn unknown_keys(plan: &serde_json::Value) -> HashMap<String, BTreeMap<String, bool>> {
    let mut map = HashMap::new();
    let Some(changes) = plan
        .get("resource_changes")
        .and_then(|value| value.as_array())
    else {
        return map;
    };
    for change in changes {
        let Some(address) = change.get("address").and_then(|value| value.as_str()) else {
            continue;
        };
        let Some(after_unknown) = change
            .get("change")
            .and_then(|value| value.get("after_unknown"))
        else {
            continue;
        };
        collect_marker_flags(after_unknown, "", &mut map, address);
    }
    map
}

fn sensitive_keys(plan: &serde_json::Value) -> HashMap<String, BTreeMap<String, bool>> {
    let mut map = HashMap::new();
    if let Some(changes) = plan
        .get("resource_changes")
        .and_then(|value| value.as_array())
    {
        for change in changes {
            let Some(address) = change.get("address").and_then(|value| value.as_str()) else {
                continue;
            };
            let Some(change_body) = change.get("change") else {
                continue;
            };
            for key in ["sensitive_values", "before_sensitive", "after_sensitive"] {
                if let Some(markers) = change_body.get(key) {
                    collect_marker_flags(markers, "", &mut map, address);
                }
            }
        }
    }
    collect_planned_sensitivity(plan, &mut map);
    if let Some(root) = plan
        .get("prior_state")
        .and_then(|value| value.get("values"))
        .and_then(|value| value.get("root_module"))
    {
        walk_planned_sensitivity(root, &mut map);
    }
    collect_output_change_sensitivity(plan, &mut map);
    map
}

/// Output values are not modeled as resources; sensitivity markers still apply if
/// outputs are ever attached to the IR later. Today they only contribute masks
/// for addresses that also appear as planned resources (defense in depth).
fn collect_output_change_sensitivity(
    plan: &serde_json::Value,
    out: &mut HashMap<String, BTreeMap<String, bool>>,
) {
    let Some(changes) = plan
        .get("output_changes")
        .and_then(|value| value.as_array())
    else {
        return;
    };
    for change in changes {
        let Some(address) = change.get("address").and_then(|value| value.as_str()) else {
            continue;
        };
        let key = format!("output.{address}");
        let Some(change_body) = change.get("change") else {
            continue;
        };
        for marker_key in ["sensitive_values", "before_sensitive", "after_sensitive"] {
            if let Some(markers) = change_body.get(marker_key) {
                collect_marker_flags(markers, "", out, &key);
            }
        }
    }
    if let Some(outputs) = plan
        .get("planned_values")
        .and_then(|value| value.get("outputs"))
        .and_then(|value| value.as_array())
    {
        for entry in outputs {
            let (Some(address), Some(markers)) = (
                entry.get("address").and_then(|value| value.as_str()),
                entry.get("sensitive_values"),
            ) else {
                continue;
            };
            let key = format!("output.{address}");
            collect_marker_flags(markers, "", out, &key);
            if entry.get("sensitive").and_then(|v| v.as_bool()) == Some(true) {
                out.entry(key).or_default().insert(String::new(), true);
            }
        }
    }
}

fn collect_planned_sensitivity(
    plan: &serde_json::Value,
    out: &mut HashMap<String, BTreeMap<String, bool>>,
) {
    let Some(root) = plan
        .get("planned_values")
        .and_then(|value| value.get("root_module"))
    else {
        return;
    };
    walk_planned_sensitivity(root, out);
}

fn walk_planned_sensitivity(
    module: &serde_json::Value,
    out: &mut HashMap<String, BTreeMap<String, bool>>,
) {
    if let Some(resources) = module.get("resources").and_then(|value| value.as_array()) {
        for entry in resources {
            let (Some(address), Some(markers)) = (
                entry.get("address").and_then(|value| value.as_str()),
                entry.get("sensitive_values"),
            ) else {
                continue;
            };
            collect_marker_flags(markers, "", out, address);
        }
    }
    if let Some(children) = module
        .get("child_modules")
        .and_then(|value| value.as_array())
    {
        for child in children {
            walk_planned_sensitivity(child, out);
        }
    }
}

fn collect_marker_flags(
    value: &serde_json::Value,
    prefix: &str,
    out: &mut HashMap<String, BTreeMap<String, bool>>,
    address: &str,
) {
    if value.as_bool() == Some(true) {
        if !prefix.is_empty() {
            out.entry(address.to_owned())
                .or_default()
                .insert(prefix.to_string(), true);
        }
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, child) in map {
                let path = if prefix.is_empty() {
                    key.clone()
                } else {
                    format!("{prefix}.{key}")
                };
                if child.as_bool() == Some(true) {
                    out.entry(address.to_owned())
                        .or_default()
                        .insert(path.clone(), true);
                } else {
                    collect_marker_flags(child, &path, out, address);
                }
            }
        }
        serde_json::Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let path = format!("{prefix}[{index}]");
                collect_marker_flags(child, &path, out, address);
            }
        }
        _ => {}
    }
}

fn walk_module(
    path: &Path,
    module: &serde_json::Value,
    unknown_by_address: &HashMap<String, BTreeMap<String, bool>>,
    sensitive_by_address: &HashMap<String, BTreeMap<String, bool>>,
    skips: &[rustmaninoff_ir::Skip],
    output: &mut ParseOutput,
    address_map: &mut HashMap<String, ResourceRef>,
) {
    if let Some(resources) = module.get("resources").and_then(|value| value.as_array()) {
        for entry in resources {
            emit_resource(
                path,
                entry,
                unknown_by_address,
                sensitive_by_address,
                skips,
                output,
                address_map,
            );
        }
    }
    if let Some(children) = module
        .get("child_modules")
        .and_then(|value| value.as_array())
    {
        for child in children {
            walk_module(
                path,
                child,
                unknown_by_address,
                sensitive_by_address,
                skips,
                output,
                address_map,
            );
        }
    }
}

fn emit_resource(
    path: &Path,
    entry: &serde_json::Value,
    unknown_by_address: &HashMap<String, BTreeMap<String, bool>>,
    sensitive_by_address: &HashMap<String, BTreeMap<String, bool>>,
    skips: &[rustmaninoff_ir::Skip],
    output: &mut ParseOutput,
    address_map: &mut HashMap<String, ResourceRef>,
) {
    let address = match entry.get("address").and_then(|value| value.as_str()) {
        Some(value) => value,
        None => return,
    };
    let mode = entry
        .get("mode")
        .and_then(|value| value.as_str())
        .unwrap_or("managed");
    let type_name = match entry.get("type").and_then(|value| value.as_str()) {
        Some(value) => value,
        None => return,
    };
    let short_name = match entry.get("name").and_then(|value| value.as_str()) {
        Some(value) => value,
        None => return,
    };
    let (kind, resource_type) = match mode {
        "data" => (ResourceKind::Data, format!("data.{type_name}")),
        _ => (ResourceKind::Managed, type_name.to_string()),
    };
    let name = prefixed_name(address, type_name, short_name);
    let mut attributes = entry
        .get("values")
        .map(json_to_value)
        .unwrap_or(Value::Object(BTreeMap::new()));
    if let Some(flags) = unknown_by_address.get(address) {
        for path in flags.keys() {
            if flags.get(path) == Some(&true) {
                set_unknown_path(&mut attributes, path);
            }
        }
    }
    if let Some(flags) = sensitive_by_address.get(address) {
        for path in flags.keys() {
            if flags.get(path) == Some(&true) {
                set_redacted_path(&mut attributes, path);
            }
        }
    }
    let from = ResourceRef::new(resource_type.clone(), name.clone()).with_file(path.to_path_buf());
    address_map.insert(address.to_string(), from.clone());
    output.resources.push(Resource {
        framework: Framework::TerraformPlan,
        kind,
        resource_type,
        name,
        attributes,
        file: path.to_path_buf(),
        start_line: 1,
        end_line: 1,
        skips: skips.to_vec(),
    });
}

fn prefixed_name(address: &str, type_name: &str, name: &str) -> String {
    let suffix = format!("{type_name}.{name}");
    if let Some(module_addr) = address
        .strip_suffix(&suffix)
        .and_then(|s| s.strip_suffix('.'))
    {
        if !module_addr.is_empty() {
            return format!("{module_addr}.{name}");
        }
    }
    name.to_string()
}

fn json_to_value(value: &serde_json::Value) -> Value {
    Value::from_json(value.clone())
}

fn set_unknown_path(value: &mut Value, path: &str) {
    let parts: Vec<&str> = path.split('.').collect();
    set_unknown_segments(value, &parts);
}

fn set_redacted_path(value: &mut Value, path: &str) {
    let parts: Vec<&str> = path.split('.').collect();
    set_redacted_segments(value, &parts);
}

fn set_redacted_segments(value: &mut Value, segments: &[&str]) {
    if segments.is_empty() {
        return;
    }
    let placeholder = Value::string(SENSITIVE_PLACEHOLDER);
    let head = segments[0];
    if let Some((key, rest)) = head.split_once('[') {
        let index: usize = rest.trim_end_matches(']').parse().unwrap_or(0);
        if let Value::Object(map) = value {
            let entry = map
                .entry(key.to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(items) = entry {
                while items.len() <= index {
                    items.push(Value::Null);
                }
                if segments.len() == 1 {
                    items[index] = placeholder;
                    return;
                }
                set_redacted_segments(&mut items[index], &segments[1..]);
            }
        }
        return;
    }
    if segments.len() == 1 {
        if let Value::Object(map) = value {
            map.insert(head.to_string(), placeholder);
        }
        return;
    }
    if let Value::Object(map) = value {
        let entry = map
            .entry(head.to_string())
            .or_insert_with(|| Value::Object(BTreeMap::new()));
        set_redacted_segments(entry, &segments[1..]);
    }
}

fn set_unknown_segments(value: &mut Value, segments: &[&str]) {
    if segments.is_empty() {
        return;
    }
    let head = segments[0];
    if let Some((key, rest)) = head.split_once('[') {
        let index: usize = rest.trim_end_matches(']').parse().unwrap_or(0);
        if let Value::Object(map) = value {
            let entry = map
                .entry(key.to_string())
                .or_insert_with(|| Value::Array(Vec::new()));
            if let Value::Array(items) = entry {
                while items.len() <= index {
                    items.push(Value::Null);
                }
                if segments.len() == 1 {
                    items[index] = Value::Unknown {
                        expr: "plan".into(),
                    };
                    return;
                }
                set_unknown_segments(&mut items[index], &segments[1..]);
            }
        }
        return;
    }
    if segments.len() == 1 {
        if let Value::Object(map) = value {
            map.insert(
                head.to_string(),
                Value::Unknown {
                    expr: "plan".into(),
                },
            );
        }
        return;
    }
    if let Value::Object(map) = value {
        let entry = map
            .entry(head.to_string())
            .or_insert_with(|| Value::Object(BTreeMap::new()));
        set_unknown_segments(entry, &segments[1..]);
    }
}

fn attach_plan_edges(
    parsed: &serde_json::Value,
    output: &mut ParseOutput,
    address_map: &HashMap<String, ResourceRef>,
) {
    for from in address_map.values() {
        let attributes = output
            .resources
            .iter()
            .find(|r| ResourceRef::from_resource(r).matches(from))
            .map(|r| r.attributes.clone());
        let Some(attributes) = attributes else {
            continue;
        };
        collect_attribute_depends_on(output, from, &attributes, address_map);
        collect_attribute_references(output, from, &attributes, "", address_map);
    }
    if let Some(root) = parsed
        .get("configuration")
        .and_then(|value| value.get("root_module"))
    {
        walk_configuration_module(output, root, address_map);
    }
}

fn resolve_plan_address<'a>(
    candidate: &str,
    address_map: &'a HashMap<String, ResourceRef>,
) -> Option<&'a ResourceRef> {
    let mut text = candidate;
    loop {
        if let Some(target) = address_map.get(text) {
            return Some(target);
        }
        let dot = text.rfind('.')?;
        text = &text[..dot];
    }
}

fn push_plan_edge(
    output: &mut ParseOutput,
    from: &ResourceRef,
    to: &ResourceRef,
    kind: EdgeKind,
    via: Option<String>,
) {
    if from.matches(to) {
        return;
    }
    let duplicate = output.edges.iter().any(|edge| {
        edge.from.matches(from) && edge.to.matches(to) && edge.kind == kind && edge.via == via
    });
    if duplicate {
        return;
    }
    let mut edge = Edge::new(from.clone(), to.clone(), kind);
    if let Some(path) = via {
        edge = edge.via(path);
    }
    output.push_edge(edge);
}

fn collect_attribute_depends_on(
    output: &mut ParseOutput,
    from: &ResourceRef,
    attributes: &Value,
    address_map: &HashMap<String, ResourceRef>,
) {
    let Some(Value::Array(items)) = attributes.get("depends_on") else {
        return;
    };
    for item in items {
        let Some(text) = item.as_str() else {
            continue;
        };
        let Some(to) = resolve_plan_address(text, address_map) else {
            continue;
        };
        push_plan_edge(output, from, to, EdgeKind::DependsOn, None);
    }
}

fn collect_attribute_references(
    output: &mut ParseOutput,
    from: &ResourceRef,
    value: &Value,
    path: &str,
    address_map: &HashMap<String, ResourceRef>,
) {
    match value {
        Value::String(text) if text != SENSITIVE_PLACEHOLDER => {
            let Some(to) = resolve_plan_address(text, address_map) else {
                return;
            };
            push_plan_edge(
                output,
                from,
                to,
                EdgeKind::References,
                Some(path.to_string()),
            );
        }
        Value::Object(map) => {
            for (key, child) in map {
                if path.is_empty() && key == "depends_on" {
                    continue;
                }
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                collect_attribute_references(output, from, child, &child_path, address_map);
            }
        }
        Value::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                let child_path = if path.is_empty() {
                    format!("[{index}]")
                } else {
                    format!("{path}[{index}]")
                };
                collect_attribute_references(output, from, child, &child_path, address_map);
            }
        }
        Value::Unknown { .. } => {}
        _ => {}
    }
}

fn walk_configuration_module(
    output: &mut ParseOutput,
    module: &serde_json::Value,
    address_map: &HashMap<String, ResourceRef>,
) {
    if let Some(resources) = module.get("resources").and_then(|value| value.as_array()) {
        for entry in resources {
            let Some(address) = entry.get("address").and_then(|value| value.as_str()) else {
                continue;
            };
            let Some(from) = address_map.get(address) else {
                continue;
            };
            if let Some(deps) = entry.get("depends_on").and_then(|value| value.as_array()) {
                for dep in deps {
                    let Some(text) = dep.as_str() else {
                        continue;
                    };
                    let Some(to) = resolve_plan_address(text, address_map) else {
                        continue;
                    };
                    push_plan_edge(output, from, to, EdgeKind::DependsOn, None);
                }
            }
            if let Some(expressions) = entry.get("expressions").and_then(|value| value.as_object())
            {
                for (attr, expr) in expressions {
                    let Some(refs) = expr.get("references").and_then(|value| value.as_array())
                    else {
                        continue;
                    };
                    for reference in refs {
                        let Some(text) = reference.as_str() else {
                            continue;
                        };
                        let Some(to) = resolve_plan_address(text, address_map) else {
                            continue;
                        };
                        push_plan_edge(output, from, to, EdgeKind::References, Some(attr.clone()));
                    }
                }
            }
        }
    }
    if let Some(calls) = module
        .get("module_calls")
        .and_then(|value| value.as_object())
    {
        for call in calls.values() {
            if let Some(child) = call.get("module") {
                walk_configuration_module(output, child, address_map);
            }
        }
    }
}

#[cfg(test)]
pub(crate) fn sensitive_paths_for_test(
    plan: &serde_json::Value,
) -> HashMap<String, BTreeMap<String, bool>> {
    sensitive_keys(plan)
}

pub fn looks_like_plan(source: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(source) else {
        return false;
    };
    value.get("format_version").is_some()
        && value
            .get("planned_values")
            .and_then(|v| v.get("root_module"))
            .is_some()
}
