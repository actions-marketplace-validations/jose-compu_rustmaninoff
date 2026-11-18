//! SARIF 2.1.0 rendering helpers (GitHub code scanning).

use std::path::{Path, PathBuf};

use rustmaninoff_engine::{Finding, Severity, Status};

use super::VERSION;

pub const SRCROOT_BASE_ID: &str = "%SRCROOT%";
pub const TOOL_INFORMATION_URI: &str = "https://github.com/jose-compu/rustmaninoff";
pub const DEFAULT_RULE_INFORMATION_URI: &str = "https://jose-compu.github.io/rustmaninoff/";

/// Scan root used to make artifact URIs repo-relative (`%SRCROOT%`).
#[derive(Clone, Debug, Default)]
pub struct SarifOptions<'a> {
    pub scan_root: Option<&'a Path>,
}

pub fn render_sarif(findings: &[Finding], options: &SarifOptions<'_>) -> String {
    let failed: Vec<_> = findings
        .iter()
        .filter(|finding| finding.status == Status::Failed)
        .collect();
    let mut rules = Vec::new();
    let mut seen = Vec::new();
    for finding in &failed {
        if seen.contains(&finding.check_id) {
            continue;
        }
        seen.push(finding.check_id.clone());
        let info_uri = rule_information_uri(finding.guidelines.as_deref());
        rules.push(serde_json::json!({
            "id": finding.check_id.as_ref(),
            "shortDescription": {"text": finding.check_name.as_ref()},
            "fullDescription": {"text": finding.check_name.as_ref()},
            "defaultConfiguration": {"level": sarif_level(finding.severity)},
            "helpUri": finding.guidelines.as_deref().unwrap_or(""),
            "informationUri": info_uri,
        }));
    }
    let results = failed
        .iter()
        .map(|finding| {
            let mut result = serde_json::json!({
                "ruleId": finding.check_id.as_ref(),
                "level": sarif_level(finding.severity),
                "message": {"text": finding.check_name.as_ref()},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": sarif_artifact_location(&finding.file, options.scan_root),
                        "region": {"startLine": finding.start_line.max(1)}
                    }
                }],
            });
            if !sarif_message_is_redundant_resource(&finding.file, &finding.resource_address) {
                result["properties"] = serde_json::json!({
                    "resourceAddress": finding.resource_address.as_ref(),
                });
            }
            result
        })
        .collect::<Vec<_>>();
    let mut run = serde_json::json!({
        "tool": {
            "driver": {
                "name": "rustmaninoff",
                "version": VERSION,
                "informationUri": TOOL_INFORMATION_URI,
                "rules": rules,
            }
        },
        "results": results,
    });
    if let Some(bases) = original_uri_base_ids(options.scan_root) {
        if let Some(obj) = run.as_object_mut() {
            obj.insert("originalUriBaseIds".into(), bases);
        }
    }
    let value = serde_json::json!({
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [run],
    });
    serde_json::to_string_pretty(&value).unwrap_or_else(|_| "{}".to_string())
}

fn sarif_level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium => "warning",
        Severity::Low => "note",
    }
}

fn sarif_message_is_redundant_resource(file: &str, resource_address: &str) -> bool {
    let file_path = Path::new(file);
    let Some(file_name) = file_path.file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    if resource_address == file_name {
        return true;
    }
    let stem = file_path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(file_name);
    resource_address == format!("{stem}.{file_name}")
        || resource_address == format!("dockerfile.{file_name}")
}

pub fn rule_information_uri(guidelines: Option<&str>) -> String {
    let Some(text) = guidelines else {
        return DEFAULT_RULE_INFORMATION_URI.to_string();
    };
    for token in text.split_whitespace() {
        if token.starts_with("http://") || token.starts_with("https://") {
            return token.trim_end_matches(['.', ',', ';']).to_string();
        }
    }
    DEFAULT_RULE_INFORMATION_URI.to_string()
}

pub fn sarif_relative_uri(file: &str, scan_root: Option<&Path>) -> String {
    let normalized = normalize_slashes(file);
    if is_repo_relative(&normalized) {
        return strip_leading_slash(&normalized);
    }
    let path = Path::new(file);
    if let Some(root) = scan_root {
        if let Ok(relative) = relativize(path, root) {
            return strip_leading_slash(&normalize_slashes(&relative.to_string_lossy()));
        }
    }
    strip_leading_slash(&normalized)
}

fn sarif_artifact_location(file: &str, scan_root: Option<&Path>) -> serde_json::Value {
    let uri = sarif_relative_uri(file, scan_root);
    if scan_root.is_some() && !uri.contains("..") {
        serde_json::json!({
            "uri": uri,
            "uriBaseId": SRCROOT_BASE_ID,
        })
    } else {
        serde_json::json!({ "uri": uri })
    }
}

fn original_uri_base_ids(scan_root: Option<&Path>) -> Option<serde_json::Value> {
    let root = scan_root?;
    let resolved = resolved_scan_root(root);
    let uri = path_to_file_uri(&resolved);
    Some(serde_json::json!({
        SRCROOT_BASE_ID: { "uri": uri }
    }))
}

fn resolved_scan_root(scan_root: &Path) -> PathBuf {
    if scan_root.is_file() {
        scan_root
            .parent()
            .map(|parent| {
                parent
                    .canonicalize()
                    .unwrap_or_else(|_| parent.to_path_buf())
            })
            .unwrap_or_else(|| {
                scan_root
                    .canonicalize()
                    .unwrap_or_else(|_| scan_root.to_path_buf())
            })
    } else {
        scan_root
            .canonicalize()
            .unwrap_or_else(|_| scan_root.to_path_buf())
    }
}

fn relativize(file: &Path, scan_root: &Path) -> Result<PathBuf, ()> {
    if scan_root.is_file() {
        return Ok(PathBuf::from(
            file.file_name()
                .or_else(|| scan_root.file_name())
                .ok_or(())?
                .to_string_lossy()
                .as_ref(),
        ));
    }
    let file_path = file.canonicalize().unwrap_or_else(|_| file.to_path_buf());
    let root = scan_root
        .canonicalize()
        .unwrap_or_else(|_| scan_root.to_path_buf());
    file_path
        .strip_prefix(&root)
        .map(|p| p.to_path_buf())
        .map_err(|_| ())
}

fn path_to_file_uri(path: &Path) -> String {
    let canonical = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());
    let posix = normalize_slashes(&canonical.to_string_lossy());
    if posix.len() >= 2 && posix.as_bytes()[1] == b':' {
        return format!("file:///{posix}");
    }
    if posix.starts_with("//") {
        return format!("file:{posix}");
    }
    format!("file://{posix}")
}

fn normalize_slashes(path: &str) -> String {
    path.replace('\\', "/")
}

fn is_repo_relative(path: &str) -> bool {
    !path.starts_with('/')
        && !path.starts_with("//")
        && !path
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() && path.contains(':'))
}

fn strip_leading_slash(path: &str) -> String {
    path.trim_start_matches('/').to_string()
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use rustmaninoff_engine::{Finding, Status};

    fn failed_finding(file: &str, id: &str) -> Finding {
        Finding {
            check_id: Arc::from(id),
            check_name: Arc::from("Test check"),
            category: Arc::from("GENERAL"),
            severity: Severity::High,
            status: Status::Failed,
            resource_address: Arc::from("aws_s3_bucket.x"),
            resource_type: Arc::from("aws_s3_bucket"),
            resource_name: Arc::from("x"),
            framework: Arc::from("terraform"),
            file: Arc::from(file),
            start_line: 3,
            end_line: 3,
            guidelines: Some(Arc::from(
                "Adapted from Checkov CKV_AWS_20. https://github.com/bridgecrewio/checkov",
            )),
            skip_reason: None,
        }
    }

    #[test]
    fn relative_uri_strips_windows_separators() {
        assert_eq!(
            sarif_relative_uri(r"nested\dir\main.tf", None),
            "nested/dir/main.tf"
        );
    }

    #[test]
    fn relative_uri_under_scan_root() {
        let root = std::env::current_dir().expect("cwd");
        let nested = root.join("nested").join("main.tf");
        let absolute = nested.canonicalize().unwrap_or(nested);
        let uri = sarif_relative_uri(absolute.to_str().unwrap(), Some(&root));
        assert_eq!(uri, "nested/main.tf");
    }

    #[test]
    fn single_file_scan_uses_basename() {
        let dir = std::env::temp_dir().join(format!("rmaninoff-sarif-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let file = dir.join("nested.tf");
        std::fs::write(&file, "x").expect("write");
        let uri = sarif_relative_uri(file.to_str().unwrap(), Some(&file));
        assert_eq!(uri, "nested.tf");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn sarif_emits_srcroot_and_rule_information_uri() {
        let root = std::env::current_dir().expect("cwd");
        let file = root.join("main.tf");
        let finding = failed_finding(file.to_str().unwrap(), "CKV_AWS_20");
        let sarif = render_sarif(
            std::slice::from_ref(&finding),
            &SarifOptions {
                scan_root: Some(&root),
            },
        );
        assert!(sarif.contains("\"uriBaseId\": \"%SRCROOT%\""));
        assert!(sarif.contains("\"originalUriBaseIds\""));
        assert!(sarif.contains("\"informationUri\": \"https://github.com/bridgecrewio/checkov\""));
        assert!(sarif.contains("\"message\": {\n            \"text\": \"Test check\"\n          }"));
        assert!(!sarif.contains("Test check aws_s3_bucket"));
    }

    #[test]
    fn docker_redundant_resource_omitted_from_properties() {
        let finding = Finding {
            check_id: Arc::from("CKV_DOCKER_5"),
            check_name: Arc::from("Ensure update instructions are not used alone"),
            category: Arc::from("DOCKER"),
            severity: Severity::High,
            status: Status::Failed,
            resource_address: Arc::from("dockerfile.Dockerfile"),
            resource_type: Arc::from("dockerfile"),
            resource_name: Arc::from("Dockerfile"),
            framework: Arc::from("docker"),
            file: Arc::from("Dockerfile"),
            start_line: 1,
            end_line: 1,
            guidelines: None,
            skip_reason: None,
        };
        let sarif = render_sarif(std::slice::from_ref(&finding), &SarifOptions::default());
        assert!(!sarif.contains("resourceAddress"));
    }
}
