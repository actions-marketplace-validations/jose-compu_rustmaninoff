# Changelog

## 0.5.3 — 2026-11-18

### Fixed

- SARIF `artifactLocation.uri` values are relative to the scan root with forward slashes, `uriBaseId` `%SRCROOT%`, and `originalUriBaseIds` for GitHub code scanning preview ([#84](https://github.com/jose-compu/rustmaninoff/issues/84)).
- SARIF result messages use the check name only; resource addresses move to result properties when they add context. Redundant Docker file labels are no longer duplicated in the message.
- Each SARIF rule carries an `informationUri` (Checkov or project docs link); the tool driver `informationUri` is `https://github.com/jose-compu/rustmaninoff`.

### Changed

- Workspace crates and the Action default `version` pin are 0.5.3.

## 0.5.2 — 2026-11-18

### Added

- CI benchmark regression gate on every pull request and on pushes to `main`: compares release binaries on fixed corpora (pinned Terraform module, Kubernetes, CloudFormation, Dockerfiles, Terraform plan JSON), writes the table to the job summary and one sticky PR comment, warns above 5% slower, fails above 15% (configurable in `benchmarks/regression_thresholds.json`). Main-branch medians are stored as workflow artifacts ([#89](https://github.com/jose-compu/rustmaninoff/issues/89)).
- Five Terraform AWS resource checks from the 0.8.0 queue: `CKV_AWS_61`, `CKV_AWS_93`, `CKV_AWS_112`, `CKV_AWS_113`, `CKV_AWS_213` (IAM assume-role scope, S3 policy lockout guard, Session Manager encryption and logging, ELB TLS policy hardening).

### Changed

- Built-in catalog: **541** checks (was 536). Terraform AWS exact overlap: **341 / 928** (`docs/fidelity.md`).
- Workspace crates and the Action default `version` pin are 0.5.2.

## 0.5.1 — 2026-11-17

### Added

- Terraform plan scanning redacts attributes Terraform marks sensitive (`sensitive_values`, `before_sensitive`, and `after_sensitive` in `resource_changes`, and `sensitive_values` on planned resources). Redacted values become the fixed placeholder `(sensitive value)` in the scan IR before checks run, so they cannot surface in CLI, JSON, SARIF, or JUnit output.

### Changed

- Workspace crates and the Action default `version` pin are 0.5.1.

### Notes

- This is not a secrets scanner: only provider-schema–marked sensitive values are redacted. Keep plan artifacts out of logs and CI output; unmarked values remain your pipeline’s responsibility.

## 0.5.0 — 2026-11-17

### Added

- Opt-in Terraform plan scanning: `rustmaninoff scan --framework terraform_plan` on a `terraform show -json` file.
- Planned resources and child-module resources use the existing Terraform checks. Data sources use the same `data.<type>` type as HCL.
- Values marked unknown in the plan do not fail the process.
- Tag `v*` pushes publish workspace crates to crates.io via `.github/workflows/publish.yml` (dependency order, skip already-published versions).

### Changed

- Workspace crates and the Action default `version` pin are 0.5.0.

### Unchanged

- 536 built-in checks. Docker 100%, Kubernetes 93.8%, Terraform AWS resource ids 36.2% (`docs/fidelity.md`).
- Default scan frameworks are still Terraform, CloudFormation, Kubernetes, and Docker.

## 0.4.4 — 2026-11-03

### Fixed

- GitHub Action input validation: bash `=~` patterns no longer embed a literal space (word-split broke path/sarif/args checks with exit 2).

### Changed

- Workspace crates are **0.4.4**.
- Action default `version` pin is **0.4.4**.

## 0.4.3 — 2026-11-03

### Changed

- Action Marketplace `description` shortened to ≤125 characters.
- Workspace crates are **0.4.3**; Action default `version` pin is **0.4.3**.

## 0.4.2 — 2026-11-03

### Changed

- Workspace crates are **0.4.2**.
- Action default `version` pin is `0.4.2`.
- Marketplace/docs refresh: Action install guidance, SEO, and [ACTION.md](ACTION.md) on the published listing README path.

## 0.4.1 — 2026-11-02

### Security

- GitHub Action (`action.yml`): pass all inputs via environment variables (no `${{ inputs.* }}` interpolation into the shell script body), validate `version` / `path` / `fail-on` / `output` / `sarif-file` / `args`, and verify the downloaded archive against the published `.sha256` before install.

### Changed

- Workspace crates are **0.4.1**.
- Action default `version` pin is `0.4.1`.

## 0.4.0 — 2026-11-02

### Added

- Catalog depth: **536** built-in checks. Docker **100%** and Kubernetes **93.8%** of pinned Checkov ids ([docs/fidelity.md](docs/fidelity.md)).
- `CKV_DOCKER_11` (unique multistage `FROM` aliases) via parser `_from_aliases` + engine `unique` operator.
- Additional Kubernetes PSP/RBAC/control-plane and Terraform AWS / `CKV2_AWS_*` attribute checks.
- Reproducible benches: `benchmarks/corpus/`, `scripts/bench.sh`, `benchmarks/history.json` (#41).
- Checkov comparison CI: `testdata/checkov-compare/`, `scripts/compare_checkov.py`, `.github/workflows/checkov-compare.yml` (#43).

### Changed

- Workspace crates are **0.4.0**.
- README timing claims refreshed against the published synthetic corpus (medians of three runs).

### Still out of scope / follow-ups

- Helm, Kustomize, Terraform plan JSON, local modules (v0.5).
- Baseline/suppressions and Marketplace listing (v0.6).
- Remaining K8s nginx/cipher gaps and TF IAM semantic checks (documented in fidelity).

## 0.3.0 — 2026-11-02

### Added

- Resource graph IR (`Edge`, `EdgeKind`, `ResourceRef`) on `ParseOutput`.
- Static edge emission from Terraform (`depends_on`, traversals), CloudFormation (`Ref` / `GetAtt` / `DependsOn`), and Kubernetes (`ownerReferences`, PVC mounts).
- Graph policy dialect `cond_type: connection` (plus `filter` alias) and `evaluate_graph` second pass.
- First-wave Terraform `CKV2_AWS_*` checks (S3 logging, S3 public access block, IAM role attachment, open SG ingress companion) — **185** built-in policies total.
- Terraform variable / local evaluation: defaults, `TF_VAR_*`, repeatable `--var-file`, same-file `locals`, simple `${var.x}` / `${local.x}` templates.
- OpenTofu `.tofu` / `.tofu.json` treated as Terraform HCL.

### Changed

- Workspace crates are **0.3.0**.
- Attribute fast path unchanged; graph checks run as a separate pass.

### Still out of scope / follow-ups

- Local module expansion, registry modules, plan JSON (`#17`, `#18`).
- Graph edge enrichment from resolved interpolations (`#19`).
- Helm, Kustomize, secrets, Azure/GCP catalog depth.

## 0.2.0 — 2026-10-15

### Added

- Terraform `data` sources in the HCL/JSON parsers. Data sources are IR resources with kind `data` and type `data.TYPE`.
- Dockerfile parser crate `rustmaninoff-parser-docker` and `--framework docker`.
- Docker checks `CKV_DOCKER_1`–`CKV_DOCKER_4` (pinned FROM tag, non-root USER, COPY vs ADD, HEALTHCHECK).
- Additional Terraform, CloudFormation, and Kubernetes attribute checks (181 built-in total).
- LinkedIn release banner template (`img/linkedin-release-banner.jpg`, `scripts/render-linkedin-banner.py`).

### Changed

- Workspace crates are **0.2.0**.
- Interpolations remain unknown. Graph checks, plan JSON, Helm, and Kustomize are still out of scope.
