# Changelog

All notable changes to ghostcloud are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and this project adheres
to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-06-20

### Added

- Initial release of ghostcloud, a multi-cloud security posture management
  (CSPM) and misconfiguration scanner.
- Offline-first design: scans a normalized resource snapshot (JSON), so it runs
  with zero cloud credentials and is fully deterministic.
- 17 security checks across AWS, GCP, and Azure:
  - AWS: S3 public access, S3 no encryption, S3 no versioning, security group
    open admin port, IAM user without MFA, IAM wildcard policy, RDS publicly
    accessible, RDS unencrypted, CloudTrail disabled, EBS volume unencrypted.
  - GCP: storage bucket public IAM, firewall allow-all ingress, service account
    primitive owner role, instance public IP with open SSH.
  - Azure: storage account public blob access, NSG admin port from the internet,
    managed disk unencrypted.
- `Check` base class, provider-keyed registry, and a normalized snapshot schema.
- Typer + rich CLI with `scan`, `checks`, and `version` commands.
- Output formats: rich console table (severity sorted), JSON, and SARIF 2.1.0.
- CI gating via `--fail-on` and noise control via `--min-severity`.
- Per-check isolation so a single failing check never aborts a scan.
- Optional, dependency-injected live collector interface for future use; the
  core scanner and tests require no cloud SDKs.
- Example snapshot fixtures and a full pytest suite that runs under bare pytest.
- MIT license, ruff configuration, and a GitHub Actions CI workflow on
  Python 3.11 and 3.12.

[0.1.0]: https://github.com/joemunene-by/ghostcloud/releases/tag/v0.1.0
