# ghostcloud

Multi-cloud security posture management (CSPM) and misconfiguration scanner for
AWS, GCP, and Azure. ghostcloud evaluates cloud resource configurations against
security best-practice checks, reports misconfigurations with severity and
remediation guidance, and can gate CI pipelines.

ghostcloud is offline-first. It scans a normalized resource snapshot (plain
JSON) rather than calling live cloud APIs, so it runs deterministically with zero
cloud credentials and is trivial to test, demo, and embed in CI. A
dependency-injected collector interface is included for teams that later want to
generate snapshots from live accounts.

## Authorized use only

ghostcloud is a defensive tool. Use it only against cloud accounts and resource
snapshots you own or are explicitly authorized to assess. You are responsible for
complying with all applicable laws, contracts, and provider terms of service.

## Install

Requires Python 3.11 or newer.

```bash
git clone https://github.com/joemunene-by/ghostcloud.git
cd ghostcloud
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

This installs the `ghostcloud` command.

## Quickstart

List every available check:

```bash
ghostcloud checks
```

Scan the bundled multi-cloud example:

```bash
ghostcloud scan --input examples/all_providers.json --provider all
```

Sample output:

```
                              ghostcloud findings
Severity   Check                Provider   Resource          Title
CRITICAL   GC-AWS-EC2-001       aws        sg-0a1b2c3d4e     Security group exposes an admin port to the internet
CRITICAL   GC-AWS-IAM-002       aws        arn:aws:iam:..    IAM policy grants wildcard action on all resources
CRITICAL   GC-AWS-S3-001        aws        arn:aws:s3:..     S3 bucket allows public access
CRITICAL   GC-AZURE-NSG-001     azure      /subscriptions/.. Network security group allows admin access from the internet
CRITICAL   GC-GCP-STORAGE-001   gcp        //storage..       Cloud Storage bucket is publicly accessible
HIGH       GC-AWS-S3-002        aws        arn:aws:s3:..     S3 bucket has no default encryption
HIGH       GC-GCP-IAM-001       gcp        deploy@demo..     Service account granted primitive owner role
MEDIUM     GC-AWS-S3-003        aws        arn:aws:s3:..     S3 bucket versioning is disabled
MEDIUM     GC-AZURE-DISK-001    azure      /subscriptions/.. Managed disk is not encrypted

9 finding(s) (5 critical, 2 high, 2 medium) across 7 resource(s).
```

Emit JSON or SARIF for downstream tooling:

```bash
ghostcloud scan --input examples/all_providers.json --format json --output report.json
ghostcloud scan --input examples/all_providers.json --format sarif --output report.sarif
```

## CLI reference

```
ghostcloud scan    Scan a resource snapshot and report misconfigurations.
ghostcloud checks  List the available security checks.
ghostcloud version Print the ghostcloud version.
```

`scan` flags:

| Flag | Values | Default | Description |
| --- | --- | --- | --- |
| `--input`, `-i` | path | required | Resource snapshot JSON file. |
| `--provider`, `-p` | `aws`, `gcp`, `azure`, `all` | `all` | Provider scope to scan. |
| `--format`, `-f` | `console`, `json`, `sarif` | `console` | Output format. |
| `--min-severity` | `info`..`critical` | `info` | Only report findings at or above this severity. |
| `--fail-on` | `info`..`critical` | unset | Exit non-zero if any reported finding is at or above this severity. |
| `--output`, `-o` | path | stdout | Write the report to a file. |
| `--verbose`, `-v` | flag | off | Enable debug logging on stderr. |

Exit codes: `0` clean (or findings below `--fail-on`), `1` findings at or above
`--fail-on`, `2` snapshot error (missing or malformed input).

## Snapshot schema

A snapshot is a JSON object. Each provider key maps to a list of normalized
resources. Provider keys are optional; a snapshot may describe a single cloud.

```json
{
  "schema_version": 1,
  "aws":   [ { "service": "s3", "type": "bucket", "id": "...", "region": "us-east-1", "config": { } } ],
  "gcp":   [ { "service": "storage", "type": "bucket", "id": "...", "region": "us", "config": { } } ],
  "azure": [ { "service": "storage", "type": "storage_account", "id": "...", "region": "eastus", "config": { } } ]
}
```

Each resource has:

| Field | Required | Description |
| --- | --- | --- |
| `service` | yes | Logical service name, for example `s3`, `ec2`, `storage`. |
| `type` | yes | Resource type within the service, for example `bucket`, `security_group`. |
| `id` | yes | Stable identifier (ARN, self link, resource id, or name). |
| `region` | no | Region or location; may be empty for global resources. |
| `config` | no | Provider-shaped configuration block the checks inspect. |

The `config` shape per service is illustrated by the fixtures under
`tests/fixtures/` (a vulnerable and a clean example for each provider) and the
multi-cloud `examples/all_providers.json`. For example, an AWS security group:

```json
{
  "service": "ec2",
  "type": "security_group",
  "id": "sg-0a1b2c3d4e",
  "region": "us-east-1",
  "config": {
    "ingress_rules": [
      { "from_port": 22, "to_port": 22, "cidrs": ["0.0.0.0/0"] }
    ]
  }
}
```

## Checks

| ID | Provider | Service | Severity | Title |
| --- | --- | --- | --- | --- |
| GC-AWS-S3-001 | aws | s3 | CRITICAL | S3 bucket allows public access |
| GC-AWS-S3-002 | aws | s3 | HIGH | S3 bucket has no default encryption |
| GC-AWS-S3-003 | aws | s3 | MEDIUM | S3 bucket versioning is disabled |
| GC-AWS-EC2-001 | aws | ec2 | CRITICAL | Security group exposes an admin port to the internet |
| GC-AWS-EBS-001 | aws | ec2 | MEDIUM | EBS volume is not encrypted |
| GC-AWS-IAM-001 | aws | iam | HIGH | IAM user with console access has no MFA |
| GC-AWS-IAM-002 | aws | iam | CRITICAL | IAM policy grants wildcard action on all resources |
| GC-AWS-RDS-001 | aws | rds | HIGH | RDS instance is publicly accessible |
| GC-AWS-RDS-002 | aws | rds | HIGH | RDS instance storage is not encrypted |
| GC-AWS-CLOUDTRAIL-001 | aws | cloudtrail | HIGH | CloudTrail is disabled or not multi-region |
| GC-GCP-STORAGE-001 | gcp | storage | CRITICAL | Cloud Storage bucket is publicly accessible |
| GC-GCP-VPC-001 | gcp | compute | CRITICAL | Firewall rule allows unrestricted ingress |
| GC-GCP-COMPUTE-001 | gcp | compute | HIGH | Instance has a public IP with SSH reachable from the internet |
| GC-GCP-IAM-001 | gcp | iam | HIGH | Service account granted primitive owner role |
| GC-AZURE-STORAGE-001 | azure | storage | HIGH | Storage account allows public blob access |
| GC-AZURE-NSG-001 | azure | network | CRITICAL | Network security group allows admin access from the internet |
| GC-AZURE-DISK-001 | azure | compute | MEDIUM | Managed disk is not encrypted |

## CI gating

Use `--fail-on` to block a pipeline when findings reach a chosen severity. The
SARIF output integrates with code-scanning dashboards.

```yaml
- name: ghostcloud scan
  run: |
    pip install -e .
    ghostcloud scan --input snapshot.json --provider all --format sarif --output ghostcloud.sarif
    ghostcloud scan --input snapshot.json --provider all --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: ghostcloud.sarif
```

## Architecture

```
src/ghostcloud/
  models.py            Severity, Resource, Finding data model
  snapshot.py          Snapshot schema parsing and validation
  scanner.py           Runs checks with per-check isolation, severity filtering
  report.py            Console table, JSON, and SARIF 2.1.0 renderers
  cli.py               Typer CLI (scan, checks, version)
  checks/
    base.py            Check base class and provider-keyed Registry
    aws.py             AWS checks
    gcp.py             GCP checks
    azure.py           Azure checks
  collectors/          Optional live-collector interface (no cloud SDKs required)
```

A check declares metadata (id, provider, service, severity, description,
remediation) and implements `evaluate(resource)`, returning a `Finding` when a
resource is misconfigured or `None` otherwise. The scanner isolates each check so
one raising an exception is recorded as a scan error without aborting the run.

## Development

```bash
pip install -e ".[dev]"
ruff check .
pytest
```

The test suite is offline and runs under bare `pytest`. Every check has a
vulnerable fixture (where it must fire) and a clean fixture (where it must stay
silent), plus tests for SARIF validity, JSON round-trip, severity thresholds,
exit codes, and malformed-snapshot handling.

## Roadmap

- Live collectors for AWS (boto3), GCP, and Azure behind the existing interface.
- More checks: KMS key rotation, public AMIs and snapshots, GuardDuty enablement,
  GCP Cloud SQL public IP, Azure Key Vault soft-delete and purge protection.
- Policy packs and per-check suppression with justification.
- Baseline diffing to surface only newly introduced misconfigurations.

## License

MIT. See [LICENSE](LICENSE).
