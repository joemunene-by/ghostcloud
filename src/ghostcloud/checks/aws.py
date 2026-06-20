"""AWS security checks.

Each check evaluates the ``config`` block of a normalized AWS resource. See
``docs`` in the README for the expected snapshot shape per service.
"""

from __future__ import annotations

from ghostcloud.checks._util import as_list, is_open_cidr, port_in_range
from ghostcloud.checks.base import Check
from ghostcloud.models import Finding, Resource, Severity


class S3PublicAccess(Check):
    id = "GC-AWS-S3-001"
    provider = "aws"
    service = "s3"
    title = "S3 bucket allows public access"
    severity = Severity.CRITICAL
    description = (
        "The bucket's public access block is not fully enabled or its ACL/policy "
        "grants access to all AWS users or anonymous principals."
    )
    remediation = (
        "Enable all four S3 Block Public Access settings on the bucket and account, "
        "and remove public-read or public-read-write ACLs and bucket policies."
    )
    applies_to_types = ("bucket",)

    def evaluate(self, resource: Resource) -> Finding | None:
        cfg = resource.config
        pab = cfg.get("public_access_block", {}) or {}
        required = (
            "block_public_acls",
            "block_public_policy",
            "ignore_public_acls",
            "restrict_public_buckets",
        )
        pab_complete = all(pab.get(k) is True for k in required)
        acl = str(cfg.get("acl", "")).lower()
        public_acl = acl in ("public-read", "public-read-write", "authenticated-read")
        if pab_complete and not public_acl:
            return None
        return self.finding(
            resource,
            evidence={"public_access_block": pab, "acl": cfg.get("acl")},
        )


class S3NoEncryption(Check):
    id = "GC-AWS-S3-002"
    provider = "aws"
    service = "s3"
    title = "S3 bucket has no default encryption"
    severity = Severity.HIGH
    description = "The bucket does not have default server-side encryption configured."
    remediation = (
        "Enable default encryption (SSE-S3 or SSE-KMS) on the bucket so all new "
        "objects are encrypted at rest."
    )
    applies_to_types = ("bucket",)

    def evaluate(self, resource: Resource) -> Finding | None:
        enc = resource.config.get("encryption", {}) or {}
        if enc.get("enabled") is True:
            return None
        return self.finding(resource, evidence={"encryption": enc})


class S3NoVersioning(Check):
    id = "GC-AWS-S3-003"
    provider = "aws"
    service = "s3"
    title = "S3 bucket versioning is disabled"
    severity = Severity.MEDIUM
    description = (
        "Versioning is disabled, so overwritten or deleted objects cannot be "
        "recovered and ransomware or accidental deletion is harder to undo."
    )
    remediation = "Enable versioning on the bucket and consider MFA delete for critical data."
    applies_to_types = ("bucket",)

    def evaluate(self, resource: Resource) -> Finding | None:
        versioning = resource.config.get("versioning", {}) or {}
        if str(versioning.get("status", "")).lower() == "enabled":
            return None
        return self.finding(resource, evidence={"versioning": versioning})


class SecurityGroupOpenAdminPort(Check):
    id = "GC-AWS-EC2-001"
    provider = "aws"
    service = "ec2"
    title = "Security group exposes an admin port to the internet"
    severity = Severity.CRITICAL
    description = (
        "An inbound rule allows 0.0.0.0/0 (or ::/0) to a remote administration "
        "port such as SSH (22) or RDP (3389)."
    )
    remediation = (
        "Restrict the inbound rule to known administrative CIDR ranges or use a "
        "bastion host, SSM Session Manager, or VPN instead of public exposure."
    )
    applies_to_types = ("security_group",)

    ADMIN_PORTS = (22, 3389)

    def evaluate(self, resource: Resource) -> Finding | None:
        offending = []
        for rule in as_list(resource.config.get("ingress_rules")):
            cidrs = as_list(rule.get("cidrs")) or as_list(rule.get("cidr"))
            if not any(is_open_cidr(str(c)) for c in cidrs):
                continue
            for port in self.ADMIN_PORTS:
                if port_in_range(port, rule.get("from_port"), rule.get("to_port")):
                    offending.append({"port": port, "cidrs": cidrs})
        if not offending:
            return None
        return self.finding(resource, evidence={"open_admin_rules": offending})


class IamUserNoMfa(Check):
    id = "GC-AWS-IAM-001"
    provider = "aws"
    service = "iam"
    title = "IAM user with console access has no MFA"
    severity = Severity.HIGH
    description = (
        "The IAM user has a console login profile but no MFA device, leaving the "
        "account protected only by a password."
    )
    remediation = (
        "Enforce MFA for all human users and add an IAM policy that denies "
        "actions performed without MFA."
    )
    applies_to_types = ("user",)

    def evaluate(self, resource: Resource) -> Finding | None:
        cfg = resource.config
        if not cfg.get("console_access", False):
            return None
        if cfg.get("mfa_enabled", False):
            return None
        return self.finding(
            resource,
            evidence={"console_access": True, "mfa_enabled": cfg.get("mfa_enabled", False)},
        )


class IamWildcardPolicy(Check):
    id = "GC-AWS-IAM-002"
    provider = "aws"
    service = "iam"
    title = "IAM policy grants wildcard action on all resources"
    severity = Severity.CRITICAL
    description = (
        "An attached policy statement allows Action '*' on Resource '*' with "
        "effect Allow, granting full administrative access."
    )
    remediation = (
        "Scope policies to the minimum actions and resources required. Avoid "
        "Action '*' combined with Resource '*' outside of break-glass roles."
    )
    applies_to_types = ("policy",)

    def evaluate(self, resource: Resource) -> Finding | None:
        offending = []
        for stmt in as_list(resource.config.get("statements")):
            if str(stmt.get("effect", "")).lower() != "allow":
                continue
            actions = [str(a) for a in as_list(stmt.get("action"))]
            resources = [str(r) for r in as_list(stmt.get("resource"))]
            if "*" in actions and "*" in resources:
                offending.append(stmt)
        if not offending:
            return None
        return self.finding(resource, evidence={"wildcard_statements": offending})


class RdsPubliclyAccessible(Check):
    id = "GC-AWS-RDS-001"
    provider = "aws"
    service = "rds"
    title = "RDS instance is publicly accessible"
    severity = Severity.HIGH
    description = "The RDS instance has PubliclyAccessible enabled, giving it a public endpoint."
    remediation = (
        "Set PubliclyAccessible to false and place the instance in private subnets "
        "reachable only from within the VPC."
    )
    applies_to_types = ("db_instance",)

    def evaluate(self, resource: Resource) -> Finding | None:
        if not resource.config.get("publicly_accessible", False):
            return None
        return self.finding(resource, evidence={"publicly_accessible": True})


class RdsUnencrypted(Check):
    id = "GC-AWS-RDS-002"
    provider = "aws"
    service = "rds"
    title = "RDS instance storage is not encrypted"
    severity = Severity.HIGH
    description = "The RDS instance does not have storage encryption enabled."
    remediation = (
        "Enable storage encryption. For existing instances, restore an encrypted "
        "copy from a snapshot since encryption cannot be toggled in place."
    )
    applies_to_types = ("db_instance",)

    def evaluate(self, resource: Resource) -> Finding | None:
        if resource.config.get("storage_encrypted", False):
            return None
        return self.finding(resource, evidence={"storage_encrypted": False})


class CloudTrailDisabled(Check):
    id = "GC-AWS-CLOUDTRAIL-001"
    provider = "aws"
    service = "cloudtrail"
    title = "CloudTrail is disabled or not multi-region"
    severity = Severity.HIGH
    description = (
        "The trail is not logging or is not multi-region, leaving gaps in the "
        "audit record of account activity."
    )
    remediation = (
        "Enable a multi-region CloudTrail with log file validation and ship logs "
        "to a dedicated, access-restricted S3 bucket."
    )
    applies_to_types = ("trail",)

    def evaluate(self, resource: Resource) -> Finding | None:
        cfg = resource.config
        if cfg.get("is_logging", False) and cfg.get("is_multi_region", False):
            return None
        return self.finding(
            resource,
            evidence={
                "is_logging": cfg.get("is_logging", False),
                "is_multi_region": cfg.get("is_multi_region", False),
            },
        )


class EbsVolumeUnencrypted(Check):
    id = "GC-AWS-EBS-001"
    provider = "aws"
    service = "ec2"
    title = "EBS volume is not encrypted"
    severity = Severity.MEDIUM
    description = "The EBS volume does not have encryption enabled, so data at rest is unprotected."
    remediation = (
        "Enable EBS encryption by default for the account and recreate the volume "
        "from an encrypted snapshot."
    )
    applies_to_types = ("volume",)

    def evaluate(self, resource: Resource) -> Finding | None:
        if resource.config.get("encrypted", False):
            return None
        return self.finding(resource, evidence={"encrypted": False})


def build() -> list[Check]:
    return [
        S3PublicAccess(),
        S3NoEncryption(),
        S3NoVersioning(),
        SecurityGroupOpenAdminPort(),
        IamUserNoMfa(),
        IamWildcardPolicy(),
        RdsPubliclyAccessible(),
        RdsUnencrypted(),
        CloudTrailDisabled(),
        EbsVolumeUnencrypted(),
    ]
