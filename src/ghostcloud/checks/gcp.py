"""GCP security checks."""

from __future__ import annotations

from ghostcloud.checks._util import as_list, is_open_cidr, port_in_range
from ghostcloud.checks.base import Check
from ghostcloud.models import Finding, Resource, Severity

# IAM members that represent "everyone on the internet" in GCP policies.
PUBLIC_MEMBERS = ("allUsers", "allAuthenticatedUsers")


class StorageBucketPublic(Check):
    id = "GC-GCP-STORAGE-001"
    provider = "gcp"
    service = "storage"
    title = "Cloud Storage bucket is publicly accessible"
    severity = Severity.CRITICAL
    description = (
        "The bucket IAM policy binds allUsers or allAuthenticatedUsers, exposing "
        "object data to anyone on the internet."
    )
    remediation = (
        "Remove allUsers and allAuthenticatedUsers bindings and enable uniform "
        "bucket-level access with public access prevention enforced."
    )
    applies_to_types = ("bucket",)

    def evaluate(self, resource: Resource) -> Finding | None:
        public = []
        for binding in as_list(resource.config.get("iam_bindings")):
            members = [str(m) for m in as_list(binding.get("members"))]
            hit = [m for m in members if m in PUBLIC_MEMBERS]
            if hit:
                public.append({"role": binding.get("role"), "members": hit})
        if not public and str(resource.config.get("public_access_prevention", "")).lower() in (
            "enforced",
        ):
            return None
        if not public:
            return None
        return self.finding(resource, evidence={"public_bindings": public})


class FirewallAllowAllIngress(Check):
    id = "GC-GCP-VPC-001"
    provider = "gcp"
    service = "compute"
    title = "Firewall rule allows unrestricted ingress"
    severity = Severity.CRITICAL
    description = (
        "An ingress firewall rule allows traffic from 0.0.0.0/0 to a sensitive "
        "port such as SSH (22) or RDP (3389)."
    )
    remediation = (
        "Restrict source ranges to trusted networks and use Identity-Aware Proxy "
        "or a bastion for administrative access."
    )
    applies_to_types = ("firewall",)

    SENSITIVE_PORTS = (22, 3389)

    def evaluate(self, resource: Resource) -> Finding | None:
        cfg = resource.config
        if str(cfg.get("direction", "INGRESS")).upper() != "INGRESS":
            return None
        source_ranges = [str(c) for c in as_list(cfg.get("source_ranges"))]
        if not any(is_open_cidr(c) for c in source_ranges):
            return None
        offending = []
        for allowed in as_list(cfg.get("allowed")):
            ports = as_list(allowed.get("ports"))
            if not ports:
                # No ports listed means all ports for the protocol.
                offending.append({"protocol": allowed.get("protocol"), "ports": "all"})
                continue
            for spec in ports:
                lo, hi = _parse_port_spec(str(spec))
                for sp in self.SENSITIVE_PORTS:
                    if port_in_range(sp, lo, hi):
                        offending.append({"protocol": allowed.get("protocol"), "port": sp})
        if not offending:
            return None
        return self.finding(
            resource,
            evidence={"source_ranges": source_ranges, "exposed": offending},
        )


class ServiceAccountOwnerRole(Check):
    id = "GC-GCP-IAM-001"
    provider = "gcp"
    service = "iam"
    title = "Service account granted primitive owner role"
    severity = Severity.HIGH
    description = (
        "The service account is bound to roles/owner or roles/editor at the "
        "project level, far exceeding least privilege."
    )
    remediation = (
        "Replace primitive roles with predefined or custom roles scoped to the "
        "specific resources and actions the service account needs."
    )
    applies_to_types = ("service_account",)

    PRIVILEGED_ROLES = ("roles/owner", "roles/editor")

    def evaluate(self, resource: Resource) -> Finding | None:
        roles = [str(r) for r in as_list(resource.config.get("roles"))]
        hit = [r for r in roles if r in self.PRIVILEGED_ROLES]
        if not hit:
            return None
        return self.finding(resource, evidence={"privileged_roles": hit})


class InstancePublicIpOpenSsh(Check):
    id = "GC-GCP-COMPUTE-001"
    provider = "gcp"
    service = "compute"
    title = "Instance has a public IP with SSH reachable from the internet"
    severity = Severity.HIGH
    description = (
        "The compute instance has an external IP address and a network tag or "
        "rule that permits SSH from anywhere."
    )
    remediation = (
        "Remove the external IP where possible and gate SSH behind IAP or a "
        "bastion. Use OS Login with IAM-controlled access."
    )
    applies_to_types = ("instance",)

    def evaluate(self, resource: Resource) -> Finding | None:
        cfg = resource.config
        if not cfg.get("has_external_ip", False):
            return None
        if not cfg.get("ssh_open_to_internet", False):
            return None
        return self.finding(
            resource,
            evidence={"has_external_ip": True, "ssh_open_to_internet": True},
        )


def _parse_port_spec(spec: str) -> tuple[int, int]:
    """Parse a GCP port spec like ``"22"`` or ``"1000-2000"`` into a range."""

    spec = spec.strip()
    if "-" in spec:
        lo_s, hi_s = spec.split("-", 1)
        return int(lo_s), int(hi_s)
    p = int(spec)
    return p, p


def build() -> list[Check]:
    return [
        StorageBucketPublic(),
        FirewallAllowAllIngress(),
        ServiceAccountOwnerRole(),
        InstancePublicIpOpenSsh(),
    ]
