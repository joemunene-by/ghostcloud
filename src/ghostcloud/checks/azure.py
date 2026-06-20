"""Azure security checks."""

from __future__ import annotations

from ghostcloud.checks._util import as_list, is_open_cidr, port_in_range
from ghostcloud.checks.base import Check
from ghostcloud.models import Finding, Resource, Severity


class StorageAccountPublicBlob(Check):
    id = "GC-AZURE-STORAGE-001"
    provider = "azure"
    service = "storage"
    title = "Storage account allows public blob access"
    severity = Severity.HIGH
    description = (
        "The storage account has allowBlobPublicAccess enabled, permitting "
        "anonymous read access to containers configured as public."
    )
    remediation = (
        "Set allowBlobPublicAccess to false on the storage account and use SAS "
        "tokens or Azure AD authentication for access."
    )
    applies_to_types = ("storage_account",)

    def evaluate(self, resource: Resource) -> Finding | None:
        if not resource.config.get("allow_blob_public_access", False):
            return None
        return self.finding(resource, evidence={"allow_blob_public_access": True})


class NsgAdminPortFromInternet(Check):
    id = "GC-AZURE-NSG-001"
    provider = "azure"
    service = "network"
    title = "Network security group allows admin access from the internet"
    severity = Severity.CRITICAL
    description = (
        "An inbound NSG rule allows traffic from Internet or 0.0.0.0/0 to SSH (22) "
        "or RDP (3389)."
    )
    remediation = (
        "Restrict the rule's source to specific address prefixes, or use Azure "
        "Bastion and just-in-time VM access instead of open management ports."
    )
    applies_to_types = ("network_security_group",)

    ADMIN_PORTS = (22, 3389)

    def evaluate(self, resource: Resource) -> Finding | None:
        offending = []
        for rule in as_list(resource.config.get("security_rules")):
            if str(rule.get("direction", "Inbound")).lower() != "inbound":
                continue
            if str(rule.get("access", "Allow")).lower() != "allow":
                continue
            src = str(rule.get("source_address_prefix", ""))
            sources = [src] + [str(s) for s in as_list(rule.get("source_address_prefixes"))]
            if not any(_is_internet_source(s) for s in sources):
                continue
            for spec in _rule_ports(rule):
                lo, hi = spec
                for port in self.ADMIN_PORTS:
                    if port_in_range(port, lo, hi):
                        offending.append({"port": port, "sources": [s for s in sources if s]})
        if not offending:
            return None
        return self.finding(resource, evidence={"open_admin_rules": offending})


class DiskUnencrypted(Check):
    id = "GC-AZURE-DISK-001"
    provider = "azure"
    service = "compute"
    title = "Managed disk is not encrypted"
    severity = Severity.MEDIUM
    description = (
        "The managed disk does not have encryption at rest enabled via a disk "
        "encryption set or platform-managed keys."
    )
    remediation = (
        "Enable encryption at rest using platform-managed keys or, for stricter "
        "control, customer-managed keys via a disk encryption set."
    )
    applies_to_types = ("disk",)

    def evaluate(self, resource: Resource) -> Finding | None:
        enc = resource.config.get("encryption", {}) or {}
        if enc.get("enabled") is True:
            return None
        return self.finding(resource, evidence={"encryption": enc})


def _is_internet_source(source: str) -> bool:
    s = source.strip().lower()
    if s in ("internet", "*", "any"):
        return True
    return is_open_cidr(source.strip())


def _rule_ports(rule: dict) -> list[tuple[int | None, int | None]]:
    """Yield (low, high) bounds for each destination port spec on a rule."""

    specs: list[tuple[int | None, int | None]] = []
    raw = []
    if rule.get("destination_port_range") is not None:
        raw.append(rule["destination_port_range"])
    raw.extend(as_list(rule.get("destination_port_ranges")))
    for spec in raw:
        text = str(spec).strip()
        if text in ("*", "any"):
            specs.append((None, None))
        elif "-" in text:
            lo_s, hi_s = text.split("-", 1)
            specs.append((int(lo_s), int(hi_s)))
        else:
            p = int(text)
            specs.append((p, p))
    return specs


def build() -> list[Check]:
    return [
        StorageAccountPublicBlob(),
        NsgAdminPortFromInternet(),
        DiskUnencrypted(),
    ]
