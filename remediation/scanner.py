"""
Security Scanner — reads findings directly from Microsoft Defender for Cloud.

Why not reimplement the checks?
  Defender already scans everything — storage, AKS, Key Vault, VMs, networking.
  Reimplementing those checks would just be a worse version of Defender.

What we add on top:
  - Dependency analysis (blast radius)
  - Terraform patch for each finding
  - Sign-off routing based on resource tags
  - GitHub Issue with all context combined

This tool is the remediation layer ON TOP of Defender, not a replacement.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from remediation import config


@dataclass
class Finding:
    resource_id:        str
    resource_name:      str
    resource_group:     str
    resource_type:      str
    finding_id:         str     # Defender assessment name (short)
    title:              str     # Defender display name
    description:        str
    remediation:        str     # Defender's own remediation text
    risk:               str     # HIGH / MEDIUM / LOW
    defender_severity:  str     # Defender's original severity
    defender_link:      str     # Link to Defender portal for this finding
    tags:               dict = field(default_factory=dict)

    @property
    def owner(self) -> str:
        return self.tags.get("owner", self.tags.get("Owner", "unknown"))

    @property
    def stakeholders(self) -> list[str]:
        raw = self.tags.get("stakeholders", self.tags.get("Stakeholders", ""))
        return [s.strip() for s in raw.split(",") if s.strip()]

    @property
    def environment(self) -> str:
        return self.tags.get("environment", self.tags.get("Environment", "unknown"))

    @property
    def terraform_resource(self) -> str:
        """Map Azure resource type to Terraform resource name."""
        mapping = {
            "microsoft.storage/storageaccounts":               "azurerm_storage_account",
            "microsoft.containerservice/managedclusters":      "azurerm_kubernetes_cluster",
            "microsoft.keyvault/vaults":                       "azurerm_key_vault",
            "microsoft.compute/virtualmachines":               "azurerm_linux_virtual_machine",
            "microsoft.network/networksecuritygroups":         "azurerm_network_security_group",
            "microsoft.sql/servers":                           "azurerm_mssql_server",
            "microsoft.resources/subscriptions/resourcegroups": "azurerm_resource_group",
        }
        return mapping.get(self.resource_type.lower(), "azurerm_resource")


@dataclass
class ScanReport:
    run_date:        str
    subscription_id: str
    findings:        list[Finding] = field(default_factory=list)
    total_assessed:  int = 0
    total_healthy:   int = 0

    @property
    def high(self)   -> list[Finding]:
        return [f for f in self.findings if f.risk == config.RISK_HIGH]

    @property
    def medium(self) -> list[Finding]:
        return [f for f in self.findings if f.risk == config.RISK_MEDIUM]

    @property
    def low(self)    -> list[Finding]:
        return [f for f in self.findings if f.risk == config.RISK_LOW]


def run_scan() -> ScanReport:
    """
    Read all unhealthy assessments from Defender for Cloud.
    Returns ScanReport with findings enriched with resource tags.
    """
    report = ScanReport(
        run_date=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        subscription_id=config.AZURE_SUBSCRIPTION_ID or "mock-subscription",
    )

    if config.USE_MOCK_DATA:
        return _mock_scan(report)

    print("🔍 Reading compliance state from Defender for Cloud...")
    print("   (This may take 30-60 seconds for large subscriptions)")
    print("")

    try:
        from azure.mgmt.security import SecurityCenter
        from azure.mgmt.resource import ResourceManagementClient

        credential      = config.get_credential()
        security_client = SecurityCenter(credential, config.AZURE_SUBSCRIPTION_ID)
        resource_client = ResourceManagementClient(credential, config.AZURE_SUBSCRIPTION_ID)

        # Build tag cache — avoid API calls per resource
        print("  Building resource tag cache...")
        tag_cache = _build_tag_cache(resource_client)
        print(f"  Cached tags for {len(tag_cache)} resources")
        print("")

        # Read all Defender assessments
        scope = f"/subscriptions/{config.AZURE_SUBSCRIPTION_ID}"
        print("  Fetching Defender assessments...")

        assessed = 0
        healthy  = 0

        for assessment in security_client.assessments.list(scope):
            assessed += 1
            status = assessment.status

            # Only process unhealthy (non-compliant) resources
            if not status or status.code != "Unhealthy":
                healthy += 1
                continue

            # Extract resource details
            resource_details = assessment.resource_details
            if not resource_details:
                continue

            resource_id = getattr(resource_details, "id", "") or ""
            if not resource_id:
                continue

            # Parse resource ID
            parts = resource_id.split("/")
            resource_name  = parts[-1] if parts else "unknown"
            resource_group = parts[4] if len(parts) > 4 else "unknown"
            resource_type  = "/".join(parts[6:8]) if len(parts) > 7 else "unknown"

            # Get tags from cache
            tags = tag_cache.get(resource_id.lower(), {})

            # Map Defender severity to our risk levels
            severity      = getattr(assessment, "severity", "Medium") or "Medium"
            risk          = _map_severity(str(severity))

            # Get assessment metadata
            metadata = assessment.display_name or assessment.name or "Unknown finding"
            description = ""
            remediation = ""

            try:
                # Fetch full assessment metadata for description + remediation
                meta = security_client.assessments_metadata.get(assessment.name)
                description = getattr(meta, "description", "") or ""
                remediation = getattr(meta, "remediation_description", "") or ""
            except Exception:
                pass

            finding_id = _short_id(assessment.name or "unknown")
            portal_link = (
                f"https://portal.azure.com/#blade/Microsoft_Azure_Security/"
                f"RecommendationsBlade/assessmentKey/{assessment.name}"
            )

            report.findings.append(Finding(
                resource_id=resource_id,
                resource_name=resource_name,
                resource_group=resource_group,
                resource_type=resource_type,
                finding_id=finding_id,
                title=metadata,
                description=description or metadata,
                remediation=remediation or "See Defender for Cloud for remediation steps.",
                risk=risk,
                defender_severity=str(severity),
                defender_link=portal_link,
                tags=tags,
            ))

        report.total_assessed = assessed
        report.total_healthy  = healthy

    except ImportError:
        print("[ERROR] azure-mgmt-security not installed. Run: pip install azure-mgmt-security")
        raise
    except Exception as e:
        print(f"[ERROR] Failed to read Defender assessments: {e}")
        raise

    # Sort: HIGH first, then MEDIUM, then LOW
    report.findings.sort(key=lambda f: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(f.risk, 3))

    print(f"✅ Defender scan complete")
    print(f"   Total assessed:   {report.total_assessed}")
    print(f"   Healthy:          {report.total_healthy}")
    print(f"   Non-compliant:    {len(report.findings)}")
    print(f"     🔴 HIGH:        {len(report.high)}")
    print(f"     🟡 MEDIUM:      {len(report.medium)}")
    print(f"     🟢 LOW:         {len(report.low)}")

    return report


def _build_tag_cache(resource_client) -> dict:
    """
    Build a cache of resource_id → tags for all resources.
    Avoids per-resource API calls during assessment processing.
    """
    cache = {}
    try:
        # Cache resource group tags
        for rg in resource_client.resource_groups.list():
            cache[rg.id.lower()] = rg.tags or {}

        # Cache individual resource tags
        for resource in resource_client.resources.list():
            cache[resource.id.lower()] = resource.tags or {}

    except Exception as e:
        print(f"  [WARN] Tag cache partially failed: {e}")

    return cache


def _map_severity(severity: str) -> str:
    """Map Defender severity string to our risk levels."""
    mapping = {
        "High":   config.RISK_HIGH,
        "Medium": config.RISK_MEDIUM,
        "Low":    config.RISK_LOW,
    }
    return mapping.get(severity, config.RISK_MEDIUM)


def _short_id(assessment_name: str) -> str:
    """Generate a short readable ID from a Defender assessment GUID/name."""
    # Defender uses GUIDs — take first 8 chars
    clean = assessment_name.replace("-", "").upper()
    return f"DEF-{clean[:8]}"


# ── Mock data ─────────────────────────────────────────────────

def _mock_scan(report: ScanReport) -> ScanReport:
    """
    Mock Defender findings for local testing.
    These mirror real Defender for Cloud assessments.
    """
    print("🔍 Reading compliance state from Defender for Cloud (MOCK)...")
    print("")

    report.total_assessed = 47
    report.total_healthy  = 42

    report.findings = [
        # HIGH findings
        Finding(
            resource_id="/subscriptions/mock/resourceGroups/devops-platform-rg/providers/Microsoft.Storage/storageAccounts/devopsplatformacr",
            resource_name="devopsplatformacr",
            resource_group="devops-platform-rg",
            resource_type="Microsoft.Storage/storageAccounts",
            finding_id="DEF-59A1B2C3",
            title="Storage accounts should restrict network access",
            description="To protect your storage accounts, add a network access rule so that only clients from allowed networks can access the storage account.",
            remediation="Add network access rules to restrict access to only required networks. Disable public network access if clients can use private endpoints.",
            risk=config.RISK_HIGH,
            defender_severity="High",
            defender_link="https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade",
            tags={"owner": "platform-team", "environment": "production", "stakeholders": "platform,finops"},
        ),
        Finding(
            resource_id="/subscriptions/mock/resourceGroups/devops-platform-rg/providers/Microsoft.ContainerService/managedClusters/devops-platform-aks",
            resource_name="devops-platform-aks",
            resource_group="devops-platform-rg",
            resource_type="Microsoft.ContainerService/managedClusters",
            finding_id="DEF-AKS00042",
            title="Kubernetes Services should be upgraded to a non-vulnerable version",
            description="Upgrade your Kubernetes service cluster to a later Kubernetes version to protect against known vulnerabilities.",
            remediation="Upgrade the Kubernetes cluster to the latest supported version.",
            risk=config.RISK_HIGH,
            defender_severity="High",
            defender_link="https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade",
            tags={"owner": "platform-team", "environment": "production", "stakeholders": "platform,finops,aiops"},
        ),
        # MEDIUM findings
        Finding(
            resource_id="/subscriptions/mock/resourceGroups/finops-rg/providers/Microsoft.Storage/storageAccounts/tfstateprachi7",
            resource_name="tfstateprachi7",
            resource_group="finops-rg",
            resource_type="Microsoft.Storage/storageAccounts",
            finding_id="DEF-SOFT001",
            title="Geo-redundant storage should be enabled for storage accounts",
            description="Use geo-redundant storage to store data in a secondary region to ensure availability in case of regional outage.",
            remediation="Enable geo-redundant storage (GRS or GZRS) for your storage account.",
            risk=config.RISK_MEDIUM,
            defender_severity="Medium",
            defender_link="https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade",
            tags={"owner": "platform-team", "environment": "production", "stakeholders": "platform"},
        ),
        Finding(
            resource_id="/subscriptions/mock/resourceGroups/devops-platform-rg/providers/Microsoft.KeyVault/vaults/devops-kv",
            resource_name="devops-kv",
            resource_group="devops-platform-rg",
            resource_type="Microsoft.KeyVault/vaults",
            finding_id="DEF-KV00021",
            title="Key vaults should have soft delete enabled",
            description="Deleting a key vault without soft delete enabled permanently deletes all secrets, keys, and certificates stored in the key vault.",
            remediation="Enable soft delete to allow recovery of deleted vaults and vault objects.",
            risk=config.RISK_MEDIUM,
            defender_severity="Medium",
            defender_link="https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade",
            tags={"owner": "platform-team", "environment": "production", "stakeholders": "platform"},
        ),
        # LOW finding
        Finding(
            resource_id="/subscriptions/mock/resourceGroups/audit-test-empty-rg",
            resource_name="audit-test-empty-rg",
            resource_group="audit-test-empty-rg",
            resource_type="Microsoft.Resources/subscriptions/resourceGroups",
            finding_id="DEF-TAG0001",
            title="Subscriptions should have a contact email address for security issues",
            description="To ensure the relevant people in your organization are notified when there is a potential security breach in one of your subscriptions.",
            remediation="Set a security contact email address in Microsoft Defender for Cloud settings.",
            risk=config.RISK_LOW,
            defender_severity="Low",
            defender_link="https://portal.azure.com/#blade/Microsoft_Azure_Security/RecommendationsBlade",
            tags={},
        ),
    ]

    print(f"✅ Defender scan complete (mock)")
    print(f"   Total assessed:   {report.total_assessed}")
    print(f"   Healthy:          {report.total_healthy}")
    print(f"   Non-compliant:    {len(report.findings)}")
    print(f"     🔴 HIGH:        {len(report.high)}")
    print(f"     🟡 MEDIUM:      {len(report.medium)}")
    print(f"     🟢 LOW:         {len(report.low)}")
    print("")

    return report