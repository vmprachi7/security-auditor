"""
Dependency Analyzer.
Calculates blast radius before proposing any security patch.

For each finding:
1. Read resource tags → owner + stakeholders
2. Query ARM Resource Graph → dependent resources
3. Query Azure Monitor → who accessed it in last 30 days
4. Return structured dependency report
"""
from dataclasses import dataclass, field
from remediation import config
from remediation.scanner import Finding


@dataclass
class DependencyReport:
    finding_id:        str
    resource_name:     str
    owner:             str
    stakeholders:      list[str]
    dependent_resources: list[dict]
    recent_accessors:  list[dict]
    blast_radius:      str    # LOW / MEDIUM / HIGH
    notes:             list[str] = field(default_factory=list)

    @property
    def requires_broad_approval(self) -> bool:
        return self.blast_radius == "HIGH" or len(self.stakeholders) > 2

    @property
    def all_stakeholders(self) -> list[str]:
        """Combined list of owner + stakeholders (deduplicated)."""
        combined = [self.owner] + self.stakeholders
        return list(dict.fromkeys(s for s in combined if s and s != "unknown"))


def analyze(finding: Finding) -> DependencyReport:
    """
    Analyse dependencies for a given finding.
    Returns structured blast radius report.
    """
    if config.USE_MOCK_DATA:
        return _mock_dependency(finding)

    dependent_resources = _get_dependent_resources(finding)
    recent_accessors    = _get_recent_accessors(finding)
    blast_radius        = _calculate_blast_radius(
        finding, dependent_resources, recent_accessors
    )
    notes = _generate_notes(finding, dependent_resources, recent_accessors)

    return DependencyReport(
        finding_id=finding.finding_id,
        resource_name=finding.resource_name,
        owner=finding.owner,
        stakeholders=finding.stakeholders,
        dependent_resources=dependent_resources,
        recent_accessors=recent_accessors,
        blast_radius=blast_radius,
        notes=notes,
    )


def _get_dependent_resources(finding: Finding) -> list[dict]:
    """Query ARM Resource Graph for resources that depend on this one."""
    try:
        from azure.mgmt.resourcegraph import ResourceGraphClient
        from azure.mgmt.resourcegraph.models import QueryRequest

        client = ResourceGraphClient(config.get_credential())

        # Find resources in the same resource group that might depend on this
        query = f"""
        Resources
        | where resourceGroup =~ '{finding.resource_group}'
        | where id != '{finding.resource_id}'
        | project name, type, resourceGroup, tags
        | limit 20
        """

        result = client.resources(QueryRequest(
            subscriptions=[config.AZURE_SUBSCRIPTION_ID],
            query=query,
        ))

        return [
            {
                "name": row.get("name"),
                "type": row.get("type", "").split("/")[-1],
                "resource_group": row.get("resourceGroup"),
            }
            for row in (result.data or [])
        ]

    except Exception as e:
        print(f"    [WARN] Resource Graph query failed: {e}")
        return []


def _get_recent_accessors(finding: Finding) -> list[dict]:
    """
    Query Azure Monitor activity logs to find who accessed
    this resource in the last DEPENDENCY_LOOKBACK_DAYS days.
    """
    # Skip subscription-level findings — no resource URI to query
    if not finding.resource_id or "/" not in finding.resource_id:
        return []

    try:
        from azure.mgmt.monitor import MonitorManagementClient
        from datetime import datetime, timedelta, timezone

        client = MonitorManagementClient(config.get_credential(), config.AZURE_SUBSCRIPTION_ID)

        end   = datetime.now(timezone.utc)
        start = end - timedelta(days=config.DEPENDENCY_LOOKBACK_DAYS)

        filter_str = (
            f"eventTimestamp ge '{start.isoformat()}' and "
            f"eventTimestamp le '{end.isoformat()}' and "
            f"resourceUri eq '{finding.resource_id}'"
        )

        accessors = {}
        for event in client.activity_logs.list(filter=filter_str, select="caller,operationName,eventTimestamp"):
            caller = event.caller or "unknown"
            if caller not in accessors:
                accessors[caller] = {
                    "caller": caller,
                    "last_access": str(event.event_timestamp),
                    "operations": [],
                }
            op = event.operation_name.value if event.operation_name else "unknown"
            if op not in accessors[caller]["operations"]:
                accessors[caller]["operations"].append(op)

        return list(accessors.values())[:10]  # top 10

    except Exception as e:
        print(f"    [WARN] Activity log query failed: {e}")
        return []


def _calculate_blast_radius(
    finding: Finding,
    dependent_resources: list[dict],
    recent_accessors: list[dict],
) -> str:
    """Classify blast radius based on dependencies and access patterns."""
    score = 0

    # High-risk finding types
    if finding.risk == config.RISK_HIGH:
        score += 3

    # Many dependents
    if len(dependent_resources) > 10:
        score += 3
    elif len(dependent_resources) > 3:
        score += 2
    elif len(dependent_resources) > 0:
        score += 1

    # Many recent accessors
    if len(recent_accessors) > 5:
        score += 2
    elif len(recent_accessors) > 1:
        score += 1

    # Multiple stakeholders
    if len(finding.stakeholders) > 2:
        score += 2
    elif len(finding.stakeholders) > 0:
        score += 1

    # Production environment
    if finding.environment == "production":
        score += 2

    if score >= 7:
        return config.RISK_HIGH
    elif score >= 4:
        return config.RISK_MEDIUM
    else:
        return config.RISK_LOW


def _generate_notes(
    finding: Finding,
    dependent_resources: list[dict],
    recent_accessors: list[dict],
) -> list[str]:
    """Generate human-readable dependency notes for the PR."""
    notes = []

    if finding.owner == "unknown":
        notes.append(
            "⚠️ No owner tag found — cannot route for approval automatically. "
            "Please tag this resource with `owner: team-name`."
        )

    if dependent_resources:
        names = [r["name"] for r in dependent_resources[:5]]
        notes.append(
            f"📦 {len(dependent_resources)} resource(s) in the same resource group: "
            f"{', '.join(names)}"
            + (" and more..." if len(dependent_resources) > 5 else "")
        )

    if recent_accessors:
        callers = [a["caller"] for a in recent_accessors[:3]]
        notes.append(
            f"👥 {len(recent_accessors)} principal(s) accessed this resource "
            f"in the last {config.DEPENDENCY_LOOKBACK_DAYS} days: "
            f"{', '.join(callers)}"
        )
    else:
        notes.append(
            f"✅ No access activity found in last {config.DEPENDENCY_LOOKBACK_DAYS} days — "
            f"lower risk to patch."
        )

    if finding.environment == "production":
        notes.append("🚨 Production resource — extra caution required before patching.")

    return notes


# ── Mock data ─────────────────────────────────────────────────

def _mock_dependency(finding: Finding) -> DependencyReport:
    """Mock dependency reports for local testing."""
    mock_data = {
        "STORAGE-001": DependencyReport(
            finding_id="STORAGE-001",
            resource_name=finding.resource_name,
            owner="platform-team",
            stakeholders=["finops", "data-engineering"],
            dependent_resources=[
                {"name": "finops-engine", "type": "Deployment", "resource_group": "devops-platform-rg"},
                {"name": "agentic-aiops", "type": "Deployment", "resource_group": "devops-platform-rg"},
            ],
            recent_accessors=[
                {"caller": "finops-sp", "last_access": "2026-05-05T08:00:00Z", "operations": ["read"]},
                {"caller": "terraform-sp", "last_access": "2026-05-04T12:00:00Z", "operations": ["write"]},
            ],
            blast_radius=config.RISK_HIGH,
            notes=[
                "🚨 Production resource — extra caution required before patching.",
                "📦 2 deployments in the same resource group depend on this storage account.",
                "👥 2 service principals accessed this in the last 30 days: finops-sp, terraform-sp",
            ],
        ),
        "STORAGE-003": DependencyReport(
            finding_id="STORAGE-003",
            resource_name=finding.resource_name,
            owner="platform-team",
            stakeholders=["platform"],
            dependent_resources=[
                {"name": "tfstateprachi7", "type": "Storage", "resource_group": "finops-rg"},
            ],
            recent_accessors=[
                {"caller": "terraform-sp", "last_access": "2026-05-05T10:00:00Z", "operations": ["read", "write"]},
            ],
            blast_radius=config.RISK_MEDIUM,
            notes=[
                "⚠️ Used for Terraform state storage — disabling SAS requires all pipelines to switch to managed identity.",
                "👥 Only terraform-sp accessed this recently — lower blast radius.",
            ],
        ),
        "AKS-001": DependencyReport(
            finding_id="AKS-001",
            resource_name=finding.resource_name,
            owner="platform-team",
            stakeholders=["platform", "finops", "aiops"],
            dependent_resources=[
                {"name": "finops-engine", "type": "Deployment", "resource_group": "devops-platform-rg"},
                {"name": "agentic-aiops", "type": "Deployment", "resource_group": "devops-platform-rg"},
                {"name": "sample-app-1",  "type": "Deployment", "resource_group": "devops-platform-rg"},
                {"name": "sample-app-2",  "type": "Deployment", "resource_group": "devops-platform-rg"},
            ],
            recent_accessors=[
                {"caller": "prachi@capgemini.com", "last_access": "2026-05-05T11:00:00Z", "operations": ["kubectl"]},
                {"caller": "github-actions-sp",   "last_access": "2026-05-05T10:00:00Z", "operations": ["deploy"]},
                {"caller": "terraform-sp",         "last_access": "2026-05-04T09:00:00Z", "operations": ["read"]},
            ],
            blast_radius=config.RISK_HIGH,
            notes=[
                "🚨 Production AKS cluster — converting to private cluster requires recreation.",
                "📦 4 workloads running on this cluster: finops-engine, agentic-aiops, sample-app-1, sample-app-2",
                "👥 3 principals accessed this cluster recently.",
                "⚠️ Recommended approach: add authorized_ip_ranges first (non-destructive), then plan private cluster migration.",
            ],
        ),
    }

    return mock_data.get(finding.finding_id, DependencyReport(
        finding_id=finding.finding_id,
        resource_name=finding.resource_name,
        owner=finding.owner or "unknown",
        stakeholders=finding.stakeholders,
        dependent_resources=[],
        recent_accessors=[],
        blast_radius=finding.risk,
        notes=["No dependency data available for this finding type."],
    ))