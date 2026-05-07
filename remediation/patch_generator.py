"""
Patch Generator.
Uses Groq AI to generate Terraform patches for each security finding.
Also generates rollback plans for HIGH risk changes.
"""
from dataclasses import dataclass
from openai import OpenAI
from remediation import config
from remediation.scanner import Finding
from remediation.dependency import DependencyReport


@dataclass
class Patch:
    finding_id:     str
    terraform_hcl:  str    # the actual fix
    rollback_plan:  str    # how to undo it
    apply_command:  str    # exact terraform command to run
    risk_notes:     str    # what could go wrong


def generate(finding: Finding, dependency: DependencyReport) -> Patch:
    """Generate a Terraform patch for the given finding."""
    if not config.GROQ_API_KEY:
        return _rule_based_patch(finding, dependency)

    try:
        client = OpenAI(
            api_key=config.GROQ_API_KEY,
            base_url="https://api.groq.com/openai/v1",
        )

        prompt = _build_prompt(finding, dependency)
        response = client.chat.completions.create(
            model=config.AI_MODEL,
            max_tokens=config.AI_MAX_TOKENS,
            messages=[{"role": "user", "content": prompt}],
        )

        return _parse_response(finding, response.choices[0].message.content)

    except Exception as e:
        print(f"    [WARN] AI patch generation failed: {e} — using rule-based fallback")
        return _rule_based_patch(finding, dependency)


def _build_prompt(finding: Finding, dependency: DependencyReport) -> str:
    deps = "\n".join(f"  - {d['name']} ({d['type']})"
                     for d in dependency.dependent_resources[:5])
    accessors = "\n".join(f"  - {a['caller']} (last: {a['last_access']})"
                          for a in dependency.recent_accessors[:3])

    return f"""You are a senior Azure DevOps engineer generating a Terraform security patch.

SECURITY FINDING
ID:           {finding.finding_id}
Title:        {finding.title}
Resource:     {finding.resource_name} ({finding.resource_type})
Risk:         {finding.risk}
Description:  {finding.description}
Recommendation: {finding.remediation}

DEPENDENCIES
Blast radius:       {dependency.blast_radius}
Owner:              {dependency.owner}
Stakeholders:       {', '.join(dependency.stakeholders) or 'none'}
Dependent resources:
{deps or '  None found'}
Recent accessors:
{accessors or '  None found'}

TASK
Generate a Terraform patch to fix this security finding.
Respond in EXACTLY this format:

## Terraform Fix
```hcl
[The minimal Terraform change needed — only the changed attributes, not the full resource]
```

## Rollback Plan
[Plain English steps to undo this change if something breaks]

## Apply Command
```bash
[Exact terraform command to apply — include -target flag to limit scope]
```

## Risk Notes
[2-3 sentences on what could go wrong and how to verify it worked]

Rules:
- Terraform fix must be minimal — only the attributes that need changing
- Include the resource name and resource group in the terraform fix
- Rollback plan must be specific — not just "revert the change"
- Apply command must use -target to limit blast radius
- If this is a HIGH risk change, note that manual verification is required after apply"""


def _parse_response(finding: Finding, raw: str) -> Patch:
    sections = {"terraform": "", "rollback": "", "apply": "", "risk": ""}

    current = None
    lines   = raw.split("\n")
    buffer  = []

    for line in lines:
        if "## Terraform Fix" in line:
            current = "terraform"
            buffer  = []
        elif "## Rollback Plan" in line:
            if current:
                sections[current] = "\n".join(buffer).strip()
            current = "rollback"
            buffer  = []
        elif "## Apply Command" in line:
            if current:
                sections[current] = "\n".join(buffer).strip()
            current = "apply"
            buffer  = []
        elif "## Risk Notes" in line:
            if current:
                sections[current] = "\n".join(buffer).strip()
            current = "risk"
            buffer  = []
        elif current:
            buffer.append(line)

    if current and buffer:
        sections[current] = "\n".join(buffer).strip()

    return Patch(
        finding_id=finding.finding_id,
        terraform_hcl=sections["terraform"] or _fallback_hcl(finding),
        rollback_plan=sections["rollback"] or "Manual review required — document current state before applying.",
        apply_command=sections["apply"] or f"terraform apply -target=azurerm_{finding.terraform_resource}.{finding.resource_name.replace('-', '_')}",
        risk_notes=sections["risk"] or "Review the change carefully before applying.",
    )


def _rule_based_patch(finding: Finding, dependency: DependencyReport) -> Patch:
    """Rule-based patches for common findings when AI is unavailable."""
    patches = {
        "STORAGE-001": Patch(
            finding_id="STORAGE-001",
            terraform_hcl=f"""resource "azurerm_storage_account" "{finding.resource_name.replace('-', '_')}" {{
  # ... existing config ...
  allow_blob_public_access  = false   # SECURITY FIX
  min_tls_version           = "TLS1_2"
}}""",
            rollback_plan=f"Set allow_blob_public_access = true in Terraform and re-apply. "
                          f"Verify with: az storage account show --name {finding.resource_name} "
                          f"--query allowBlobPublicAccess",
            apply_command=f"terraform apply -target=azurerm_storage_account.{finding.resource_name.replace('-', '_')}",
            risk_notes="Any app reading public blobs anonymously will get 403 after this change. "
                       "Verify all clients use authenticated access before applying. "
                       "Check Storage Browser in Azure Portal for public containers first.",
        ),
        "STORAGE-002": Patch(
            finding_id="STORAGE-002",
            terraform_hcl=f"""resource "azurerm_storage_account" "{finding.resource_name.replace('-', '_')}" {{
  blob_properties {{
    delete_retention_policy {{
      days = 30   # SECURITY FIX — enable soft delete
    }}
    container_delete_retention_policy {{
      days = 30
    }}
  }}
}}""",
            rollback_plan="Disable soft delete in portal: Storage account → Data protection → "
                          "Uncheck 'Enable soft delete for blobs'. Note: already-soft-deleted items "
                          "will be retained until their expiry.",
            apply_command=f"terraform apply -target=azurerm_storage_account.{finding.resource_name.replace('-', '_')}",
            risk_notes="Safe to apply — enabling soft delete has no impact on running applications. "
                       "It only affects what happens when blobs are deleted. Zero risk change.",
        ),
        "STORAGE-003": Patch(
            finding_id="STORAGE-003",
            terraform_hcl=f"""resource "azurerm_storage_account" "{finding.resource_name.replace('-', '_')}" {{
  # ... existing config ...
  shared_access_key_enabled = false   # SECURITY FIX — disable SAS tokens
}}

# IMPORTANT: All clients must switch to managed identity BEFORE applying this.
# Test with one non-production client first.""",
            rollback_plan=f"Set shared_access_key_enabled = true and re-apply. "
                          f"Immediately re-issue SAS tokens to any affected clients. "
                          f"Command: az storage account update --name {finding.resource_name} "
                          f"--allow-shared-key-access true",
            apply_command=f"terraform apply -target=azurerm_storage_account.{finding.resource_name.replace('-', '_')}",
            risk_notes="HIGH IMPACT — any app using SAS tokens or storage account keys will "
                       "immediately lose access. Requires all clients to use managed identity. "
                       "Do not apply without verifying all clients are migrated first.",
        ),
        "AKS-001": Patch(
            finding_id="AKS-001",
            terraform_hcl=f"""resource "azurerm_kubernetes_cluster" "{finding.resource_name.replace('-', '_')}" {{
  # OPTION 1 (non-destructive — recommended first step):
  api_server_access_profile {{
    authorized_ip_ranges = [
      "YOUR_OFFICE_IP/32",
      "YOUR_PIPELINE_IP/32",
    ]
  }}

  # OPTION 2 (destructive — requires cluster recreation):
  # private_cluster_enabled = true
}}""",
            rollback_plan="Remove authorized_ip_ranges to restore open access. "
                          "For private cluster: cluster must be recreated — plan a maintenance window. "
                          "Keep kubectl access from a bastion host during migration.",
            apply_command=f"terraform apply -target=azurerm_kubernetes_cluster.{finding.resource_name.replace('-', '_')}",
            risk_notes="Option 1 (IP restriction) is non-destructive and reversible — recommended first. "
                       "Option 2 (private cluster) requires cluster recreation — coordinate with all teams. "
                       "Verify your pipeline runner IP is in the allowlist before applying.",
        ),
        "KV-001": Patch(
            finding_id="KV-001",
            terraform_hcl=f"""resource "azurerm_key_vault" "{finding.resource_name.replace('-', '_')}" {{
  # ... existing config ...
  soft_delete_retention_days = 90   # SECURITY FIX
  purge_protection_enabled   = true  # prevents permanent deletion
}}""",
            rollback_plan="Cannot disable soft delete once enabled — this is by design. "
                          "Purge protection also cannot be disabled once on. "
                          "These are safe-only changes with no rollback path.",
            apply_command=f"terraform apply -target=azurerm_key_vault.{finding.resource_name.replace('-', '_')}",
            risk_notes="Safe to apply — soft delete and purge protection only affect deletion behaviour. "
                       "No impact on read/write operations. Zero downtime. Strongly recommended.",
        ),
        "KV-002": Patch(
            finding_id="KV-002",
            terraform_hcl=f"""resource "azurerm_key_vault" "{finding.resource_name.replace('-', '_')}" {{
  # ... existing config ...
  network_acls {{
    default_action             = "Deny"
    bypass                     = "AzureServices"
    ip_rules                   = ["YOUR_OFFICE_IP/32"]
    virtual_network_subnet_ids = [
      azurerm_subnet.aks_subnet.id,
    ]
  }}
}}""",
            rollback_plan=f"Set default_action = Allow and re-apply. "
                          f"Command: az keyvault update --name {finding.resource_name} "
                          f"--default-action Allow",
            apply_command=f"terraform apply -target=azurerm_key_vault.{finding.resource_name.replace('-', '_')}",
            risk_notes="Any app not in the allowlist will get 403. "
                       "Add AKS subnet, pipeline runner IPs, and your own IP before applying. "
                       "Test access from each caller after applying.",
        ),
    }

    return patches.get(finding.finding_id, Patch(
        finding_id=finding.finding_id,
        terraform_hcl=_fallback_hcl(finding),
        rollback_plan="Document current state before applying. Revert the specific attribute changed.",
        apply_command=f"terraform apply -target={finding.terraform_resource}.{finding.resource_name.replace('-', '_')}",
        risk_notes="Manual review required. Verify dependencies before applying.",
    ))


def _fallback_hcl(finding: Finding) -> str:
    return f"""# Fix for {finding.finding_id}: {finding.title}
# Resource: {finding.resource_name}
#
# {finding.remediation}
#
# TODO: Add specific Terraform attributes for {finding.terraform_resource}"""