"""
AI Explainer for shift-left scan results.
Takes raw Checkov + tfsec JSON output and produces:
1. Plain English explanation of each finding
2. Specific fix for the exact Terraform code
3. PR comment in markdown
"""
import json
import sys
import os
from dataclasses import dataclass, field
from openai import OpenAI


@dataclass
class ShiftLeftFinding:
    tool:        str       # checkov or tfsec
    check_id:    str       # e.g. CKV_AZURE_59
    severity:    str       # HIGH / MEDIUM / LOW
    title:       str
    resource:    str       # resource name in Terraform
    file:        str       # which .tf file
    line:        int       # line number
    description: str
    fix_link:    str = ""


@dataclass
class ExplainedFinding:
    finding:     ShiftLeftFinding
    plain_english: str    # what's wrong, why it matters
    terraform_fix: str    # exact code to add/change
    effort:      str      # "1 line change" / "requires refactor"


def load_checkov(path: str) -> list[ShiftLeftFinding]:
    """Parse Checkov JSON output into findings."""
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)

        # Handle both single and multi-framework output
        results = data.get("results", data)
        if isinstance(results, dict):
            failed = results.get("failed_checks", [])
        else:
            failed = []

        for check in failed:
            severity = _checkov_severity(check.get("check_id", ""))
            findings.append(ShiftLeftFinding(
                tool="checkov",
                check_id=check.get("check_id", "UNKNOWN"),
                severity=severity,
                title=check.get("check_name", "Unknown check"),
                resource=check.get("resource", "unknown"),
                file=check.get("repo_file_path", check.get("file_path", "unknown")),
                line=check.get("file_line_range", [0, 0])[0],
                description=check.get("check_name", ""),
                fix_link=check.get("guideline", ""),
            ))
    except Exception as e:
        print(f"[WARN] Failed to parse Checkov results: {e}", file=sys.stderr)
    return findings


def load_tfsec(path: str) -> list[ShiftLeftFinding]:
    """Parse tfsec JSON output into findings."""
    findings = []
    try:
        with open(path) as f:
            data = json.load(f)

        for result in data.get("results", []):
            severity = result.get("severity", "MEDIUM").upper()
            if severity == "WARNING":
                severity = "MEDIUM"
            elif severity == "ERROR":
                severity = "HIGH"

            findings.append(ShiftLeftFinding(
                tool="tfsec",
                check_id=result.get("rule_id", "UNKNOWN"),
                severity=severity,
                title=result.get("rule_summary", "Unknown"),
                resource=result.get("resource", "unknown"),
                file=result.get("location", {}).get("filename", "unknown"),
                line=result.get("location", {}).get("start_line", 0),
                description=result.get("rule_description", ""),
                fix_link=result.get("links", [""])[0] if result.get("links") else "",
            ))
    except Exception as e:
        print(f"[WARN] Failed to parse tfsec results: {e}", file=sys.stderr)
    return findings


def explain_findings(
    findings: list[ShiftLeftFinding],
    tf_context: str = "",
) -> list[ExplainedFinding]:
    """Use Groq AI to explain each finding and generate fixes."""
    groq_key = os.getenv("GROQ_API_KEY", "")
    if not groq_key or not findings:
        return [_rule_based_explanation(f) for f in findings]

    explained = []
    try:
        client = OpenAI(
            api_key=groq_key,
            base_url="https://api.groq.com/openai/v1",
        )

        # Batch all findings in one prompt to save API calls
        findings_text = "\n".join([
            f"{i+1}. [{f.check_id}] {f.title}\n"
            f"   Resource: {f.resource} in {f.file}:{f.line}\n"
            f"   Severity: {f.severity}"
            for i, f in enumerate(findings[:10])  # max 10
        ])

        prompt = f"""You are a senior DevOps engineer reviewing Terraform security findings on an Azure PR.

FINDINGS:
{findings_text}

TERRAFORM CONTEXT (relevant snippets):
{tf_context[:2000] if tf_context else "Not provided"}

For each finding, respond with this exact format (one block per finding):

---FINDING 1---
PLAIN_ENGLISH: [1-2 sentences: what's wrong and why it matters to a developer, no jargon]
TERRAFORM_FIX: [exact attribute(s) to add/change — minimal, copy-pasteable]
EFFORT: [one of: "1 line change" / "2-3 line change" / "requires refactor"]

---FINDING 2---
...

Rules:
- Plain English must be understood by a developer who doesn't know security
- Terraform fix must be the minimal change — just the attribute(s), not the full resource
- If it's a false positive or not applicable to Azure, say so in plain English"""

        response = client.chat.completions.create(
            model="llama-3.1-8b-instant",
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )

        explained = _parse_ai_response(findings, response.choices[0].message.content)

    except Exception as e:
        print(f"[WARN] AI explanation failed: {e} — using rule-based", file=sys.stderr)
        explained = [_rule_based_explanation(f) for f in findings]

    return explained


def _parse_ai_response(
    findings: list[ShiftLeftFinding],
    raw: str,
) -> list[ExplainedFinding]:
    """Parse AI response into ExplainedFinding objects."""
    explained = []
    blocks    = raw.split("---FINDING")

    for i, finding in enumerate(findings):
        plain   = ""
        tf_fix  = ""
        effort  = "review required"

        # Find matching block
        for block in blocks:
            if block.strip().startswith(str(i + 1)):
                lines = block.split("\n")
                for line in lines:
                    if line.startswith("PLAIN_ENGLISH:"):
                        plain = line.replace("PLAIN_ENGLISH:", "").strip()
                    elif line.startswith("TERRAFORM_FIX:"):
                        tf_fix = line.replace("TERRAFORM_FIX:", "").strip()
                    elif line.startswith("EFFORT:"):
                        effort = line.replace("EFFORT:", "").strip()
                break

        explained.append(ExplainedFinding(
            finding=finding,
            plain_english=plain or finding.title,
            terraform_fix=tf_fix or "# See documentation for fix",
            effort=effort,
        ))

    return explained


def _rule_based_explanation(finding: ShiftLeftFinding) -> ExplainedFinding:
    """Fallback explanations for common checks."""
    explanations = {
        "CKV_AZURE_59": ExplainedFinding(
            finding=finding,
            plain_english="Your storage account allows public anonymous access to blobs. "
                          "Anyone on the internet can read your data without a password.",
            terraform_fix="allow_blob_public_access = false",
            effort="1 line change",
        ),
        "CKV_AZURE_33": ExplainedFinding(
            finding=finding,
            plain_english="Your storage account doesn't log read operations. "
                          "You won't know if someone reads sensitive data.",
            terraform_fix='logging {\n  read = true\n  write = true\n  delete = true\n  version = "2.0"\n  retention_policy_days = 30\n}',
            effort="2-3 line change",
        ),
        "CKV_AZURE_7": ExplainedFinding(
            finding=finding,
            plain_english="Your AKS cluster doesn't use RBAC. "
                          "All authenticated users have full cluster access — no fine-grained permissions.",
            terraform_fix="role_based_access_control_enabled = true",
            effort="1 line change",
        ),
        "CKV_AZURE_5": ExplainedFinding(
            finding=finding,
            plain_english="Your AKS cluster API server is publicly accessible. "
                          "The Kubernetes API can be reached from anywhere on the internet.",
            terraform_fix='api_server_access_profile {\n  authorized_ip_ranges = ["YOUR_OFFICE_IP/32"]\n}',
            effort="2-3 line change",
        ),
        "azure-storage-allow-microsoft-service-bypass": ExplainedFinding(
            finding=finding,
            plain_english="Your storage account doesn't allow Azure services to bypass the firewall. "
                          "Azure Backup, Defender, and other services may not work.",
            terraform_fix='network_rules {\n  default_action = "Deny"\n  bypass = ["AzureServices"]\n}',
            effort="2-3 line change",
        ),
    }

    return explanations.get(finding.check_id, ExplainedFinding(
        finding=finding,
        plain_english=finding.title,
        terraform_fix=f"# Fix required for {finding.check_id}\n# See: {finding.fix_link}",
        effort="review required",
    ))


def generate_pr_comment(
    explained: list[ExplainedFinding],
    pr_number: int = 0,
) -> str:
    """Generate a markdown PR comment from explained findings."""
    if not explained:
        return """## ✅ Security Scan Passed

No security issues found in the Terraform changes.

*Scanned by [security-auditor](https://github.com/vmprachi7/security-auditor) using Checkov + tfsec*
"""

    high   = [e for e in explained if e.finding.severity == "HIGH"]
    medium = [e for e in explained if e.finding.severity == "MEDIUM"]
    low    = [e for e in explained if e.finding.severity == "LOW"]

    status = "❌ BLOCKED" if high else "⚠️ WARNINGS"
    header = f"## {status} — Security Scan Found {len(explained)} Issue(s)\n\n"

    if high:
        header += (
            f"> ⛔ **This PR is blocked.** "
            f"{len(high)} HIGH severity issue(s) must be fixed before merge.\n\n"
        )
    else:
        header += (
            f"> ⚠️ No HIGH severity issues — PR can merge but please review findings below.\n\n"
        )

    header += (
        f"| Severity | Count |\n"
        f"|---|---|\n"
        f"| 🔴 HIGH | {len(high)} |\n"
        f"| 🟡 MEDIUM | {len(medium)} |\n"
        f"| 🟢 LOW | {len(low)} |\n\n"
        f"---\n\n"
    )

    sections = []
    for group, emoji in [(high, "🔴"), (medium, "🟡"), (low, "🟢")]:
        for e in group:
            f = e.finding
            section = f"""{emoji} **{f.check_id}** — {f.title}

**What's wrong:** {e.plain_english}

**Where:** `{f.file}` line {f.line} — resource `{f.resource}`

**Effort:** {e.effort}

**Fix:**
```hcl
{e.terraform_fix}
```
"""
            if f.fix_link:
                section += f"**Reference:** {f.fix_link}\n"

            sections.append(section)

    footer = (
        "\n---\n\n"
        "*Scanned by [security-auditor](https://github.com/vmprachi7/security-auditor) "
        "using Checkov + tfsec + Groq AI (Llama 3.1)*\n\n"
        "*To suppress a false positive, add `#checkov:skip=CHECK_ID:reason` "
        "on the relevant line.*"
    )

    return header + "\n---\n\n".join(sections) + footer


def _checkov_severity(check_id: str) -> str:
    """Map Checkov check IDs to severity levels."""
    high_checks = {
        "CKV_AZURE_59",   # storage public access
        "CKV_AZURE_5",    # AKS public API
        "CKV_AZURE_7",    # AKS no RBAC
        "CKV_AZURE_41",   # key vault soft delete
        "CKV_AZURE_42",   # key vault purge protection
        "CKV_AZURE_110",  # storage no public network access
    }
    low_checks = {
        "CKV_AZURE_33",   # storage logging
        "CKV_AZURE_44",   # storage https only
    }

    if check_id in high_checks:
        return "HIGH"
    elif check_id in low_checks:
        return "LOW"
    return "MEDIUM"


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--checkov", default="/tmp/scan-results/checkov.json")
    parser.add_argument("--tfsec",   default="/tmp/scan-results/tfsec.json")
    parser.add_argument("--tf-dir",  default=".")
    parser.add_argument("--output",  default="/tmp/scan-results/pr-comment.md")
    args = parser.parse_args()

    # Load findings
    checkov_findings = load_checkov(args.checkov)
    tfsec_findings   = load_tfsec(args.tfsec)
    all_findings     = checkov_findings + tfsec_findings

    print(f"Checkov: {len(checkov_findings)} findings")
    print(f"tfsec:   {len(tfsec_findings)} findings")
    print(f"Total:   {len(all_findings)} findings")

    # Load Terraform context for AI
    tf_context = ""
    if args.tf_dir and os.path.exists(args.tf_dir):
        for fname in os.listdir(args.tf_dir):
            if fname.endswith(".tf"):
                try:
                    with open(os.path.join(args.tf_dir, fname)) as f:
                        tf_context += f"\n# {fname}\n" + f.read()
                except Exception:
                    pass

    # Generate explanations
    explained = explain_findings(all_findings, tf_context)

    # Generate PR comment
    comment = generate_pr_comment(explained)

    # Write output
    with open(args.output, "w") as f:
        f.write(comment)

    print(f"\nPR comment written to {args.output}")

    # Exit 1 if HIGH findings — blocks the PR
    high_count = len([e for e in explained if e.finding.severity == "HIGH"])
    if high_count > 0:
        print(f"\n❌ {high_count} HIGH severity finding(s) — blocking PR")
        sys.exit(1)
    else:
        print("\n✅ No HIGH severity findings")
        sys.exit(0)