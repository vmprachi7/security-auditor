"""
GitHub client for security-auditor.

Issue hierarchy per scan:

  #N   🔍 Weekly Audit — 2026-05-06 — 5 findings        (master summary)
         └── #N+1 📦 devops-platform-rg — 3 findings    (per RG)
                    └── #N+2 🔴 Storage public access   (per finding)
                    └── #N+3 🔴 AKS public API server
                    └── #N+4 🟡 Key Vault soft delete
         └── #N+5 📦 finops-rg — 2 findings
                    └── #N+6 🟡 Storage geo-redundancy
                    └── #N+7 🟢 Missing owner tag

When a finding Issue is closed → checkbox in RG Issue auto-ticks.
When all finding Issues closed → RG Issue shows 100% complete.
"""
from collections import defaultdict
from datetime import datetime, timezone
from github import Github, GithubException
from remediation import config
from remediation.scanner import Finding, ScanReport
from remediation.dependency import DependencyReport
from remediation.patch_generator import Patch


# ── Labels ────────────────────────────────────────────────────

LABELS = [
    ("security",         "e53e3e", "Security finding from Defender for Cloud"),
    ("risk-high",        "b60205", "HIGH risk — CISO sign-off required"),
    ("risk-medium",      "e4e669", "MEDIUM risk — team lead sign-off required"),
    ("risk-low",         "0e8a16", "LOW risk — single reviewer required"),
    ("audit-master",     "0075ca", "Weekly audit master summary"),
    ("audit-rg",         "5319e7", "Per resource group audit summary"),
    ("audit-finding",    "f9d0c4", "Individual security finding"),
]


# ── Main entry point ──────────────────────────────────────────

def create_audit_hierarchy(
    report:        ScanReport,
    findings_data: list[dict],   # [{finding, dependency, patch}]
) -> str:
    """
    Create the full Issue hierarchy for a scan run.
    Returns master Issue URL.
    """
    gh   = Github(config.GITHUB_TOKEN)
    repo = gh.get_repo(config.GITHUB_REPO)
    now  = datetime.now(timezone.utc)

    _ensure_labels(repo)

    # Group findings by resource group
    by_rg = defaultdict(list)
    for d in findings_data:
        by_rg[d["finding"].resource_group].append(d)

    # ── Step 1: Create individual finding Issues ──────────────
    print(f"\n  Creating {len(findings_data)} finding Issues...")
    for d in findings_data:
        issue = _create_finding_issue(repo, d, now)
        d["issue_number"] = issue.number
        d["issue_url"]    = issue.html_url
        print(f"    #{issue.number} [{d['finding'].risk}] {d['finding'].title[:45]}")

    # ── Step 2: Create one RG Issue per resource group ────────
    print(f"\n  Creating {len(by_rg)} resource group Issues...")
    rg_issues = {}
    for rg_name, rg_findings in sorted(by_rg.items()):
        rg_issue = _create_rg_issue(repo, rg_name, rg_findings, now)
        rg_issues[rg_name] = {
            "issue_number": rg_issue.number,
            "issue_url":    rg_issue.html_url,
            "findings":     rg_findings,
        }
        print(f"    #{rg_issue.number} {rg_name} ({len(rg_findings)} findings)")

    # ── Step 3: Create master summary Issue ───────────────────
    print(f"\n  Creating master summary Issue...")
    master = _create_master_issue(repo, report, rg_issues, now)
    print(f"    #{master.number} Master summary")

    print(f"\n  ✅ Issue hierarchy created:")
    print(f"     Master:    #{master.number} → {master.html_url}")
    for rg, info in rg_issues.items():
        print(f"     RG:        #{info['issue_number']} {rg}")
        for d in info["findings"]:
            print(f"       Finding: #{d['issue_number']} {d['finding'].finding_id}")

    return master.html_url


# ── Finding Issue ─────────────────────────────────────────────

def _create_finding_issue(repo, d: dict, now: datetime):
    """One Issue per security finding — full detail."""
    finding    = d["finding"]
    dependency = d["dependency"]
    patch      = d["patch"]

    risk_emoji  = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding.risk, "⚪")
    blast_emoji = {"HIGH": "💥", "MEDIUM": "⚠️", "LOW": "✅"}.get(dependency.blast_radius, "⚪")

    title = (
        f"{risk_emoji} [{finding.finding_id}] {finding.title} — "
        f"`{finding.resource_name}`"
    )

    dep_list = "\n".join(
        f"- `{r['name']}` ({r['type']})"
        for r in dependency.dependent_resources[:5]
    ) or "_None found_"

    accessor_list = "\n".join(
        f"- `{a['caller']}` — last: {a['last_access']}"
        for a in dependency.recent_accessors[:3]
    ) or f"_No access in last {config.DEPENDENCY_LOOKBACK_DAYS} days — lower risk_"

    notes_list = "\n".join(f"- {n}" for n in dependency.notes)
    approval   = _approval_text(finding, dependency)
    verify     = _verify_cmd(finding)

    body = f"""## {risk_emoji} {finding.finding_id} — {finding.title}

| Field | Value |
|---|---|
| **Resource** | `{finding.resource_name}` |
| **Resource Group** | `{finding.resource_group}` |
| **Type** | `{finding.resource_type}` |
| **Risk** | {finding.risk} |
| **Blast Radius** | {blast_emoji} {dependency.blast_radius} |
| **Owner** | `{dependency.owner}` |
| **Environment** | `{finding.environment}` |
| **Defender** | [View in Defender for Cloud]({finding.defender_link}) |

### What's wrong
{finding.description}

### Defender's remediation guidance
{finding.remediation}

---

## {blast_emoji} Dependency Analysis

**Dependent resources** ({len(dependency.dependent_resources)} found):
{dep_list}

**Recent accessors** (last {config.DEPENDENCY_LOOKBACK_DAYS} days):
{accessor_list}

**Assessment:**
{notes_list}

---

## {approval}

---

## 🔧 Terraform Fix

Copy this snippet to `devops-platform-foundation` and raise a PR:

```hcl
{patch.terraform_hcl}
```

**Apply command** (after all approvals):
```bash
{patch.apply_command}
```

**Verify:**
```bash
{verify}
```

**Rollback plan:**
{patch.rollback_plan}

**Risk notes:**
{patch.risk_notes}

---

*[security-auditor](https://github.com/{config.GITHUB_REPO}) · \
{now.strftime("%Y-%m-%d %H:%M UTC")} · Source: Defender for Cloud*
"""

    labels = [
        "security",
        "audit-finding",
        f"risk-{finding.risk.lower()}",
    ]

    return repo.create_issue(title=title, body=body, labels=labels)


# ── RG Issue ──────────────────────────────────────────────────

def _create_rg_issue(
    repo,
    rg_name:     str,
    rg_findings: list[dict],
    now:         datetime,
):
    """
    One Issue per resource group.
    Contains a tasklist of finding Issues — checkboxes auto-tick when closed.
    """
    high   = [d for d in rg_findings if d["finding"].risk == config.RISK_HIGH]
    medium = [d for d in rg_findings if d["finding"].risk == config.RISK_MEDIUM]
    low    = [d for d in rg_findings if d["finding"].risk == config.RISK_LOW]

    # Determine RG owner from first finding's tags
    owner = rg_findings[0]["dependency"].owner if rg_findings else "unknown"
    env   = rg_findings[0]["finding"].environment if rg_findings else "unknown"

    status_emoji = "🔴" if high else "🟡" if medium else "🟢"

    title = (
        f"{status_emoji} Security Findings — `{rg_name}` — "
        f"{len(rg_findings)} finding(s) "
        f"[{len(high)}H · {len(medium)}M · {len(low)}L]"
    )

    # Build tasklist — checks auto-tick when Issues are closed
    def tasklist(findings_group):
        lines = []
        for d in findings_group:
            risk_e = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(
                d["finding"].risk, "⚪"
            )
            lines.append(
                f"- [ ] {risk_e} #{d['issue_number']} "
                f"[{d['finding'].finding_id}] {d['finding'].title[:50]} — "
                f"`{d['finding'].resource_name}`"
            )
        return "\n".join(lines)

    all_tasks = tasklist(high + medium + low)

    body = f"""## {status_emoji} Resource Group: `{rg_name}`

| | |
|---|---|
| **Owner** | `{owner}` |
| **Environment** | `{env}` |
| **Findings** | {len(rg_findings)} total · {len(high)} HIGH · {len(medium)} MEDIUM · {len(low)} LOW |

---

## Findings — check off as fixed

{all_tasks}

---

## How to use this Issue

1. **Each checkbox above is a linked finding Issue** — click to see full detail
2. **Fix the finding** → copy Terraform snippet to `devops-platform-foundation` → raise PR
3. **Close the finding Issue** when the PR is merged → checkbox auto-ticks here
4. **Close this RG Issue** when all findings are resolved

---

*[security-auditor](https://github.com/{config.GITHUB_REPO}) · \
{now.strftime("%Y-%m-%d %H:%M UTC")}*
"""

    return repo.create_issue(
        title=title,
        body=body,
        labels=["security", "audit-rg"],
    )


# ── Master Summary Issue ──────────────────────────────────────

def _create_master_issue(
    repo,
    report:    ScanReport,
    rg_issues: dict,
    now:       datetime,
):
    """
    One master Issue per scan run.
    Links to all RG Issues — gives the full picture at a glance.
    """
    total_high   = len(report.high)
    total_medium = len(report.medium)
    total_low    = len(report.low)
    status_emoji = "🔴" if total_high else "🟡" if total_medium else "🟢"

    title = (
        f"🔍 Weekly Security Audit — {report.run_date} — "
        f"{len(report.findings)} finding(s) "
        f"[{total_high}H · {total_medium}M · {total_low}L]"
    )

    # RG tasklist — links to RG Issues
    rg_tasklist = "\n".join(
        f"- [ ] #{info['issue_number']} "
        f"`{rg}` — {len(info['findings'])} finding(s) "
        f"[{len([d for d in info['findings'] if d['finding'].risk=='HIGH'])}H · "
        f"{len([d for d in info['findings'] if d['finding'].risk=='MEDIUM'])}M · "
        f"{len([d for d in info['findings'] if d['finding'].risk=='LOW'])}L]"
        for rg, info in sorted(rg_issues.items())
    )

    # Summary table by resource group
    rg_table = "| Resource Group | Owner | HIGH | MEDIUM | LOW | RG Issue |\n|---|---|---|---|---|---|\n"
    for rg, info in sorted(rg_issues.items()):
        h = len([d for d in info["findings"] if d["finding"].risk == "HIGH"])
        m = len([d for d in info["findings"] if d["finding"].risk == "MEDIUM"])
        l = len([d for d in info["findings"] if d["finding"].risk == "LOW"])
        owner = info["findings"][0]["dependency"].owner if info["findings"] else "unknown"
        rg_table += (
            f"| `{rg}` | `{owner}` | "
            f"{'🔴 ' + str(h) if h else '-'} | "
            f"{'🟡 ' + str(m) if m else '-'} | "
            f"{'🟢 ' + str(l) if l else '-'} | "
            f"#{info['issue_number']} |\n"
        )

    body = f"""## 🔍 Weekly Security Audit — {report.run_date}

**Source:** Microsoft Defender for Cloud
**Subscription:** `{report.subscription_id}`

| Metric | Value |
|---|---|
| Total assessed | {report.total_assessed} |
| Healthy (compliant) | {report.total_healthy} |
| 🔴 HIGH | {total_high} |
| 🟡 MEDIUM | {total_medium} |
| 🟢 LOW | {total_low} |
| **Non-compliant total** | **{len(report.findings)}** |

---

## By Resource Group

{rg_table}

---

## Resource Group Issues — check off as resolved

{rg_tasklist}

---

## How this works

```
This Issue (master)
  └── RG Issue per resource group  ← one team's findings
        └── Finding Issue per finding  ← full detail, terraform fix, sign-off
```

1. **Click a RG Issue** → see all findings for that resource group
2. **Click a finding Issue** → see dependency analysis, Terraform fix, sign-off checklist
3. **Fix the finding** → raise PR in `devops-platform-foundation` → merge
4. **Close the finding Issue** → checkbox auto-ticks in the RG Issue
5. **Close the RG Issue** → checkbox auto-ticks here

---

> No changes applied automatically.
> Each finding Issue has the Terraform snippet ready to copy.

*[security-auditor](https://github.com/{config.GITHUB_REPO}) · \
{now.strftime("%Y-%m-%d %H:%M UTC")} · Defender for Cloud API*
"""

    return repo.create_issue(
        title=title,
        body=body,
        labels=["security", "audit-master"],
    )


# ── Helpers ───────────────────────────────────────────────────

def _approval_text(finding: Finding, dep: DependencyReport) -> str:
    stakeholders = dep.all_stakeholders
    if finding.risk == config.RISK_HIGH or dep.blast_radius == config.RISK_HIGH:
        checks = "\n".join(
            f"- [ ] Stakeholder: `{s}`" for s in stakeholders
        )
        return (
            f"✋ Sign-off Required — HIGH RISK\n\n"
            f"- [ ] Owner: `{dep.owner}`\n"
            f"{checks}\n"
            f"- [ ] Test in non-production first\n"
            f"- [ ] Schedule maintenance window\n"
            f"- [ ] Notify on-call team"
        )
    elif finding.risk == config.RISK_MEDIUM:
        return (
            f"⚠️ Sign-off Required — MEDIUM RISK\n\n"
            f"- [ ] Team lead: `{dep.owner}`\n"
            f"- [ ] Verify no dependent services break\n"
            f"- [ ] Apply during low-traffic window"
        )
    return f"✅ LOW RISK — one reviewer from `{dep.owner}`"


def _verify_cmd(finding: Finding) -> str:
    cmds = {
        "storage":        f"az storage account show --name {finding.resource_name} --query '{{public:allowBlobPublicAccess,sharedKey:allowSharedKeyAccess}}'",
        "managedcluster": f"az aks show --name {finding.resource_name} -g {finding.resource_group} --query apiServerAccessProfile",
        "vault":          f"az keyvault show --name {finding.resource_name} --query properties.{{softDelete:enableSoftDelete,network:networkAcls}}",
    }
    rt = finding.resource_type.lower()
    for key, cmd in cmds.items():
        if key in rt:
            return cmd
    return f"az resource show --ids {finding.resource_id} --query properties"


def _ensure_labels(repo):
    existing = {l.name for l in repo.get_labels()}
    for name, color, desc in LABELS:
        if name not in existing:
            try:
                repo.create_label(name=name, color=color, description=desc)
            except GithubException:
                pass