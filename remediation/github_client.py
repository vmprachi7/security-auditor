"""
GitHub client for security-auditor.

Issue structure per scan run:

  #N  🔍 Weekly Audit — 2026-05-07 — 3 RGs — 12 findings  (master)
        └── #N+1 📦 devops-platform-rg — 8 findings        (one per RG)
        └── #N+2 📦 finops-rg — 3 findings
        └── #N+3 📦 audit-test-rg — 1 finding

Each RG Issue contains ALL findings for that RG in one place.
Only HIGH and MEDIUM findings are actioned — LOW are listed but not detailed.
"""
from collections import defaultdict
from datetime import datetime, timezone
from github import Github, GithubException
from remediation import config
from remediation.scanner import Finding, ScanReport
from remediation.dependency import DependencyReport
from remediation.patch_generator import Patch


LABELS = [
    ("security",      "e53e3e", "Security finding from Prowler scan"),
    ("audit-master",  "0075ca", "Weekly audit master summary"),
    ("audit-rg",      "5319e7", "Per resource group security findings"),
    ("risk-high",     "b60205", "HIGH risk findings"),
    ("risk-medium",   "e4e669", "MEDIUM risk findings"),
]


def create_audit_hierarchy(
    report:        ScanReport,
    findings_data: list[dict],
) -> str:
    """
    Create master Issue + one RG Issue per resource group.
    Returns master Issue URL.
    """
    gh   = Github(config.GITHUB_TOKEN)
    repo = gh.get_repo(config.GITHUB_REPO)
    now  = datetime.now(timezone.utc)

    _ensure_labels(repo)

    # Group by resource group — only HIGH and MEDIUM
    by_rg = defaultdict(list)
    for d in findings_data:
        if d["finding"].risk in (config.RISK_HIGH, config.RISK_MEDIUM):
            by_rg[d["finding"].resource_group].append(d)

    if not by_rg:
        print("  ℹ️  No HIGH/MEDIUM findings — no RG Issues to create")
        return _create_clean_master(repo, report, now)

    # Step 1 — One Issue per RG (all findings inside)
    print(f"\n  Creating {len(by_rg)} RG Issues...")
    rg_issues = {}
    for rg_name, rg_data in sorted(by_rg.items()):
        issue = _create_rg_issue(repo, rg_name, rg_data, now)
        rg_issues[rg_name] = {
            "issue_number": issue.number,
            "issue_url":    issue.html_url,
            "count":        len(rg_data),
            "high":         len([d for d in rg_data if d["finding"].risk == config.RISK_HIGH]),
            "medium":       len([d for d in rg_data if d["finding"].risk == config.RISK_MEDIUM]),
        }
        print(f"    #{issue.number} {rg_name} "
              f"({rg_issues[rg_name]['high']}H "
              f"{rg_issues[rg_name]['medium']}M)")

    # Step 2 — Master summary Issue
    print(f"\n  Creating master summary Issue...")
    master = _create_master_issue(repo, report, rg_issues, findings_data, now)
    print(f"    #{master.number} Master summary → {master.html_url}")

    return master.html_url


def _create_rg_issue(repo, rg_name: str, rg_data: list[dict], now: datetime):
    """
    One Issue per resource group.
    Contains all HIGH + MEDIUM findings inline — no sub-issues needed.
    """
    high_data   = [d for d in rg_data if d["finding"].risk == config.RISK_HIGH]
    medium_data = [d for d in rg_data if d["finding"].risk == config.RISK_MEDIUM]

    owner = rg_data[0]["dependency"].owner if rg_data else "unknown"
    env   = rg_data[0]["finding"].environment if rg_data else "unknown"

    status_emoji = "🔴" if high_data else "🟡"
    title = (
        f"{status_emoji} Security Findings — `{rg_name}` — "
        f"{len(rg_data)} finding(s) "
        f"[{len(high_data)}H · {len(medium_data)}M]"
    )

    # ── Summary table ─────────────────────────────────────────
    table_rows = ["| # | Severity | Finding | Resource | Blast Radius | Owner |",
                  "|---|---|---|---|---|---|"]
    for i, d in enumerate(high_data + medium_data, 1):
        f   = d["finding"]
        dep = d["dependency"]
        sev_emoji = "🔴" if f.risk == config.RISK_HIGH else "🟡"
        blast_emoji = {"HIGH": "💥", "MEDIUM": "⚠️", "LOW": "✅"}.get(
            dep.blast_radius, "⚪"
        )
        table_rows.append(
            f"| {i} | {sev_emoji} {f.risk} "
            f"| {f.title[:45]} "
            f"| `{f.resource_name}` "
            f"| {blast_emoji} {dep.blast_radius} "
            f"| `{dep.owner}` |"
        )

    # ── Progress checklist ────────────────────────────────────
    checklist = "\n".join(
        f"- [ ] [{d['finding'].finding_id}] {d['finding'].title[:55]} — "
        f"`{d['finding'].resource_name}`"
        for d in (high_data + medium_data)
    )

    # ── Finding detail sections ───────────────────────────────
    detail_sections = ""
    for d in (high_data + medium_data):
        detail_sections += _finding_detail_block(d) + "\n"

    body = f"""## {status_emoji} Resource Group: `{rg_name}`

| | |
|---|---|
| **Owner** | `{owner}` |
| **Environment** | `{env}` |
| **HIGH findings** | {len(high_data)} |
| **MEDIUM findings** | {len(medium_data)} |
| **Scanned by** | Prowler — open source CSPM |

---

## Summary

{chr(10).join(table_rows)}

---

## Fix Checklist

Check off each finding as you fix it:

{checklist}

---

## Finding Details

{detail_sections}

---

## How to fix

1. **Review dependency analysis** for each finding — understand blast radius
2. **Get sign-off** from stakeholders listed per finding
3. **Copy the Terraform snippet** to `devops-platform-foundation`
4. **Raise a PR** — title: `security: fix [ID] resource-name`
5. **Check the box above** when the PR is merged

---
*[security-auditor](https://github.com/{config.GITHUB_REPO}) · \
Prowler scan · {now.strftime("%Y-%m-%d %H:%M UTC")}*
"""

    labels = ["security", "audit-rg",
              "risk-high" if high_data else "risk-medium"]

    return repo.create_issue(title=title, body=body, labels=labels)


def _finding_detail_block(d: dict) -> str:
    """Inline detail block for one finding inside the RG Issue."""
    finding    = d["finding"]
    dependency = d["dependency"]
    patch      = d["patch"]

    risk_emoji  = "🔴" if finding.risk == config.RISK_HIGH else "🟡"
    blast_emoji = {"HIGH": "💥", "MEDIUM": "⚠️", "LOW": "✅"}.get(
        dependency.blast_radius, "⚪"
    )

    dep_list = "\n".join(
        f"  - `{r['name']}` ({r['type']})"
        for r in dependency.dependent_resources[:3]
    ) or "  _None found_"

    accessor_list = "\n".join(
        f"  - `{a['caller']}` — last: {a['last_access']}"
        for a in dependency.recent_accessors[:3]
    ) or f"  _No access in last {config.DEPENDENCY_LOOKBACK_DAYS} days_"

    approval = _approval_text(finding, dependency)
    verify   = _verify_cmd(finding)

    return f"""<details>
<summary>{risk_emoji} <strong>[{finding.finding_id}]</strong> \
{finding.title} — <code>{finding.resource_name}</code> \
{blast_emoji} {dependency.blast_radius} blast radius</summary>

**What's wrong:**
{finding.description}

**Prowler check:** `{finding.prowler_check_id}`

**Remediation guidance:**
{finding.remediation}

---

**{blast_emoji} Dependency Analysis**

Dependent resources:
{dep_list}

Recent accessors (last {config.DEPENDENCY_LOOKBACK_DAYS} days):
{accessor_list}

Notes:
{"  ".join(f"- {n}" for n in dependency.notes) or "  _No notes_"}

---

**{approval}**

---

**Terraform Fix** — copy to `devops-platform-foundation`:
```hcl
{patch.terraform_hcl}
```

Apply after approval:
```bash
{patch.apply_command}
```

Verify:
```bash
{verify}
```

Rollback: {patch.rollback_plan}

</details>
"""


def _create_master_issue(
    repo,
    report:      ScanReport,
    rg_issues:   dict,
    all_data:    list[dict],
    now:         datetime,
):
    """Master summary — links to all RG Issues."""
    high_count   = len(report.high)
    medium_count = len(report.medium)
    low_count    = len(report.low)
    actioned     = high_count + medium_count

    status_emoji = "🔴" if high_count else "🟡" if medium_count else "🟢"

    title = (
        f"🔍 Weekly Security Audit — {report.run_date} — "
        f"{len(rg_issues)} RG(s) — "
        f"{actioned} actioned "
        f"[{high_count}H · {medium_count}M]"
    )

    # RG summary table
    rg_table = (
        "| Resource Group | HIGH | MEDIUM | Issue |\n"
        "|---|---|---|---|\n"
    )
    for rg, info in sorted(rg_issues.items()):
        rg_table += (
            f"| `{rg}` "
            f"| {'🔴 ' + str(info['high']) if info['high'] else '-'} "
            f"| {'🟡 ' + str(info['medium']) if info['medium'] else '-'} "
            f"| #{info['issue_number']} |\n"
        )

    # RG checklist
    rg_checklist = "\n".join(
        f"- [ ] #{info['issue_number']} `{rg}` — "
        f"{info['high']}H · {info['medium']}M"
        for rg, info in sorted(rg_issues.items())
    )

    # LOW findings summary (listed but not actioned)
    low_summary = ""
    if report.low:
        low_summary = f"""---

## 🟢 LOW Severity — {low_count} findings (informational)

These are best-practice gaps. No immediate action required.

| Finding | Resource | RG |
|---|---|---|
"""
        for d in all_data:
            if d["finding"].risk == config.RISK_LOW:
                f = d["finding"]
                low_summary += (
                    f"| {f.title[:50]} | `{f.resource_name}` "
                    f"| `{f.resource_group}` |\n"
                )

    body = f"""## 🔍 Weekly Security Audit — {report.run_date}

**Scanner:** Prowler (open source CSPM — 300+ Azure checks)
**Subscription:** `{report.subscription_id}`

| Metric | Value |
|---|---|
| Total assessed | {report.total_assessed} |
| Healthy | {report.total_healthy} |
| 🔴 HIGH | {high_count} |
| 🟡 MEDIUM | {medium_count} |
| 🟢 LOW (info only) | {low_count} |
| **Actioned (H+M)** | **{actioned}** |
| Resource groups affected | {len(rg_issues)} |

---

## By Resource Group

{rg_table}

---

## Resource Group Issues — check off as resolved

{rg_checklist}

---

## How this works

Each RG Issue above contains:
- Summary table of all findings
- Fix checklist (check off as you fix each one)
- Collapsible detail per finding with dependency analysis + Terraform patch

**LOW findings** are listed below for awareness — no Issue created for them.

{low_summary}

---

> No changes applied automatically.
> Fix finding → raise PR in `devops-platform-foundation` → merge → check the box.

*[security-auditor](https://github.com/{config.GITHUB_REPO}) · \
Prowler · {now.strftime("%Y-%m-%d %H:%M UTC")}*
"""

    return repo.create_issue(
        title=title,
        body=body,
        labels=["security", "audit-master"],
    )


def _create_clean_master(repo, report: ScanReport, now: datetime):
    """Master Issue when no HIGH/MEDIUM findings."""
    issue = repo.create_issue(
        title=f"✅ Weekly Security Audit — {report.run_date} — All clear",
        body=f"""## ✅ No HIGH or MEDIUM findings

**Scanner:** Prowler
**Subscription:** `{report.subscription_id}`
**Assessed:** {report.total_assessed} resources
**LOW findings:** {len(report.low)} (informational only)

Subscription is clean for this week. 🎉

*[security-auditor](https://github.com/{config.GITHUB_REPO}) · {now.strftime("%Y-%m-%d %H:%M UTC")}*
""",
        labels=["security", "audit-master"],
    )
    return issue.html_url


def _approval_text(finding: Finding, dep: DependencyReport) -> str:
    stakeholders = dep.all_stakeholders
    if finding.risk == config.RISK_HIGH or dep.blast_radius == config.RISK_HIGH:
        checks = "\n".join(f"- [ ] `{s}`" for s in stakeholders)
        return (
            f"✋ Sign-off Required — HIGH RISK\n\n"
            f"- [ ] Owner: `{dep.owner}`\n"
            f"{checks}\n"
            f"- [ ] Test in non-production first\n"
            f"- [ ] Schedule maintenance window"
        )
    return (
        f"⚠️ Sign-off Required — MEDIUM RISK\n\n"
        f"- [ ] Team lead: `{dep.owner}`\n"
        f"- [ ] Verify no dependent services break"
    )


def _verify_cmd(finding: Finding) -> str:
    cmds = {
        "stor": f"az storage account show --name {finding.resource_name} --query '{{public:allowBlobPublicAccess,sharedKey:allowSharedKeyAccess}}'",
        "mana": f"az aks show --name {finding.resource_name} -g {finding.resource_group} --query apiServerAccessProfile",
        "vaul": f"az keyvault show --name {finding.resource_name} --query properties.networkAcls",
    }
    rt = finding.resource_type.lower().split("/")[-1][:4]
    return cmds.get(rt, f"az resource show --ids {finding.resource_id} --query properties")


def _ensure_labels(repo):
    existing = {l.name for l in repo.get_labels()}
    for name, color, desc in LABELS:
        if name not in existing:
            try:
                repo.create_label(name=name, color=color, description=desc)
            except GithubException:
                pass