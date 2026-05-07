"""
GitHub client for security-auditor.

Issue structure:
  Master Issue  — summary table of all RGs
  RG Issue      — summary table + checklist (body stays small)
  Comments      — one comment per finding (full detail, Terraform patch)

Splitting detail into comments avoids the 65536 char GitHub body limit.
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

# GitHub body limit — stay well under 65536
MAX_BODY_CHARS = 60000


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

    # Group by RG — only HIGH and MEDIUM
    by_rg = defaultdict(list)
    for d in findings_data:
        if d["finding"].risk in (config.RISK_HIGH, config.RISK_MEDIUM):
            by_rg[d["finding"].resource_group].append(d)

    if not by_rg:
        print("  ℹ️  No HIGH/MEDIUM findings — subscription is clean")
        return _create_clean_master(repo, report, now)

    # Step 1 — One RG Issue per resource group
    print(f"\n  Creating {len(by_rg)} RG Issues...")
    rg_issues = {}
    for rg_name, rg_data in sorted(by_rg.items()):
        issue = _create_rg_issue(repo, rg_name, rg_data, now)
        rg_issues[rg_name] = {
            "issue_number": issue.number,
            "issue_url":    issue.html_url,
            "count":        len(rg_data),
            "high":   len([d for d in rg_data if d["finding"].risk == config.RISK_HIGH]),
            "medium": len([d for d in rg_data if d["finding"].risk == config.RISK_MEDIUM]),
        }
        print(f"    #{issue.number} {rg_name[:50]} "
              f"({rg_issues[rg_name]['high']}H "
              f"{rg_issues[rg_name]['medium']}M)")

        # Add one comment per finding — keeps body small
        _add_finding_comments(issue, rg_data, now)

    # Step 2 — Master summary Issue
    print(f"\n  Creating master summary Issue...")
    master = _create_master_issue(repo, report, rg_issues, findings_data, now)
    print(f"    #{master.number} → {master.html_url}")

    return master.html_url


# ── RG Issue body (summary only — detail goes in comments) ────

def _create_rg_issue(repo, rg_name: str, rg_data: list[dict], now: datetime):
    """
    RG Issue body = summary table + checklist only.
    Full detail per finding is added as comments.
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

    # Summary table
    rows = [
        "| # | Severity | Finding | Resource | Blast Radius |",
        "|---|---|---|---|---|",
    ]
    for i, d in enumerate(high_data + medium_data, 1):
        f   = d["finding"]
        dep = d["dependency"]
        sev = "🔴 HIGH" if f.risk == config.RISK_HIGH else "🟡 MEDIUM"
        blast = {"HIGH": "💥 HIGH", "MEDIUM": "⚠️ MEDIUM", "LOW": "✅ LOW"}.get(
            dep.blast_radius, dep.blast_radius
        )
        rows.append(
            f"| {i} | {sev} | {f.title[:45]} | `{f.resource_name}` | {blast} |"
        )

    # Fix checklist
    checklist = "\n".join(
        f"- [ ] [{d['finding'].finding_id}] "
        f"{d['finding'].title[:55]} — `{d['finding'].resource_name}`"
        for d in (high_data + medium_data)
    )

    body = f"""## {status_emoji} Resource Group: `{rg_name}`

| | |
|---|---|
| **Owner** | `{owner}` |
| **Environment** | `{env}` |
| **HIGH** | {len(high_data)} |
| **MEDIUM** | {len(medium_data)} |
| **Scanner** | Prowler (open source CSPM) |

---

## Findings Summary

{chr(10).join(rows)}

> Full detail (dependency analysis + Terraform patch + sign-off) is in the comments below — one comment per finding.

---

## Fix Checklist

Check off each finding after the PR is merged:

{checklist}

---

## How to fix

1. Read the **comment** for the finding you want to fix
2. Check dependency analysis — understand blast radius before acting
3. Get sign-off from listed stakeholders
4. Copy the Terraform snippet to `devops-platform-foundation`
5. Raise a PR — title: `security: fix [ID] resource-name`
6. Check the box above when merged

---
*[security-auditor](https://github.com/{config.GITHUB_REPO}) · \
Prowler · {now.strftime("%Y-%m-%d %H:%M UTC")}*
"""

    # Truncate if still somehow too long
    if len(body) > MAX_BODY_CHARS:
        body = body[:MAX_BODY_CHARS] + "\n\n...[truncated — see comments for details]"

    labels = ["security", "audit-rg",
              "risk-high" if high_data else "risk-medium"]

    return repo.create_issue(title=title, body=body, labels=labels)


# ── Finding detail as comments ────────────────────────────────

def _add_finding_comments(issue, rg_data: list[dict], now: datetime):
    """Add one comment per finding to the RG Issue."""
    high_data   = [d for d in rg_data if d["finding"].risk == config.RISK_HIGH]
    medium_data = [d for d in rg_data if d["finding"].risk == config.RISK_MEDIUM]

    for d in (high_data + medium_data):
        comment = _finding_comment(d, now)

        # Truncate comment if too long
        if len(comment) > MAX_BODY_CHARS:
            comment = comment[:MAX_BODY_CHARS] + \
                "\n\n...[truncated — run Prowler locally for full output]"

        try:
            issue.create_comment(comment)
        except Exception as e:
            print(f"    [WARN] Comment failed for {d['finding'].finding_id}: {e}")


def _finding_comment(d: dict, now: datetime) -> str:
    """Full detail comment for one finding."""
    finding    = d["finding"]
    dependency = d["dependency"]
    patch      = d["patch"]

    risk_emoji  = "🔴" if finding.risk == config.RISK_HIGH else "🟡"
    blast_emoji = {"HIGH": "💥", "MEDIUM": "⚠️", "LOW": "✅"}.get(
        dependency.blast_radius, "⚪"
    )

    dep_list = "\n".join(
        f"- `{r['name']}` ({r['type']})"
        for r in dependency.dependent_resources[:5]
    ) or "_None found_"

    accessor_list = "\n".join(
        f"- `{a['caller']}` — last: {a['last_access']}"
        for a in dependency.recent_accessors[:3]
    ) or f"_No access in last {config.DEPENDENCY_LOOKBACK_DAYS} days — lower risk_"

    notes = "\n".join(f"- {n}" for n in dependency.notes) or "_No notes_"
    approval = _approval_text(finding, dependency)
    verify   = _verify_cmd(finding)

    return f"""{risk_emoji} **[{finding.finding_id}] {finding.title}**

**Resource:** `{finding.resource_name}` in `{finding.resource_group}`
**Prowler check:** `{finding.prowler_check_id}`
**Risk:** {finding.risk} · **Blast Radius:** {blast_emoji} {dependency.blast_radius}

---

### What's wrong
{finding.description}

### Remediation guidance
{finding.remediation}

---

### {blast_emoji} Dependency Analysis

**Dependent resources** ({len(dependency.dependent_resources)} found):
{dep_list}

**Recent accessors** (last {config.DEPENDENCY_LOOKBACK_DAYS} days):
{accessor_list}

**Notes:**
{notes}

---

### {approval}

---

### Terraform Fix

Copy to `devops-platform-foundation`:
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

**Rollback:** {patch.rollback_plan}

**Risk notes:** {patch.risk_notes}

---
*{now.strftime("%Y-%m-%d %H:%M UTC")}*
"""


# ── Master Issue ──────────────────────────────────────────────

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

    title = (
        f"🔍 Weekly Security Audit — {report.run_date} — "
        f"{len(rg_issues)} RG(s) — "
        f"{actioned} actioned "
        f"[{high_count}H · {medium_count}M]"
    )

    # RG table
    rg_table = (
        "| Resource Group | HIGH | MEDIUM | Issue |\n"
        "|---|---|---|---|\n"
    )
    for rg, info in sorted(rg_issues.items()):
        rg_table += (
            f"| `{rg[:50]}` "
            f"| {'🔴 ' + str(info['high']) if info['high'] else '-'} "
            f"| {'🟡 ' + str(info['medium']) if info['medium'] else '-'} "
            f"| #{info['issue_number']} |\n"
        )

    # RG checklist
    rg_checklist = "\n".join(
        f"- [ ] #{info['issue_number']} `{rg[:50]}` — "
        f"{info['high']}H · {info['medium']}M"
        for rg, info in sorted(rg_issues.items())
    )

    # LOW summary (table only, no detail)
    low_section = ""
    if report.low:
        low_rows = ["| Finding | Resource | RG |", "|---|---|---|"]
        for d in all_data:
            if d["finding"].risk == config.RISK_LOW:
                f = d["finding"]
                low_rows.append(
                    f"| {f.title[:50]} | `{f.resource_name}` | `{f.resource_group[:30]}` |"
                )
        low_section = f"""---

## 🟢 LOW Severity — {low_count} findings (informational)

No action required. Listed for awareness only.

{chr(10).join(low_rows[:52])}
{"" if len(low_rows) <= 52 else f"_...and {len(low_rows)-52} more — run Prowler locally for full list_"}
"""

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
| **Actioned** | **{actioned}** |
| Resource groups | {len(rg_issues)} |

---

## By Resource Group

{rg_table}

---

## RG Issues — check off as resolved

{rg_checklist}

---

## How it works

```
This Issue (master)
  └── RG Issue per resource group
        └── One comment per finding (dependency + Terraform patch)
```

Fix a finding → raise PR in `devops-platform-foundation` → merge
→ check the box in the RG Issue → close RG Issue when all done
→ check the box here when all RGs resolved.

{low_section}

---
*[security-auditor](https://github.com/{config.GITHUB_REPO}) · \
Prowler · {now.strftime("%Y-%m-%d %H:%M UTC")}*
"""

    # Truncate if needed
    if len(body) > MAX_BODY_CHARS:
        body = body[:MAX_BODY_CHARS] + "\n\n...[truncated]"

    return repo.create_issue(
        title=title,
        body=body,
        labels=["security", "audit-master"],
    )


def _create_clean_master(repo, report: ScanReport, now: datetime):
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


# ── Helpers ───────────────────────────────────────────────────

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
        "stor": f"az storage account show --name {finding.resource_name} "
                f"--query '{{public:allowBlobPublicAccess,sharedKey:allowSharedKeyAccess}}'",
        "mana": f"az aks show --name {finding.resource_name} "
                f"-g {finding.resource_group} --query apiServerAccessProfile",
        "vaul": f"az keyvault show --name {finding.resource_name} "
                f"--query properties.networkAcls",
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