"""
Security Auditor — Remediation Scanner
Creates a 3-level GitHub Issue hierarchy:
  Master → RG Issues → Finding Issues
"""
import sys
from remediation import config
from remediation.scanner import run_scan, Finding
from remediation.dependency import analyze as analyze_dependency
from remediation.patch_generator import generate as generate_patch
from remediation.github_client import create_audit_hierarchy


def process_finding(finding: Finding) -> dict:
    risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}.get(finding.risk, "⚪")
    print(f"  {risk_emoji} [{finding.finding_id}] {finding.resource_name} — {finding.title[:40]}")

    dependency = analyze_dependency(finding)
    patch      = generate_patch(finding, dependency)

    return {"finding": finding, "dependency": dependency, "patch": patch}


def main():
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  Security Auditor — Remediation Scanner")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
    print(f"  Mode: {'MOCK DATA' if config.USE_MOCK_DATA else 'LIVE — Defender for Cloud'}")
    print(f"  Repo: {config.GITHUB_REPO}")
    print("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")

    missing = config.validate()
    if missing:
        print(f"[ERROR] Missing: {', '.join(missing)}")
        sys.exit(1)

    # Step 1 — Read Defender findings
    report = run_scan()
    if not report.findings:
        print("\n✅ No non-compliant resources — subscription is clean!")
        return

    # Step 2 — Process each finding (HIGH → MEDIUM → LOW)
    print(f"\nAnalysing {len(report.findings)} findings...\n")
    findings_data = []
    for finding in (report.high + report.medium + report.low):
        try:
            findings_data.append(process_finding(finding))
        except Exception as e:
            print(f"  [ERROR] {finding.finding_id}: {e}")

    # Step 3 — Create Issue hierarchy
    print(f"\nCreating GitHub Issue hierarchy...")
    try:
        master_url = create_audit_hierarchy(report, findings_data)
    except Exception as e:
        print(f"[ERROR] Failed to create issues: {e}")
        sys.exit(1)

    print(f"\n{'━'*55}")
    print(f"  ✅ Done — {master_url}")
    print(f"  🔴 HIGH:   {len(report.high)}")
    print(f"  🟡 MEDIUM: {len(report.medium)}")
    print(f"  🟢 LOW:    {len(report.low)}")
    print(f"\n  Issue structure:")
    print(f"  Master Issue → RG Issues → Finding Issues")
    print(f"  Close finding Issues as you fix them →")
    print(f"  checkboxes auto-tick up the hierarchy")
    print(f"{'━'*55}")


if __name__ == "__main__":
    main()