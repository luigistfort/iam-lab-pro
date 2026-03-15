#!/usr/bin/env python3
"""
access_certification.py — IAM Access Certification Campaign Automation
Part of IAM-Lab-Pro | github.com/luigistfort/iam-lab-pro

Automates quarterly access review certification campaigns:
- Loads user access data from JSON/CSV
- Detects SoD (Segregation of Duties) violations
- Generates manager review assignments
- Produces certification report with risk scoring

Author  : Luigi St Fort
GitHub  : github.com/luigistfort/iam-lab-pro
"""

import json
import csv
import sys
import argparse
from datetime import datetime, timedelta
from dataclasses import dataclass, field, asdict
from typing import Optional


# ── DATA MODELS ──────────────────────────────────────────────────────────────

@dataclass
class UserAccess:
    username: str
    display_name: str
    department: str
    job_title: str
    manager: str
    last_login_days_ago: int
    mfa_enrolled: bool
    groups: list[str] = field(default_factory=list)
    applications: list[str] = field(default_factory=list)
    risk_score: int = 0
    risk_flags: list[str] = field(default_factory=list)


@dataclass
class CertificationDecision:
    username: str
    display_name: str
    certifier: str
    resource: str
    decision: str  # "certify" | "revoke" | "pending"
    justification: str
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat()


# ── SAMPLE DATA (replace with real AD/Okta export in production) ─────────────

SAMPLE_USERS = [
    UserAccess("l.stfort",   "Luigi St Fort",   "IT",      "IAM Administrator",  "cto@corp.local",      1,  True,  ["GG-IT-Department","GG-IAM-Admins","GG-Admins","GG-AllEmployees"],  ["Okta Admin","Azure Portal","GitHub","ServiceNow"]),
    UserAccess("s.chen",     "Sarah Chen",       "Finance", "Finance Manager",    "cfo@corp.local",      1,  True,  ["GG-Finance-Department","GG-Managers","GG-AllEmployees"],             ["NetSuite","Power BI","QuickBooks","Okta SSO Portal"]),
    UserAccess("m.johnson",  "Marcus Johnson",   "Sales",   "Sales Manager",      "vpsales@corp.local",  1,  True,  ["GG-Sales-Department","GG-Managers","GG-CRM-Admins"],                 ["Salesforce Admin","HubSpot","Zoom","Okta SSO Portal"]),
    UserAccess("k.wong",     "Kevin Wong",       "IT",      "Base Employee",      "itmanager@corp.local",98, False, ["GG-IT-Department","GG-AllEmployees","GG-Admins"],                    ["Azure Portal","AWS Console"]),    # RISK: dormant + no MFA + admin
    UserAccess("t.wright",   "Tom Wright",       "IT",      "Helpdesk",           "itmanager@corp.local", 1, True,  ["GG-IT-Department","GG-Helpdesk","GG-AllEmployees"],                  ["ServiceNow","AD Admin Tools"]),
    UserAccess("a.reyes",    "Anna Reyes",       "HR",      "HR Analyst",         "hrdir@corp.local",    2,  True,  ["GG-HR-Department","GG-Finance-ReadOnly","GG-AllEmployees"],           ["Workday","BambooHR"]),           # RISK: SoD - HR + Finance access
    UserAccess("j.carter",   "Jennifer Carter",  "Sales",   "Sales Analyst",      "vpsales@corp.local",  0,  True,  ["GG-Sales-Department","GG-AllEmployees"],                             ["Salesforce","Okta SSO Portal"]),
    UserAccess("svc.backup", "svc.backup.acct",  "IT",      "Service Account",    "itmanager@corp.local",0,  False, ["GG-Backup-Operators","GG-Admins"],                                   []),                               # RISK: service acct, no MFA, admin
]

# SoD conflict rules — these role combinations violate separation of duties
SOD_VIOLATIONS = [
    ("GG-Finance-Department", "GG-Accounts-Payable", "Finance + AP access violates SoD"),
    ("GG-HR-Department",      "GG-Finance-ReadOnly",  "HR + Finance access — review required"),
    ("GG-Admins",             "GG-Audit-Team",        "Admin + Audit role conflict"),
    ("GG-CRM-Admins",         "GG-Finance-Department","CRM Admin + Finance — data access risk"),
]


# ── RISK SCORING ENGINE ───────────────────────────────────────────────────────

def calculate_risk(user: UserAccess) -> UserAccess:
    """Score user access risk and attach flags."""
    score = 0
    flags = []

    # Dormant account
    if user.last_login_days_ago > 90:
        score += 40
        flags.append(f"DORMANT: No login in {user.last_login_days_ago} days")
    elif user.last_login_days_ago > 60:
        score += 20
        flags.append(f"INACTIVE: No login in {user.last_login_days_ago} days")

    # No MFA
    if not user.mfa_enrolled:
        score += 30
        flags.append("NO MFA: Account not enrolled in multi-factor authentication")

    # Admin groups without MFA
    admin_groups = [g for g in user.groups if "Admin" in g or "Backup" in g]
    if admin_groups and not user.mfa_enrolled:
        score += 25
        flags.append(f"CRITICAL: Admin rights ({', '.join(admin_groups)}) without MFA")

    # Service account checks
    if "svc." in user.username.lower() or "service" in user.display_name.lower():
        if not user.mfa_enrolled:
            score += 20
            flags.append("SERVICE ACCOUNT: No MFA — consider managed identity or certificate auth")
        if "GG-Admins" in user.groups:
            score += 25
            flags.append("SERVICE ACCOUNT: Has admin group membership — review required")

    # SoD violations
    for group_a, group_b, reason in SOD_VIOLATIONS:
        if group_a in user.groups and group_b in user.groups:
            score += 35
            flags.append(f"SOD VIOLATION: {reason}")

    # Excess application access (more than 8 apps for non-IT)
    if user.department != "IT" and len(user.applications) > 8:
        score += 10
        flags.append(f"EXCESS APPS: {len(user.applications)} applications — review for least privilege")

    user.risk_score = min(score, 100)
    user.risk_flags = flags
    return user


# ── CERTIFICATION CAMPAIGN ────────────────────────────────────────────────────

def run_certification_campaign(campaign_id: str, users: list[UserAccess]) -> dict:
    """Generate access certification campaign data."""

    print(f"\n{'═'*60}")
    print(f"  IAM-Lab-Pro | Access Certification Campaign")
    print(f"  Campaign ID : {campaign_id}")
    print(f"  Generated   : {datetime.now().strftime('%Y-%m-%d %H:%M')}")
    print(f"  Author      : Luigi St Fort")
    print(f"{'═'*60}\n")

    # Score all users
    scored_users = [calculate_risk(u) for u in users]

    # Statistics
    high_risk   = [u for u in scored_users if u.risk_score >= 70]
    medium_risk = [u for u in scored_users if 30 <= u.risk_score < 70]
    low_risk    = [u for u in scored_users if u.risk_score < 30]
    no_mfa      = [u for u in scored_users if not u.mfa_enrolled]
    dormant     = [u for u in scored_users if u.last_login_days_ago > 90]

    print(f"📊 CAMPAIGN SUMMARY")
    print(f"   Total users      : {len(scored_users)}")
    print(f"   🔴 High risk      : {len(high_risk)}")
    print(f"   🟡 Medium risk    : {len(medium_risk)}")
    print(f"   🟢 Low risk       : {len(low_risk)}")
    print(f"   ⚠️  No MFA         : {len(no_mfa)}")
    print(f"   💤 Dormant (90d+) : {len(dormant)}")

    # Print risk details
    if high_risk:
        print(f"\n🔴 HIGH RISK USERS — IMMEDIATE REVIEW REQUIRED")
        print(f"{'─'*60}")
        for u in sorted(high_risk, key=lambda x: x.risk_score, reverse=True):
            print(f"\n  👤 {u.display_name} ({u.username})")
            print(f"     Dept     : {u.department} | Title: {u.job_title}")
            print(f"     Risk     : {u.risk_score}/100")
            print(f"     Last Login: {u.last_login_days_ago} days ago | MFA: {'✅' if u.mfa_enrolled else '❌'}")
            print(f"     Groups   : {', '.join(u.groups[:4])}{'...' if len(u.groups)>4 else ''}")
            for flag in u.risk_flags:
                print(f"     🚩 {flag}")

    # Generate certification decisions (auto-certify low risk, flag rest)
    decisions = []
    for u in scored_users:
        if u.risk_score < 20 and u.last_login_days_ago < 30 and u.mfa_enrolled:
            # Auto-certify clean accounts
            for app in u.applications:
                decisions.append(CertificationDecision(
                    username=u.username, display_name=u.display_name,
                    certifier="system.auto-cert", resource=app,
                    decision="certify", justification="Auto-certified: Low risk, active, MFA enrolled"
                ))
        else:
            # Flag for manual review
            for app in u.applications:
                decisions.append(CertificationDecision(
                    username=u.username, display_name=u.display_name,
                    certifier=u.manager, resource=app,
                    decision="pending", justification="Pending manager review — risk flags detected"
                ))

    # Export report
    report = {
        "campaign_id": campaign_id,
        "generated": datetime.now().isoformat(),
        "generated_by": "Luigi St Fort | IAM-Lab-Pro",
        "summary": {
            "total_users": len(scored_users),
            "high_risk": len(high_risk),
            "medium_risk": len(medium_risk),
            "low_risk": len(low_risk),
            "no_mfa": len(no_mfa),
            "dormant_accounts": len(dormant),
        },
        "users": [asdict(u) for u in scored_users],
        "decisions": [asdict(d) for d in decisions],
    }

    # Save JSON report
    filename = f"certification-{campaign_id}-{datetime.now().strftime('%Y%m%d')}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent=2)

    # Save CSV for manager review
    csv_filename = f"certification-{campaign_id}-manager-review.csv"
    pending = [d for d in decisions if d.decision == "pending"]
    with open(csv_filename, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Username","Display Name","Certifier/Manager","Resource","Current Decision","Risk Score","Action Required"])
        for d in pending:
            user = next((u for u in scored_users if u.username == d.username), None)
            risk = user.risk_score if user else "N/A"
            writer.writerow([d.username, d.display_name, d.certifier, d.resource, d.decision, risk, "CERTIFY or REVOKE"])

    print(f"\n📋 CERTIFICATION OUTPUT")
    print(f"   JSON report : {filename}")
    print(f"   Manager CSV : {csv_filename}")
    print(f"   Total decisions : {len(decisions)} ({len([d for d in decisions if d.decision == 'certify'])} auto-certified, {len(pending)} pending manager review)")
    print(f"\n{'═'*60}")
    print(f"  Campaign complete. Distribute {csv_filename} to managers.")
    print(f"  Deadline: {(datetime.now() + timedelta(days=14)).strftime('%Y-%m-%d')} (14-day review window)")
    print(f"{'═'*60}\n")

    return report


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="IAM-Lab-Pro Access Certification Campaign Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 access_certification.py --campaign Q1-2025
  python3 access_certification.py --campaign Q1-2025 --input users.json
        """
    )
    parser.add_argument("--campaign", default=f"Q{((datetime.now().month-1)//3)+1}-{datetime.now().year}", help="Campaign ID (e.g. Q1-2025)")
    parser.add_argument("--input",    default=None, help="Path to user access JSON file (uses sample data if not provided)")
    args = parser.parse_args()

    # Load users
    if args.input:
        with open(args.input) as f:
            raw = json.load(f)
        users = [UserAccess(**u) for u in raw]
    else:
        print("ℹ️  No input file provided — using sample user data")
        print("   In production: export from AD/Okta and pass as --input users.json\n")
        users = SAMPLE_USERS

    run_certification_campaign(args.campaign, users)


if __name__ == "__main__":
    main()
