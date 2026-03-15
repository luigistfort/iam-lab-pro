# 🔐 IAM-Lab-Pro
### Enterprise Identity & Access Management Simulation Platform

[![SC-300](https://img.shields.io/badge/Microsoft-SC--300%20Aligned-0078D4?logo=microsoft)](https://learn.microsoft.com/en-us/certifications/exams/sc-300)
[![Okta](https://img.shields.io/badge/Okta-Platform%20Ready-007DC1?logo=okta)](https://developer.okta.com/)
[![Security+](https://img.shields.io/badge/CompTIA-Security%2B%20Concepts-E1261A?logo=comptia)](https://www.comptia.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-5391FE?logo=powershell)](https://learn.microsoft.com/en-us/powershell/)
[![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB?logo=python)](https://www.python.org/)

> **Built by Luigi St Fort** — IAM Engineer candidate with hands-on expertise in Okta, Microsoft Entra ID, Active Directory, and identity automation.  
> This project simulates a production-grade enterprise IAM environment and demonstrates core skills required for IAM Engineer, IAM Analyst, and Solutions Engineer roles.

---

## 🎯 What This Project Demonstrates

| IAM Competency | Implementation |
|---|---|
| **Identity Lifecycle (JML)** | Full Joiner-Mover-Leaver workflow engine with automated triggers |
| **RBAC Design** | Role matrix with 6 departments, 18 roles, least-privilege enforcement |
| **Access Request Workflow** | Submit → Approve → Provision → Audit pipeline |
| **Privileged Access Management** | Admin account vaulting, JIT elevation, session tracking |
| **MFA Enforcement** | Enrollment tracking, risk-based step-up authentication logic |
| **Audit & Compliance** | Full audit log with event ID mapping (AD Event 4624, 4625, 4740) |
| **PowerShell Automation** | Bulk provisioning, automated offboarding, access reporting |
| **Zero Trust Concepts** | Risk scoring engine, conditional access policy simulation |
| **SAML/OAuth2/OIDC** | Protocol documentation with flow diagrams |
| **Identity Governance** | Access certification campaigns, orphaned account detection |

---

## 🏗️ Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    IAM-Lab-Pro Platform                      │
├──────────────────┬──────────────────┬───────────────────────┤
│   Identity Store │  Access Engine   │  Governance Layer     │
│  ┌────────────┐  │ ┌─────────────┐  │ ┌───────────────────┐ │
│  │ User       │  │ │ RBAC Engine │  │ │ Access Reviews    │ │
│  │ Directory  │──┼─│ Policy Eval │  │ │ Certification     │ │
│  │ (AD Sim)   │  │ │ Risk Scorer │  │ │ Orphan Detection  │ │
│  └────────────┘  │ └─────────────┘  │ └───────────────────┘ │
│  ┌────────────┐  │ ┌─────────────┐  │ ┌───────────────────┐ │
│  │ Group/Role │  │ │ Auth Flows  │  │ │ Audit Log Engine  │ │
│  │ Manager    │  │ │ SAML / OIDC │  │ │ Event Correlation │ │
│  └────────────┘  │ └─────────────┘  │ └───────────────────┘ │
├──────────────────┴──────────────────┴───────────────────────┤
│              Automation Layer (PowerShell + Python)          │
│   Bulk Provisioning │ Auto-Offboarding │ Access Reporting    │
└─────────────────────────────────────────────────────────────┘
```

---

## 📁 Project Structure

```
iam-lab-pro/
├── 📊 dashboard/
│   └── index.html              # Full interactive IAM Admin Dashboard (single file)
│
├── ⚙️  scripts/
│   ├── powershell/
│   │   ├── New-BulkADUsers.ps1         # Bulk user provisioning from CSV
│   │   ├── Invoke-Offboarding.ps1      # Automated leaver process
│   │   ├── Get-AccessReport.ps1        # Group membership audit report
│   │   ├── Find-InactiveAccounts.ps1   # Dormant account detection
│   │   └── Set-EntraIDUser.ps1         # Graph API user management
│   └── python/
│       ├── access_certification.py     # Access review automation
│       ├── rbac_analyzer.py            # Role conflict detection
│       └── orphan_detector.py          # Orphaned account scanner
│
├── 📋 docs/
│   ├── architecture/
│   │   ├── IAM-Architecture.md         # Full environment design
│   │   └── RBAC-Role-Matrix.md         # Complete role catalog
│   └── runbooks/
│       ├── Onboarding-Runbook.md       # Joiner process SOP
│       ├── Offboarding-Runbook.md      # Leaver process SOP
│       └── AccessReview-Runbook.md     # Certification campaign SOP
│
└── README.md
```

---

## 🖥️ Interactive IAM Dashboard

**Live Demo:** Open `dashboard/index.html` in any browser — no server required.

### Dashboard Features:
- **📊 Identity Overview** — Real-time identity health metrics, MFA adoption rate, risk indicators
- **👥 User Lifecycle Manager** — Create, modify, suspend, and delete identities with full JML workflow
- **🔑 RBAC Role Matrix** — Visual role-to-permission mapping with conflict detection
- **📝 Access Request Engine** — Submit, approve/deny, and provision access with full audit trail
- **⚠️ Risk Center** — Risk-scored user list, impossible travel detection, dormant account alerts
- **📜 Audit Log Viewer** — Windows Security Event ID mapped log entries with search and filter
- **🏛️ Governance Panel** — Access certification campaigns, orphaned account remediation

---

## ⚡ PowerShell Automation Scripts

### Bulk User Provisioning
```powershell
# Creates 50 users from CSV in under 30 seconds
.\New-BulkADUsers.ps1 -CSVPath ".\users.csv" -OUPath "OU=NewHires,DC=corp,DC=local"
```

### Automated Offboarding
```powershell
# Full leaver workflow: disable, remove groups, move to disabled OU, revoke tokens
.\Invoke-Offboarding.ps1 -Username "jsmith" -TicketID "INC0042891"
```

### Access Report Generation
```powershell
# Exports all group memberships + last logon to Excel for access review
.\Get-AccessReport.ps1 -Department "Finance" -OutputPath ".\reports\"
```

---

## 🐍 Python Governance Tools

### RBAC Conflict Analyzer
```bash
python3 rbac_analyzer.py --users users.json --roles roles.json --output conflicts_report.csv
```
Detects Segregation of Duties (SoD) violations where a user holds conflicting roles.

### Access Certification Automation
```bash
python3 access_certification.py --campaign Q3-2024 --send-notifications --manager-list managers.csv
```
Generates access review campaigns, emails managers, and tracks certification decisions.

---

## 🏛️ RBAC Role Model

| Department | Role | Key Permissions | Privilege Level |
|---|---|---|---|
| IT | Global Admin | All resources | 🔴 Critical |
| IT | IAM Admin | Identity management | 🔴 Critical |
| IT | Helpdesk | Password reset, unlock accounts | 🟡 Elevated |
| Finance | Finance Manager | GL, AP/AR, reporting | 🟡 Elevated |
| Finance | Finance Analyst | Read GL, AP/AR | 🟢 Standard |
| HR | HR Manager | HRIS full access, AD provisioning trigger | 🟡 Elevated |
| HR | HR Analyst | HRIS read, org chart | 🟢 Standard |
| Sales | Sales Manager | CRM full, deal approval | 🟡 Elevated |
| All | Base Employee | Email, Teams, Intranet, SSO portal | 🟢 Standard |

---

## 🔄 Identity Lifecycle Flow

```
HR System Trigger
      │
      ▼
┌─────────────┐    ┌──────────────────┐    ┌──────────────────┐
│   JOINER    │    │     MOVER        │    │    LEAVER        │
│             │    │                  │    │                  │
│ Create AD   │    │ Update AD attrs  │    │ Disable account  │
│ Sync Entra  │    │ Add new role     │    │ Revoke all tokens│
│ Assign role │    │ Remove old role  │    │ Remove groups    │
│ Provision   │    │ Update app access│    │ Archive mailbox  │
│   apps      │    │ Notify managers  │    │ Move to disabled │
│ Enroll MFA  │    │                  │    │   OU             │
│ Notify user │    │                  │    │ Delete after 90d │
└─────────────┘    └──────────────────┘    └──────────────────┘
      │                    │                        │
      └────────────────────┴────────────────────────┘
                           │
                    Audit Log Entry
```

---

## 🛡️ Zero Trust Implementation

This lab implements Zero Trust principles across the identity layer:

| Zero Trust Principle | Implementation |
|---|---|
| **Verify explicitly** | Every access request evaluated against user risk score + device compliance |
| **Least privilege** | RBAC with time-limited elevated access via JIT simulation |
| **Assume breach** | Audit log captures every access event; anomaly detection flags deviations |

Conditional Access Policies simulated:
- Require MFA for all admin role assignments
- Block access from high-risk IP ranges
- Require compliant device for privileged actions
- Step-up authentication for sensitive data access

---

## 📊 Compliance Mapping

| Control Framework | Control ID | Implementation |
|---|---|---|
| NIST CSF | PR.AC-1 | Identity and credential management policies |
| NIST CSF | PR.AC-4 | Access permissions and authorizations managed |
| ISO 27001 | A.9.2.1 | User registration and de-registration |
| ISO 27001 | A.9.2.6 | Removal of access rights |
| HIPAA | §164.312(a)(1) | Access control policy and procedures |
| SOX | ITGC CC6.1 | Logical access security policies |

---

## 🚀 Getting Started

### Prerequisites
- Windows 10/11 or macOS/Linux
- PowerShell 5.1+ (Windows) or PowerShell 7+ (cross-platform)
- Python 3.9+
- Any modern browser (for dashboard)

### Lab Environment Setup
```bash
# Clone the repository
git clone https://github.com/luigistfort/iam-lab-pro.git
cd iam-lab-pro

# Install Python dependencies
pip install -r requirements.txt

# Open the dashboard
open dashboard/index.html    # macOS
start dashboard/index.html   # Windows
```

### For Full AD Lab Integration
See [docs/architecture/IAM-Architecture.md](docs/architecture/IAM-Architecture.md) for instructions on connecting scripts to a live Active Directory environment using Windows Server 2022 Evaluation.

---

## 👤 About the Author

**Luigi St Fort** — Identity & Access Management Engineer  
📍 Indianapolis, IN | Open to Remote  
🎓 B.S. Computer Science (In Progress) — Thomas Edison State University, 86 credits  
🏆 SC-300: Microsoft Identity & Access Administrator | CompTIA Security+ (In Progress)

**Core IAM Stack:** Okta · Microsoft Entra ID · Active Directory · AWS IAM · CyberArk (Concepts) · SailPoint (Concepts)  
**Protocols:** SAML 2.0 · OAuth 2.0 · OpenID Connect · LDAP · SCIM  
**Automation:** PowerShell · Microsoft Graph API · Python · Bash

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0077B5?logo=linkedin)](https://linkedin.com/in/luigistfort)
[![Email](https://img.shields.io/badge/Email-stfort91%40gmail.com-D14836?logo=gmail)](mailto:stfort91@gmail.com)

---

## 📄 License

MIT License — See [LICENSE](LICENSE) for details.

---

> *"Identity is the new perimeter. This project is my proof of work."*  
> — Luigi St Fort
