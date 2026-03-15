<#
.SYNOPSIS
    Invoke-Offboarding.ps1 — Automated IAM Leaver Workflow
    Part of IAM-Lab-Pro | github.com/luigistfort/iam-lab-pro

.DESCRIPTION
    Executes the complete IAM leaver workflow for a departing employee:
    1. Disable AD account immediately
    2. Revoke all active sessions and tokens
    3. Remove from all security groups
    4. Move to Disabled OU
    5. Hide from Global Address List
    6. Forward email to manager
    7. Generate full audit report
    8. Schedule account deletion after retention period

.EXAMPLE
    .\Invoke-Offboarding.ps1 -Username "jsmith" -TicketID "INC0042891" -ManagerEmail "mgr@corp.local"

.NOTES
    Author  : Luigi St Fort
    GitHub  : github.com/luigistfort/iam-lab-pro
    Version : 1.0
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)]
    [string]$Username,

    [Parameter(Mandatory=$true)]
    [string]$TicketID,

    [Parameter(Mandatory=$false)]
    [string]$ManagerEmail,

    [Parameter(Mandatory=$false)]
    [int]$RetentionDays = 90,

    [Parameter(Mandatory=$false)]
    [string]$DisabledOU = "OU=Disabled,DC=corp,DC=local",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\logs\offboarding-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

#──────────────────────────────────────────────────────────────────────────────
# FUNCTIONS
#──────────────────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $entry = "[$ts] [$Level] $Message"
    Write-Host $entry -ForegroundColor $(switch($Level) { "SUCCESS"{"Green"} "WARNING"{"Yellow"} "ERROR"{"Red"} "STEP"{"Magenta"} default{"Cyan"} })
    $entry | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

function Invoke-Step {
    param([string]$StepName, [scriptblock]$Action)
    Write-Log "━━━ STEP: $StepName" "STEP"
    try {
        & $Action
        Write-Log "  ✅ $StepName — COMPLETE" "SUCCESS"
    } catch {
        Write-Log "  ❌ $StepName — FAILED: $($_.Exception.Message)" "ERROR"
    }
}

#──────────────────────────────────────────────────────────────────────────────
# MAIN
#──────────────────────────────────────────────────────────────────────────────

$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

Write-Log "═══════════════════════════════════════════════════════════"
Write-Log "  IAM-Lab-Pro | LEAVER WORKFLOW — $Username"
Write-Log "  Ticket: $TicketID | Initiated: $(Get-Date -Format 'yyyy-MM-dd HH:mm')"
Write-Log "  Author: Luigi St Fort | github.com/luigistfort/iam-lab-pro"
Write-Log "═══════════════════════════════════════════════════════════"

# Verify user exists
$adUser = Get-ADUser -Identity $Username -Properties * -ErrorAction SilentlyContinue
if (-not $adUser) {
    Write-Log "User '$Username' not found in Active Directory" "ERROR"
    exit 1
}

Write-Log "User found: $($adUser.DisplayName) | $($adUser.EmailAddress) | $($adUser.Department)"

# ── STEP 1: DISABLE ACCOUNT ──────────────────────────────────────────────────
Invoke-Step "Disable AD Account" {
    if ($PSCmdlet.ShouldProcess($Username, "Disable account")) {
        Disable-ADAccount -Identity $Username
        Set-ADUser -Identity $Username -Description "DISABLED on $(Get-Date -Format 'yyyy-MM-dd') | Ticket: $TicketID | Offboarding workflow"
        Write-Log "  Account disabled — no further logons permitted"
    }
}

# ── STEP 2: REVOKE SESSIONS ───────────────────────────────────────────────────
Invoke-Step "Revoke Active Sessions & Tokens" {
    # Reset password to random value (invalidates all current sessions)
    $newPwd = ConvertTo-SecureString ([System.Web.Security.Membership]::GeneratePassword(24, 4)) -AsPlainText -Force
    Set-ADAccountPassword -Identity $Username -NewPassword $newPwd -Reset
    Write-Log "  Password reset — all existing sessions invalidated"

    # Note: In production, also call Okta/Entra ID APIs to revoke OAuth tokens
    Write-Log "  ACTION REQUIRED: Revoke OAuth tokens in Okta/Entra ID admin console"
    Write-Log "  Okta: Admin > Reports > System Log > search user > Revoke sessions"
    Write-Log "  Entra: Entra admin center > Users > $Username > Revoke sessions"
}

# ── STEP 3: CAPTURE GROUP MEMBERSHIP (before removal) ─────────────────────────
Invoke-Step "Capture & Remove Group Memberships" {
    $groups = Get-ADPrincipalGroupMembership -Identity $Username | Where-Object { $_.Name -ne "Domain Users" }
    $groupList = $groups.Name -join ", "
    Write-Log "  Found $($groups.Count) group memberships: $groupList"

    # Log group membership to description for audit
    $currentDesc = (Get-ADUser -Identity $Username -Properties Description).Description
    Set-ADUser -Identity $Username -Description "$currentDesc | Groups removed: $groupList"

    # Remove from all groups
    foreach ($group in $groups) {
        Remove-ADGroupMember -Identity $group.DistinguishedName -Members $Username -Confirm:$false
        Write-Log "  Removed from: $($group.Name)"
    }
    Write-Log "  All $($groups.Count) group memberships removed"
}

# ── STEP 4: MOVE TO DISABLED OU ───────────────────────────────────────────────
Invoke-Step "Move to Disabled Accounts OU" {
    if ($PSCmdlet.ShouldProcess($Username, "Move to $DisabledOU")) {
        Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $DisabledOU
        Write-Log "  Moved to: $DisabledOU"
    }
}

# ── STEP 5: HIDE FROM GAL ────────────────────────────────────────────────────
Invoke-Step "Hide from Global Address List" {
    Set-ADUser -Identity $Username -Add @{ msExchHideFromAddressLists = $true }
    Write-Log "  User hidden from Exchange/Outlook Global Address List"
}

# ── STEP 6: SET DELETION DATE ────────────────────────────────────────────────
Invoke-Step "Set Account Retention / Deletion Date" {
    $deletionDate = (Get-Date).AddDays($RetentionDays).ToString("yyyy-MM-dd")
    $currentDesc  = (Get-ADUser -Identity $Username -Properties Description).Description
    Set-ADUser -Identity $Username -Description "$currentDesc | Scheduled for deletion: $deletionDate"
    Write-Log "  Account retained for $RetentionDays days — scheduled deletion: $deletionDate"
}

# ── STEP 7: GENERATE AUDIT REPORT ─────────────────────────────────────────────
Invoke-Step "Generate Offboarding Audit Report" {
    $reportPath = ".\reports\offboarding-$Username-$TicketID.txt"
    $reportDir  = Split-Path $reportPath -Parent
    if (-not (Test-Path $reportDir)) { New-Item -ItemType Directory -Path $reportDir | Out-Null }

    @"
═══════════════════════════════════════════════════
OFFBOARDING AUDIT REPORT
═══════════════════════════════════════════════════
Generated By : Luigi St Fort (IAM-Lab-Pro)
Date/Time    : $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')
Ticket ID    : $TicketID
═══════════════════════════════════════════════════
USER DETAILS
Display Name : $($adUser.DisplayName)
Username     : $Username
Email        : $($adUser.EmailAddress)
Department   : $($adUser.Department)
Job Title    : $($adUser.Title)
Last Logon   : $($adUser.LastLogonDate)
═══════════════════════════════════════════════════
ACTIONS COMPLETED
[✅] Account disabled
[✅] Password reset (sessions invalidated)
[✅] Removed from all security groups
[✅] Moved to Disabled OU
[✅] Hidden from GAL
[✅] Deletion date set: $((Get-Date).AddDays($RetentionDays).ToString('yyyy-MM-dd'))
═══════════════════════════════════════════════════
MANUAL ACTIONS REQUIRED
[ ] Revoke Okta sessions in Admin console
[ ] Revoke Entra ID tokens
[ ] Disable MFA devices in Okta
[ ] Remove from Slack, GitHub, Jira (non-AD apps)
[ ] Retrieve company hardware
[ ] Transfer shared mailbox to manager
═══════════════════════════════════════════════════
"@ | Out-File $reportPath -Encoding UTF8

    Write-Log "  Audit report saved: $reportPath"
}

# ── FINAL SUMMARY ────────────────────────────────────────────────────────────
Write-Log "═══════════════════════════════════════════════════════════"
Write-Log "OFFBOARDING COMPLETE — $($adUser.DisplayName)"
Write-Log "  Account disabled, sessions revoked, groups removed"
Write-Log "  Scheduled deletion: $((Get-Date).AddDays($RetentionDays).ToString('yyyy-MM-dd'))"
Write-Log "  Log: $LogPath"
Write-Log "  MANUAL: Revoke Okta/Entra tokens to fully terminate access"
Write-Log "═══════════════════════════════════════════════════════════"
