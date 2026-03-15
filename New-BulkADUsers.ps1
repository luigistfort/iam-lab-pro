<#
.SYNOPSIS
    New-BulkADUsers.ps1 — Bulk Active Directory User Provisioning
    Part of IAM-Lab-Pro | github.com/luigistfort/iam-lab-pro

.DESCRIPTION
    Creates AD user accounts in bulk from a CSV file, assigns to correct OUs,
    adds to security groups based on department, and sets a temporary password.
    Simulates real enterprise IAM joiner workflow automation.

.PARAMETER CSVPath
    Path to the input CSV file with user data.

.PARAMETER OUPath
    Distinguished name of the target OU.

.PARAMETER DefaultPassword
    Temporary password for new accounts. Users must change on first login.

.EXAMPLE
    .\New-BulkADUsers.ps1 -CSVPath ".\users.csv" -OUPath "OU=NewHires,DC=corp,DC=local"

.NOTES
    Author  : Luigi St Fort
    GitHub  : github.com/luigistfort/iam-lab-pro
    Version : 1.0
    Requires: ActiveDirectory PowerShell module
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory=$true)]
    [string]$CSVPath,

    [Parameter(Mandatory=$false)]
    [string]$OUPath = "OU=NewHires,DC=corp,DC=local",

    [Parameter(Mandatory=$false)]
    [string]$DefaultPassword = "Welcome@Corp2024!",

    [Parameter(Mandatory=$false)]
    [string]$LogPath = ".\logs\provisioning-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
)

#──────────────────────────────────────────────────────────────────────────────
# FUNCTIONS
#──────────────────────────────────────────────────────────────────────────────

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry  = "[$timestamp] [$Level] $Message"
    Write-Host $logEntry -ForegroundColor $(
        switch($Level) {
            "SUCCESS" { "Green"  }
            "WARNING" { "Yellow" }
            "ERROR"   { "Red"    }
            default   { "Cyan"   }
        }
    )
    $logEntry | Out-File -FilePath $LogPath -Append -Encoding UTF8
}

function New-Username {
    param([string]$FirstName, [string]$LastName)
    # Format: f.lastname (e.g., l.stfort)
    $username = "$($FirstName.Substring(0,1).ToLower()).$($LastName.ToLower())"
    $username = $username -replace '[^a-z0-9.]', ''

    # Check for conflicts and append number if needed
    $counter = 1
    $base    = $username
    while (Get-ADUser -Filter { SamAccountName -eq $username } -ErrorAction SilentlyContinue) {
        $username = "$base$counter"
        $counter++
    }
    return $username
}

function Get-DepartmentOU {
    param([string]$Department, [string]$BaseOU)
    $deptMap = @{
        "IT"          = "OU=IT,$BaseOU"
        "Finance"     = "OU=Finance,$BaseOU"
        "HR"          = "OU=HR,$BaseOU"
        "Sales"       = "OU=Sales,$BaseOU"
        "Operations"  = "OU=Operations,$BaseOU"
        "Engineering" = "OU=Engineering,$BaseOU"
    }
    return $deptMap[$Department] ?? $BaseOU
}

function Add-UserToGroups {
    param([string]$Username, [string]$Department, [string]$JobTitle)

    # Base groups every employee gets
    $groups = @("GG-AllEmployees", "GG-VPN-Users", "GG-O365-Licensed")

    # Department groups
    $deptGroups = @{
        "IT"          = @("GG-IT-Department", "GG-Helpdesk-Tier1")
        "Finance"     = @("GG-Finance-Department", "GG-Finance-ReadOnly")
        "HR"          = @("GG-HR-Department", "GG-HRIS-Access")
        "Sales"       = @("GG-Sales-Department", "GG-CRM-Users")
        "Operations"  = @("GG-Operations-Department")
        "Engineering" = @("GG-Engineering-Department", "GG-GitHub-Access")
    }

    if ($deptGroups.ContainsKey($Department)) {
        $groups += $deptGroups[$Department]
    }

    # Role-based elevated groups
    if ($JobTitle -match "Manager") {
        $groups += "GG-Managers"
    }
    if ($JobTitle -match "Admin|Administrator") {
        $groups += "GG-Admins"
    }

    foreach ($group in $groups) {
        try {
            Add-ADGroupMember -Identity $group -Members $Username -ErrorAction Stop
            Write-Log "  Added $Username to $group" "SUCCESS"
        } catch {
            Write-Log "  Could not add $Username to $group — group may not exist" "WARNING"
        }
    }
}

#──────────────────────────────────────────────────────────────────────────────
# MAIN SCRIPT
#──────────────────────────────────────────────────────────────────────────────

# Create log directory
$logDir = Split-Path $LogPath -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir | Out-Null }

Write-Log "═══════════════════════════════════════════════════"
Write-Log "  IAM-Lab-Pro | Bulk AD Provisioning Script"
Write-Log "  Author: Luigi St Fort | github.com/luigistfort"
Write-Log "═══════════════════════════════════════════════════"
Write-Log "CSV Path  : $CSVPath"
Write-Log "Target OU : $OUPath"

# Verify CSV exists
if (-not (Test-Path $CSVPath)) {
    Write-Log "CSV file not found: $CSVPath" "ERROR"
    exit 1
}

# Import CSV
$users = Import-Csv -Path $CSVPath
Write-Log "Found $($users.Count) users to provision" "INFO"

# Counters
$created  = 0
$skipped  = 0
$failed   = 0
$securePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force

# Process each user
foreach ($user in $users) {

    Write-Log "─── Processing: $($user.FirstName) $($user.LastName) [$($user.Department)]"

    try {
        # Generate username
        $samAccount = New-Username -FirstName $user.FirstName -LastName $user.LastName
        $upn        = "$samAccount@corp.local"

        # Check if already exists
        if (Get-ADUser -Filter { SamAccountName -eq $samAccount } -ErrorAction SilentlyContinue) {
            Write-Log "  SKIP — $samAccount already exists" "WARNING"
            $skipped++
            continue
        }

        # Determine target OU
        $targetOU = Get-DepartmentOU -Department $user.Department -BaseOU $OUPath

        # Build AD user parameters
        $adParams = @{
            SamAccountName        = $samAccount
            UserPrincipalName     = $upn
            Name                  = "$($user.FirstName) $($user.LastName)"
            GivenName             = $user.FirstName
            Surname               = $user.LastName
            DisplayName           = "$($user.FirstName) $($user.LastName)"
            EmailAddress          = $upn
            Department            = $user.Department
            Title                 = $user.JobTitle
            Company               = "Corp LLC"
            OfficePhone           = $user.Phone
            Path                  = $targetOU
            AccountPassword       = $securePassword
            Enabled               = $true
            ChangePasswordAtLogon = $true
            Description           = "Provisioned via IAM-Lab-Pro on $(Get-Date -Format 'yyyy-MM-dd') | Ticket: $($user.TicketID)"
        }

        if ($PSCmdlet.ShouldProcess($samAccount, "Create AD User")) {
            New-ADUser @adParams -ErrorAction Stop
            Write-Log "  CREATED: $samAccount ($upn) in $targetOU" "SUCCESS"

            # Add to groups
            Add-UserToGroups -Username $samAccount -Department $user.Department -JobTitle $user.JobTitle

            $created++
        }

    } catch {
        Write-Log "  FAILED: $($user.FirstName) $($user.LastName) — $($_.Exception.Message)" "ERROR"
        $failed++
    }
}

#──────────────────────────────────────────────────────────────────────────────
# SUMMARY
#──────────────────────────────────────────────────────────────────────────────
Write-Log "═══════════════════════════════════════════════════"
Write-Log "PROVISIONING SUMMARY"
Write-Log "  Total processed : $($users.Count)"
Write-Log "  ✅ Created       : $created"
Write-Log "  ⚠️  Skipped       : $skipped (already existed)"
Write-Log "  ❌ Failed        : $failed"
Write-Log "  Log file        : $LogPath"
Write-Log "═══════════════════════════════════════════════════"

if ($failed -gt 0) {
    Write-Log "Review the log file for failed accounts and resolve manually" "WARNING"
}
