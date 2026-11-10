<#
.SYNOPSIS
    Turns a fresh, disposable Windows Server virtual machine into a test Active Directory forest.

.DESCRIPTION
    NOT TESTED ON A REAL MACHINE YET. Run it only on a throw-away VM (Hyper-V, VirtualBox, VMware or a cloud VM)
    that is not connected to your production network. It installs AD DS, creates the forest "lab.local", and
    restarts the machine. After the restart, sign in as LAB\Administrator and run:

        .\tools\lds\Seed-Lab.ps1 -Server localhost -Port 389 -BaseDn 'DC=lab,DC=local' -ActiveDirectory

    A GitHub-hosted runner cannot do this: promoting a domain controller needs a restart, and a hosted
    runner is lost when it restarts.
#>
[CmdletBinding()]
param(
    [string]$DomainName = 'lab.local',
    [string]$NetbiosName = 'LAB'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) session.'
}

Write-Warning "This will turn '$env:COMPUTERNAME' into a domain controller for '$DomainName' and restart it."
if ((Read-Host 'Type YES to continue') -ne 'YES') { return }

$safeMode = Read-Host 'Choose a Directory Services Restore Mode password' -AsSecureString

Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
Install-ADDSForest `
    -DomainName $DomainName `
    -DomainNetbiosName $NetbiosName `
    -SafeModeAdministratorPassword $safeMode `
    -InstallDns `
    -Force
