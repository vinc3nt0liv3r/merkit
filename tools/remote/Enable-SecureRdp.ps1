<#
.SYNOPSIS
    Turns on Remote Desktop on a CI runner so that it can only be reached over Tailscale.

.DESCRIPTION
    - Creates a local administrator "merkit" whose password comes from the RDP_PASSWORD environment variable
      (a GitHub secret, so it is masked in logs). The password is never printed or written to disk.
    - Requires Network Level Authentication and TLS.
    - Opens the Remote Desktop firewall rules ONLY to Tailscale addresses (100.64.0.0/10 and fd7a:115c:a1e0::/48).
    - Locks the account out after 5 wrong passwords.
#>
[CmdletBinding()]
param(
    [string]$UserName = 'merkit'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$plain = $env:RDP_PASSWORD
if ([string]::IsNullOrEmpty($plain) -or $plain.Length -lt 16) {
    throw 'RDP_PASSWORD must be set and at least 16 characters long.'
}
$password = ConvertTo-SecureString -String $plain -AsPlainText -Force
$plain = $null

if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
    Set-LocalUser -Name $UserName -Password $password
}
else {
    New-LocalUser -Name $UserName -Password $password -PasswordNeverExpires -AccountNeverExpires `
        -Description 'Temporary Merkit test session' | Out-Null
}
foreach ($group in 'Administrators', 'Remote Desktop Users') {
    $member = Get-LocalGroupMember -Group $group -Member $UserName -ErrorAction SilentlyContinue
    if (-not $member) { Add-LocalGroupMember -Group $group -Member $UserName }
}

& net accounts /lockoutthreshold:5 /lockoutduration:30 /lockoutwindow:30 | Out-Null

$ts = 'HKLM:\System\CurrentControlSet\Control\Terminal Server'
Set-ItemProperty -Path $ts -Name 'fDenyTSConnections' -Value 0
$rdpTcp = "$ts\WinStations\RDP-Tcp"
Set-ItemProperty -Path $rdpTcp -Name 'UserAuthentication' -Value 1   # Network Level Authentication
Set-ItemProperty -Path $rdpTcp -Name 'SecurityLayer' -Value 2        # TLS

Set-Service -Name TermService -StartupType Automatic
if ((Get-Service TermService).Status -ne 'Running') { Start-Service TermService }

$tailscaleRanges = @('100.64.0.0/10', 'fd7a:115c:a1e0::/48')
$rules = Get-NetFirewallRule -DisplayGroup 'Remote Desktop' -ErrorAction SilentlyContinue
if (-not $rules) {
    New-NetFirewallRule -DisplayName 'Remote Desktop (Tailscale only)' -Direction Inbound -Protocol TCP `
        -LocalPort 3389 -Action Allow -RemoteAddress $tailscaleRanges | Out-Null
}
else {
    $rules | Set-NetFirewallRule -Enabled True -RemoteAddress $tailscaleRanges
}

Write-Host "Remote Desktop is on for user '$UserName', reachable from Tailscale addresses only."
