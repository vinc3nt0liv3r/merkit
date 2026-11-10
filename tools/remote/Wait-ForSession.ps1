<#
.SYNOPSIS
    Keeps the runner alive until the time limit, until C:\stop-session.txt appears, or until nobody has been
    connected over Remote Desktop for a while.
#>
[CmdletBinding()]
param(
    [int]$Minutes = 60,
    [int]$IdleMinutes = 20
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$Minutes = [Math]::Min([Math]::Max($Minutes, 10), 120)
$deadline = (Get-Date).AddMinutes($Minutes)
$lastSeen = Get-Date
$lastNote = Get-Date

Write-Host "Session open for up to $Minutes minutes. To end it early, create C:\stop-session.txt on this machine."

while ((Get-Date) -lt $deadline) {
    if (Test-Path 'C:\stop-session.txt') { Write-Host 'Stop file found. Ending the session.'; break }

    $connected = @(& qwinsta 2>$null | Select-String -Pattern 'rdp-tcp#\d+\s+\S+').Count
    if ($connected -gt 0) { $lastSeen = Get-Date }
    elseif (((Get-Date) - $lastSeen).TotalMinutes -ge $IdleMinutes) {
        Write-Host "No Remote Desktop user for $IdleMinutes minutes. Ending the session."
        break
    }

    if (((Get-Date) - $lastNote).TotalMinutes -ge 5) {
        $left = [int]($deadline - (Get-Date)).TotalMinutes
        Write-Host "$left minutes left."
        $lastNote = Get-Date
    }
    Start-Sleep -Seconds 20
}
