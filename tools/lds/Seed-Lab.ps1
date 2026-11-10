<#
.SYNOPSIS
    Fills a test directory with sample OUs, groups, users and deliberately imperfect permissions.

.DESCRIPTION
    Creates a small tree so every Merkit feature has something to show:
      OU=Workstations   protected from accidental deletion
      OU=Servers        Everyone can write properties, and a group has full control (both flagged as risky)
      OU=Users          contains OU=Helpdesk and OU=Sales; one permission points at a deleted group (orphaned SID)
      OU=Groups         delegation groups and sample users
    Safe to run again: existing objects are left as they are.

.PARAMETER ActiveDirectory
    Use when seeding a real Active Directory domain (sets sAMAccountName). Leave off for AD LDS.
#>
[CmdletBinding()]
param(
    [string]$Server = 'localhost',
    [int]$Port = 50389,
    [string]$BaseDn = 'CN=MerkitTest,DC=local',
    [switch]$ActiveDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-Entry([string]$dn) {
    New-Object System.DirectoryServices.DirectoryEntry("LDAP://${Server}:${Port}/$dn")
}

function Test-Entry([string]$dn) {
    [System.DirectoryServices.DirectoryEntry]::Exists("LDAP://${Server}:${Port}/$dn")
}

function New-Child($parent, [string]$parentDn, [string]$class, [string]$rdn, [hashtable]$props = @{}) {
    $dn = "$rdn,$parentDn"
    if (Test-Entry $dn) { return Get-Entry $dn }
    $child = $parent.Children.Add($rdn, $class)
    foreach ($key in $props.Keys) { $child.Properties[$key].Value = $props[$key] }
    $child.CommitChanges()
    Write-Host "  created $dn"
    return $child
}

function Get-Sid($entry) {
    $entry.RefreshCache(@('objectSid'))
    New-Object System.Security.Principal.SecurityIdentifier(([byte[]]$entry.Properties['objectSid'].Value), 0)
}

function Add-Rule($entry, $sid, [string]$rights, [string]$type, [string]$inherit = 'None') {
    $security = $entry.ObjectSecurity
    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
        $sid,
        [System.DirectoryServices.ActiveDirectoryRights]$rights,
        [System.Security.AccessControl.AccessControlType]$type,
        [System.DirectoryServices.ActiveDirectorySecurityInheritance]$inherit)
    $security.AddAccessRule($rule)
    $entry.ObjectSecurity = $security
    $entry.CommitChanges()
}

$root = Get-Entry $BaseDn
Write-Host "Seeding $BaseDn on ${Server}:${Port}"

$ouWorkstations = New-Child $root $BaseDn 'organizationalUnit' 'OU=Workstations' @{ description = 'All workstations and laptops' }
$ouServers      = New-Child $root $BaseDn 'organizationalUnit' 'OU=Servers'      @{ description = 'Member and application servers' }
$ouUsers        = New-Child $root $BaseDn 'organizationalUnit' 'OU=Users'        @{ description = 'Employee accounts' }
$ouGroups       = New-Child $root $BaseDn 'organizationalUnit' 'OU=Groups'       @{ description = 'Delegation groups' }
$null           = New-Child $ouUsers "OU=Users,$BaseDn" 'organizationalUnit' 'OU=Helpdesk'
$null           = New-Child $ouUsers "OU=Users,$BaseDn" 'organizationalUnit' 'OU=Sales'

$groupsDn = "OU=Groups,$BaseDn"
$groups = @{}
foreach ($name in 'DLG_Helpdesk_PwdReset', 'DLG_Workstation_Admins', 'DLG_Server_Operators', 'DLG_Obsolete') {
    $props = @{}
    if ($ActiveDirectory) { $props['sAMAccountName'] = $name }
    $groups[$name] = New-Child $ouGroups $groupsDn 'group' "CN=$name" $props
}

foreach ($person in 'Alice Example', 'Bob Example') {
    $props = @{}
    if ($ActiveDirectory) { $props['sAMAccountName'] = ($person -replace ' ', '.').ToLower() }
    $null = New-Child $ouGroups $groupsDn 'user' "CN=$person" $props
}

$everyone = New-Object System.Security.Principal.SecurityIdentifier('S-1-1-0')

# Workstations: protected from accidental deletion.
Add-Rule $ouWorkstations $everyone 'Delete, DeleteTree' 'Deny'
Add-Rule $ouWorkstations (Get-Sid $groups['DLG_Workstation_Admins']) 'ReadProperty, WriteProperty' 'Allow' 'Descendents'

# Servers: two risky entries on purpose.
Add-Rule $ouServers $everyone 'WriteProperty' 'Allow' 'Descendents'
Add-Rule $ouServers (Get-Sid $groups['DLG_Server_Operators']) 'GenericAll' 'Allow' 'All'

# Users: a delegation whose group is then deleted, leaving an orphaned SID behind.
Add-Rule $ouUsers (Get-Sid $groups['DLG_Obsolete']) 'ReadProperty, WriteProperty' 'Allow' 'Descendents'
Add-Rule $ouUsers (Get-Sid $groups['DLG_Helpdesk_PwdReset']) 'ReadProperty' 'Allow' 'Descendents'
$groups['DLG_Obsolete'].DeleteTree()

Write-Host 'Done.'
