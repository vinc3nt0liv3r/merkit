<#
.SYNOPSIS
    Creates a throw-away AD LDS (Active Directory Lightweight Directory Services) instance for testing Merkit.

.DESCRIPTION
    AD LDS speaks the same LDAP protocol and uses the same security descriptors as Active Directory, but it
    installs without a reboot, so it works on a GitHub-hosted runner. It is NOT a full domain: there is no
    Kerberos domain, no computers, and no domain SIDs from a real forest. Use it to test the directory layer and
    the permission editing. Use tools/lab/New-LabForest.ps1 on a virtual machine for a real AD DS forest.

    The instance listens on localhost only by default and gives BUILTIN\Administrators full control.
    Nothing here is suitable for production.
#>
[CmdletBinding()]
param(
    [string]$InstanceName = 'MerkitTest',
    [int]$LdapPort = 50389,
    [int]$SslPort = 50636,
    [string]$PartitionDn = 'CN=MerkitTest,DC=local',
    [string]$Root = 'C:\MerkitLds'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$principal = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Run this script from an elevated (Administrator) session.'
}

$serviceName = "ADAM_$InstanceName"
if (Get-Service -Name $serviceName -ErrorAction SilentlyContinue) {
    Write-Host "AD LDS instance '$InstanceName' already exists."
}
else {
    $installer = Join-Path $env:windir 'ADAM\adaminstall.exe'
    if (-not (Test-Path $installer)) {
        Write-Host 'Installing the AD LDS role...'
        if (Get-Command Install-WindowsFeature -ErrorAction SilentlyContinue) {
            $result = Install-WindowsFeature -Name ADLDS
            if (-not $result.Success) { throw 'The AD LDS role could not be installed.' }
        }
        else {
            Enable-WindowsOptionalFeature -Online -FeatureName DirectoryServices-ADAM -All -NoRestart | Out-Null
        }
    }
    if (-not (Test-Path $installer)) { throw "adaminstall.exe was not found at $installer after installing the role." }

    $data = Join-Path $Root 'data'
    $logs = Join-Path $Root 'logs'
    New-Item -ItemType Directory -Force -Path $data, $logs | Out-Null

    $answerFile = Join-Path $Root 'answer.txt'
    @"
[ADAMInstall]
InstallType=Unique
InstanceName=$InstanceName
LocalLDAPPortToListenOn=$LdapPort
LocalSSLPortToListenOn=$SslPort
NewApplicationPartitionToCreate=$PartitionDn
DataFilesPath=$data
LogFilesPath=$logs
Administrators=BUILTIN\Administrators
ImportLDIFFiles="MS-InetOrgPerson.LDF" "MS-User.LDF" "MS-UserProxy.LDF"
SourceUserName=
SourcePassword=
SourceServer=
SourceDomain=
"@ | Set-Content -Path $answerFile -Encoding ASCII

    Write-Host "Creating AD LDS instance '$InstanceName' (LDAP $LdapPort, partition $PartitionDn)..."
    $process = Start-Process -FilePath $installer -ArgumentList "/answer:`"$answerFile`"" -Wait -PassThru -NoNewWindow
    if ($process.ExitCode -ne 0) {
        $log = Join-Path $env:windir 'Debug\adamsetup.log'
        if (Test-Path $log) { Get-Content $log -Tail 40 | ForEach-Object { Write-Host $_ } }
        throw "adaminstall.exe failed with exit code $($process.ExitCode)."
    }
}

$service = Get-Service -Name $serviceName
if ($service.Status -ne 'Running') { Start-Service -Name $serviceName }

$deadline = (Get-Date).AddSeconds(60)
while ($true) {
    try {
        $client = New-Object Net.Sockets.TcpClient
        $client.Connect('localhost', $LdapPort)
        $client.Close()
        break
    }
    catch {
        if ((Get-Date) -gt $deadline) { throw "The directory did not start listening on port $LdapPort." }
        Start-Sleep -Seconds 2
    }
}

Write-Host "AD LDS is ready on localhost:$LdapPort, partition $PartitionDn"
