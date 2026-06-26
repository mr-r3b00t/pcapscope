<#
  lab_capture.ps1 - elevated capture of authentication traffic to a lab DC.

  Uses the built-in Windows pktmon to capture FULL packets (--pkt-size 0)
  filtered to the DC, generates SMB authentications (NTLM via IP, Kerberos via
  name), converts the .etl to .pcapng, then leaves the file for pcapscope.

  The password is passed as a parameter (never written to this file). Progress
  is logged to lab_capture.log WITHOUT the password.
#>
param(
  [string]$Dc       = "192.168.119.136",
  [string]$Fqdn     = "demodc1.lab.local",
  [string]$Netbios  = "DEMODC1",
  [string]$Domain   = "LAB",
  [string]$Realm    = "lab.local",
  [string]$User     = "administrator",
  [string]$Password,
  [string]$OutDir   = "C:\Users\user\Desktop\pcap_analysis"
)

# Prompt securely (masked) if no password was supplied on the command line,
# so the credential never lands in shell history.
if (-not $Password) {
  $sec = Read-Host "Password for $Domain\$User" -AsSecureString
  $Password = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
                [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec))
}

$ErrorActionPreference = "Continue"
$etl  = Join-Path $OutDir "lab_capture.etl"
$pcap = Join-Path $OutDir "lab_capture.pcapng"
$log  = Join-Path $OutDir "lab_capture.log"

function Log($m){ $line = "{0}  {1}" -f (Get-Date -Format "HH:mm:ss"), $m; Add-Content -Path $log -Value $line; Write-Host $line }
Set-Content -Path $log -Value "=== pktmon lab capture ==="

$admin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
Log "elevated: $admin   target DC: $Dc ($Fqdn / $Netbios, domain $Domain)"
if (-not $admin) { Log "ERROR: must run elevated (Administrator)"; exit 1 }

# clean any prior session / filters
& pktmon stop 2>$null | Out-Null
Remove-Item $etl, $pcap -ErrorAction SilentlyContinue
& pktmon filter remove 2>$null | Out-Null
(& pktmon filter add LabDC -i $Dc 2>&1) | ForEach-Object { Log "filter: $_" }

Log "starting capture (full packet size)..."
(& pktmon start --capture --pkt-size 0 --file-name $etl 2>&1) | ForEach-Object { Log "start: $_" }
Start-Sleep -Seconds 1

$nrptAdded = $false
try {
  # The local resolver doesn't know the lab domain - scope *.$Realm to the DC's
  # DNS so the client can resolve the DC FQDN and the _kerberos SRV records
  # (required for Kerberos). Reversible; removed in finally.
  Log "adding NRPT rule: *.$Realm -> $Dc (so lab DNS goes to the DC)"
  try {
    Add-DnsClientNrptRule -Namespace ".$Realm" -NameServers $Dc -ErrorAction Stop
    $nrptAdded = $true
  } catch { Log "  NRPT add failed (Kerberos may fall back to NTLM): $($_.Exception.Message)" }
  (& ipconfig /flushdns 2>&1) | Out-Null
  (& klist purge 2>&1) | Out-Null

  Log "--- auth #1: SMB to \\$Dc\IPC$ as $Domain\$User  (by IP -> expect NTLM) ---"
  (& net use "\\$Dc\IPC$" /user:"$Domain\$User" $Password 2>&1) | ForEach-Object { Log "  net: $_" }
  (& net use "\\$Dc\IPC$" /delete /y 2>&1) | Out-Null

  $upn = "$User@$Realm"
  Log "--- auth #2: SMB to \\$Fqdn\SYSVOL as $upn  (by FQDN -> expect Kerberos) ---"
  (& net use "\\$Fqdn\SYSVOL" /user:$upn $Password 2>&1) | ForEach-Object { Log "  net: $_" }
  (& net use "\\$Fqdn\SYSVOL" /delete /y 2>&1) | Out-Null

  Add-Type -AssemblyName System.DirectoryServices.Protocols
  $upn = "$User@$Realm"

  # BAD: cleartext LDAP simple bind on 389 - the password is sent in the clear,
  # so pcapscope's LDAP analyzer recovers it even if the DC rejects the bind.
  Log "--- auth #3 (BAD): LDAP simple bind on ${Fqdn}:389 (cleartext, demonstrates exposure) ---"
  try {
    $li3 = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Fqdn, 389)
    $c3 = New-Object System.DirectoryServices.Protocols.LdapConnection($li3)
    $c3.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
    $c3.SessionOptions.ProtocolVersion = 3
    $c3.Timeout = [TimeSpan]::FromSeconds(10)
    $c3.Bind((New-Object System.Net.NetworkCredential($upn, $Password)))
    Log "  LDAP 389 simple bind: success (password traversed the wire in CLEARTEXT)"
    $c3.Dispose()
  } catch { Log "  LDAP 389 simple bind rejected: $($_.Exception.Message) - but the cleartext password was already sent" }

  # GOOD: the same simple bind over LDAPS:636 - protected by TLS, so only the
  # TLS handshake + server certificate are visible, never the password.
  Log "--- auth #4 (GOOD): LDAPS simple bind on ${Fqdn}:636 (TLS-protected, demonstrates assurance) ---"
  try {
    $li4 = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($Fqdn, 636)
    $c4 = New-Object System.DirectoryServices.Protocols.LdapConnection($li4)
    $c4.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
    $c4.SessionOptions.ProtocolVersion = 3
    $c4.SessionOptions.SecureSocketLayer = $true
    $c4.SessionOptions.VerifyServerCertificate = { param($a, $b) $true }   # lab: accept any cert
    $c4.Timeout = [TimeSpan]::FromSeconds(10)
    $c4.Bind((New-Object System.Net.NetworkCredential($upn, $Password)))
    Log "  LDAPS 636 simple bind: success (password protected by TLS)"
    $c4.Dispose()
  } catch { Log "  LDAPS 636 simple bind: $($_.Exception.Message)" }

  Log "--- Kerberos ticket cache after auth ---"
  (& klist 2>&1) | ForEach-Object { Log "  klist: $_" }
}
finally {
  if ($nrptAdded) {
    Log "removing NRPT rule"
    Get-DnsClientNrptRule | Where-Object { $_.Namespace -eq ".$Realm" -and $_.NameServers -contains $Dc } |
      Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue
    (& ipconfig /flushdns 2>&1) | Out-Null
  }
  Start-Sleep -Seconds 1
  Log "stopping capture..."
  (& pktmon stop 2>&1) | ForEach-Object { Log "stop: $_" }
}

Log "converting .etl -> .pcapng ..."
(& pktmon etl2pcap $etl --out $pcap 2>&1) | ForEach-Object { Log "conv: $_" }

if (Test-Path $pcap) {
  Log ("OK  pcapng = {0}  ({1} bytes)" -f $pcap, (Get-Item $pcap).Length)
} else {
  Log "ERROR: conversion produced no pcapng (see messages above)"
}
Log "=== done ==="
