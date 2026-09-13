# Fixed per-profile SYSTEM broker registration. No owner credentials are used.
param([Parameter(Mandatory=$true)][string]$OwnerSid)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if (-not [Environment]::Is64BitProcess -or $OwnerSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Invalid native authentication installation context.' }
$record = Get-ItemProperty -LiteralPath ('HKLM:\SOFTWARE\EkuboWalletV2\Owners\' + $OwnerSid)
$bytes = [byte[]]$record.Profile
if ($bytes.Length -gt 4096) { throw 'Oversized installed profile.' }
$profile = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
$id = [Guid]$profile.profile_id
if ($id -eq [Guid]::Empty -or $profile.owner_sid -ne $OwnerSid) { throw 'Installed profile identity mismatch.' }
$service = 'EkuboWalletV2-' + $id.ToString('N')
$sid = [Security.Principal.NTAccount]::new('NT SERVICE', $service).Translate([Security.Principal.SecurityIdentifier]).Value
if ($sid -ne $profile.service_sid) { throw 'Installed service SID mismatch.' }
$install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2'
$binary = Join-Path $install 'ekubo-wallet-service.exe'
foreach ($file in @($binary, (Join-Path $install 'ekubo-wallet-v2-owner-auth.exe'))) {
    if ((Get-AuthenticodeSignature -LiteralPath $file).Status -ne 'Valid') { throw "Invalid signed native authentication binary: $file" }
}
$name = $service + '-Auth'
$command = '"' + $binary + '" --authenticate-owner-sid ' + $OwnerSid
$existing = Get-CimInstance Win32_Service -Filter "Name='$name'"
if ($existing) {
    if ($existing.PathName -ne $command -or $existing.StartName -ne 'LocalSystem') { throw 'Unexpected native authentication service registration; refusing replacement.' }
} else {
    # New-Service passes BinaryPathName directly to SCM. Avoid Windows PowerShell
    # 5's legacy native-argv quote stripping around a Program Files executable.
    # Omitting Credential creates this fixed broker as LocalSystem.
    New-Service -Name $name -BinaryPathName $command -StartupType Automatic | Out-Null
}
$sc = Join-Path ([Environment]::GetFolderPath('System')) 'sc.exe'
& $sc sdset $name 'O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)'
if ($LASTEXITCODE -ne 0) { throw 'Could not protect native authentication registration.' }
& $sc privs $name 'SeTcbPrivilege/SeAssignPrimaryTokenPrivilege/SeIncreaseQuotaPrivilege/SeImpersonatePrivilege/SeChangeNotifyPrivilege'
if ($LASTEXITCODE -ne 0) { throw 'Could not scope native authentication privileges.' }
Start-Service $name
(Get-Service $name).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
