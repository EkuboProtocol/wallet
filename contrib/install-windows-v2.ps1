# Run from the signed v2 installation directory, in elevated 64-bit PowerShell.
# The actual owner separately runs ekubo-wallet-v2-enroll.exe --owner.
param(
    [Parameter(Mandatory=$true)][string]$OwnerSid,
    [Parameter(Mandatory=$true)][Guid]$RelayEndpoint
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or -not [Environment]::Is64BitProcess) {
    throw 'Run the signed installer in elevated 64-bit PowerShell.'
}
if ($OwnerSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$' -or $RelayEndpoint -eq [Guid]::Empty) {
    throw 'An explicit ordinary owner SID and live relay endpoint are required.'
}
$install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2'
$binary = Join-Path $install 'ekubo-wallet-service.exe'
$enroll = Join-Path $install 'ekubo-wallet-v2-enroll.exe'
foreach ($file in @($binary, $enroll)) {
    if ((Get-AuthenticodeSignature -LiteralPath $file).Status -ne 'Valid') {
        throw "The installed v2 binary must have a valid Authenticode signature: $file"
    }
}
$registry = 'HKLM:\SOFTWARE\EkuboWalletV2'
$storage = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EkuboWalletV2'
# v2's first release installs one profile per machine. Existing machine roots
# are deliberately not repaired or overwritten by fresh enrollment.
if ((Test-Path -LiteralPath $registry) -or (Test-Path -LiteralPath $storage)) {
    throw 'Existing v2 setup retained. Fresh enrollment cannot reset or repair installed custody.'
}
$mutex = [Threading.Mutex]::new($false, 'Global\EkuboWalletV2-Installer')
if (-not $mutex.WaitOne(0)) { throw 'Another v2 installer is running.' }
try {
    if ((Test-Path -LiteralPath $registry) -or (Test-Path -LiteralPath $storage)) { throw 'Concurrent v2 setup detected.' }
    $profile = [Guid]::NewGuid()
    $service = 'EkuboWalletV2-' + $profile.ToString('N')
    & sc.exe create $service binPath= ('"' + $binary + '" --provision-owner-sid ' + $OwnerSid) start= demand obj= ('NT SERVICE\' + $service)
    if ($LASTEXITCODE -ne 0) { throw 'Could not create the protected service.' }
    $sid = [Security.Principal.NTAccount]::new('NT SERVICE', $service).Translate([Security.Principal.SecurityIdentifier]).Value
    $machineAcl = [Security.AccessControl.DirectorySecurity]::new()
    $machineAcl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BU)(A;OICI;FRFX;;;$sid)")
    foreach ($path in @($storage, (Join-Path $storage 'Pending'), (Join-Path $storage 'Owners'))) {
        New-Item -ItemType Directory -Path $path | Out-Null
        Set-Acl -LiteralPath $path -AclObject $machineAcl
    }
    $pending = Join-Path (Join-Path $storage 'Pending') $profile.ToString('N')
    New-Item -ItemType Directory -Path $pending | Out-Null
    $privateAcl = [Security.AccessControl.DirectorySecurity]::new()
    $privateAcl.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;$sid)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
    Set-Acl -LiteralPath $pending -AclObject $privateAcl
    New-Item -ItemType File -Path (Join-Path $pending 'service.lock') | Out-Null
    & icacls.exe $pending /setowner ('*' + $sid) /T /Q
    if ($LASTEXITCODE -ne 0) { throw 'Could not assign private storage ownership.' }
    New-Item -Path $registry | Out-Null
    $registryAcl = [Security.AccessControl.RegistrySecurity]::new()
    $registryAcl.SetSecurityDescriptorSddlForm("O:BAD:P(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KR;;;BU)(A;CI;KR;;;$sid)")
    Set-Acl -LiteralPath $registry -AclObject $registryAcl
    $pendingKey = Join-Path $registry ('Pending\' + $OwnerSid)
    New-Item -Path $pendingKey -Force | Out-Null
    $metadata = @{owner_sid=$OwnerSid; service_sid=$sid; profile_id=$profile.ToString()} | ConvertTo-Json -Compress
    $bytes = [Text.Encoding]::UTF8.GetBytes($metadata)
    New-ItemProperty -LiteralPath $pendingKey -Name Profile -PropertyType Binary -Value $bytes | Out-Null
    (Get-Item -LiteralPath $pendingKey).Flush()
    Start-Service -Name $service
    (Get-Service $service).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    & $enroll --installer $OwnerSid $RelayEndpoint.ToString()
    if ($LASTEXITCODE -ne 0) { throw 'Enrollment or authenticated owner relay failed; pending setup retained.' }
    New-ItemProperty -LiteralPath $pendingKey -Name RelayConfirmed -PropertyType DWord -Value 1 | Out-Null
    (Get-Item -LiteralPath $pendingKey).Flush()
    Stop-Service $service
    (Get-Service $service).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    if ([IO.File]::ReadAllText((Join-Path $pending 'fresh-profile-ready')) -ne $profile.ToString()) { throw 'Fresh profile did not become ready.' }
    $active = Join-Path (Join-Path $storage 'Owners') $profile.ToString('N')
    [IO.Directory]::Move($pending, $active)
    & sc.exe config $service binPath= ('"' + $binary + '" --owner-sid ' + $OwnerSid) start= auto
    if ($LASTEXITCODE -ne 0) { throw 'Service activation configuration failed; profile retained.' }
    $activeKey = Join-Path $registry ('Owners\' + $OwnerSid)
    New-Item -Path $activeKey -Force | Out-Null
    New-ItemProperty -LiteralPath $activeKey -Name Profile -PropertyType Binary -Value $bytes | Out-Null
    (Get-Item -LiteralPath $activeKey).Flush()
    Start-Service $service
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    while (-not (Test-Path -LiteralPath (Join-Path $active 'setup-complete'))) {
        if ([DateTime]::UtcNow -gt $deadline) { throw 'Installed profile retained; owner unlock/readiness is still pending.' }
        Start-Sleep -Seconds 1
    }
    if ([IO.File]::ReadAllText((Join-Path $active 'setup-complete')) -ne $profile.ToString()) { throw 'Service completion profile mismatch.' }
    Write-Output 'Fresh protected v2 enrollment complete.'
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
