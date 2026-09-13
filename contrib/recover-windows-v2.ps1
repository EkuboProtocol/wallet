# Explicit recovery of a relay-confirmed fresh setup; never recreates custody.
param([Parameter(Mandatory=$true)][string]$OwnerSid, [switch]$DiscardUnused)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
Set-StrictMode -Version Latest
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or -not [Environment]::Is64BitProcess) { throw 'Elevated 64-bit PowerShell is required.' }
if ($OwnerSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'An ordinary owner SID is required.' }
$mutex = [Threading.Mutex]::new($false, 'Global\EkuboWalletV2-Installer')
if (-not $mutex.WaitOne(0)) { throw 'Another v2 installer is running.' }
try {
    $registry = 'HKLM:\SOFTWARE\EkuboWalletV2'
    $pendingKey = Join-Path $registry ('Pending\' + $OwnerSid)
    $record = Get-ItemProperty -LiteralPath $pendingKey
    $confirmed = $record.PSObject.Properties['RelayConfirmed'] -and $record.RelayConfirmed -eq 1
    $bytes = [byte[]]$record.Profile
    if ($bytes.Length -gt 4096) { throw 'Oversized profile metadata.' }
    $metadata = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    $profile = [Guid]$metadata.profile_id
    if ($profile -eq [Guid]::Empty -or $metadata.owner_sid -ne $OwnerSid) { throw 'Fresh setup identity mismatch.' }
    $service = 'EkuboWalletV2-' + $profile.ToString('N')
    $sc = Join-Path ([Environment]::GetFolderPath('System')) 'sc.exe'
    $sid = [Security.Principal.NTAccount]::new('NT SERVICE', $service).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($sid -ne $metadata.service_sid) { throw 'Service identity changed.' }
    $activeKey = Join-Path $registry ('Owners\' + $OwnerSid)
    $storage = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EkuboWalletV2'
    $pending = Join-Path (Join-Path $storage 'Pending') $profile.ToString('N')
    $active = Join-Path (Join-Path $storage 'Owners') $profile.ToString('N')
    if ($DiscardUnused) {
        if ($confirmed -or (Test-Path -LiteralPath $activeKey) -or (Test-Path -LiteralPath $active)) { throw 'Confirmed or installed profiles can never be discarded.' }
        # Only this first-install layout can be reset. Never remove a shared root
        # containing another owner, another profile, or unknown nested storage.
        if (@(Get-ChildItem -LiteralPath (Join-Path $registry 'Pending')).Count -ne 1 -or
            @(Get-ChildItem -LiteralPath (Join-Path $storage 'Pending')).Count -ne 1 -or
            @(Get-ChildItem -LiteralPath (Join-Path $storage 'Owners')).Count -ne 0) { throw 'Unexpected shared v2 state; refusing cleanup.' }
        if (Test-Path -LiteralPath (Join-Path $registry 'Owners')) { throw 'An installed-owner collection exists; refusing cleanup.' }
        Stop-Service $service
        (Get-Service $service).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        $items = @(Get-ChildItem -LiteralPath $pending -Force)
        foreach ($item in $items) {
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                $item.Name.StartsWith('key-account-') -or $item.Name -eq 'setup-complete') { throw 'Pending profile may have active authority or unsafe objects; refusing cleanup.' }
        }
        foreach ($item in $items) { Remove-Item -LiteralPath $item.FullName -Force }
        [IO.Directory]::Delete($pending)
        [IO.Directory]::Delete((Join-Path $storage 'Pending'))
        [IO.Directory]::Delete((Join-Path $storage 'Owners'))
        [IO.Directory]::Delete($storage)
        Remove-Item -LiteralPath $pendingKey -Recurse
        Remove-Item -LiteralPath (Join-Path $registry 'Pending')
        Remove-Item -LiteralPath $registry
        & sc.exe delete $service
        if ($LASTEXITCODE -ne 0) { throw 'Unused files removed, but service registration cleanup failed.' }
        Write-Output 'Discarded only unpublished unused v2 setup. Owner credential entries were not read or deleted.'
        return
    }
    if (-not $confirmed) { throw 'Relay was not durably confirmed. Only explicit -DiscardUnused can discard this unpublished attempt.' }
    if (Test-Path -LiteralPath $activeKey) {
        $activeRecord = Get-ItemProperty -LiteralPath $activeKey
        if ($activeRecord.PSObject.Properties['Profile']) {
            $activeBytes = [byte[]]$activeRecord.Profile
            if ([Convert]::ToBase64String($activeBytes) -ne [Convert]::ToBase64String($bytes)) { throw 'Installed identity differs; refusing recovery.' }
            (Get-Item -LiteralPath $activeKey).Flush()
            & $sc sdset $service "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LCRP;;;$OwnerSid)"
            if ($LASTEXITCODE -ne 0) { throw 'Could not restore owner service query/start access.' }
            & (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2\register-windows-v2-auth.ps1') -OwnerSid $OwnerSid
            Start-Service $service
            Write-Output 'Existing installed v2 service started; unlock from the owner desktop.'
            return
        }
    }
    Stop-Service $service
    (Get-Service $service).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    if ((Test-Path -LiteralPath $pending) -and (Test-Path -LiteralPath $active)) { throw 'Conflicting profile locations; refusing recovery.' }
    $current = if (Test-Path -LiteralPath $pending) { $pending } else { $active }
    if ([IO.File]::ReadAllText((Join-Path $current 'fresh-profile-ready')) -ne $profile.ToString()) { throw 'Incomplete service-created profile.' }
    if ($current -eq $pending) { [IO.Directory]::Move($pending, $active) }
    $binary = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2\ekubo-wallet-service.exe'
    if ((Get-AuthenticodeSignature -LiteralPath $binary).Status -ne 'Valid') { throw 'Invalid signed service binary.' }
    $registration = Get-CimInstance Win32_Service -Filter "Name='$service'"
    if ($registration.StartName -ne ('NT SERVICE\' + $service)) { throw 'Unexpected authority service account.' }
    $changed = Invoke-CimMethod -InputObject $registration -MethodName Change -Arguments @{PathName=('"' + $binary + '" --owner-sid ' + $OwnerSid); StartMode='Automatic'}
    if ($changed.ReturnValue -ne 0) { throw "Service activation configuration failed: $($changed.ReturnValue)" }
    & $sc sdset $service "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LCRP;;;$OwnerSid)"
    if ($LASTEXITCODE -ne 0) { throw 'Could not restore owner service query/start access.' }
    New-Item -Path $activeKey -Force | Out-Null
    New-ItemProperty -LiteralPath $activeKey -Name Profile -PropertyType Binary -Value $bytes | Out-Null
    (Get-Item -LiteralPath $activeKey).Flush()
    & (Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2\register-windows-v2-auth.ps1') -OwnerSid $OwnerSid
    Start-Service $service
    Write-Output 'Relay-confirmed v2 profile published. Unlock from the owner desktop to finish readiness.'
} finally {
    $mutex.ReleaseMutex()
    $mutex.Dispose()
}
