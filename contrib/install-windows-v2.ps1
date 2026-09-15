# Run from the signed v2 installation directory, in elevated 64-bit PowerShell.
# The actual owner separately runs ekubo-wallet-v2-enroll.exe --owner.
param(
    [Parameter(Mandatory=$true)][string]$OwnerSid,
    [Parameter(Mandatory=$true)][Guid]$RelayEndpoint
)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
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
foreach ($file in @($binary, $enroll, (Join-Path $install 'ekubo-wallet-v2-owner-auth.exe'))) {
    if ((Get-AuthenticodeSignature -LiteralPath $file).Status -ne 'Valid') {
        throw "The installed v2 binary must have a valid Authenticode signature: $file"
    }
}
# The nested native-auth registration below runs with process-scoped Bypass,
# never AllSigned: a real user without the publisher in TrustedPublisher
# would otherwise face the untrusted-publisher prompt a second time here,
# and "Never run" would brick enrollment. Bypass is NOT trust: the exact
# bytes are bound by Authenticode plus the approved hash captured here and
# re-validated immediately before invocation. AllSigned is never weakened
# globally and publisher trust is never installed.
$authScript = Join-Path $install 'register-windows-v2-auth.ps1'
if ((Get-AuthenticodeSignature -LiteralPath $authScript).Status -ne 'Valid') {
    throw 'The installed native authentication registration must have a valid Authenticode signature.'
}
$approvedAuthHash = (Get-FileHash -LiteralPath $authScript -Algorithm SHA256).Hash
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
    # Virtual accounts require a NULL password, not PSCredential's empty string.
    # Pass the quoted command directly to SCM, without native-argv reparsing.
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class EkuboV2VirtualService {
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr OpenSCManagerW(string machine, string database, uint access);
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    private static extern IntPtr CreateServiceW(IntPtr manager, string name, string display,
        uint access, uint type, uint start, uint error, string binary, string group,
        IntPtr tag, string dependencies, string account, string password);
    [DllImport("advapi32.dll")]
    private static extern bool CloseServiceHandle(IntPtr handle);
    public static void Create(string name, string command) {
        IntPtr manager = OpenSCManagerW(null, null, 2);
        if (manager == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            IntPtr service = CreateServiceW(manager, name, name, 4, 0x10, 3, 1,
                command, null, IntPtr.Zero, null, @"NT SERVICE\" + name, null);
            if (service == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
            CloseServiceHandle(service);
        } finally { CloseServiceHandle(manager); }
    }
}
'@
    [EkuboV2VirtualService]::Create($service, ('"' + $binary + '" --provision-owner-sid ' + $OwnerSid))
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
    # Verify the durable owner-relay confirmation before publishing: the
    # privileged enrollment entry (enroll --installer) already bound the relay
    # recipient to this exact pending profile, and publication below must only
    # follow that recorded confirmation.
    $confirmedRecord = Get-ItemProperty -LiteralPath $pendingKey
    if (-not ($confirmedRecord.PSObject.Properties['RelayConfirmed'] -and $confirmedRecord.RelayConfirmed -eq 1)) { throw 'Owner relay confirmation was not durably recorded; refusing publication.' }
    Stop-Service $service
    (Get-Service $service).WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    if ([IO.File]::ReadAllText((Join-Path $pending 'fresh-profile-ready')) -ne $profile.ToString()) { throw 'Fresh profile did not become ready.' }
    $active = Join-Path (Join-Path $storage 'Owners') $profile.ToString('N')
    [IO.Directory]::Move($pending, $active)
    $registration = Get-CimInstance Win32_Service -Filter "Name='$service'"
    $changed = Invoke-CimMethod -InputObject $registration -MethodName Change -Arguments @{PathName=('"' + $binary + '" --owner-sid ' + $OwnerSid); StartMode='Automatic'}
    if ($changed.ReturnValue -ne 0) { throw "Service activation configuration failed ($($changed.ReturnValue)); profile retained." }
    $sc = Join-Path ([Environment]::GetFolderPath('System')) 'sc.exe'
    & $sc sdset $service "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;LCRP;;;$OwnerSid)"
    if ($LASTEXITCODE -ne 0) { throw 'Could not grant the owner service query/start access.' }
    $activeKey = Join-Path $registry ('Owners\' + $OwnerSid)
    New-Item -Path $activeKey -Force | Out-Null
    New-ItemProperty -LiteralPath $activeKey -Name Profile -PropertyType Binary -Value $bytes | Out-Null
    (Get-Item -LiteralPath $activeKey).Flush()
    if ((Get-AuthenticodeSignature -LiteralPath $authScript).Status -ne 'Valid') { throw 'Native authentication registration signature changed; refusing invocation.' }
    if ((Get-FileHash -LiteralPath $authScript -Algorithm SHA256).Hash -cne $approvedAuthHash) { throw 'Native authentication registration changed after approval; refusing invocation.' }
    # Process-scoped Bypass: the fixed bootstrap above already verified both
    # Authenticode and the exact bytes. -NonInteractive fails closed on any
    # unexpected prompt instead of hanging.
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $authScript -OwnerSid $OwnerSid
    if ($LASTEXITCODE -ne 0) { throw 'Native authentication registration failed; profile retained.' }
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
