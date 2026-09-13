# Disposable hosted VM only. This creates fixture CA trust, a standard owner and
# actual installed service state. It never requests Hello or signs a release.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($PSVersionTable.PSVersion.Major -lt 7) { throw 'Invoke acceptance with pwsh (PowerShell 7).' }
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Installed acceptance requires a disposable GitHub-hosted Windows VM.'
}
$administrator = [Security.Principal.WindowsIdentity]::GetCurrent()
if (-not [Environment]::Is64BitProcess -or -not ([Security.Principal.WindowsPrincipal]::new($administrator)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'Acceptance coordinator must be a 64-bit administrator.'
}
if ($administrator.User.Value -notmatch '^S-1-5-21-') { throw 'CreateProcessWithLogonW requires the hosted administrator logon, not SYSTEM.' }
$install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2'
$storage = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EkuboWalletV2'
$registry = 'HKLM:\SOFTWARE\EkuboWalletV2'
$powershell = Join-Path $env:WINDIR 'System32/WindowsPowerShell/v1.0/powershell.exe'
function Assert-Clean {
    foreach ($path in @($install, $storage)) {
        if (Get-ChildItem -LiteralPath (Split-Path $path) -Force | Where-Object Name -EQ (Split-Path $path -Leaf)) { throw "Existing v2 path: $path" }
    }
    if (Test-Path -LiteralPath $registry) { throw 'Existing v2 registry.' }
    if (@([ServiceProcess.ServiceController]::GetServices() | Where-Object Name -Like 'EkuboWalletV2-*').Count) { throw 'Existing v2 services.' }
    if (@(Get-LocalUser | Where-Object Name -Like 'ewv2ci_*').Count) { throw 'Existing acceptance owner account.' }
    if (@(Get-CimInstance Win32_UserProfile | Where-Object { (Split-Path $_.LocalPath -Leaf) -like 'ewv2ci_*' -or (Split-Path $_.LocalPath -Leaf) -like 'EkuboWalletV2-*' }).Count) { throw 'Existing acceptance/virtual service profile.' }
    if (Get-Process -Name 'ekubo-wallet-v2-owner-auth' -ErrorAction SilentlyContinue) { throw 'Existing collector process.' }
}
Assert-Clean

function Build-Artifacts([string[]]$arguments) {
    $lines = & cargo @arguments --message-format=json
    if ($LASTEXITCODE -ne 0) { throw 'Focused acceptance build failed.' }
    $artifacts = @($lines | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object reason -EQ 'compiler-artifact')
    if (@($artifacts | Where-Object { $_.features -contains 'test-hooks' }).Count) { throw 'Acceptance resolved test-hooks; refusing installation.' }
    return $artifacts
}
# Ordering matters: examples can enable dev dependencies. The last build selects
# only production bins and explicitly verifies its resolved feature artifacts.
$fixtureArtifacts = Build-Artifacts @('build', '--locked', '-p', 'ekubo-wallet-client', '--example', 'windows-installed-owner')
$productionArtifacts = Build-Artifacts @('build', '--locked', '--no-default-features', '-p', 'ekubo-wallet-service', '-p', 'ekubo-wallet-windows-owner-auth', '--bins')
function Executable($artifacts, $name) {
    $selected = @($artifacts | Where-Object { $_.target.name -eq $name -and $_.executable })
    if ($selected.Count -ne 1) { throw "Ambiguous compiled executable: $name" }
    return $selected[0].executable
}
Assert-Clean

# CreateProcessWithLogonW(LOGON_WITH_PROFILE, environment=NULL) creates the real
# user's environment/profile instead of inheriting the administrator's paths.
# The password travels only from SecureString to a zeroed native buffer, never
# through argv, files, environment variables, transcripts, or GitHub outputs.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
public sealed class WalletAcceptanceLogon : IDisposable {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
        public int cb; public string reserved, desktop, title;
        public int x,y,xs,ys,xc,yc,fill,flags; public short show,cb2;
        public IntPtr reserved2,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct Info { public IntPtr process,thread; public uint pid,tid; }
    [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern bool CreateProcessWithLogonW(string user,string domain,IntPtr password,uint logon,string app,StringBuilder cmd,uint flags,IntPtr environment,string cwd,ref Startup startup,out Info info);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint ms);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr handle,out uint code);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr handle,uint code);
    [DllImport("wtsapi32.dll", EntryPoint="WTSQuerySessionInformationW", SetLastError=true)]
    static extern bool SessionInfo(IntPtr server,uint session,int kind,out IntPtr buffer,out uint size);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr buffer);
    static string SessionText(uint session,int kind) {
        IntPtr buffer; uint size;
        if(!SessionInfo(IntPtr.Zero,session,kind,out buffer,out size)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try { return Marshal.PtrToStringUni(buffer); } finally { WTSFreeMemory(buffer); }
    }
    public static string SessionAccount(uint session) { return SessionText(session,7)+"\\"+SessionText(session,5); }
    IntPtr handle; public uint Id { get; private set; }
    public static WalletAcceptanceLogon Start(string user,SecureString password,string exe,string arguments,string cwd) {
        IntPtr secret=Marshal.SecureStringToGlobalAllocUnicode(password);
        try {
            var startup=new Startup(); startup.cb=Marshal.SizeOf(typeof(Startup)); Info info;
            if(!CreateProcessWithLogonW(user,".",secret,1,exe,new StringBuilder("\""+exe+"\" "+arguments),0x08000000,IntPtr.Zero,cwd,ref startup,out info)) throw new Win32Exception(Marshal.GetLastWin32Error());
            CloseHandle(info.thread); return new WalletAcceptanceLogon {handle=info.process,Id=info.pid};
        } finally { Marshal.ZeroFreeGlobalAllocUnicode(secret); }
    }
    public bool Wait(uint milliseconds) { return WaitForSingleObject(handle,milliseconds)==0; }
    public uint ExitCode { get { uint code; if(!GetExitCodeProcess(handle,out code)) throw new Win32Exception(); return code; } }
    public void Dispose() { if(handle!=IntPtr.Zero) { if(!Wait(0)) { TerminateProcess(handle,1); Wait(10000); } CloseHandle(handle); handle=IntPtr.Zero; } }
}
'@

function Set-DirectoryAcl($path, $ownerSid, $rights) {
    $acl = [Security.AccessControl.DirectorySecurity]::new()
    $acl.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;$rights;;;$ownerSid)")
    Set-Acl -LiteralPath $path -AclObject $acl
}
function Publish($directory, $name, $value) {
    $temporary = Join-Path $directory "$name.pending"
    $value | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $temporary -Encoding utf8
    Move-Item -LiteralPath $temporary -Destination (Join-Path $directory $name)
}
function Await-Report($directory, $name, $process, $seconds = 90) {
    $deadline = [DateTime]::UtcNow.AddSeconds($seconds)
    while (-not (Test-Path -LiteralPath (Join-Path $directory $name))) {
        if (Test-Path -LiteralPath (Join-Path $directory 'failure.json')) { throw (Get-Content (Join-Path $directory 'failure.json') -Raw) }
        if ($process.Wait(0)) { throw "Owner fixture exited early: $($process.ExitCode)" }
        if ([DateTime]::UtcNow -gt $deadline) { throw "Timed out waiting for $name" }
        Start-Sleep -Milliseconds 100
    }
    return Get-Content -LiteralPath (Join-Path $directory $name) -Raw | ConvertFrom-Json
}
function Invoke-SetupScript($path, [string[]]$arguments) {
    & $powershell -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File $path @arguments
    if ($LASTEXITCODE -ne 0) { throw "Signed setup script failed: $path" }
}
function Wait-ServiceState($name, $state) {
    $controller = Get-Service $name
    try { $controller.WaitForStatus($state, [TimeSpan]::FromSeconds(30)) } finally { $controller.Dispose() }
}
function Restart-FixtureService($name) {
    Stop-Service -Name $name -NoWait
    Wait-ServiceState $name ([ServiceProcess.ServiceControllerStatus]::Stopped)
    Start-Service -Name $name
    Wait-ServiceState $name ([ServiceProcess.ServiceControllerStatus]::Running)
}
function Remove-FixtureProfile($sid) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'"
        if (-not $profile -or -not $profile.Loaded) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($profile) { $profile | Remove-CimInstance }
}

$nonce = [Guid]::NewGuid().ToString('N')
$username = 'ewv2ci_' + $nonce.Substring(0,8)
$work = Join-Path $env:RUNNER_TEMP "installed-acceptance-$nonce"
New-Item -ItemType Directory -Path $work | Out-Null
$password = [Security.SecureString]::new()
foreach ($character in 'Aa1!'.ToCharArray()) { $password.AppendChar($character) }
$random = [Security.Cryptography.RandomNumberGenerator]::GetBytes(32)
foreach ($byte in $random) { $password.AppendChar([char](33 + ($byte % 94))) }
[Array]::Clear($random, 0, $random.Length)
$password.MakeReadOnly()
$ownerSid = $null; $certificate = $null; $installer = $null; $worker = $null; $trace = $null
$createdInstall = $false; $startedInstall = $false
try {
    $account = New-LocalUser -Name $username -Password $password -AccountNeverExpires -Description 'Disposable Ekubo installed acceptance owner'
    $ownerSid = $account.SID.Value
    if (-not @(Get-LocalGroupMember -SID 'S-1-5-32-545' | Where-Object { $_.SID.Value -eq $ownerSid }).Count) {
        Add-LocalGroupMember -SID 'S-1-5-32-545' -Member $username
    }
    if ($ownerSid -eq $administrator.User.Value) { throw 'Owner and installer identities coincide.' }
    if (@(Get-LocalGroupMember -SID 'S-1-5-32-544' | Where-Object { $_.SID.Value -eq $ownerSid }).Count) { throw 'Owner is an administrator.' }
    $installerSession = (Get-Process -Id $PID).SessionId
    if ($installerSession -ne 0) {
        $interactive = [Security.Principal.NTAccount]::new([WalletAcceptanceLogon]::SessionAccount($installerSession)).Translate([Security.Principal.SecurityIdentifier]).Value
        if ($interactive -ne $administrator.User.Value -or $interactive -eq $ownerSid) { throw 'Cannot prove the interactive session belongs to the different installer administrator.' }
    }
    Set-DirectoryAcl $work $ownerSid 'FRFX'
    $fixture = Join-Path $work 'windows-installed-owner.exe'
    Copy-Item -LiteralPath (Executable $fixtureArtifacts 'windows-installed-owner') -Destination $fixture
    $certificate = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=Disposable wallet acceptance $nonce" -CertStoreLocation Cert:\LocalMachine\My -KeyExportPolicy NonExportable -NotAfter (Get-Date).AddDays(1)
    $public = Join-Path $work 'fixture-public.cer'
    Export-Certificate -Cert $certificate -FilePath $public | Out-Null
    Import-Certificate -FilePath $public -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $public -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
    $staging = Join-Path $work 'payload'
    New-Item -ItemType Directory $staging | Out-Null
    foreach ($name in @('ekubo-wallet-service', 'ekubo-wallet-v2-enroll', 'ekubo-wallet-v2-owner-auth')) {
        Copy-Item -LiteralPath (Executable $productionArtifacts $name) -Destination (Join-Path $staging "$name.exe")
    }
    foreach ($name in @('install-windows-v2.ps1', 'recover-windows-v2.ps1', 'register-windows-v2-auth.ps1', 'package-windows-v2.ps1')) {
        Copy-Item -LiteralPath (Join-Path $PSScriptRoot $name) -Destination $staging
    }
    foreach ($file in Get-ChildItem -LiteralPath $staging -File) {
        $signed = Set-AuthenticodeSignature -LiteralPath $file.FullName -Certificate $certificate -HashAlgorithm SHA256
        if ($signed.Status -ne 'Valid') { throw "Fixture Authenticode signing failed: $($file.Name): $($signed.Status)" }
    }
    # Exactly the existing package code-directory hooks; no path substitution.
    $createdInstall = $true
    Invoke-SetupScript (Join-Path $staging 'package-windows-v2.ps1') @('-Mode', 'Before')
    Copy-Item -Path "$staging/*" -Destination $install
    Invoke-SetupScript (Join-Path $install 'package-windows-v2.ps1') @('-Mode', 'After')
    $baseline = $null
    foreach ($phase in @('enroll', 'reconnect')) {
        $exchange = Join-Path $work $phase
        New-Item -ItemType Directory $exchange | Out-Null
        Set-DirectoryAcl $exchange $ownerSid '0x1301bf'
        $worker = [WalletAcceptanceLogon]::Start($username, $password, $fixture, "$phase `"$exchange`" $ownerSid", $work)
        $identity = Await-Report $exchange 'identity.json' $worker 30
        $nativeProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$ownerSid'"
        if ($identity.owner_sid -ne $ownerSid -or $nativeProfile.LocalPath -ne $identity.profile -or $identity.session -ne $installerSession) { throw 'Owner token/profile/session mapping is not the fixture logon.' }
        Publish $exchange 'begin.json' @{}
        if ($phase -eq 'enroll') {
            $relay = Await-Report $exchange 'relay.json' $worker
            if ($relay.owner_sid -ne $ownerSid -or $relay.owner_sid -eq $administrator.User.Value) { throw 'Relay is not owned by the standard fixture user.' }
            $stdout = Join-Path $work 'installer.stdout.log'; $stderr = Join-Path $work 'installer.stderr.log'
            $startedInstall = $true
            $installer = Start-Process -FilePath $powershell -ArgumentList @('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'AllSigned', '-File', "`"$install/install-windows-v2.ps1`"", '-OwnerSid', $ownerSid, '-RelayEndpoint', $relay.endpoint) -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
            if (-not $installer.WaitForExit(120000)) { throw 'Production enrollment exceeded 120 seconds.' }
            Get-Content $stdout, $stderr | Write-Output
            if ($installer.ExitCode -ne 0) { throw "Production enrollment failed: $($installer.ExitCode)" }
        }
        $ready = Await-Report $exchange 'ready.json' $worker
        $nativeProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$ownerSid'"
        if ($nativeProfile.LocalPath -ne $ready.profile) { throw 'Owner environment did not load its real Windows profile.' }
        if ($ready.session -ne $installerSession) { throw 'Fixture did not use the installer session with a distinct owner logon.' }
        if ($phase -eq 'enroll') { $baseline = $ready } else {
            if ($ready.logon -eq $baseline.logon -or $ready.profile_id -ne $baseline.profile_id -or $ready.service_sid -ne $baseline.service_sid -or ($ready.account | ConvertTo-Json -Compress) -ne ($baseline.account | ConvertTo-Json -Compress)) { throw 'New logon/restart did not retain the exact service and account identities.' }
        }
        if ($ready.owner_sid -ne $ownerSid -or $ready.service_sid -eq $ownerSid) { throw 'Published service/owner identity is not isolated.' }
        $service = Get-CimInstance Win32_Service -Filter "Name='$($ready.service_name)'"
        $broker = Get-CimInstance Win32_Service -Filter "Name='$($ready.service_name)-Auth'"
        if ($service.State -ne 'Running' -or $service.StartName -ne "NT SERVICE\$($ready.service_name)" -or $broker.State -ne 'Running' -or $broker.StartName -ne 'LocalSystem') { throw 'Installed SCM identities/readiness are wrong.' }
        $active = Join-Path $storage ('Owners/' + ([Guid]$ready.profile_id).ToString('N'))
        if ([IO.File]::ReadAllText((Join-Path $active 'setup-complete')) -ne $ready.profile_id) { throw 'Published profile is not durably ready.' }
        $raw = @('wallet.db', 'wrapping.key', 'key-database', ('key-account-' + $ready.account.instance_id)) | ForEach-Object { Join-Path $active $_ }
        foreach ($file in $raw) { if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing actual protected file: $file" } }
        $trace = "wallet-collector-$nonce-$phase"
        if ($installerSession -ne 0) {
            $interactive = [Security.Principal.NTAccount]::new([WalletAcceptanceLogon]::SessionAccount($installerSession)).Translate([Security.Principal.SecurityIdentifier]).Value
            if ($interactive -ne $administrator.User.Value) { throw 'Interactive session changed before the negative authorization check.' }
        }
        Register-CimIndicationEvent -Query "SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName='ekubo-wallet-v2-owner-auth.exe'" -SourceIdentifier $trace | Out-Null
        Publish $exchange 'checks.json' @{raw_paths=$raw}
        $checked = Await-Report $exchange 'checked.json' $worker 30
        Start-Sleep -Seconds 1
        if (@(Get-Event -SourceIdentifier $trace -ErrorAction SilentlyContinue).Count) { throw 'A collector was launched for the mismatched owner logon; possible prompt.' }
        Unregister-Event -SourceIdentifier $trace; $trace = $null
        if ($checked.raw_files_denied -ne 4 -or -not $checked.legal_unchanged -or -not $checked.legacy_unchanged -or -not $checked.auth_denied) { throw 'Incomplete boundary assertions.' }
        Publish $exchange 'finish.json' @{}
        if (-not $worker.Wait(15000) -or $worker.ExitCode -ne 0) { throw 'Owner did not close its real client/relay cleanly.' }
        $worker.Dispose(); $worker = $null
        if ($phase -eq 'enroll') {
            Restart-FixtureService ($ready.service_name + '-Auth')
            Restart-FixtureService $ready.service_name
            $restarted = Get-CimInstance Win32_Service -Filter "Name='$($ready.service_name)'"
            if ($restarted.ProcessId -eq $service.ProcessId) { throw 'Authority process did not restart.' }
        }
        Write-Output "$phase PASS: real owner logon, protected authority/account, raw file access denied, native authorization rejected without a collector, 1.x sentinel unchanged."
    }
} finally {
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        if ($worker) { $worker.Dispose() }
        if ($installer -and -not $installer.HasExited) { $installer.Kill($true); $null = $installer.WaitForExit(10000) }
    } catch { $cleanupErrors.Add($_.Exception.Message) }
    if ($trace) { Unregister-Event -SourceIdentifier $trace -ErrorAction SilentlyContinue; Remove-Event -SourceIdentifier $trace -ErrorAction SilentlyContinue }
    try {
        if ($startedInstall) {
            $services = @(Get-CimInstance Win32_Service | Where-Object Name -Like 'EkuboWalletV2-*')
            foreach ($service in $services) {
                if ($service.Name -notmatch '^EkuboWalletV2-[0-9a-f]{32}(-Auth)?$' -or -not $service.PathName.Contains($ownerSid) -or -not $service.PathName.Contains($install)) { throw 'Refusing to remove a service not bound to this fixture owner/install.' }
            }
            if (-not $services.Count -and ((Test-Path $registry) -or (Test-Path $storage))) { throw 'No fixture service provenance for protected root cleanup.' }
            foreach ($collection in @('Owners', 'Pending')) {
                $key = Join-Path $registry $collection
                if (Test-Path $key) {
                    if (@(Get-ChildItem -LiteralPath $key | Where-Object PSChildName -NE $ownerSid).Count) { throw 'Refusing to remove another owner profile.' }
                }
            }
            foreach ($service in $services) {
                Stop-Service $service.Name -NoWait
                Wait-ServiceState $service.Name ([ServiceProcess.ServiceControllerStatus]::Stopped)
            }
            foreach ($service in $services) {
                if ($service.StartName -like 'NT SERVICE\*') {
                    $virtualSid = [Security.Principal.NTAccount]::new($service.StartName).Translate([Security.Principal.SecurityIdentifier]).Value
                    if ($virtualSid -notlike 'S-1-5-80-*') { throw 'Unexpected fixture virtual account SID.' }
                    Remove-FixtureProfile $virtualSid
                }
                & sc.exe delete $service.Name | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Could not remove fixture SCM registration.' }
            }
            if (Test-Path $registry) { Remove-Item -LiteralPath $registry -Recurse -Force }
            if (Test-Path $storage) { Remove-Item -LiteralPath $storage -Recurse -Force }
        }
        if ($createdInstall -and (Test-Path $install)) { Remove-Item -LiteralPath $install -Recurse -Force }
    } catch { $cleanupErrors.Add($_.Exception.Message) }
    try {
        if ($ownerSid) {
            Remove-FixtureProfile $ownerSid
        }
    } catch { $cleanupErrors.Add($_.Exception.Message) }
    try { if ($ownerSid) { Remove-LocalUser -SID $ownerSid } } catch { $cleanupErrors.Add($_.Exception.Message) }
    if ($certificate) {
        foreach ($store in @('Root', 'TrustedPublisher', 'My')) {
            try {
                $path = "Cert:\LocalMachine\$store\$($certificate.Thumbprint)"
                if (Test-Path $path) {
                    if ($store -eq 'My') { Remove-Item -LiteralPath $path -DeleteKey } else { Remove-Item -LiteralPath $path }
                }
            } catch { $cleanupErrors.Add($_.Exception.Message) }
        }
    }
    $password.Dispose()
    foreach ($phase in @('enroll', 'reconnect')) {
        $pending = Join-Path $work "$phase/connect-error.txt"
        if (Test-Path $pending) { Write-Output "$phase last pending connection diagnostic:"; Get-Content -LiteralPath $pending | Write-Output }
        $failure = Join-Path $work "$phase/failure.json"
        if (Test-Path $failure) { Get-Content -LiteralPath $failure | Write-Output }
    }
    try { Remove-Item -LiteralPath $work -Recurse -Force } catch { $cleanupErrors.Add($_.Exception.Message) }
    if ($cleanupErrors.Count) { throw ('Fixture cleanup failed: ' + ($cleanupErrors -join '; ')) }
}
Write-Output 'Installed acceptance PASS. Fixture certificate trust removed. Positive Windows Hello remains a manual human gate.'
