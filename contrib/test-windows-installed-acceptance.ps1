# Disposable hosted VM only. This creates fixture chain trust, a standard owner
# and actual installed service state. It never requests Hello or signs a release.
# Installer invocations drive the real enroll --launch-install trampoline (the
# signed helper's verify_installer_process + run_install_script verified Bypass
# bootstrap); the nested auth-registration calls use the same verified pattern.
# Resume republication is asserted on the restarted service plus the durable
# readiness marker, never on exit 0 alone; a stranded confirmed-but-never-ready
# installer run (owner silenced at RelayConfirmed) exercises -ResetConfirmed
# against the exact post-publish records production leaves behind.
# Only LocalMachine Root carries fixture chain trust so Authenticode reads
# Valid. The fixture publisher is deliberately absent from TrustedPublisher,
# so an AllSigned regression would prompt and fail closed under NonInteractive
# instead of passing silently. Only the OS-mediated UAC credential prompt is
# unexercised: the coordinator is already elevated.
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
// SYNCHRONIZE only: pin the exact SCM process before STOP, without opening it
// with mutation rights or mistaking a recycled PID for the stopped process.
public sealed class WalletAcceptanceServiceProcess : IDisposable {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint ms);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    IntPtr handle; public uint Id { get; private set; }
    public static WalletAcceptanceServiceProcess Pin(uint pid) {
        IntPtr handle=OpenProcess(0x00100000,false,pid);
        if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        return new WalletAcceptanceServiceProcess {handle=handle,Id=pid};
    }
    public bool Wait(uint ms) {
        uint result=WaitForSingleObject(handle,ms);
        if(result==0xffffffff) throw new Win32Exception(Marshal.GetLastWin32Error());
        return result==0;
    }
    public void Dispose() { if(handle!=IntPtr.Zero) { CloseHandle(handle); handle=IntPtr.Zero; } }
}
// A synthetic, uniquely named credential in the disposable coordinator account.
// Never enumerate or read any pre-existing credential.
public static class WalletAcceptanceCredential {
    [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Credential {
        public uint flags,type; public string target,comment; public long written;
        public uint size; public IntPtr blob; public uint persist,count;
        public IntPtr attributes; public string alias,user;
    }
    [DllImport("advapi32.dll", EntryPoint="CredWriteW", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredWriteW(ref Credential value,uint flags);
    [DllImport("advapi32.dll", EntryPoint="CredReadW", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredReadW(string target,uint type,uint flags,out IntPtr value);
    [DllImport("advapi32.dll", EntryPoint="CredDeleteW", ExactSpelling=true, CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CredDeleteW(string target,uint type,uint flags);
    [DllImport("advapi32.dll", ExactSpelling=true)] static extern void CredFree(IntPtr value);
    public static void Create(string target) {
        IntPtr existing;
        if(CredReadW(target,1,0,out existing)) { CredFree(existing); throw new InvalidOperationException("Existing fixture credential"); }
        if(Marshal.GetLastWin32Error()!=1168) throw new Win32Exception(Marshal.GetLastWin32Error());
        var bytes=Encoding.UTF8.GetBytes("disposable-recovery-sentinel");
        IntPtr blob=Marshal.AllocHGlobal(bytes.Length);
        try {
            Marshal.Copy(bytes,0,blob,bytes.Length);
            var value=new Credential {type=1,target=target,user="fixture",size=(uint)bytes.Length,blob=blob,persist=2};
            if(!CredWriteW(ref value,0)) throw new Win32Exception(Marshal.GetLastWin32Error());
        } finally { Marshal.FreeHGlobal(blob); }
    }
    public static void Verify(string target) {
        IntPtr pointer;
        if(!CredReadW(target,1,0,out pointer)) throw new Win32Exception(Marshal.GetLastWin32Error());
        try {
            var value=(Credential)Marshal.PtrToStructure(pointer,typeof(Credential));
            var bytes=new byte[value.size]; Marshal.Copy(value.blob,bytes,0,bytes.Length);
            if(value.user!="fixture" || Encoding.UTF8.GetString(bytes)!="disposable-recovery-sentinel") throw new InvalidOperationException("Unrelated credential changed");
        } finally { CredFree(pointer); }
    }
    public static void Delete(string target) { if(!CredDeleteW(target,1,0)) throw new Win32Exception(Marshal.GetLastWin32Error()); }
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
function Invoke-SetupScript($path, [string[]]$arguments, [switch]$AllowFailure) {
    # No store trust: verify the exact fixture signature, then a process-scoped
    # Bypass invocation with -NonInteractive. Authenticode Valid already binds
    # the exact approved bytes, mirroring the production verified bootstrap.
    $setup = Get-AuthenticodeSignature -LiteralPath $path
    if ($setup.Status -ne 'Valid' -or $setup.SignerCertificate.Thumbprint -cne $certificate.Thumbprint) { throw "Setup script is not the exact fixture-signed file: $path" }
    & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $path @arguments
    if ($LASTEXITCODE -ne 0 -and -not $AllowFailure) { throw "Signed setup script failed: $path" }
}
function Assert-LaunchInstallTrust {
    # Fail-closed preflight for the real --launch-install trampoline: every
    # file the trampoline executes must carry the exact fixture signature.
    # Only chain trust (LocalMachine Root) is present so Authenticode reads
    # Valid. The fixture publisher must stay absent from TrustedPublisher:
    # that absence proves the verified Bypass path is exercised, because an
    # AllSigned regression would prompt and fail closed under NonInteractive.
    # Production trust behavior is unchanged; only this disposable VM carries
    # fixture chain trust.
    foreach ($file in @((Join-Path $install 'ekubo-wallet-v2-enroll.exe'), (Join-Path $install 'install-windows-v2.ps1'), (Join-Path $install 'register-windows-v2-auth.ps1'))) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne $certificate.Thumbprint) { throw "Trampoline input is not the exact fixture-signed file: $file" }
    }
    if (-not (Test-Path -LiteralPath "Cert:\LocalMachine\Root\$($certificate.Thumbprint)")) { throw 'Fixture chain trust is absent from LocalMachine/Root; Authenticode cannot read Valid.' }
    if (Test-Path -LiteralPath "Cert:\LocalMachine\TrustedPublisher\$($certificate.Thumbprint)") { throw 'Fixture publisher trust is present in LocalMachine/TrustedPublisher; the verified Bypass path is not being exercised.' }
}
function Invoke-RecoveryFixture([switch]$RunOnce) {
    # Fixture-only equivalent of an operator approving this one signed script.
    # The normal baseline invokes -File with verified process-scoped Bypass
    # (no store trust anywhere). Diagnostics run in Windows PowerShell 5.1,
    # not the coordinating pwsh 7 process.
    $path = Join-Path $install 'recover-windows-v2.ps1'
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    $thumbprint = $certificate.Thumbprint
    if ($hash -notmatch '^[0-9A-Fa-f]{64}$' -or $thumbprint -notmatch '^[0-9A-Fa-f]{40}$' -or $ownerSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'Invalid fixture bootstrap identity.' }
    $bootstrap = @'
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
try {
    if ($PSVersionTable.PSVersion.Major -ne 5 -or $PSVersionTable.PSVersion.Minor -ne 1) { throw 'Expected Windows PowerShell 5.1.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    Write-Output "RECOVERY PREFLIGHT: PS=$($PSVersionTable.PSVersion); SID=$($identity.User.Value); profile=$env:USERPROFILE; RunOnce=__RUN_ONCE__"
    Get-ExecutionPolicy -List | Format-Table -AutoSize | Out-Host
    foreach ($store in @('CurrentUser', 'LocalMachine')) {
        foreach ($kind in @('Root', 'TrustedPublisher', 'Disallowed')) {
            Write-Output ("Fixture certificate {0}/{1}: {2}" -f $store, $kind, (Test-Path -LiteralPath "Cert:\$store\$kind\__THUMB__"))
        }
    }
    $path = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2\recover-windows-v2.ps1'
    $signature = Get-AuthenticodeSignature -LiteralPath $path
    Write-Output "Recovery signature: status=$($signature.Status); message=$($signature.StatusMessage)"
    $hash = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    Write-Output "Recovery SHA256=$hash"
    $bytes = [IO.File]::ReadAllBytes($path)
    $text = [Text.Encoding]::UTF8.GetString($bytes)
    Write-Output ("Recovery encoding: prefix={0}; CRLF={1}; bareLF={2}" -f ([BitConverter]::ToString($bytes, 0, [Math]::Min(3, $bytes.Length))), ([regex]::Matches($text, "`r`n").Count), ([regex]::Matches($text, "(?<!`r)`n").Count))
    $tokens = $null; $parseErrors = $null
    $null = [Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$parseErrors)
    foreach ($parseError in $parseErrors) { [Console]::Error.WriteLine("PS5.1 parse: $($parseError.ErrorId) line=$($parseError.Extent.StartLineNumber): $($parseError.Message)") }
    if (@($parseErrors).Count) { throw 'Recovery script has Windows PowerShell 5.1 parse errors.' }
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Thumbprint -cne '__THUMB__' -or $hash -cne '__HASH__') { throw 'Recovery is not the exact signed fixture-approved file.' }
    Write-Output 'RECOVERY PREFLIGHT PASS: valid fixture signature, exact approved hash, PS5.1 parse clean.'
    if (__RUN_ONCE__) {
        if (Test-Path -LiteralPath 'Cert:\LocalMachine\TrustedPublisher\__THUMB__') { throw 'No-machine-publisher case still has machine publisher trust.' }
        Write-Output 'RECOVERY INVOKE: fixture-validated Run once; production script and SYSTEM bootstrap follow.'
        & $path -OwnerSid '__OWNER__' -DiscardUnused
    }
    exit 0
} catch {
    [Console]::Error.WriteLine($_.ToString())
    [Console]::Error.WriteLine($_.InvocationInfo.PositionMessage)
    [Console]::Error.WriteLine($_.ScriptStackTrace)
    exit 1
}
'@
    $run = if ($RunOnce) { '$true' } else { '$false' }
    $bootstrap = $bootstrap.Replace('__HASH__', $hash).Replace('__THUMB__', $thumbprint).Replace('__OWNER__', $ownerSid).Replace('__RUN_ONCE__', $run)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    & $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded
    if ($LASTEXITCODE -ne 0) { throw 'Windows PowerShell 5.1 recovery preflight/validated invocation failed; see diagnostics above.' }
    if (-not $RunOnce) { Invoke-SetupScript $path @('-OwnerSid', $ownerSid, '-DiscardUnused') }
}
function Wait-ServiceState($name, $state) {
    $controller = Get-Service $name
    try { $controller.WaitForStatus($state, [TimeSpan]::FromSeconds(30)) } finally { $controller.Dispose() }
}
function Stop-FixtureService($name) {
    $snapshot = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if ($snapshot.ProcessId -ne 0) {
        $process = [WalletAcceptanceServiceProcess]::Pin($snapshot.ProcessId)
        $pinnedServices.Add([pscustomobject]@{Name=$name; Process=$process; Exited=$false})
        $current = Get-CimInstance Win32_Service -Filter "Name='$name'"
        if ($current.ProcessId -ne $process.Id) { throw "SCM process changed while pinning $name; refusing an ambiguous stop." }
        Write-Output "Stopping $name; pinned PID=$($process.Id)"
    }
    Stop-Service -Name $name -NoWait
    Wait-ServiceState $name ([ServiceProcess.ServiceControllerStatus]::Stopped)
    # Keep pins even on timeout so cleanup cannot forget a still-exiting process
    # merely because SCM now reports STOPPED / ProcessId=0.
    foreach ($pin in $pinnedServices | Where-Object Name -EQ $name) {
        if ($pin.Exited) { continue }
        if (-not $pin.Process.Wait(30000)) { throw "SCM STOPPED but $name PID=$($pin.Process.Id) did not exit within 30 seconds." }
        Write-Output "$name PID=$($pin.Process.Id) exited (process handle signaled)."
        $pin.Process.Dispose()
        $pin.Exited = $true
    }
}
function Restart-FixtureService($name) {
    Stop-FixtureService $name
    Write-Output "Starting $name after confirmed process exit."
    Start-Service -Name $name
    Wait-ServiceState $name ([ServiceProcess.ServiceControllerStatus]::Running)
}
function Wait-FixtureProfileUnloaded($sid) {
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'"
        if (-not $profile -or -not $profile.Loaded) { break }
        Start-Sleep -Milliseconds 200
    } while ([DateTime]::UtcNow -lt $deadline)
    if ($profile -and $profile.Loaded) { throw "Fixture profile still loaded after 30 seconds: SID=$sid; path=$($profile.LocalPath). Not deleting or forcing unload." }
    Write-Output "Fixture profile unloaded: SID=$sid"
}
function Remove-FixtureProfile($sid, [switch]$AllowCachedVirtualProfile) {
    if ($AllowCachedVirtualProfile) {
        $cached = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'"
        if ($cached -and $cached.Loaded) {
            $parent = Join-Path ([Environment]::GetFolderPath('Windows')) 'ServiceProfiles'
            if ($sid -notlike 'S-1-5-80-*' -or
                (Split-Path $cached.LocalPath) -ne $parent -or
                (Split-Path $cached.LocalPath -Leaf) -notmatch '^EkuboWalletV2-[0-9a-f]{32}$') {
                throw 'Refusing to defer an unrelated loaded profile.'
            }
            # SCM/LSASS may keep this OS-owned hive loaded until reboot after
            # service deletion. Do not force-unload it. This disposable VM is
            # destroyed after the job; application custody is removed below.
            Write-Output "OS-cached fixture virtual profile deferred to runner teardown: $sid"
            return
        }
    }
    Wait-FixtureProfileUnloaded $sid
    $profile = Get-CimInstance Win32_UserProfile -Filter "SID='$sid'"
    if ($profile) {
        if ($profile.Loaded) { throw "Profile reloaded before deletion: SID=$sid; path=$($profile.LocalPath)" }
        $profile | Remove-CimInstance
    }
}

function Remove-FixtureStorageAsSystem($path) {
    $expected = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EkuboWalletV2'
    if ($path -ne $expected) { throw 'Invalid fixture storage cleanup path.' }
    # Service-created files carry SYSTEM integrity as well as private DACLs.
    # Use their existing SYSTEM grant after all service processes have exited;
    # do not lower the labels or weaken the application storage implementation.
    $name = 'EkuboWalletV2-Cleanup-' + [Guid]::NewGuid().ToString('N')
    $literal = $path.Replace("'", "''")
    $command = "`$ErrorActionPreference='Stop'; `$env:PSModulePath=[IO.Path]::Combine(`$PSHOME,'Modules'); if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { exit 2 }; Remove-Item -LiteralPath '$literal' -Recurse -Force; if (Test-Path -LiteralPath '$literal') { exit 3 }; exit 0"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $action = New-ScheduledTaskAction -Execute $powershell -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
    $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    try {
        Register-ScheduledTask -TaskName $name -Action $action -Principal $principal | Out-Null
        $started = [DateTime]::Now.AddSeconds(-2)
        Start-ScheduledTask -TaskName $name
        $deadline = [DateTime]::Now.AddSeconds(30)
        $completedRun = $null
        # State and last-result are separate scheduler reads that converge
        # with a delay: require the same terminal run/result twice rather
        # than accepting a transition snapshot (e.g. a stale 0x41301
        # never-ran code after the state already reads Ready).
        do {
            Start-Sleep -Milliseconds 200
            $info = Get-ScheduledTaskInfo -TaskName $name
            $task = Get-ScheduledTask -TaskName $name
            if ([DateTime]::Now -gt $deadline) { throw 'SYSTEM fixture storage cleanup timed out.' }
            $terminal = $info.LastRunTime -gt $started -and $task.State -ne 'Running' -and $task.State -ne 'Queued' -and $info.LastTaskResult -ne 0x41301
            $run = if ($terminal) { "$($info.LastRunTime.Ticks):$($info.LastTaskResult)" } else { $null }
            $finished = $terminal -and $run -eq $completedRun
            $completedRun = $run
        } until ($finished)
        if ($info.LastTaskResult -ne 0 -or (Test-Path -LiteralPath $path)) { throw "SYSTEM fixture cleanup failed: $($info.LastTaskResult)" }
    } finally {
        if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
            Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $name -Confirm:$false
        }
    }
}
function Write-FixtureFailure($step, $record) {
    $details = "${step}: $($record.Exception.GetType().FullName): $($record.Exception.Message); HResult=$($record.Exception.HResult.ToString('X8')); ErrorId=$($record.FullyQualifiedErrorId); TargetObject=$($record.TargetObject)"
    [Console]::Error.WriteLine($details)
    if ($record.InvocationInfo) { [Console]::Error.WriteLine([string]$record.InvocationInfo.PositionMessage) }
    [Console]::Error.WriteLine([string]$record.ScriptStackTrace)
    for ($cause = $record.Exception; $null -ne $cause; $cause = $cause.InnerException) {
        if ($cause -is [ComponentModel.Win32Exception]) { [Console]::Error.WriteLine("Native Win32 error=$($cause.NativeErrorCode): $($cause.Message)") }
    }
    return $details
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
$primaryError = $null
$stage = 'prepare fixture owner and signed installation'
$pinnedServices = [Collections.Generic.List[object]]::new()
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
    # Chain trust only, so Authenticode reads Valid. Never import the fixture
    # publisher into TrustedPublisher: prompt suppression would let an
    # AllSigned regression pass silently instead of failing closed.
    Import-Certificate -FilePath $public -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
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
        $stage = "$phase / owner profile and new logon"
        Write-Output "STEP $stage"
        if ($phase -eq 'reconnect') { Wait-FixtureProfileUnloaded $ownerSid }
        $exchange = Join-Path $work $phase
        New-Item -ItemType Directory $exchange | Out-Null
        Set-DirectoryAcl $exchange $ownerSid '0x1301bf'
        $worker = [WalletAcceptanceLogon]::Start($username, $password, $fixture, "$phase `"$exchange`" $ownerSid", $work)
        Write-Output "$phase owner PID=$($worker.Id) started."
        $stage = "$phase / await real owner identity"
        $identity = Await-Report $exchange 'identity.json' $worker 30
        $nativeProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$ownerSid'"
        if ($identity.owner_sid -ne $ownerSid -or $nativeProfile.LocalPath -ne $identity.profile -or $identity.session -ne $installerSession) { throw 'Owner token/profile/session mapping is not the fixture logon.' }
        if ($phase -eq 'enroll') {
            # Hold the real owner at begin.json until both interruption cases
            # finish, so they do not consume its 90-second connection deadline.
            $stdout = Join-Path $work 'installer.stdout.log'; $stderr = Join-Path $work 'installer.stderr.log'
            $startedInstall = $true
            $stage = 'interrupted enrollment / production provisioning with absent relay'
            $unrelated = Join-Path $work 'unrelated-recovery-sentinel'
            [IO.File]::WriteAllText($unrelated, 'unrelated disposable data')
            $unrelatedHash = (Get-FileHash -LiteralPath $unrelated).Hash
            $profilesBefore = @(Get-CimInstance Win32_UserProfile | Select-Object SID, LocalPath)
            $credentialTarget = "EkuboWalletV2-Acceptance-$nonce"
            [WalletAcceptanceCredential]::Create($credentialTarget)
            try {
                foreach ($trustMode in @('machine-publisher-baseline', 'validated-run-once')) {
                    $stage = "interrupted enrollment / $trustMode / absent relay"
                    Write-Output "STEP $stage"
                    # Real empty SQLCipher/key creation precedes failed handoff.
                    $missingRelay = [Guid]::NewGuid().ToString()
                    # Real trampoline, not a direct script call: the signed enroll
                    # helper (already elevated here; the only unexercised step
                    # is the OS-mediated UAC credential prompt) re-executes the
                    # signed install script through the verified Bypass
                    # bootstrap via verify_installer_process +
                    # run_install_script. The relay still comes from the
                    # genuine standard-owner logon, so a trust regression
                    # fails here: provisioning never reaches service-created
                    # state and the pending-file checks below fail closed.
                    Assert-LaunchInstallTrust
                    $installer = Start-Process -FilePath (Join-Path $install 'ekubo-wallet-v2-enroll.exe') -ArgumentList @('--launch-install', $ownerSid, $missingRelay) -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
                    if (-not $installer.WaitForExit(120000)) { throw 'Interrupted enrollment did not fail within 120 seconds.' }
                    Get-Content -LiteralPath $stdout, $stderr | Write-Output
                    if ($installer.ExitCode -eq 0) { throw 'Absent owner relay unexpectedly completed enrollment.' }
                    $pendingRecord = Get-ItemProperty -LiteralPath (Join-Path $registry "Pending/$ownerSid")
                    if ($pendingRecord.PSObject.Properties['RelayConfirmed']) { throw 'Interrupted enrollment published relay confirmation.' }
                    $pendingIdentity = [Text.Encoding]::UTF8.GetString([byte[]]$pendingRecord.Profile) | ConvertFrom-Json
                    $pendingPath = Join-Path $storage ('Pending/' + ([Guid]$pendingIdentity.profile_id).ToString('N'))
                    foreach ($name in @('wallet.db', 'key-database', 'wrapping.key', 'fresh-profile-ready')) {
                        if (-not (Test-Path -LiteralPath (Join-Path $pendingPath $name))) { throw "Interruption did not reach actual service-created $name" }
                    }
                    $stage = "interrupted enrollment / $trustMode / production SYSTEM discard"
                    Write-Output "STEP $stage"
                    if ($trustMode -eq 'machine-publisher-baseline') {
                        Invoke-RecoveryFixture
                    } else {
                        # No publisher approval is silently installed in either
                        # user store, and machine TrustedPublisher stays absent
                        # throughout: the verified invocation must not need it.
                        # Model Run once only for the verified bytes.
                        if (Test-Path -LiteralPath "Cert:\LocalMachine\TrustedPublisher\$($certificate.Thumbprint)") { throw 'Machine publisher trust must stay absent; the verified recovery invocation must not need it.' }
                        Invoke-RecoveryFixture -RunOnce
                    }
                    if ((Test-Path -LiteralPath $registry) -or (Test-Path -LiteralPath $storage) -or
                        @(Get-Service -Name 'EkuboWalletV2-*' -ErrorAction SilentlyContinue).Count) { throw 'Production discard left setup-blocking state.' }
                    if ((Get-FileHash -LiteralPath $unrelated).Hash -ne $unrelatedHash) { throw 'Discard changed unrelated files.' }
                    foreach ($before in $profilesBefore) {
                        $after = Get-CimInstance Win32_UserProfile -Filter "SID='$($before.SID)'"
                        if (-not $after -or $after.LocalPath -ne $before.LocalPath) { throw 'Discard changed an unrelated Windows profile.' }
                    }
                    [WalletAcceptanceCredential]::Verify($credentialTarget)
                    Remove-FixtureProfile $pendingIdentity.service_sid -AllowCachedVirtualProfile
                    Write-Output "$trustMode PASS: real unpublished custody discarded; unrelated profiles, file and synthetic credential unchanged."
                }
            } finally { [WalletAcceptanceCredential]::Delete($credentialTarget) }
            $stage = 'stranded confirmed-but-never-active profile / installer without owner readiness'
            Write-Output "STEP $stage"
            # Build the exact stranded state the installer leaves when its
            # 60s readiness wait fails: Owners records published, no
            # setup-complete. The owner worker is terminated the moment
            # RelayConfirmed is durably recorded, so readiness can never
            # complete — exactly as a forged relay receipt or a lost
            # credential entry strands it. Afterwards -ResetConfirmed must
            # remove precisely that state. No state is fabricated: every
            # record below is written by the production installer itself.
            Publish $exchange 'begin.json' @{}
            $strandRelay = Await-Report $exchange 'relay.json' $worker
            if ($strandRelay.owner_sid -ne $ownerSid) { throw 'Strand relay is not owned by the standard fixture user.' }
            $strandStdout = Join-Path $work 'strand.stdout.log'; $strandStderr = Join-Path $work 'strand.stderr.log'
            Assert-LaunchInstallTrust
            $stranded = Start-Process -FilePath (Join-Path $install 'ekubo-wallet-v2-enroll.exe') -ArgumentList @('--launch-install', $ownerSid, $strandRelay.endpoint) -PassThru -RedirectStandardOutput $strandStdout -RedirectStandardError $strandStderr
            $strandPending = Join-Path $registry "Pending/$ownerSid"
            $strandDeadline = [DateTime]::UtcNow.AddSeconds(90)
            $strandConfirmed = $false
            while (-not $strandConfirmed) {
                Start-Sleep -Milliseconds 200
                if ($stranded.HasExited) { break }
                $strandRecord = Get-ItemProperty -LiteralPath $strandPending -ErrorAction SilentlyContinue
                if ($strandRecord -and $strandRecord.PSObject.Properties['RelayConfirmed'] -and $strandRecord.RelayConfirmed -eq 1) { $strandConfirmed = $true }
                if (-not $strandConfirmed -and [DateTime]::UtcNow -gt $strandDeadline) { throw 'Strand installer never recorded relay confirmation.' }
            }
            if (-not $strandConfirmed) {
                Get-Content -LiteralPath $strandStdout, $strandStderr | Write-Output
                throw 'Strand installer exited before relay confirmation; see output above.'
            }
            # Owner silence from here: readiness can never complete.
            $worker.Dispose(); $worker = $null
            if (-not $stranded.WaitForExit(120000)) {
                $stranded.Kill($true)
                if (-not $stranded.WaitForExit(10000)) { throw 'Strand installer process did not exit after termination.' }
                throw 'Strand installer did not fail its readiness wait within 120 seconds.'
            }
            Get-Content -LiteralPath $strandStdout, $strandStderr | Write-Output
            if ($stranded.ExitCode -eq 0) { throw 'TODO: stranded orchestration lost the race (installer reached readiness); reset coverage needs a silent owner, not this worker.' }
            $stranded.Dispose(); $stranded = $null
            $stage = 'stranded profile / assert post-publish records without readiness'
            $strandRecord = Get-ItemProperty -LiteralPath $strandPending
            $strandIdentity = [Text.Encoding]::UTF8.GetString([byte[]]$strandRecord.Profile) | ConvertFrom-Json
            $strandGuid = ([Guid]$strandIdentity.profile_id).ToString('N')
            $strandOwnersKey = Join-Path $registry "Owners/$ownerSid"
            $strandActive = Join-Path $storage "Owners/$strandGuid"
            $strandPendingDir = Join-Path $storage "Pending/$strandGuid"
            if (-not ((Test-Path -LiteralPath $strandOwnersKey) -and (Test-Path -LiteralPath $strandActive))) { throw 'TODO: installer did not strand post-publish Owners records; reset has nothing post-publish to cover.' }
            foreach ($location in @($strandPendingDir, $strandActive)) {
                if (Test-Path -LiteralPath (Join-Path $location 'setup-complete')) { throw 'Stranded profile unexpectedly reached readiness.' }
            }
            if (@(Get-ChildItem -LiteralPath $strandActive -Force | Where-Object Name -Like 'key-account-*').Count) { throw 'Stranded profile unexpectedly holds account keys.' }
            $strandService = 'EkuboWalletV2-' + $strandGuid
            $strandRegistration = Get-CimInstance Win32_Service -Filter "Name='$strandService'"
            $strandCommand = '"' + (Join-Path $install 'ekubo-wallet-service.exe') + '" --owner-sid ' + $ownerSid
            if (-not $strandRegistration -or $strandRegistration.PathName -ne $strandCommand) { throw 'TODO: stranded service is not the never-ready activated command; refusing to invent reset coverage.' }
            $stage = 'stranded profile / production SYSTEM reset'
            Write-Output "STEP $stage"
            Invoke-SetupScript (Join-Path $install 'recover-windows-v2.ps1') @('-OwnerSid', $ownerSid, '-ResetConfirmed')
            if ($LASTEXITCODE -ne 0) { throw 'Production reset of the stranded profile failed.' }
            $leftover = @()
            if (Test-Path -LiteralPath $registry) { $leftover += "registry:$registry" }
            if (Test-Path -LiteralPath $storage) { $leftover += "storage:$storage" }
            $leftover += @(Get-Service -Name 'EkuboWalletV2-*' -ErrorAction SilentlyContinue | ForEach-Object { "service:$($_.Name)" })
            if ($leftover.Count) { throw "Production reset left setup-blocking state: $($leftover -join ', ')." }
            if ((Get-FileHash -LiteralPath $unrelated).Hash -ne $unrelatedHash) { throw 'Reset changed unrelated files.' }
            foreach ($before in $profilesBefore) {
                $after = Get-CimInstance Win32_UserProfile -Filter "SID='$($before.SID)'"
                if (-not $after -or $after.LocalPath -ne $before.LocalPath) { throw 'Reset changed an unrelated Windows profile.' }
            }
            Remove-FixtureProfile $strandIdentity.service_sid -AllowCachedVirtualProfile
            Write-Output 'stranded reset PASS: post-publish never-ready records removed; unrelated profiles and file unchanged.'
            $stage = 'stranded profile / restore preconditions for a fresh owner'
            # Fixture-harness state only: the terminated worker already wrote
            # the disposable 1.x sentinel, and production reset correctly left
            # it alone. Remove it and the consumed exchange reports so the
            # next worker starts from the exact preconditions the owner
            # fixture asserts. No wallet state is fabricated.
            $strandOwnerProfile = (Get-CimInstance Win32_UserProfile -Filter "SID='$ownerSid'").LocalPath
            $strandSentinel = Join-Path $strandOwnerProfile 'AppData\Local\Ekubo\wallet\acceptance-sentinel'
            if (-not (Test-Path -LiteralPath $strandSentinel -PathType Leaf)) { throw 'Disposable 1.x sentinel is missing after the stranded run.' }
            Remove-Item -LiteralPath $strandSentinel -Force
            # The restarted worker's enroll phase requires no 1.x owner
            # directory at all, not just no sentinel file. Remove the exact
            # fixture-owned directory the worker asserts on.
            $strandLegacyDir = Join-Path $strandOwnerProfile 'AppData\Local\Ekubo\wallet'
            if (Test-Path -LiteralPath $strandLegacyDir) { Remove-Item -LiteralPath $strandLegacyDir -Recurse -Force }
            foreach ($name in @('identity.json', 'begin.json', 'relay.json', 'connect-error.txt', 'failure.json')) {
                $report = Join-Path $exchange $name
                if (Test-Path -LiteralPath $report) { Remove-Item -LiteralPath $report -Force }
            }
            $worker = [WalletAcceptanceLogon]::Start($username, $password, $fixture, "enroll `"$exchange`" $ownerSid", $work)
            Write-Output "enroll owner PID=$($worker.Id) restarted after stranded reset."
            $stage = 'enroll / await real owner identity'
            $identity = Await-Report $exchange 'identity.json' $worker 30
            $nativeProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$ownerSid'"
            if ($identity.owner_sid -ne $ownerSid -or $nativeProfile.LocalPath -ne $identity.profile -or $identity.session -ne $installerSession) { throw 'Owner token/profile/session mapping is not the fixture logon.' }
            $stage = 'enroll / retry production installer after discard and stranded reset'
            Publish $exchange 'begin.json' @{}
            $relay = Await-Report $exchange 'relay.json' $worker
            if ($relay.owner_sid -ne $ownerSid -or $relay.owner_sid -eq $administrator.User.Value) { throw 'Relay is not owned by the standard fixture user.' }
            Assert-LaunchInstallTrust
            $installer = Start-Process -FilePath (Join-Path $install 'ekubo-wallet-v2-enroll.exe') -ArgumentList @('--launch-install', $ownerSid, $relay.endpoint) -PassThru -RedirectStandardOutput $stdout -RedirectStandardError $stderr
            if (-not $installer.WaitForExit(120000)) { throw 'Production enrollment exceeded 120 seconds.' }
            Get-Content $stdout, $stderr | Write-Output
            if ($installer.ExitCode -ne 0) { throw "Production enrollment failed: $($installer.ExitCode)" }
            # The elevated install script records its own transcript (the
            # launcher cannot redirect an elevated child's console); a missing
            # transcript means elevated diagnostics are not recording.
            $installLog = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EkuboWalletV2-install.log'
            if (-not (Test-Path -LiteralPath $installLog)) { throw 'Install transcript is missing; elevated diagnostics are not recording.' }
        } else { Publish $exchange 'begin.json' @{} }
        $stage = "$phase / authenticated readiness and persistence"
        $ready = Await-Report $exchange 'ready.json' $worker
        $nativeProfile = Get-CimInstance Win32_UserProfile -Filter "SID='$ownerSid'"
        if ($nativeProfile.LocalPath -ne $ready.profile) { throw 'Owner environment did not load its real Windows profile.' }
        if ($ready.session -ne $installerSession) { throw 'Fixture did not use the installer session with a distinct owner logon.' }
        if ($phase -eq 'enroll') { $baseline = $ready } else {
            if ($ready.logon -eq $baseline.logon) { throw "The new process reused authentication LUID $($ready.logon)." }
            if ($ready.profile_id -ne $baseline.profile_id) { throw 'Protected profile identity changed across restart.' }
            if ($ready.service_sid -ne $baseline.service_sid) { throw 'Service account identity changed across restart.' }
            if (($ready.account | ConvertTo-Json -Compress) -ne ($baseline.account | ConvertTo-Json -Compress)) {
                Write-Output ('Before: ' + ($baseline.account | ConvertTo-Json -Compress))
                Write-Output ('After: ' + ($ready.account | ConvertTo-Json -Compress))
                throw 'Stored account metadata changed across restart.'
            }
        }
        if ($ready.owner_sid -ne $ownerSid -or $ready.service_sid -eq $ownerSid) { throw 'Published service/owner identity is not isolated.' }
        $service = Get-CimInstance Win32_Service -Filter "Name='$($ready.service_name)'"
        $broker = Get-CimInstance Win32_Service -Filter "Name='$($ready.service_name)-Auth'"
        if ($service.State -ne 'Running' -or $service.StartName -ne "NT SERVICE\$($ready.service_name)" -or $broker.State -ne 'Running' -or $broker.StartName -ne 'LocalSystem') { throw 'Installed SCM identities/readiness are wrong.' }
        $active = Join-Path $storage ('Owners/' + ([Guid]$ready.profile_id).ToString('N'))
        if ([IO.File]::ReadAllText((Join-Path $active 'setup-complete')) -ne $ready.profile_id) { throw 'Published profile is not durably ready.' }
        $raw = @('wallet.db', 'wrapping.key', 'key-database', ('key-account-' + $ready.account.instance_id)) | ForEach-Object { Join-Path $active $_ }
        foreach ($file in $raw) { if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing actual protected file: $file" } }
        if ($phase -eq 'enroll') {
            $stage = 'active profile / production discard must refuse'
            # Bypass (not AllSigned) so the non-zero exit below proves the
            # script's own active-profile guard refused, not a policy prompt.
            Invoke-SetupScript (Join-Path $install 'recover-windows-v2.ps1') @('-OwnerSid', $ownerSid, '-DiscardUnused') -AllowFailure
            if ($LASTEXITCODE -eq 0) { throw 'Production discard accepted an active wallet.' }
            $stillRunning = Get-CimInstance Win32_Service -Filter "Name='$($ready.service_name)'"
            if ($stillRunning.ProcessId -ne $service.ProcessId -or $stillRunning.State -ne 'Running') { throw 'Rejected discard disrupted the active authority.' }
            foreach ($file in $raw) { if (-not (Test-Path -LiteralPath $file)) { throw 'Rejected discard removed active custody.' } }
        }
        $trace = "wallet-collector-$nonce-$phase"
        $stage = "$phase / raw access and negative native authorization"
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
        $stage = "$phase / owner process exit"
        if (-not $worker.Wait(15000) -or $worker.ExitCode -ne 0) { throw 'Owner did not close its real client/relay cleanly.' }
        $worker.Dispose(); $worker = $null
        if ($phase -eq 'enroll') {
            $stage = 'enroll / resume republication restarts the published service'
            Write-Output "STEP $stage"
            # Regression backstop for the elevated resume launcher: exit 0
            # alone once hid a -Command string-literal no-op that printed and
            # exited without publishing. Stop the authority, drive the resume
            # path, and require the published service itself (not just the
            # exit code) plus the durable readiness marker with the unchanged
            # profile identity. The Rust run_elevated Resume argument string
            # is pinned separately by its -EncodedCommand unit test; UAC
            # mediation keeps this fixture from driving that launcher
            # directly, so this covers the script half of the same hole.
            Stop-FixtureService $ready.service_name
            Invoke-SetupScript (Join-Path $install 'recover-windows-v2.ps1') @('-OwnerSid', $ownerSid)
            if ($LASTEXITCODE -ne 0) { throw 'Resume republication failed.' }
            Wait-ServiceState $ready.service_name ([ServiceProcess.ServiceControllerStatus]::Running)
            $resumed = Get-CimInstance Win32_Service -Filter "Name='$($ready.service_name)'"
            if ($resumed.State -ne 'Running' -or $resumed.StartName -ne "NT SERVICE\$($ready.service_name)") { throw 'Resume did not restore the published authority.' }
            if ([IO.File]::ReadAllText((Join-Path $active 'setup-complete')) -ne $ready.profile_id) { throw 'Resume lost durable readiness.' }
            Write-Output 'resume republication PASS: published authority restarted with durable readiness.'
            $stage = 'enroll / restart broker and authority'
            Restart-FixtureService ($ready.service_name + '-Auth')
            Restart-FixtureService $ready.service_name
            $restarted = Get-CimInstance Win32_Service -Filter "Name='$($ready.service_name)'"
            if ($restarted.ProcessId -eq $resumed.ProcessId) { throw 'Authority process did not restart.' }
        }
        Write-Output "$phase PASS: real owner logon, protected authority/account, raw file access denied, native authorization rejected without a collector, 1.x sentinel unchanged."
    }
} catch {
    $primaryError = $_
    $null = Write-FixtureFailure "PRIMARY [$stage]" $_
} finally {
    $cleanupErrors = [Collections.Generic.List[string]]::new()
    try {
        if ($worker) { $worker.Dispose() }
        if ($installer) {
            if (-not $installer.HasExited) {
                $installer.Kill($true)
                if (-not $installer.WaitForExit(10000)) { throw 'Fixture installer process did not exit after termination.' }
            }
            $installer.Dispose()
            $installer = $null
        }
    } catch { $cleanupErrors.Add((Write-FixtureFailure 'CLEANUP [owner/installer processes]' $_)) }
    if ($trace) { Unregister-Event -SourceIdentifier $trace -ErrorAction SilentlyContinue; Remove-Event -SourceIdentifier $trace -ErrorAction SilentlyContinue }
    try {
        $cleanupStep = 'validate fixture service provenance'
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
                $cleanupStep = "stop and await exit: $($service.Name)"
                Stop-FixtureService $service.Name
            }
            $virtualProfiles = [Collections.Generic.List[string]]::new()
            foreach ($service in $services) {
                if ($service.StartName -like 'NT SERVICE\*') {
                    $virtualSid = [Security.Principal.NTAccount]::new($service.StartName).Translate([Security.Principal.SecurityIdentifier]).Value
                    if ($virtualSid -notlike 'S-1-5-80-*') { throw 'Unexpected fixture virtual account SID.' }
                    $virtualProfiles.Add($virtualSid)
                }
                $cleanupStep = "delete SCM registration: $($service.Name)"
                & sc.exe delete $service.Name | Out-Null
                if ($LASTEXITCODE -ne 0) { throw 'Could not remove fixture SCM registration.' }
            }
            # SCM can retain the virtual account's profile while its registration
            # exists, even after the service process has exited.
            foreach ($virtualSid in $virtualProfiles) {
                $cleanupStep = "remove virtual profile after SCM deletion: $virtualSid"
                Remove-FixtureProfile $virtualSid -AllowCachedVirtualProfile
            }
            $cleanupStep = "remove registry: $registry"
            if (Test-Path $registry) { Remove-Item -LiteralPath $registry -Recurse -Force }
            $cleanupStep = "remove protected storage: $storage"
            if (Test-Path $storage) {
                if (@(Get-ChildItem -LiteralPath $storage -Recurse -Force | Where-Object { $_.Attributes -band [IO.FileAttributes]::ReparsePoint }).Count) {
                    throw 'Refusing redirected fixture storage during administrative cleanup.'
                }
                Remove-FixtureStorageAsSystem $storage
            }
        }
        $cleanupStep = "remove code: $install"
        if ($createdInstall -and (Test-Path $install)) { Remove-Item -LiteralPath $install -Recurse -Force }
    } catch { $cleanupErrors.Add((Write-FixtureFailure "CLEANUP [$cleanupStep]" $_)) }
    try {
        if ($ownerSid) {
            Remove-FixtureProfile $ownerSid
        }
    } catch { $cleanupErrors.Add((Write-FixtureFailure "CLEANUP [owner profile: $ownerSid]" $_)) }
    try { if ($ownerSid) { Remove-LocalUser -SID $ownerSid } } catch { $cleanupErrors.Add((Write-FixtureFailure "CLEANUP [owner account: $ownerSid]" $_)) }
    if ($certificate) {
        foreach ($store in @('Root', 'TrustedPublisher', 'My')) {
            try {
                $path = "Cert:\LocalMachine\$store\$($certificate.Thumbprint)"
                if (Test-Path $path) {
                    if ($store -eq 'My') { Remove-Item -LiteralPath $path -DeleteKey } else { Remove-Item -LiteralPath $path }
                }
            } catch { $cleanupErrors.Add((Write-FixtureFailure "CLEANUP [certificate: $path]" $_)) }
        }
    }
    $password.Dispose()
    foreach ($phase in @('enroll', 'reconnect')) {
        foreach ($name in @('connect-error.txt', 'failure.json')) {
            $diagnostic = Join-Path $work "$phase/$name"
            try {
                if (Test-Path $diagnostic) { Write-Output "Owner diagnostic: $diagnostic"; Get-Content -LiteralPath $diagnostic | Write-Output }
            } catch { $cleanupErrors.Add((Write-FixtureFailure "CLEANUP [read diagnostic: $diagnostic]" $_)) }
        }
    }
    try { Remove-Item -LiteralPath $work -Recurse -Force } catch { $cleanupErrors.Add((Write-FixtureFailure "CLEANUP [temporary files: $work]" $_)) }
    foreach ($pin in $pinnedServices) { $pin.Process.Dispose() }
    if ($cleanupErrors.Count -and $null -eq $primaryError) { throw ('Fixture cleanup failed: ' + ($cleanupErrors -join '; ')) }
}
if ($null -ne $primaryError) { throw $primaryError }
Write-Output 'Installed acceptance PASS. Fixture certificate trust removed. Positive Windows Hello remains a manual human gate.'
