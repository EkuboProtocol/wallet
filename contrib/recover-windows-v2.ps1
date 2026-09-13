# Explicit publication recovery or exact unused pending discard; never recreates custody.
param([Parameter(Mandatory=$true)][string]$OwnerSid, [switch]$DiscardUnused)
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
Set-StrictMode -Version Latest
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) -or -not [Environment]::Is64BitProcess) { throw 'Elevated 64-bit PowerShell is required.' }
if ($OwnerSid -notmatch '^S-1-5-21-\d+-\d+-\d+-\d+$') { throw 'An ordinary owner SID is required.' }
if ([Security.Principal.SecurityIdentifier]::new($OwnerSid).Value -cne $OwnerSid) { throw 'A canonical owner SID is required.' }
# The administrator cannot delete SYSTEM-integrity private files. Re-enter only
# this fixed installed script; SYSTEM repeats every prerequisite under the mutex.
# The interactive AllSigned parent may have been approved with Run once. That
# approval does not install publisher trust in SYSTEM's certificate store.
$install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2'
$script = Join-Path $install 'recover-windows-v2.ps1'
if ($DiscardUnused) {
    if ($PSCommandPath -ne $script) { throw 'Discard must use the signed installed recovery script.' }
    $signature = Get-AuthenticodeSignature -LiteralPath $script
    if ($signature.Status -ne 'Valid') { throw 'Installed recovery signature is not valid.' }
}
if ($DiscardUnused -and [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') {
    $powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $taskName = 'EkuboWalletV2-Discard-' + $OwnerSid
    $approvedHash = (Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash
    # Process-only Bypass avoids the SYSTEM publisher prompt; it is NOT signature
    # validation. The fixed bootstrap explicitly verifies both Authenticode and
    # the exact bytes of the parent-approved installed script before invocation.
    # Machine/User Group Policy still takes precedence and is never changed.
    $bootstrap = @'
$ErrorActionPreference = 'Stop'
$env:PSModulePath = [IO.Path]::Combine($PSHOME, 'Modules')
try {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Recovery task is not SYSTEM.' }
    $script = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2\recover-windows-v2.ps1'
    if ((Get-AuthenticodeSignature -LiteralPath $script).Status -ne 'Valid') { throw 'Installed recovery signature is not valid under SYSTEM.' }
    if ((Get-FileHash -LiteralPath $script -Algorithm SHA256).Hash -cne '__HASH__') { throw 'Installed recovery changed after operator approval.' }
    & $script -OwnerSid '__OWNER__' -DiscardUnused
    exit 0
} catch {
    $failure = $_
    # Task Scheduler discards stderr. Its existing task description is a bounded
    # diagnostic channel, never authority or an input to cleanup. No new file,
    # registry state, credential data, or caller-selected destination is written.
    $detail = "Recovery line=$($failure.InvocationInfo.ScriptLineNumber); errorId=$($failure.FullyQualifiedErrorId)"
    $exception = $failure.Exception
    for ($depth = 0; $null -ne $exception -and $depth -lt 4; $depth++) {
        $detail += "; $($exception.GetType().FullName) HResult=$($exception.HResult.ToString('X8')): $($exception.Message)"
        $exception = $exception.InnerException
    }
    if ($detail.Length -gt 2048) { $detail = $detail.Substring(0, 2048) }
    [Console]::Error.WriteLine($detail)
    try {
        $task = Get-ScheduledTask -TaskPath '\' -TaskName 'EkuboWalletV2-Discard-__OWNER__'
        $task.Description = $detail
        Set-ScheduledTask -InputObject $task | Out-Null
    } catch { [Console]::Error.WriteLine('Could not publish recovery task diagnostic.') }
    exit (10000 + $failure.InvocationInfo.ScriptLineNumber)
}
'@
    $bootstrap = $bootstrap.Replace('__HASH__', $approvedHash).Replace('__OWNER__', $OwnerSid)
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($bootstrap))
    $action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + $encoded)
    $previous = Get-ScheduledTask -TaskPath '\' -TaskName $taskName -ErrorAction SilentlyContinue
    if ($previous) {
        if ($previous.State -eq 'Running' -or $previous.State -eq 'Queued') { throw 'The previous SYSTEM discard is still running; wait for its completion.' }
        if (@($previous.Actions).Count -ne 1 -or $previous.Actions[0].Execute -ne $action.Execute -or
            $previous.Actions[0].Arguments -ne $action.Arguments -or $previous.Principal.UserId -notin @('SYSTEM', 'S-1-5-18')) {
            throw 'Unexpected task occupies the fixed recovery task name; refusing to replace it.'
        }
        # A launcher crash does not strand the durable cleanup journal. Remove
        # only its completed exact task before repeating protected validation.
        Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false
    }
    $system = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero)
    Register-ScheduledTask -TaskPath '\' -TaskName $taskName -Action $action -Principal $system -Settings $settings | Out-Null
    $started = [DateTime]::Now.AddSeconds(-2)
    Start-ScheduledTask -TaskPath '\' -TaskName $taskName
    $wait = [Diagnostics.Stopwatch]::StartNew()
    $completedRun = $null
    # Never terminate a cleanup halfway through its durable, resumable steps.
    do {
        Start-Sleep -Milliseconds 200
        $info = Get-ScheduledTaskInfo -TaskPath '\' -TaskName $taskName
        $task = Get-ScheduledTask -TaskPath '\' -TaskName $taskName
        $terminal = $info.LastRunTime -gt $started -and $task.State -ne 'Running' -and $task.State -ne 'Queued' -and $info.LastTaskResult -ne 0x41301
        # State and last-result are separate scheduler reads. Require the same
        # terminal run/result twice rather than accepting a transition snapshot.
        $run = if ($terminal) { "$($info.LastRunTime.Ticks):$($info.LastTaskResult)" } else { $null }
        $finished = $terminal -and $run -eq $completedRun
        $completedRun = $run
        if (-not $finished -and $wait.Elapsed.TotalSeconds -ge 120) {
            throw "SYSTEM discard has not completed within 120 seconds (task $taskName, state $($task.State), result $($info.LastTaskResult)). Task and recovery journal retained; inspect completion before retrying. Cleanup was not terminated."
        }
    } until ($finished)
    Unregister-ScheduledTask -TaskPath '\' -TaskName $taskName -Confirm:$false
    if ($info.LastTaskResult -ne 0) {
        $detail = [string]$task.Description
        if ($detail.Length -gt 2048) { $detail = $detail.Substring(0, 2048) }
        throw "SYSTEM discard failed ($($info.LastTaskResult)); codes above 10000 identify the source line. Task diagnostic: $detail. Inspect pending state before retrying."
    }
    Write-Output 'SYSTEM discarded the unused pending setup; fresh setup can retry.'
    return
}

# Pin a SYNCHRONIZE handle before STOP: SCM STOPPED can precede process exit.
Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class EkuboRecoveryProcess {
    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint rights,bool inherit,uint pid);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle,uint ms);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
    public static IntPtr Pin(uint pid) {
        var handle=OpenProcess(0x00100000,false,pid);
        if(handle==IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        return handle;
    }
    public static void Wait(IntPtr handle) {
        if(WaitForSingleObject(handle,30000)!=0) throw new InvalidOperationException("Authority process has not exited; cleanup refused.");
    }
}
'@
function Stop-RecoveryService($name) {
    $snapshot = Get-CimInstance Win32_Service -Filter "Name='$name'"
    if (-not $snapshot) { return }
    $handles = [Collections.Generic.List[IntPtr]]::new()
    try {
        if ($snapshot.ProcessId -ne 0) {
            $handles.Add([EkuboRecoveryProcess]::Pin($snapshot.ProcessId))
            if ((Get-CimInstance Win32_Service -Filter "Name='$name'").ProcessId -ne $snapshot.ProcessId) { throw 'Authority process changed during stop.' }
        } elseif ($snapshot.State -ne 'Stopped') { throw 'Authority is transitioning; retry recovery.' }
        # A previous stop/crash may already have made SCM forget its PID while
        # that process is still exiting. Find only the exact fixed service command.
        foreach ($candidate in Get-CimInstance Win32_Process -Filter "Name='ekubo-wallet-service.exe'") {
            if (-not $candidate.CommandLine) { throw 'Cannot identify a surviving authority process; refusing cleanup.' }
            if ($candidate.CommandLine -eq $snapshot.PathName -and $candidate.ProcessId -ne $snapshot.ProcessId) {
                $handles.Add([EkuboRecoveryProcess]::Pin($candidate.ProcessId))
            }
        }
        Stop-Service -Name $name -NoWait
        $controller = Get-Service $name
        try { $controller.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30)) } finally { $controller.Dispose() }
        foreach ($handle in $handles) { [EkuboRecoveryProcess]::Wait($handle) }
    } finally { foreach ($handle in $handles) { [void][EkuboRecoveryProcess]::CloseHandle($handle) } }
}
function Assert-PlainDirectory($path) {
    if (Test-Path -LiteralPath $path) {
        $item = Get-Item -LiteralPath $path -Force
        if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Redirected recovery directory; refusing cleanup.' }
    }
}
function Assert-DirectoryChildren([string]$path, [string[]]$allowedNames) {
    if (Test-Path -LiteralPath $path) {
        foreach ($item in Get-ChildItem -LiteralPath $path -Force) {
            if ($item.Name -notin $allowedNames) { throw 'Unexpected shared v2 state; refusing cleanup.' }
        }
    }
}
function Assert-ProtectedRegistry($path, [bool]$requireProtected = $false) {
    # Decode only the three fixed product keys, never an arbitrary provider path.
    # Registry64 is explicit even if an invoking environment changes its view.
    $root = 'HKLM:\SOFTWARE\EkuboWalletV2'
    if ([string]::IsNullOrEmpty($path) -or $path -cnotin @($root, ($root + '\Pending'), ($root + '\Pending\' + $OwnerSid))) {
        throw 'Unexpected or empty registry security path.'
    }
    $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    $key = $null
    try {
        $key = $machine.OpenSubKey($path.Substring(6), [Microsoft.Win32.RegistryKeyPermissionCheck]::Default, [Security.AccessControl.RegistryRights]::ReadPermissions)
        if ($null -eq $key) { throw "Missing fixed recovery registry key: $path" }
        $sections = [Security.AccessControl.AccessControlSections]::Owner -bor [Security.AccessControl.AccessControlSections]::Access
        $acl = $key.GetAccessControl($sections)
    } finally {
        if ($null -ne $key) { $key.Dispose() }
        $machine.Dispose()
    }
    # Installer sets D:P on the product root; Pending and owner keys inherit its
    # CI entries. Do not require protected-DACL mode on those inherited children.
    if ($requireProtected -and -not $acl.AreAccessRulesProtected) { throw 'Product registry DACL is not protected.' }
    $trusted = @('S-1-5-18', 'S-1-5-32-544')
    if ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $trusted) { throw 'Untrusted pending registry owner.' }
    $descriptor = [Security.AccessControl.RawSecurityDescriptor]::new($acl.GetSecurityDescriptorBinaryForm(), 0)
    if ($null -eq $descriptor.DiscretionaryAcl) { throw 'Unrestricted pending registry DACL.' }
    foreach ($rule in $acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier])) {
        # Mirror core's read-only allowlist, not a partial write-bit blacklist:
        # GENERIC_READ | GENERIC_EXECUTE | READ_CONTROL | query/enumerate/notify.
        # KR = 0x20019 is permitted. Inherit-only ACEs do not grant this key access;
        # the resolved effective ACE is checked again on each child key.
        $mask = ([int64]$rule.RegistryRights) -band 4294967295
        $inheritOnly = ($rule.PropagationFlags -band [Security.AccessControl.PropagationFlags]::InheritOnly) -ne 0
        if ($rule.AccessControlType -eq 'Allow' -and -not $inheritOnly -and ($mask -band (-bnot [int64]2684485657)) -and $rule.IdentityReference.Value -notin $trusted) {
            throw 'Pending registry is writable by an untrusted identity.'
        }
    }
}
$mutex = [Threading.Mutex]::new($false, 'Global\EkuboWalletV2-Installer')
try { $locked = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $locked = $true }
if (-not $locked) { throw 'Another v2 installer is running.' }
try {
    $registry = 'HKLM:\SOFTWARE\EkuboWalletV2'
    $pendingKey = Join-Path $registry ('Pending\' + $OwnerSid)
    Assert-ProtectedRegistry $registry $true
    # Finish only empty registry scaffolding after a crash in the final registry
    # removals. There must be no storage or service left anywhere in this product.
    if ($DiscardUnused -and -not (Test-Path -LiteralPath $pendingKey)) {
        $root = Get-Item -LiteralPath $registry
        $pendingRoot = Join-Path $registry 'Pending'
        if ($root.ValueCount -ne 0 -or @($root.GetSubKeyNames() | Where-Object { $_ -ne 'Pending' }).Count -or
            (Test-Path -LiteralPath (Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EkuboWalletV2')) -or
            @(Get-Service -Name 'EkuboWalletV2-*' -ErrorAction SilentlyContinue).Count) { throw 'No exact pending identity; refusing cleanup.' }
        if (Test-Path -LiteralPath $pendingRoot) {
            $empty = Get-Item -LiteralPath $pendingRoot
            if ($empty.ValueCount -ne 0 -or $empty.SubKeyCount -ne 0) { throw 'Pending registry is not empty.' }
            Remove-Item -LiteralPath $pendingRoot
        }
        Remove-Item -LiteralPath $registry
        return
    }
    Assert-ProtectedRegistry (Join-Path $registry 'Pending')
    Assert-ProtectedRegistry $pendingKey
    $record = Get-ItemProperty -LiteralPath $pendingKey
    $confirmed = $record.PSObject.Properties['RelayConfirmed'] -and $record.RelayConfirmed -eq 1
    $bytes = [byte[]]$record.Profile
    if ($bytes.Length -gt 4096) { throw 'Oversized profile metadata.' }
    $metadata = [Text.Encoding]::UTF8.GetString($bytes) | ConvertFrom-Json
    $profile = [Guid]$metadata.profile_id
    if ($profile -eq [Guid]::Empty -or $metadata.owner_sid -ne $OwnerSid) { throw 'Fresh setup identity mismatch.' }
    $service = 'EkuboWalletV2-' + $profile.ToString('N')
    $sc = Join-Path ([Environment]::GetFolderPath('System')) 'sc.exe'
    # Derive the fixed virtual-service SID even when a resumed discard has already
    # deleted SCM registration. Windows service SIDs are SHA1(UTF16 uppercase name).
    $hash = [Security.Cryptography.SHA1]::Create()
    try { $digest = $hash.ComputeHash([Text.Encoding]::Unicode.GetBytes($service.ToUpperInvariant())) } finally { $hash.Dispose() }
    $sid = 'S-1-5-80-' + ((0..4 | ForEach-Object { [BitConverter]::ToUInt32($digest, $_ * 4) }) -join '-')
    if ($sid -ne $metadata.service_sid) { throw 'Service identity changed.' }
    $activeKey = Join-Path $registry ('Owners\' + $OwnerSid)
    $storage = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EkuboWalletV2'
    $pending = Join-Path (Join-Path $storage 'Pending') $profile.ToString('N')
    $active = Join-Path (Join-Path $storage 'Owners') $profile.ToString('N')
    if ($DiscardUnused) {
        if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne 'S-1-5-18') { throw 'Discard requires SYSTEM.' }
        if ($confirmed -or (Test-Path -LiteralPath $activeKey) -or (Test-Path -LiteralPath $active)) { throw 'Confirmed or installed profiles can never be discarded.' }
        # Only this first-install layout can be reset. Never remove a shared root
        # containing another owner, another profile, or unknown nested storage.
        foreach ($path in @($storage, (Join-Path $storage 'Pending'), (Join-Path $storage 'Owners'), $pending)) { Assert-PlainDirectory $path }
        if (@(Get-ChildItem -LiteralPath (Join-Path $registry 'Pending')).Count -ne 1) { throw 'Unexpected pending owners.' }
        Assert-DirectoryChildren -path $storage -allowedNames @('Pending', 'Owners')
        Assert-DirectoryChildren -path (Join-Path $storage 'Pending') -allowedNames @($profile.ToString('N'))
        Assert-DirectoryChildren -path (Join-Path $storage 'Owners') -allowedNames @()
        if (Test-Path -LiteralPath (Join-Path $registry 'Owners')) { throw 'An installed-owner collection exists; refusing cleanup.' }
        $root = Get-Item -LiteralPath $registry
        if ($root.ValueCount -ne 0 -or @($root.GetSubKeyNames() | Where-Object { $_ -ne 'Pending' }).Count) { throw 'Unexpected product registry state.' }
        $pendingRoot = Get-Item -LiteralPath (Join-Path $registry 'Pending')
        $leaf = Get-Item -LiteralPath $pendingKey
        if ($pendingRoot.ValueCount -ne 0 -or $leaf.SubKeyCount -ne 0 -or
            @($leaf.GetValueNames() | Where-Object { $_ -notin @('Profile', 'RelayConfirmed', 'Discarding') }).Count) { throw 'Unexpected pending registry state.' }
        $discarding = $record.PSObject.Properties['Discarding'] -and $record.Discarding -eq 1
        $registration = Get-CimInstance Win32_Service -Filter "Name='$service'"
        if ($registration) {
            $expectedCommand = '"' + (Join-Path $install 'ekubo-wallet-service.exe') + '" --provision-owner-sid ' + $OwnerSid
            if ($registration.StartName -ne ('NT SERVICE\' + $service) -or $registration.PathName -ne $expectedCommand) { throw 'Not the exact pending provisioning service.' }
            # Prevent a restart while removing state. This is recoverable even if
            # validation below fails: explicit confirmed recovery restores startup.
            Set-Service -Name $service -StartupType Disabled
            Stop-RecoveryService $service
        } elseif (-not $discarding) { throw 'Missing pending provisioning service.' }
        $again = Get-ItemProperty -LiteralPath $pendingKey
        if ([Convert]::ToBase64String([byte[]]$again.Profile) -ne [Convert]::ToBase64String($bytes) -or
            ($again.PSObject.Properties['RelayConfirmed'] -and $again.RelayConfirmed -ne 0) -or
            (Test-Path -LiteralPath (Join-Path $registry 'Owners')) -or (Test-Path -LiteralPath $active)) { throw 'Pending authority changed; refusing cleanup.' }
        $items = @()
        if (Test-Path -LiteralPath $pending) { $items = @(Get-ChildItem -LiteralPath $pending -Force) }
        elseif (-not $discarding) { throw 'Missing pending storage without a discard journal.' }
        # Closed allowlist, never a recursive arbitrary-file delete. Provisioning
        # creates an empty database; account custody cannot exist without a
        # key-account-* record, and active/readiness/move records are not allowed.
        $allowed = @('service.lock', 'wallet.db', 'wallet.db-wal', 'wallet.db-shm', 'wrapping.key', 'key-database', 'custody.json', 'fresh-profile-ready')
        foreach ($item in $items) {
            if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
                $item.Name -notin $allowed) { throw 'Pending profile may have active authority or unsafe objects; refusing cleanup.' }
        }
        if (Test-Path -LiteralPath (Join-Path $pending 'fresh-profile-ready')) {
            if ([IO.File]::ReadAllText((Join-Path $pending 'fresh-profile-ready')) -ne $profile.ToString()) { throw 'Pending readiness identity mismatch.' }
        }
        # Durable intent survives a crash after any deletion. Keep the identity
        # until files and SCM are gone, so rerunning repeats the exact checks.
        New-ItemProperty -LiteralPath $pendingKey -Name Discarding -PropertyType DWord -Value 1 -Force | Out-Null
        (Get-Item -LiteralPath $pendingKey).Flush()
        foreach ($item in $items) { Remove-Item -LiteralPath $item.FullName -Force }
        foreach ($path in @($pending, (Join-Path $storage 'Pending'), (Join-Path $storage 'Owners'), $storage)) {
            if (Test-Path -LiteralPath $path) { [IO.Directory]::Delete($path) }
        }
        if ($registration) {
            & $sc delete $service
            if ($LASTEXITCODE -ne 0) { throw 'Service registration cleanup failed; rerun discard with retained pending identity.' }
            $deadline = [DateTime]::UtcNow.AddSeconds(30)
            while (Get-CimInstance Win32_Service -Filter "Name='$service'") {
                if ([DateTime]::UtcNow -gt $deadline) { throw 'Service deletion is still pending; identity retained for retry.' }
                Start-Sleep -Milliseconds 200
            }
        }
        Remove-Item -LiteralPath $pendingKey -Recurse
        Remove-Item -LiteralPath (Join-Path $registry 'Pending')
        Remove-Item -LiteralPath $registry
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
    Stop-RecoveryService $service
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
