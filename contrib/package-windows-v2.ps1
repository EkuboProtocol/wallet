# Package lifecycle only. Fresh enrollment needs the actual owner's live relay,
# and must be invoked explicitly with install-windows-v2.ps1, never guessed here.
param([Parameter(Mandatory=$true)][ValidateSet('Before', 'After', 'Remove')][string]$Mode)
trap {
    # Put the cause first: nsExec's stack output is bounded by NSIS_MAX_STRLEN.
    # Avoid PowerShell's verbose error rendering burying it below context.
    [Console]::Error.WriteLine(('V2 {0}: {1}: {2}' -f $Mode, $_.Exception.GetType().FullName, $_.Exception.Message))
    [Console]::Error.WriteLine(('ErrorId={0}; line={1}; PS={2}; 64bit={3}' -f $_.FullyQualifiedErrorId, $_.InvocationInfo.ScriptLineNumber, $PSVersionTable.PSVersion, [Environment]::Is64BitProcess))
    [Console]::Error.WriteLine($_.ScriptStackTrace)
    exit 1
}
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2'
if (-not [Environment]::Is64BitProcess) { throw 'Package lifecycle requires 64-bit PowerShell.' }
function Assert-ProtectedCode($path) {
    if ((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw "Refusing redirected installed code: $path"
    }
    $acl = Get-Acl -LiteralPath $path
    $owner = $acl.GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -notin @('S-1-5-18', 'S-1-5-32-544')) { throw "Untrusted code owner: $path" }
    $write = [Security.AccessControl.FileSystemRights]::Write -bor [Security.AccessControl.FileSystemRights]::Delete -bor [Security.AccessControl.FileSystemRights]::DeleteSubdirectoriesAndFiles -bor [Security.AccessControl.FileSystemRights]::ChangePermissions -bor [Security.AccessControl.FileSystemRights]::TakeOwnership
    foreach ($rule in $acl.Access) {
        $sid = $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
        if ($rule.AccessControlType -eq 'Allow' -and ($rule.FileSystemRights -band $write) -ne 0 -and $sid -notin @('S-1-5-18', 'S-1-5-32-544')) {
            throw "Non-administrator code writer: $path ($sid)"
        }
    }
}
if ($Mode -eq 'Before') {
    foreach ($name in @('ekubo-wallet-v2', 'ekubo-wallet-v2-mcp-bridge', 'ekubo-wallet-v2-enroll')) {
        if (Get-Process -Name $name -ErrorAction SilentlyContinue) {
            throw "Close $name before upgrading Ekubo Wallet 2."
        }
    }
    if (-not (Test-Path -LiteralPath $install)) {
        $acl = [Security.AccessControl.DirectorySecurity]::new()
        $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FRFX;;;AU)')
        [IO.Directory]::CreateDirectory($install, $acl) | Out-Null
    }
    Assert-ProtectedCode $install
    # Stop at any reparse point before recursion, rather than following it.
    $directories = [Collections.Generic.Queue[string]]::new()
    $directories.Enqueue($install)
    while ($directories.Count -gt 0) {
        foreach ($entry in Get-ChildItem -LiteralPath ($directories.Dequeue()) -Force) {
            Assert-ProtectedCode $entry.FullName
            if ($entry.PSIsContainer) { $directories.Enqueue($entry.FullName) }
        }
    }
}
if ($Mode -eq 'After') {
    # Only the fixed executable installation tree, never custody/configuration.
    # Explicit ownership avoids making the interactive administrator's normal
    # unelevated token the owner of subsequently installed executable files.
    $directories = [Collections.Generic.Queue[string]]::new()
    $directories.Enqueue($install)
    while ($directories.Count -gt 0) {
        $directory = $directories.Dequeue()
        $entries = @((Get-Item -LiteralPath $directory)) + @(Get-ChildItem -LiteralPath $directory -Force)
        foreach ($entry in $entries) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Refusing redirected installed code.' }
            if ($entry.PSIsContainer) {
                $acl = [Security.AccessControl.DirectorySecurity]::new()
                $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FRFX;;;AU)')
                if ($entry.FullName -ne $directory) { $directories.Enqueue($entry.FullName) }
            } else {
                $acl = [Security.AccessControl.FileSecurity]::new()
                $acl.SetSecurityDescriptorSddlForm('O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;AU)')
            }
            Set-Acl -LiteralPath $entry.FullName -AclObject $acl
        }
    }
}
if ($Mode -eq 'After' -and (Test-Path -LiteralPath 'HKLM:\SOFTWARE\EkuboWalletV2\Owners')) {
    foreach ($owner in Get-ChildItem -LiteralPath 'HKLM:\SOFTWARE\EkuboWalletV2\Owners') {
        & (Join-Path $install 'register-windows-v2-auth.ps1') -OwnerSid $owner.PSChildName
    }
}
$services = @(Get-Service -Name 'EkuboWalletV2-*' -ErrorAction SilentlyContinue | Sort-Object Name)
foreach ($service in $services) {
    if ($service.Name -notmatch '^EkuboWalletV2-[0-9a-f]{32}(-Auth)?$') { throw 'Unexpected v2 service identity.' }
    $config = Get-CimInstance Win32_Service -Filter "Name='$($service.Name)'"
    if ($Mode -eq 'Before' -and $config.PathName -match '--provision-owner-sid' -and $service.Status -ne 'Stopped') {
        throw 'Complete or recover the in-progress v2 enrollment before replacing installed code.'
    }
    if ($Mode -eq 'After') {
        # Start only completed registrations, never an interrupted provisioner.
        if ($config.PathName -match '--provision-owner-sid') { continue }
        if ($config.StartMode -eq 'Auto') { Start-Service $service.Name }
    } else {
        Stop-Service $service.Name
        $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    }
}
