# Synthetic cross-account fixture for disposable GitHub Windows runners only.
param([Parameter(Mandatory = $true)][string]$FixtureBinary, [switch]$StopAfterClient)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This fixture requires a disposable GitHub Windows runner.'
}
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'The fixture requires an elevated runner.'
}
if (-not [Environment]::Is64BitProcess) { throw 'The fixture requires the 64-bit registry view.' }
$registryPath = 'HKLM:\SOFTWARE\EkuboWallet'
if (Test-Path $registryPath) { throw 'Refusing to touch an existing Ekubo installation.' }
$storageRoot = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) 'EkuboWallet'
if (Test-Path $storageRoot) { throw 'Refusing to touch existing Ekubo storage.' }
$profile = [Guid]::NewGuid()
$serviceName = 'EkuboWallet-' + $profile.ToString('N')
$owner = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
$directory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('EkuboScmFixture-' + $profile.ToString('N'))
if (Test-Path $directory) { throw 'Fixture directory already exists.' }
$binary = Join-Path $directory 'ekubo-wallet-scm-fixture.exe'
$serviceCreated = $false
$registryCreated = $false
$directoryCreated = $false
$storageCreated = $false
$serviceProcess = $null

function Invoke-Sc([string[]]$Arguments) {
    & sc.exe @Arguments
    if ($LASTEXITCODE -ne 0) { throw "sc.exe failed: $($Arguments[0]) ($LASTEXITCODE)" }
}

try {
    New-Item -ItemType Directory -Path $directory | Out-Null
    $directoryCreated = $true
    Copy-Item -LiteralPath (Resolve-Path -LiteralPath $FixtureBinary).Path -Destination $binary
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'restart-windows-provisioning-fixture.ps1') -Destination $directory
    $command = '"' + $binary + '" service ' + $owner
    Invoke-Sc -Arguments @('create', $serviceName, 'binPath=', $command, 'start=', 'demand', 'obj=', ('NT SERVICE\' + $serviceName))
    $serviceCreated = $true
    $serviceSid = [Security.Principal.NTAccount]::new('NT SERVICE', $serviceName).Translate([Security.Principal.SecurityIdentifier]).Value
    if ($serviceSid -eq $owner) { throw 'Service and installer identities must differ.' }

    # Only administrators/System may change the fixture executable. The virtual
    # account receives read/execute access, not the runner's user authority.
    $fileSecurity = [Security.AccessControl.DirectorySecurity]::new()
    $fileSecurity.SetSecurityDescriptorSddlForm("O:BAD:P(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FRFX;;;$serviceSid)")
    Set-Acl -LiteralPath $directory -AclObject $fileSecurity
    $exeSecurity = [Security.AccessControl.FileSecurity]::new()
    $exeSecurity.SetSecurityDescriptorSddlForm("O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;$serviceSid)")
    Set-Acl -LiteralPath $binary -AclObject $exeSecurity
    Set-Acl -LiteralPath (Join-Path $directory 'restart-windows-provisioning-fixture.ps1') -AclObject $exeSecurity
    $resultFile = Join-Path $directory 'service-result.txt'
    Set-Content -LiteralPath $resultFile -Value 'Service has not returned.'
    $resultSecurity = [Security.AccessControl.FileSecurity]::new()
    $resultSecurity.SetSecurityDescriptorSddlForm("O:BAD:P(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFW;;;$serviceSid)")
    Set-Acl -LiteralPath $resultFile -AclObject $resultSecurity

    New-Item -Path $registryPath | Out-Null
    $registryCreated = $true
    $registrySecurity = [Security.AccessControl.RegistrySecurity]::new()
    $registrySecurity.SetSecurityDescriptorSddlForm("O:BAD:P(A;CI;KA;;;BA)(A;CI;KA;;;SY)(A;CI;KR;;;$serviceSid)")
    $machine = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::Registry64)
    try {
        $key = $machine.OpenSubKey('SOFTWARE\EkuboWallet', [Microsoft.Win32.RegistryKeyPermissionCheck]::ReadWriteSubTree, [Security.AccessControl.RegistryRights]::FullControl)
        if ($null -eq $key) { throw 'The fixture registry key was not created.' }
        try { [Microsoft.Win32.RegistryAclExtensions]::SetAccessControl($key, $registrySecurity) }
        finally { $key.Dispose() }
    } finally { $machine.Dispose() }
    $pendingPath = Join-Path $registryPath ('Pending\' + $owner)
    New-Item -Path $pendingPath -Force | Out-Null
    $metadata = @{ owner_sid = $owner; service_sid = $serviceSid; profile_id = $profile.ToString() } | ConvertTo-Json -Compress
    New-ItemProperty -LiteralPath $pendingPath -Name Profile -PropertyType Binary -Value ([Text.Encoding]::UTF8.GetBytes($metadata)) | Out-Null

    New-Item -ItemType Directory -Path $storageRoot | Out-Null
    $storageCreated = $true
    Set-Acl -LiteralPath $storageRoot -AclObject $fileSecurity
    $pendingStorage = Join-Path $storageRoot 'Pending'
    New-Item -ItemType Directory -Path $pendingStorage | Out-Null
    Set-Acl -LiteralPath $pendingStorage -AclObject $fileSecurity
    $privateStorage = Join-Path $pendingStorage ($profile.ToString('N'))
    New-Item -ItemType Directory -Path $privateStorage | Out-Null
    $privateSecurity = [Security.AccessControl.DirectorySecurity]::new()
    $privateSecurity.SetSecurityDescriptorSddlForm("D:P(A;OICI;FA;;;$serviceSid)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)")
    Set-Acl -LiteralPath $privateStorage -AclObject $privateSecurity
    New-Item -ItemType File -Path (Join-Path $privateStorage 'service.lock') | Out-Null
    # Assign ownership only within the freshly created synthetic private tree.
    & icacls.exe $privateStorage /setowner ("*" + $serviceSid) /T /Q
    if ($LASTEXITCODE -ne 0) { throw 'Could not assign fixture storage to the virtual account.' }

    Invoke-Sc -Arguments @('start', $serviceName)
    $service = Get-Service -Name $serviceName
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
    $processId = (Get-CimInstance Win32_Service -Filter "Name='$serviceName'").ProcessId
    $serviceProcess = Get-Process -Id $processId
    & $binary client $owner
    if ($LASTEXITCODE -ne 0) { throw "Native cross-account exchange failed ($LASTEXITCODE)." }
    if ($StopAfterClient) {
        $processId = (Get-CimInstance Win32_Service -Filter "Name='$serviceName'").ProcessId
        $serviceProcess = Get-Process -Id $processId
        Stop-Service -Name $serviceName
    }
    $service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
    $status = Get-CimInstance Win32_Service -Filter "Name='$serviceName'"
    if ($status.ExitCode -ne 0 -or $status.ServiceSpecificExitCode -ne 0) {
        throw "Service reported failure: $($status.ExitCode)/$($status.ServiceSpecificExitCode)"
    }
    Write-Output 'Production pending SCM bootstrap, protected storage and cross-account provisioning authentication passed.'
} finally {
    if ($serviceCreated) {
        # Only this invocation's randomly named synthetic service is stopped.
        & sc.exe queryex $serviceName
        $cleanupService = Get-Service -Name $serviceName
        if ($cleanupService.Status -ne [ServiceProcess.ServiceControllerStatus]::Stopped) {
            $processId = (Get-CimInstance Win32_Service -Filter "Name='$serviceName'").ProcessId
            if ($processId -ne 0) { $serviceProcess = Get-Process -Id $processId -ErrorAction SilentlyContinue }
            Stop-Service -Name $serviceName
            $cleanupService.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
        }
        Invoke-Sc -Arguments @('delete', $serviceName)
    }
    if ($null -ne $serviceProcess -and -not $serviceProcess.WaitForExit(30000)) {
        throw 'Fixture process did not exit; preserving its files for diagnosis.'
    }
    if (Test-Path (Join-Path $directory 'service-result.txt')) {
        Get-Content -LiteralPath (Join-Path $directory 'service-result.txt')
    }
    # Refusal above and creation flags confine cleanup to this fixture's objects.
    if ($registryCreated) { Remove-Item -LiteralPath $registryPath -Recurse }
    if ($storageCreated) { Remove-Item -LiteralPath $storageRoot -Recurse }
    if ($directoryCreated) { Remove-Item -LiteralPath $directory -Recurse }
}
