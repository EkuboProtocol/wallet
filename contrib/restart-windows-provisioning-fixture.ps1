# Copied beside the synthetic fixture executable on disposable Windows runners.
param(
    [Parameter(Mandatory = $true)][ValidatePattern('^EkuboWallet-[0-9a-f]{32}$')][string]$ServiceName,
    [Parameter(Mandatory = $true)][ValidatePattern('^S-[0-9]+(?:-[0-9]+)+$')][string]$OwnerSid,
    [switch]$StopOnly
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Service restart fixture is restricted to disposable GitHub Windows runners.'
}
$profile = $ServiceName.Substring('EkuboWallet-'.Length)
$directory = Join-Path ([Environment]::GetFolderPath('CommonApplicationData')) ('EkuboScmFixture-' + $profile)
if ([IO.Path]::GetFullPath($PSScriptRoot) -ne [IO.Path]::GetFullPath($directory)) {
    throw 'Restart helper is not in the matching synthetic fixture directory.'
}
$binary = Join-Path $directory 'ekubo-wallet-scm-fixture.exe'
$status = Get-CimInstance Win32_Service -Filter "Name='$ServiceName'"
if ($status.StartName -ne ('NT SERVICE\' + $ServiceName) -or
    $status.PathName -ne ('"' + $binary + '" service ' + $OwnerSid) -or
    $status.ProcessId -eq 0) {
    throw 'Refusing to restart a service outside the matching live fixture.'
}
$original = Get-Process -Id $status.ProcessId
$service = Get-Service -Name $ServiceName
Stop-Service -Name $ServiceName
$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Stopped, [TimeSpan]::FromSeconds(30))
if (-not $original.WaitForExit(30000)) {
    throw 'Original service process did not exit; refusing to start a replacement.'
}
if ($StopOnly) {
    Write-Output 'Original synthetic service process exited for cutover.'
    exit 0
}
Start-Service -Name $ServiceName
$service.WaitForStatus([ServiceProcess.ServiceControllerStatus]::Running, [TimeSpan]::FromSeconds(30))
Write-Output 'Original synthetic service process exited and SCM started the replacement.'
