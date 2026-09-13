param([Parameter(Mandatory=$true)][string]$Installer, [switch]$RequireSignature)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'Installer smoke tests are restricted to disposable GitHub Windows runners.'
}
$Installer = (Resolve-Path -LiteralPath $Installer).Path
if ($RequireSignature -and (Get-AuthenticodeSignature -LiteralPath $Installer).Status -ne 'Valid') {
    throw 'The final NSIS installer is not Authenticode-valid.'
}
$install = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet 2'
$legacy = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Ekubo Wallet'
function LegacySnapshot {
    if (Test-Path -LiteralPath $legacy) {
        Get-ChildItem -LiteralPath $legacy -Recurse -File | Sort-Object FullName | Get-FileHash | ConvertTo-Json -Compress
    }
}
$before = LegacySnapshot
foreach ($attempt in 1..2) {
    $process = Start-Process -FilePath $Installer -ArgumentList '/S' -Wait -PassThru
    if ($process.ExitCode -ne 0) { throw "NSIS install failed: $($process.ExitCode)" }
    foreach ($file in @('ekubo-wallet-v2.exe', 'ekubo-wallet-v2-mcp-bridge.exe', 'ekubo-wallet-service.exe', 'ekubo-wallet-v2-enroll.exe', 'ekubo-wallet-v2-owner-auth.exe', 'install-windows-v2.ps1', 'recover-windows-v2.ps1', 'register-windows-v2-auth.ps1')) {
        if (-not (Test-Path -LiteralPath (Join-Path $install $file))) { throw "Missing installed payload: $file" }
        if ($RequireSignature -and ($file.EndsWith('.exe') -or $file.EndsWith('.ps1')) -and (Get-AuthenticodeSignature -LiteralPath (Join-Path $install $file)).Status -ne 'Valid') {
            throw "The installed executable is not Authenticode-valid: $file"
        }
    }
    $registration = Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\org.ekubo.wallet.v2'
    if ($registration.DisplayName -ne 'Ekubo Wallet 2') { throw 'Wrong installed product identity.' }
}
$process = Start-Process -FilePath (Join-Path $install 'uninstall.exe') -ArgumentList @('/S', "_?=$install") -Wait -PassThru
if ($process.ExitCode -ne 0) { throw 'NSIS uninstall failed.' }
if (Test-Path -LiteralPath (Join-Path $install 'ekubo-wallet-service.exe')) { throw 'Service binary survived uninstall.' }
if ((LegacySnapshot) -ne $before) { throw 'Legacy installation changed.' }
Write-Output 'Actual NSIS install/reinstall/remove passed; fresh enrollment and native authorization remain unverified.'
