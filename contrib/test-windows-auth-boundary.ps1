# Disposable CI only. Never installs a service, changes accounts, or requests consent.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
if ($env:GITHUB_ACTIONS -ne 'true' -or $env:RUNNER_ENVIRONMENT -ne 'github-hosted' -or $env:RUNNER_OS -ne 'Windows') {
    throw 'This SYSTEM process fixture is restricted to disposable GitHub-hosted Windows runners.'
}
$collectorArtifacts = & cargo build --locked -p ekubo-wallet-windows-owner-auth --bin ekubo-wallet-v2-owner-auth --message-format=json
if ($LASTEXITCODE -ne 0) { throw 'Could not build the read-only diagnostic collector.' }
$collectors = @($collectorArtifacts | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.target.name -eq 'ekubo-wallet-v2-owner-auth' -and $_.executable } | ForEach-Object executable)
if ($collectors.Count -ne 1) { throw 'Expected exactly one compiled collector executable.' }
$artifacts = & cargo test --locked -p ekubo-wallet-windows-owner-auth --lib --no-run --message-format=json
if ($LASTEXITCODE -ne 0) { throw 'Could not select the native fixture executable.' }
$executables = @($artifacts | ForEach-Object { $_ | ConvertFrom-Json } | Where-Object { $_.reason -eq 'compiler-artifact' -and $_.executable -and $_.profile.test } | ForEach-Object executable)
if ($executables.Count -ne 1) { throw 'Expected exactly one native fixture executable.' }
$name = 'EkuboWalletV2-NativeFixture-' + [Guid]::NewGuid().ToString('N')
$log = Join-Path $env:RUNNER_TEMP ($name + '.log')
$exeLiteral = $executables[0].Replace("'", "''")
$logLiteral = $log.Replace("'", "''")
$collectorLiteral = $collectors[0].Replace("'", "''")
$command = "`$env:EKUBO_WALLET_AUTH_FIXTURE_COLLECTOR='$collectorLiteral'; & '$exeLiteral' --ignored --exact native::tests::system_created_collector_denies_owner_mutation_from_birth --nocapture *> '$logLiteral'; exit `$LASTEXITCODE"
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$powershell = Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$action = New-ScheduledTaskAction -Execute $powershell -Argument ('-NoProfile -NonInteractive -EncodedCommand ' + $encoded)
$principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
try {
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal | Out-Null
    $started = [DateTime]::Now.AddSeconds(-2)
    Start-ScheduledTask -TaskName $name
    $deadline = [DateTime]::Now.AddSeconds(90)
    do {
        Start-Sleep -Milliseconds 200
        $info = Get-ScheduledTaskInfo -TaskName $name
        $task = Get-ScheduledTask -TaskName $name
        if ([DateTime]::Now -gt $deadline) { throw 'Native process fixture timed out.' }
    } until ($info.LastRunTime -gt $started -and $task.State -ne 'Running' -and $task.State -ne 'Queued')
    if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log }
    if ($info.LastTaskResult -ne 0) { throw "Native process boundary fixture failed: $($info.LastTaskResult)" }
} finally {
    if (Get-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue) {
        Stop-ScheduledTask -TaskName $name -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $name -Confirm:$false
    }
}
