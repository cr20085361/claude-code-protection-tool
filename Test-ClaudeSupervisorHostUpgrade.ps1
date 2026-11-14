#requires -Version 7.4
[CmdletBinding()]
param()
$ErrorActionPreference = 'Stop'
$repo = $PSScriptRoot
. (Join-Path $repo 'Update-ClaudeSupervisorHost.ps1')

# Exercise the actual installer and filesystem operations in TEMP. Only the live
# dependencies (task scheduler, clients, policy, network and health) are doubles.
$suite = Join-Path ([IO.Path]::GetTempPath()) ('ClaudeHostUpgradeTests-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $suite
$cases = [Collections.Generic.List[string]]::new()
function Require([bool]$Condition, [string]$Message) { if (-not $Condition) { throw $Message } }
function Get-GuardPath([string]$Name) { Join-Path $script:fixture $Name }
function Read-GuardJson([string]$Path) { [IO.File]::ReadAllText($Path) | ConvertFrom-Json }
function Write-GuardJson([string]$Path, $Value) { [IO.File]::WriteAllText($Path, ($Value | ConvertTo-Json -Depth 30)) }
function Get-GuardHash([string]$Path) { (Get-FileHash -LiteralPath $Path).Hash }
function Get-GuardState { Read-GuardJson (Get-GuardPath 'private\deployment.json') }
function Get-GuardCorePath($State) { Get-GuardPath 'runtime\core.bin' }
function Test-GuardAdmin { $true }
function Get-GuardMaintenanceLock($Purpose) { [Threading.Mutex]::new($false) }
function Get-GuardMaintenanceSnapshot { [pscustomobject]@{Active=$false; Interrupted=$false; Operation=$null} }
function Get-CimInstance($ClassName) { @() }
function Export-ScheduledTask($TaskName,$TaskPath) { '<Task>unchanged</Task>' }
function Get-ScheduledTask($TaskName,$TaskPath) { [pscustomobject]@{TaskName=$TaskName; State=$script:taskState} }
function Assert-GuardSupervisorTask($Task,$State) { Assert-HostFileHash $State.Reliability.HostPath $State.Reliability.HostHash }
function Assert-GuardReliabilityFiles($State) { Assert-GuardSupervisorTask $null $State }
function Assert-GuardCore([switch]$ConfigurationOnly) {
    if (-not $ConfigurationOnly -and $script:taskState -ne 'Running') { throw 'Runtime check in the stopped window.' }
    if ($ConfigurationOnly) { $script:configChecked=$true }
}
function Assert-GuardPolicy([switch]$RuntimeOnly) { }
function Assert-GuardFirewall { }
function Test-GuardEgress { [pscustomobject]@{VerifiedProbeCount=2} }
function Suspend-GuardSupervisorTask($State) {
    Assert-GuardSupervisorTask $null $State
    $script:stops++
    $script:taskState='Disabled'
}
function Resume-GuardSupervisorTask($State) {
    Assert-GuardSupervisorTask $null $State
    Assert-GuardSupervisorTask $null (Get-GuardState)
    Require (-not (Test-Path (Get-GuardPath 'private\maintenance.json'))) 'Marker left at restart.'
    $script:taskState='Running'
    $script:run=[guid]::NewGuid().ToString()
    $script:started=[datetimeoffset]::UtcNow
}
function Wait-GuardSupervisorReady($TimeoutSeconds) {
    Require ($script:taskState -eq 'Running') 'Wait before resume.'
    $id = if ($script:inject -eq 'stale' -and $script:stops -eq 1) { 'prior' } else { $script:run }
    [pscustomobject]@{RunId=$id; HostStarted=$script:started; LastEgressCheck=$script:started; LastSafetyCheck=$script:started}
}
function Get-GuardSupervisorSnapshot {
    $id = if ($script:inject -eq 'changed-run' -and $script:stops -eq 1) { 'other' } else { $script:run }
    [pscustomobject]@{Ready=$true;Kind='Healthy';Health=[pscustomobject]@{RunId=$id;HostPid=101;Status='Healthy'
        LastSafetyCheck=$script:started.AddSeconds(61);LastEgressCheck=$script:started.AddSeconds(62)}}
}
function New-Fixture([string]$Name) {
    $script:fixture=Join-Path $suite $Name
    $script:inject=''; $script:stops=0; $script:run='prior'; $script:started=[datetimeoffset]::UtcNow.AddMinutes(-5)
    $script:configChecked=$false; $script:taskState='Running'
    $null=New-Item -ItemType Directory -Path (Get-GuardPath 'private'),(Get-GuardPath 'runtime'),(Get-GuardPath 'config')
    foreach ($file in @('runtime\core.bin','runtime\ClaudeSupervisorHost.exe','runtime\ClaudeProGuard.exe',
        'private\proxy.json','private\firewall.json','config\settings.json','original.json','approved.exe')) {
        [IO.File]::WriteAllText((Get-GuardPath $file), "fixture $file")
    }
    Copy-Item (Join-Path $repo 'ClaudeSupervisorHost.cs') (Get-GuardPath 'ClaudeSupervisorHost.cs')
    [IO.File]::WriteAllText((Get-GuardPath 'Test-ClaudeIterationVersion.ps1'), 'param($LauncherAssembly) [pscustomobject]@{Passed=$true;Version="v9.8.7"}')
    $script:hostFile=Get-GuardPath 'runtime\ClaudeSupervisorHost.exe'
    $script:deploymentFile=Get-GuardPath 'private\deployment.json'
    $script:active=Get-GuardPath 'private\host-upgrade-active.json'
    $script:oldHost=Get-GuardHash $script:hostFile
    Write-GuardJson $script:deploymentFile @{UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        Reliability=@{HostPath=$script:hostFile;HostHash=$script:oldHost;TaskName='Fixture';UnrecognizedField='preserve-me'}
        Desktop=@{Path='fixture-desktop'};CodePaths=@((Get-GuardPath 'approved.exe'));ConfigDir=(Get-GuardPath 'config')
        OriginalCli=@{Path=(Get-GuardPath 'original.json')};OriginalDate='2026-11-01T10:21:34.120+08:00'}
    $script:oldManifest=Get-GuardHash $script:deploymentFile
    Write-GuardJson (Get-GuardPath 'private\proxy-process.json') @{Pid=202;Started=[datetimeoffset]::UtcNow}
}
function Expect-Failure([scriptblock]$Action,[string]$Text) {
    try { $null=& $Action } catch {
        if ($_.Exception.Message -notlike "*$Text*") { throw }
        return
    }
    throw "Expected refusal: $Text"
}
function Assert-Restored {
    Assert-HostFileHash $script:hostFile $script:oldHost
    Assert-HostFileHash $script:deploymentFile $script:oldManifest
    Require ($script:taskState -eq 'Running' -and -not [IO.File]::Exists($script:active)) 'Rollback did not complete.'
}
try {
    New-Fixture 'check'
    $r=Invoke-HostUpgrade -CheckOnly
    Require ($r.Status -eq 'Checked' -and $script:stops -eq 0) 'Check-only disrupted the task.'
    Assert-Restored
    $cases.Add('Check-only compiles and verifies before any suspension')

    New-Fixture 'install'
    $r=Invoke-HostUpgrade
    $stage=Read-GuardJson (Join-Path $r.Directory 'stage.json')
    Assert-HostFileHash $script:hostFile $stage.NewHost
    Assert-HostFileHash $script:deploymentFile $stage.NewDeployment
    Assert-HostFileHash (Join-Path $r.Directory 'host.before.exe') $script:oldHost
    $json=[Text.Json.Nodes.JsonNode]::Parse([IO.File]::ReadAllText($script:deploymentFile))
    Require ($json['OriginalDate'].ToString() -ceq '2026-11-01T10:21:34.120+08:00' -and $json['Reliability']['UnrecognizedField'].ToString() -ceq 'preserve-me') 'Non-host approval changed.'
    Require ($r.Success -and $r.Health.RunId -ne 'prior' -and $script:configChecked -and $script:stops -eq 1) 'Install did not verify a new run.'
    $cases.Add('Install preserves unrelated approvals, task identity and checked backups')

    foreach ($fault in @('stale','changed-run')) {
        New-Fixture $fault
        $script:inject=$fault
        Expect-Failure {Invoke-HostUpgrade} 'RolledBack'
        Assert-Restored
        $cases.Add("Reject $fault health and restore original bytes with a fresh healthy run")
    }
    foreach ($split in @('binary-only','manifest-only','unknown-host','corrupt-backup','foreign-marker')) {
        New-Fixture $split
        $r=Invoke-HostUpgrade -CheckOnly
        $manifest=Join-Path $r.Directory 'stage.json'
        $stage=Read-GuardJson $manifest
        Write-GuardJson $script:active @{Id=$r.Id;ManifestHash=(Get-GuardHash $manifest)}
        $script:taskState='Disabled'
        switch ($split) {
            'binary-only' {Install-HostFile (Join-Path $r.Directory 'candidate.exe') $script:hostFile $stage.NewHost}
            'manifest-only' {Install-HostFile (Join-Path $r.Directory 'deployment.after.json') $script:deploymentFile $stage.NewDeployment}
            'unknown-host' {[IO.File]::WriteAllText($script:hostFile,'unknown')}
            'corrupt-backup' {[IO.File]::WriteAllText((Join-Path $r.Directory 'host.before.exe'),'corrupt')}
            'foreign-marker' {Write-GuardJson (Get-GuardPath 'private\maintenance.json') @{Mode='VersionMigration';Token='different'}}
        }
        if ($split -in @('binary-only','manifest-only')) {
            $restored=Invoke-HostUpgrade -RecoveryId $r.Id
            Require ($restored.Status -eq 'RolledBack') 'Interrupted transaction did not recover.'
            Assert-Restored
        } else {
            Expect-Failure {Invoke-HostUpgrade -RecoveryId $r.Id} 'RecoveryRequired'
            Require ([IO.File]::Exists($script:active) -and $script:stops -eq 0) 'Refusal modified an unknown deployment.'
        }
        $cases.Add("Interrupted transaction: $split")
    }
    [pscustomobject]@{Passed=$true;ProductionTouched=$false;Count=$cases.Count;Cases=$cases.ToArray()}
} finally {
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
    if ([IO.Path]::GetDirectoryName($suite) -ne $temp -or [IO.Path]::GetFileName($suite) -notmatch '^ClaudeHostUpgradeTests-[0-9a-f]{32}$') { throw 'Invalid fixture cleanup path.' }
    Remove-Item -LiteralPath $suite -Recurse -Force
}
