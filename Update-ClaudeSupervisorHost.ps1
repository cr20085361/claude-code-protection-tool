#requires -Version 7.4
<#
.SYNOPSIS
Build and install the supervisor host for the currently verified source tree.
.DESCRIPTION
Run in the deployment account's elevated pwsh. -CheckOnly stages the build and
checks the running installation. -Recover resumes rollback of an interrupted
transaction identified by the ID in private/host-upgrade-active.json.
#>
[CmdletBinding(DefaultParameterSetName='Install')]
param(
    [Parameter(ParameterSetName='Check')][switch]$CheckOnly,
    [Parameter(Mandatory,ParameterSetName='Recover')][ValidatePattern('^[0-9a-f]{32}$')][string]$Recover
)
$ErrorActionPreference = 'Stop'

function Assert-HostFileHash([string]$Path, [string]$Expected) {
    if ($Expected -notmatch '^[0-9a-f]{64}$' -or (Get-GuardHash $Path) -ne $Expected) {
        throw "File no longer matches its recorded SHA256: $Path"
    }
}

function Install-HostFile([string]$Source, [string]$Target, [string]$Hash) {
    # A same-volume replacement cannot expose a partially copied EXE or manifest.
    $temp = $Target + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        [IO.File]::Copy($Source, $temp)
        Assert-HostFileHash $temp $Hash
        [IO.File]::Replace($temp, $Target, [NullString]::Value)
        Assert-HostFileHash $Target $Hash
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}

function Assert-HostUpgradeIdle($State) {
    $op = Get-GuardMaintenanceSnapshot
    if ($op.Active -or $op.Interrupted -or $op.Operation.RecoveryRequired) {
        throw 'Complete the existing version maintenance operation first.'
    }
    $paths = @($State.Desktop.Path) + @($State.CodePaths)
    if (Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -in $paths }) {
        throw 'Exit the protected Claude Desktop and local Code sessions before upgrading the host.'
    }
}

function Set-HostUpgradeMarker([string]$Id) {
    $path = Get-GuardPath 'private\maintenance.json'
    $temp = $path + '.' + $Id + '.tmp'
    try {
        Write-GuardJson $temp @{Mode='HostUpgrade'; Token=$Id; Until=[datetimeoffset]::UtcNow.AddMinutes(8).ToString('o')}
        [IO.File]::Move($temp, $path) # Create only. Other maintenance owns any existing marker.
    } finally {
        if ([IO.File]::Exists($temp)) { [IO.File]::Delete($temp) }
    }
}

function Clear-HostUpgradeMarker([string]$Id) {
    $path = Get-GuardPath 'private\maintenance.json'
    if ([IO.File]::Exists($path)) {
        $marker = Read-GuardJson $path
        if ($marker.Mode -ne 'HostUpgrade' -or $marker.Token -cne $Id) { throw 'Another operation owns the maintenance marker.' }
        [IO.File]::Delete($path)
    }
}

function Get-HostUpgradeTask($State) {
    $task = Get-ScheduledTask -TaskName $State.Reliability.TaskName -TaskPath '\' -ErrorAction Stop
    Assert-GuardSupervisorTask $task $State
    $task
}

function New-HostUpgradeStage($State, [string]$Directory) {
    $source = Get-GuardPath 'ClaudeSupervisorHost.cs'
    $exe = Join-Path $Directory 'candidate.exe'
    $launcher = Get-GuardPath 'runtime\ClaudeProGuard.exe'
    $oldHost = Get-GuardPath 'runtime\ClaudeSupervisorHost.exe'
    $statePath = Get-GuardPath 'private\deployment.json'
    $stageState = Join-Path $Directory 'deployment.after.json'
    $originalState = Join-Path $Directory 'deployment.before.json'
    # Hold the exact source bytes from the ledger check through compilation.
    $pin = [IO.File]::Open($source, 'Open', 'Read', 'Read')
    try {
        $version = & (Get-GuardPath 'Test-ClaudeIterationVersion.ps1') -LauncherAssembly $launcher
        if (-not $version.Passed) { throw 'Source/launcher version check failed.' }
        $sourceHash = Get-GuardHash $source
        $compiler = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
        $output = & $compiler /nologo /target:winexe /platform:x64 /reference:System.Web.Extensions.dll ("/out:$exe") $source 2>&1
        if ($LASTEXITCODE -ne 0) { throw "Supervisor host compilation failed: $output" }
    } finally { $pin.Dispose() }

    Assert-GuardReliabilityFiles $State
    $task = Get-HostUpgradeTask $State
    $health = Wait-GuardSupervisorReady -TimeoutSeconds 90
    Assert-GuardCore
    Assert-GuardPolicy -RuntimeOnly
    Assert-GuardFirewall
    $protectedPaths = @((Get-GuardPath 'private\proxy.json'), (Get-GuardPath 'private\firewall.json'),
        (Get-GuardCorePath $State), $launcher, (Join-Path $State.ConfigDir 'settings.json'), $State.OriginalCli.Path) + @($State.CodePaths)
    $protected = @(foreach ($file in $protectedPaths | Sort-Object -Unique) {
        [pscustomobject]@{Path=$file; Hash=(Get-GuardHash $file)}
    })

    $taskPath = Join-Path $Directory 'task.before.xml'
    [IO.File]::WriteAllText($taskPath, (Export-ScheduledTask -TaskName $task.TaskName -TaskPath '\'))
    [IO.File]::Copy($oldHost, (Join-Path $Directory 'host.before.exe'))
    Assert-HostFileHash (Join-Path $Directory 'host.before.exe') $State.Reliability.HostHash
    [IO.File]::Copy($statePath, $originalState)
    $beforeHash = Get-GuardHash $originalState
    Assert-HostFileHash $statePath $beforeHash
    $newHash = Get-GuardHash $exe
    # Preserve historical dates, unknown fields and all non-host approvals.
    $json = [Text.Json.Nodes.JsonNode]::Parse([IO.File]::ReadAllText($originalState))
    if ($json['Reliability']['HostHash'].ToString() -ne $State.Reliability.HostHash) { throw 'Deployment changed during staging.' }
    $json['Reliability']['HostHash'] = [Text.Json.Nodes.JsonValue]::Create([string]$newHash)
    [IO.File]::WriteAllText($stageState, $json.ToJsonString([Text.Json.JsonSerializerOptions]@{WriteIndented=$true}))
    [pscustomobject]@{Version=$version.Version; SourceHash=$sourceHash; OldHost=$State.Reliability.HostHash; NewHost=$newHash
        OldDeployment=$beforeHash; NewDeployment=(Get-GuardHash $stageState); TaskXmlHash=(Get-GuardHash $taskPath)
        RunId=$health.RunId; Proxy=(Read-GuardJson (Get-GuardPath 'private\proxy-process.json')); Protected=$protected}
}

function Confirm-HostUpgrade($State, $Stage, [string]$PreviousRun, [datetimeoffset]$RestartedAt) {
    Assert-GuardReliabilityFiles $State
    $null = Get-HostUpgradeTask $State
    $first = Wait-GuardSupervisorReady -TimeoutSeconds 120
    if ($first.RunId -eq $PreviousRun -or [datetimeoffset]$first.HostStarted -lt $RestartedAt) {
        throw 'Readiness does not belong to the newly started host.'
    }
    Assert-GuardCore
    Assert-GuardPolicy -RuntimeOnly
    Assert-GuardFirewall
    $egress = Test-GuardEgress
    # Compare UTC instants, including when pwsh deserializes JSON dates as DateTime.
    $deadline = [datetimeoffset]::UtcNow.AddSeconds(150)
    do {
        $snapshot = Get-GuardSupervisorSnapshot
        $health = $snapshot.Health
        if ($snapshot.Kind -eq 'SafetyHold' -or ($health.RunId -and $health.RunId -ne $first.RunId)) {
            throw 'Supervisor stopped or changed runs during verification.'
        }
        if ($snapshot.Ready -and [datetimeoffset]$health.LastEgressCheck -gt [datetimeoffset]$first.LastEgressCheck -and
            [datetimeoffset]$health.LastSafetyCheck -gt [datetimeoffset]$first.LastSafetyCheck) { break }
        if ([datetimeoffset]::UtcNow -ge $deadline) { throw 'No second safety and egress cycle on the same host run.' }
        Start-Sleep -Seconds 2
    } while ($true)
    foreach ($entry in $Stage.Protected) { Assert-HostFileHash $entry.Path $entry.Hash }
    Assert-GuardReliabilityFiles $State
    $proxy = Read-GuardJson (Get-GuardPath 'private\proxy-process.json')
    [pscustomobject]@{RunId=$health.RunId; HostPid=$health.HostPid; Status=$health.Status; ProxyPid=$proxy.Pid
        ProxyContinuous=($proxy.Pid -eq $Stage.Proxy.Pid -and [datetimeoffset]$proxy.Started -eq [datetimeoffset]$Stage.Proxy.Started)
        LastSafetyCheck=$health.LastSafetyCheck; LastEgressCheck=$health.LastEgressCheck; VerifiedProbeCount=$egress.VerifiedProbeCount}
}

function Restore-HostUpgrade($Stage, [string]$Directory, [string]$Id) {
    $hostPath = Get-GuardPath 'runtime\ClaudeSupervisorHost.exe'
    $statePath = Get-GuardPath 'private\deployment.json'
    $backupHost = Join-Path $Directory 'host.before.exe'
    $backupState = Join-Path $Directory 'deployment.before.json'
    Assert-HostFileHash $backupHost $Stage.OldHost
    Assert-HostFileHash $backupState $Stage.OldDeployment
    Assert-HostFileHash (Join-Path $Directory 'task.before.xml') $Stage.TaskXmlHash
    $diskHash = Get-GuardHash $hostPath
    if ($diskHash -notin @($Stage.OldHost,$Stage.NewHost) -or (Get-GuardHash $statePath) -notin @($Stage.OldDeployment,$Stage.NewDeployment)) {
        throw 'Unrecognized host or deployment. Backups retained for review.'
    }
    $old = Read-GuardJson $backupState
    $diskState = Read-GuardJson $backupState
    $diskState.Reliability.HostHash = $diskHash # Only one of the two pre-recorded identities.
    $null = Get-HostUpgradeTask $diskState
    $marker = Get-GuardPath 'private\maintenance.json'
    if ([IO.File]::Exists($marker)) {
        $owner = Read-GuardJson $marker
        if ($owner.Token -cne $Id -or $owner.Mode -ne 'HostUpgrade') { throw 'Another operation owns the maintenance marker.' }
    } else { Set-HostUpgradeMarker $Id }
    $null = Suspend-GuardSupervisorTask -State $diskState
    if ($diskHash -ne $Stage.OldHost) { Install-HostFile $backupHost $hostPath $Stage.OldHost }
    Install-HostFile $backupState $statePath $Stage.OldDeployment
    Assert-GuardReliabilityFiles $old
    Assert-GuardCore -ConfigurationOnly
    Clear-HostUpgradeMarker $Id
    $start = [datetimeoffset]::UtcNow
    Resume-GuardSupervisorTask -State $old
    Confirm-HostUpgrade $old $Stage $Stage.RunId $start
}

function Invoke-HostUpgrade([switch]$CheckOnly, [string]$RecoveryId) {
    $lock = Get-GuardMaintenanceLock 'Install'
    $held = $false
    $dir = $null
    $activePath = Get-GuardPath 'private\host-upgrade-active.json'
    $markerPath = Get-GuardPath 'private\maintenance.json'
    $owned = $false
    try {
        try { $held = $lock.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'A component installer is already running.' }
        $state = Get-GuardState
        if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $state.UserSid -or (-not $CheckOnly -and -not (Test-GuardAdmin))) {
            throw 'Use the installation account and elevate pwsh to install or recover.'
        }
        Assert-HostUpgradeIdle $state
        if ($RecoveryId) {
            $active = Read-GuardJson $activePath
            if ($active.Id -cne $RecoveryId) { throw 'Only the active host transaction can be recovered.' }
            $id = $RecoveryId
        } else {
            if ([IO.File]::Exists($activePath)) { throw "Recover the interrupted host transaction first. See $activePath" }
            if ([IO.File]::Exists($markerPath)) { throw 'Another maintenance marker is present.' }
            $id = [guid]::NewGuid().ToString('N')
        }
        $dir = Get-GuardPath ('private\host-upgrade-' + $id)
        $manifest = Join-Path $dir 'stage.json'
        $result = [ordered]@{Id=$id;Directory=$dir;StartedAt=[datetimeoffset]::Now;Success=$false;Status='Preparing'}
        if ($RecoveryId) {
            Assert-HostFileHash $manifest $active.ManifestHash
            $stage = Read-GuardJson $manifest
            $result.Health = Restore-HostUpgrade $stage $dir $id
            $result.Status = 'RolledBack'
        } else {
            $null = New-Item -ItemType Directory -Path $dir -ErrorAction Stop
            $stage = New-HostUpgradeStage $state $dir
            Write-GuardJson $manifest $stage
            $result.Version = $stage.Version
            if ($CheckOnly) {
                $result.Status = 'Checked'
            } else {
                Assert-HostUpgradeIdle $state
                Assert-HostFileHash (Get-GuardPath 'private\deployment.json') $stage.OldDeployment
                Assert-HostFileHash (Get-GuardPath 'runtime\ClaudeSupervisorHost.exe') $stage.OldHost
                $active = @{Id=$id;ManifestHash=(Get-GuardHash $manifest)}
                Write-GuardJson $activePath $active
                try { Set-HostUpgradeMarker $id } catch {
                    [IO.File]::Delete($activePath)
                    throw
                }
                $owned = $true
                $null = Suspend-GuardSupervisorTask -State $state
                Assert-GuardCore -ConfigurationOnly
                $after = Join-Path $dir 'deployment.after.json'
                Assert-HostFileHash $after $stage.NewDeployment
                $candidate = Read-GuardJson $after
                Install-HostFile (Join-Path $dir 'candidate.exe') $state.Reliability.HostPath $stage.NewHost
                Assert-GuardReliabilityFiles $candidate
                $null = Get-HostUpgradeTask $candidate
                Install-HostFile $after (Get-GuardPath 'private\deployment.json') $stage.NewDeployment
                Clear-HostUpgradeMarker $id
                $start = [datetimeoffset]::UtcNow
                Resume-GuardSupervisorTask -State $candidate
                $result.Health = Confirm-HostUpgrade $candidate $stage $stage.RunId $start
                $result.Status = 'Installed'
            }
        }
        $result.Success = $true
        Write-GuardJson (Join-Path $dir 'result.json') $result
        if ($owned -or $RecoveryId) { [IO.File]::Delete($activePath) }
        [pscustomobject]$result
    } catch {
        $failure = $_
        if ($dir -and [IO.Directory]::Exists($dir)) {
            $result.Error = $failure.Exception.Message
            $result.Success = $false
            $result.Status = 'Failed'
            if ($owned) {
                try {
                    Assert-HostFileHash $manifest $active.ManifestHash
                    $result.RollbackHealth = Restore-HostUpgrade (Read-GuardJson $manifest) $dir $id
                    $result.Status = 'RolledBack'
                } catch {
                    $result.Status = 'RecoveryRequired'
                    $result.RollbackError = $_.Exception.Message
                }
            } elseif ($RecoveryId) { $result.Status = 'RecoveryRequired' }
            Write-GuardJson (Join-Path $dir 'result.json') $result
            if ($result.Status -eq 'RolledBack') { [IO.File]::Delete($activePath) }
            throw "$($failure.Exception.Message) [$($result.Status)] $dir\result.json"
        }
        throw
    } finally {
        if ($held) { $lock.ReleaseMutex() }
        $lock.Dispose()
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
    Invoke-HostUpgrade -CheckOnly:$CheckOnly -RecoveryId $Recover
}
