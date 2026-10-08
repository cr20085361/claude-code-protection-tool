[CmdletBinding()]
param([ValidateRange(15,600)][int]$Seconds=300)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$d=Get-GuardState
$last=Read-GuardJson (Get-GuardPath 'evidence\last-launch.json')
$main=Get-Process -Id $last.Pid -ErrorAction Stop
if($main.Path -ne $d.Desktop.Path -or $main.StartTime.ToUniversalTime().Ticks -ne ([datetime]$last.ProcessStart).ToUniversalTime().Ticks){throw 'No matching protected Desktop.'}
$record=[ordered]@{Time=(Get-Date -Format o);DesktopPid=$last.Pid;DesktopStart=$last.ProcessStart;DesktopHash=$d.Desktop.Hash;CodeHash=$d.CodeGate.PayloadHash;Status='Sampling';CodeObserved=$false;DedicatedCodeProxyObserved=$false;UnexpectedConnectionObserved=$false;CodeIdentities=@();Samples=@();AuthenticatedCodeResponseVerified=$false;Scope='Bounded read-only TCP sampling of exact approved Code paths; no prompt or credentials are collected. Response and file-read evidence are separate.'}
$identities=@{}
$until=(Get-Date).AddSeconds($Seconds)
try {
    while((Get-Date) -lt $until) {
        $alive=Get-Process -Id $last.Pid -ErrorAction SilentlyContinue
        if(-not $alive -or $alive.StartTime.ToUniversalTime().Ticks -ne ([datetime]$last.ProcessStart).ToUniversalTime().Ticks){throw 'Protected Desktop ended during sampling.'}
        $code=@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in @($d.CodePaths)})
        foreach($p in $code) {
            $running=Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue
            if(-not $running){continue}
            $key=([string]$p.ProcessId)+':'+$running.StartTime.ToUniversalTime().Ticks
            if(-not $identities.ContainsKey($key)){$identities[$key]=[ordered]@{Pid=$p.ProcessId;ParentPid=$p.ParentProcessId;Path=$p.ExecutablePath;Hash=(Get-GuardHash $p.ExecutablePath);Started=$running.StartTime.ToUniversalTime().ToString('o')}}
        }
        if($code.Count){$record.CodeObserved=$true}
        $connections=@(Get-NetTCPConnection -ErrorAction SilentlyContinue|Where-Object {$_.OwningProcess -in @($code.ProcessId) -and $_.State -in 'Established','SynSent'}|Select-Object OwningProcess,@{n='State';e={$_.State.ToString()}},RemoteAddress,RemotePort)
        if(@($connections|Where-Object {$_.RemoteAddress -eq '127.0.0.1' -and $_.RemotePort -eq 10818 -and $_.State -eq 'Established'}).Count){$record.DedicatedCodeProxyObserved=$true}
        if(@($connections|Where-Object {($_.RemoteAddress -ne '::1' -and $_.RemoteAddress -notlike '127.*') -or $_.RemotePort -in @(10808,10813)}).Count){$record.UnexpectedConnectionObserved=$true;throw 'Unexpected approved Code connection observed.'}
        if($connections.Count){$record.Samples+=@{Time=(Get-Date -Format o);Connections=$connections}}
        $record.CodeIdentities=@($identities.Values)
        Write-GuardJson (Get-GuardPath 'evidence\code-tcp-observation-v2.json') $record
        Start-Sleep -Seconds 2
    }
    $record.Status='Completed'
} catch {$record.Status='Failed';$record['Error']=$_.Exception.Message;throw}
finally {Write-GuardJson (Get-GuardPath 'evidence\code-tcp-observation-v2.json') $record}
[pscustomobject]$record|Select-Object Time,Status,CodeObserved,DedicatedCodeProxyObserved,UnexpectedConnectionObserved,@{n='CodeIdentityCount';e={$_.CodeIdentities.Count}},@{n='SampleCount';e={$_.Samples.Count}}|ConvertTo-Json
