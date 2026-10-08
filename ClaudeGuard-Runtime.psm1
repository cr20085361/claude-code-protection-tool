Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1')
function Invoke-GuardEnvironmentReader([string]$PythonPath,[string]$ReaderPath,[int]$ProcessId,[int]$TimeoutMilliseconds) {
    if($TimeoutMilliseconds -le 0){return [pscustomobject]@{ExitCode=124;Output='';TimedOut=$true}}
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$PythonPath;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.ArgumentList.Add($ReaderPath);$info.ArgumentList.Add([string]$ProcessId)
    $reader=[Diagnostics.Process]::new();$reader.StartInfo=$info
    $deadlineClock=[Diagnostics.Stopwatch]::StartNew()
    try {
        if(-not $reader.Start()){throw 'Environment evidence reader could not start.'}
        $output=$reader.StandardOutput.ReadToEndAsync();$errors=$reader.StandardError.ReadToEndAsync()
        $remaining=[Math]::Max(0,$TimeoutMilliseconds-[int]$deadlineClock.ElapsedMilliseconds)
        if(-not $reader.WaitForExit($remaining)){
            # 仅结束本次创建的 reader；不终止目标 Claude 或其它证据进程。
            try{$reader.Kill()}catch{}
            return [pscustomobject]@{ExitCode=124;Output='';TimedOut=$true}
        }
        [pscustomobject]@{ExitCode=$reader.ExitCode;Output=$output.GetAwaiter().GetResult();TimedOut=($reader.ExitCode -eq 124)}
    }finally{$reader.Dispose()}
}
function Get-GuardRuntimeSafety([ValidateRange(1,30000)][int]$EvidenceBudgetMilliseconds=30000,[ValidateRange(1,10000)][int]$ReaderTimeoutMilliseconds=10000) {
    $d=Get-GuardState
    $processes=@(Get-CimInstance Win32_Process)
    $desktop=@($processes|Where-Object ExecutablePath -eq $d.Desktop.Path)
    $code=@($processes|Where-Object {$_.ExecutablePath -in @($d.CodePaths)})
    $mains=@($desktop|Where-Object {$_.CommandLine -notmatch '--type='})
    $issues=[Collections.Generic.List[string]]::new()
    foreach($main in $mains){if($main.CommandLine -notmatch '--proxy-server=http://127.0.0.1:10818'){$issues.Add('DesktopFixedProxyMissing')}}
    $pids=@($desktop|ForEach-Object ProcessId)+@($code|ForEach-Object ProcessId)
    $descendants=@($pids)
    do{$added=@($processes|Where-Object {$_.ParentProcessId -in $descendants -and $_.ProcessId -notin $descendants}|ForEach-Object ProcessId);$descendants+=@($added)}while($added.Count)
    $connections=@(Get-NetTCPConnection -ErrorAction SilentlyContinue|Where-Object {$_.OwningProcess -in $pids -and $_.State -in 'Established','SynSent'}|Select-Object OwningProcess,RemoteAddress,RemotePort,@{n='State';e={$_.State.ToString()}})
    $localServices=@(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue|Where-Object OwningProcess -in $descendants)
    $localPorts=@($localServices|ForEach-Object LocalPort)
    $unexpected=@($connections|Where-Object {
        if($_.RemoteAddress -ne '::1' -and $_.RemoteAddress -notlike '127.*'){$true}
        elseif($_.RemoteAddress -eq '127.0.0.1' -and $_.RemotePort -eq 10818){$false}
        else{$_.RemotePort -notin $localPorts}
    })
    if($unexpected.Count){$issues.Add('UnexpectedRuntimeNetworkPath')}
    $python=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'
    $environments=@()
    $readerClock=[Diagnostics.Stopwatch]::StartNew()
    $readerTimeoutPids=@()
    $deadlineExceeded=$false
    foreach($p in @($mains)+@($code)) {
        # 瞬间已退出的子进程不作为失败；仍在运行却不能回读时停止核准。
        if(-not (Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue)){continue}
        $remaining=[Math]::Max(0,$EvidenceBudgetMilliseconds-[int]$readerClock.ElapsedMilliseconds)
        if(-not $remaining){$deadlineExceeded=$true;$issues.Add('RuntimeEnvironmentUnreadable');continue}
        try{$read=Invoke-GuardEnvironmentReader $python (Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py') $p.ProcessId ([Math]::Min($ReaderTimeoutMilliseconds,$remaining))}
        catch{if(Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue){$issues.Add('RuntimeEnvironmentUnreadable')};continue}
        if($read.TimedOut){$readerTimeoutPids+=@($p.ProcessId)}
        if($readerClock.ElapsedMilliseconds -ge $EvidenceBudgetMilliseconds){$deadlineExceeded=$true}
        if($read.ExitCode -ne 0){if(Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue){$issues.Add('RuntimeEnvironmentUnreadable')};continue}
        try{
            $e=$read.Output|ConvertFrom-Json
            $required=@('Pid','ApprovedPath','ConfigDirMatches','HttpProxyMatches','HttpsProxyMatches','AllProxyMatches','NoProxyOnlyLoopback','TlsVerificationEnabled','UnexpectedTlsOverrideNames','UnexpectedProviderOverrideNames')
            if(-not $e -or @($required|Where-Object {-not $e.PSObject.Properties[$_]}).Count -or $e.Pid -ne $p.ProcessId -or $e.ApprovedPath -ne $true){throw 'Runtime evidence response is invalid.'}
        }catch{if(Get-Process -Id $p.ProcessId -ErrorAction SilentlyContinue){$issues.Add('RuntimeEnvironmentUnreadable')};continue}
        $environments+=$e
        if(-not $e.ConfigDirMatches -or -not $e.HttpProxyMatches -or -not $e.HttpsProxyMatches -or -not $e.AllProxyMatches -or -not $e.NoProxyOnlyLoopback -or -not $e.TlsVerificationEnabled -or @($e.UnexpectedTlsOverrideNames).Count -or @($e.UnexpectedProviderOverrideNames).Count){$issues.Add('RuntimeEnvironmentMismatch')}
    }
    $identities=@($pids|ForEach-Object {$running=Get-Process -Id $_ -ErrorAction SilentlyContinue;if($running){@{Pid=$_;Started=$running.StartTime.ToUniversalTime().ToString('o')}}})
    [pscustomobject]@{Time=[datetime]::UtcNow.ToString('o');Safe=($issues.Count -eq 0);Issues=@($issues);DesktopProcessCount=$desktop.Count;CodeProcessCount=$code.Count;UnexpectedConnections=$unexpected;Environments=$environments;OwnedPids=@($pids);OwnedProcesses=$identities;EvidenceDeadlineExceeded=$deadlineExceeded;ReaderTimeoutPids=$readerTimeoutPids;EvidenceReaderElapsedMilliseconds=$readerClock.ElapsedMilliseconds}
}
function Stop-GuardUnsafeRuntime($Snapshot) {
    $d=Get-GuardState
    foreach($identity in @($Snapshot.OwnedProcesses)) {
        $ownedPid=$identity.Pid
        $p=Get-CimInstance Win32_Process -Filter "ProcessId=$ownedPid" -ErrorAction SilentlyContinue
        $running=Get-Process -Id $ownedPid -ErrorAction SilentlyContinue
        if($p -and $running -and $running.StartTime.ToUniversalTime().Ticks -eq ([datetime]$identity.Started).ToUniversalTime().Ticks -and ($p.ExecutablePath -eq $d.Desktop.Path -or $p.ExecutablePath -in @($d.CodePaths))){Stop-Process -Id $ownedPid -ErrorAction SilentlyContinue}
    }
}
Export-ModuleMember -Function *-Guard*
