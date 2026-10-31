Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1')
function Invoke-GuardEnvironmentReader([string]$PythonPath,[string]$ReaderPath,[int]$ProcessId,[int]$TimeoutMilliseconds,[string]$LocalServicePath='',[long]$LocalServiceStarted=0) {
    if($TimeoutMilliseconds -le 0){return [pscustomobject]@{ExitCode=124;Output='';TimedOut=$true}}
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$PythonPath;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $info.ArgumentList.Add($ReaderPath);$info.ArgumentList.Add([string]$ProcessId)
    if($LocalServicePath){
        $info.ArgumentList.Add('--local-service-path');$info.ArgumentList.Add($LocalServicePath)
        $info.ArgumentList.Add('--local-service-started');$info.ArgumentList.Add([string]$LocalServiceStarted)
    }
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
function Test-GuardRuntimeEnvironment($Evidence) {
    $required=@('ConfigDirMatches','HttpProxyMatches','HttpsProxyMatches','AllProxyMatches','NoProxyOnlyLoopback','TlsVerificationEnabled','UnexpectedTlsOverrideNames','UnexpectedProviderOverrideNames')
    if(-not $Evidence -or @($required|Where-Object {-not $Evidence.PSObject.Properties[$_]}).Count){return $false}
    $Evidence.ConfigDirMatches -eq $true -and $Evidence.HttpProxyMatches -eq $true -and $Evidence.HttpsProxyMatches -eq $true -and
        $Evidence.AllProxyMatches -eq $true -and $Evidence.NoProxyOnlyLoopback -eq $true -and $Evidence.TlsVerificationEnabled -eq $true -and
        @($Evidence.UnexpectedTlsOverrideNames).Count -eq 0 -and @($Evidence.UnexpectedProviderOverrideNames).Count -eq 0
}
function Test-GuardLoopbackAddress([string]$Address){$Address -eq '::1' -or $Address -like '127.*'}
function Get-GuardTcpListeners {
    # Query the LISTENER table class, not State or an empty remote endpoint:
    # Windows also exposes non-listening bind() sockets with remote port zero.
    if(-not ('ClaudeGuardNativeListeners' -as [type])){
        Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;
public sealed class ClaudeGuardListenerRow {
    public int OwningProcess; public string LocalAddress; public int LocalPort;
    public int ReportedState; public string State = "Listen";
}
public static class ClaudeGuardNativeListeners {
    [DllImport("iphlpapi.dll")]
    private static extern uint GetExtendedTcpTable(IntPtr table, ref uint size, bool order, uint family, int tableClass, uint reserved);
    public static ClaudeGuardListenerRow[] Read() {
        var result = new List<ClaudeGuardListenerRow>();
        foreach(uint family in new uint[]{2,23}) {
            uint size=0; uint code=GetExtendedTcpTable(IntPtr.Zero, ref size, false, family, 3, 0);
            if(code!=122 && code!=0) throw new InvalidOperationException("Listener table sizing failed: "+code);
            bool complete=false;
            for(int attempt=0;attempt<5;attempt++) {
                if(size<4 || size>67108864) throw new InvalidOperationException("Invalid listener table size.");
                int capacity=(int)size; IntPtr buffer=Marshal.AllocHGlobal(capacity);
                try {
                    code=GetExtendedTcpTable(buffer, ref size, false, family, 3, 0);
                    if(code==122) continue;
                    if(code!=0) throw new InvalidOperationException("Listener table read failed: "+code);
                    int count=Marshal.ReadInt32(buffer), stride=family==2?24:56;
                    if(count<0 || count>(capacity-4)/stride) throw new InvalidOperationException("Truncated listener table.");
                    for(int i=0;i<count;i++) {
                        IntPtr row=IntPtr.Add(buffer,4+i*stride); string address;
                        if(family==2) address=new IPAddress((long)(uint)Marshal.ReadInt32(row,4)).ToString();
                        else {var bytes=new byte[16];Marshal.Copy(row,bytes,0,16);address=new IPAddress(bytes,(long)(uint)Marshal.ReadInt32(row,16)).ToString();}
                        int port=Marshal.ReadInt32(row,family==2?8:20);
                        result.Add(new ClaudeGuardListenerRow{OwningProcess=Marshal.ReadInt32(row,family==2?20:52),
                            LocalAddress=address,LocalPort=((port&255)<<8)|((port>>8)&255),ReportedState=Marshal.ReadInt32(row,family==2?0:48)});
                    }
                    complete=true;break;
                } finally {Marshal.FreeHGlobal(buffer);}
            }
            if(!complete) throw new InvalidOperationException("Listener table kept changing.");
        }
        return result.ToArray();
    }
}
'@
    }
    [ClaudeGuardNativeListeners]::Read()
}
function Test-GuardLocalServiceConnection($Connection,$Services) {
    @($Services|Where-Object {$_.LocalPort -eq $Connection.RemotePort -and ($_.LocalAddress -eq $Connection.RemoteAddress -or $_.LocalAddress -in @('0.0.0.0','::'))}).Count -gt 0
}
function Get-GuardRuntimeSnapshot([ValidateRange(1,30000)][int]$EvidenceBudgetMilliseconds=30000,[ValidateRange(1,10000)][int]$ReaderTimeoutMilliseconds=10000) {
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
    $tcp=@(Get-NetTCPConnection -ErrorAction Stop)
    $listeners=@(Get-GuardTcpListeners)
    $connections=@($tcp|Where-Object {$_.OwningProcess -in $pids -and $_.State -in 'Established','SynSent'})
    $localServices=@($listeners|Where-Object OwningProcess -in $descendants)
    $python=(Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe')
    $readerClock=[Diagnostics.Stopwatch]::StartNew()
    $previewServices=@();$previewPids=@();$readerTimeoutPids=@();$deadlineExceeded=$false
    $previewChecks=[Collections.Generic.List[object]]::new()
    # detached 服务不依赖已经退出的 shell；仅核验 Claude 实际连接的回环端点。
    $candidates=@($listeners|Where-Object {
        $listener=$_
        $listener.OwningProcess -notin $descendants -and $listener.LocalPort -notin @(10808,10813,10818) -and
        (Test-GuardLoopbackAddress $listener.LocalAddress) -and @($connections|Where-Object {
            $_.State -eq 'Established' -and $_.RemoteAddress -eq $listener.LocalAddress -and $_.RemotePort -eq $listener.LocalPort
        }).Count -gt 0
    }|Sort-Object OwningProcess -Unique)
    # Verify root services first, then listeners of their live descendants. The
    # latter are needed for a gateway's internal worker, not an arbitrary port grant.
    $pending=[Collections.Generic.Queue[object]]::new()
    foreach($candidate in $candidates){$pending.Enqueue($candidate)}
    $checkedOwners=@();$previewDescendants=@()
    while($pending.Count){
        $candidate=$pending.Dequeue()
        $ownerId=[int]$candidate.OwningProcess
        if($ownerId -in $checkedOwners){continue};$checkedOwners+=@($ownerId)
        $check=[pscustomobject]@{Pid=$ownerId;LocalAddress=$candidate.LocalAddress;LocalPort=$candidate.LocalPort;Accepted=$false;Reason='OwnerUnavailable'}
        $previewChecks.Add($check)
        $owner=@($processes|Where-Object ProcessId -eq $ownerId|Select-Object -First 1)
        if($owner.Count -ne 1 -or -not $owner[0].ExecutablePath){continue}
        if(@($listeners|Where-Object {$_.OwningProcess -eq $ownerId -and -not (Test-GuardLoopbackAddress $_.LocalAddress)}).Count){$check.Reason='NonLoopbackListener';continue}
        $remaining=[Math]::Max(0,$EvidenceBudgetMilliseconds-[int]$readerClock.ElapsedMilliseconds)
        if(-not $remaining){$deadlineExceeded=$true;$check.Reason='EvidenceDeadline';continue}
        try{
            $live=Get-Process -Id $ownerId -ErrorAction Stop
            $started=$live.StartTime.ToUniversalTime().ToFileTimeUtc()
            $read=Invoke-GuardEnvironmentReader $python (Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py') $ownerId ([Math]::Min($ReaderTimeoutMilliseconds,$remaining)) $owner[0].ExecutablePath $started
            if($read.TimedOut){$readerTimeoutPids+=@($ownerId)}
            if($read.ExitCode -ne 0){$check.Reason=if($read.TimedOut){'ReaderTimeout'}else{'IdentityReaderFailed'};continue}
            $e=$read.Output|ConvertFrom-Json
            if($e.Pid -ne $ownerId -or $e.LocalServiceIdentityVerified -ne $true){$check.Reason='IdentityMismatch';continue}
            if(-not (Test-GuardRuntimeEnvironment $e)){$check.Reason='EnvironmentMismatch';continue}
            if((Get-Process -Id $ownerId -ErrorAction Stop).StartTime.ToUniversalTime().ToFileTimeUtc() -ne $started){$check.Reason='ProcessIdentityChanged';continue}
            $previewServices+=@([pscustomobject]@{Pid=$ownerId;Started=$live.StartTime.ToUniversalTime().ToString('o');Path=$owner[0].ExecutablePath;IdentityVerified=$true;Environment=$e})
            $previewPids+=@($ownerId)
            $check.Accepted=$true;$check.Reason='Verified'
            $previewDescendants=@($previewPids)
            do{$added=@($processes|Where-Object {$_.ParentProcessId -in $previewDescendants -and $_.ProcessId -notin $previewDescendants}|ForEach-Object ProcessId);$previewDescendants+=@($added)}while($added.Count)
            foreach($childListener in @($listeners|Where-Object {$_.OwningProcess -in $previewDescendants -and $_.OwningProcess -notin $checkedOwners})){$pending.Enqueue($childListener)}
        }catch{$check.Reason='EvidenceException';continue}
    }
    $previewDescendants=@($previewPids)
    do{$added=@($processes|Where-Object {$_.ParentProcessId -in $previewDescendants -and $_.ProcessId -notin $previewDescendants}|ForEach-Object ProcessId);$previewDescendants+=@($added)}while($added.Count)
    $localServices+=@($listeners|Where-Object OwningProcess -in $previewPids)
    # 预览服务和存活子进程的出站一并受检；服务端已接受连接按本地监听端点识别。
    $connections+=@($tcp|Where-Object {
        $connection=$_
        $connection.OwningProcess -in $previewDescendants -and $connection.OwningProcess -notin $pids -and $connection.State -in 'Established','SynSent' -and
        -not @($listeners|Where-Object {$_.OwningProcess -eq $connection.OwningProcess -and $_.LocalPort -eq $connection.LocalPort -and $_.LocalAddress -eq $connection.LocalAddress -and (Test-GuardLoopbackAddress $connection.RemoteAddress)}).Count
    })
    # 未建立的本机连接不代表已通过其它服务联网；监听器启动/退出也可能跨越两次快照。
    # 共享代理始终拒绝，已建立的未知本机连接和外部直连仍触发保护。
    $unconfirmedLoopback=@($connections|Where-Object {
        ($_.RemoteAddress -eq '::1' -or $_.RemoteAddress -like '127.*') -and
        $_.State -eq 'SynSent' -and $_.RemotePort -notin @(10808,10813,10818) -and -not (Test-GuardLocalServiceConnection $_ $localServices)
    })
    $unexpected=@($connections|Where-Object {
        if($_.RemoteAddress -ne '::1' -and $_.RemoteAddress -notlike '127.*'){$true}
        elseif($_.RemotePort -in @(10808,10813)){$true}
        elseif($_.RemoteAddress -eq '127.0.0.1' -and $_.RemotePort -eq 10818){$false}
        elseif(Test-GuardLocalServiceConnection $_ $localServices){$false}
        else{$_.State -ne 'SynSent'}
    })
    if($unexpected.Count){$issues.Add('UnexpectedRuntimeNetworkPath')}
    $environments=@()
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
        if(-not (Test-GuardRuntimeEnvironment $e)){$issues.Add('RuntimeEnvironmentMismatch')}
    }
    $identities=@($pids|ForEach-Object {$running=Get-Process -Id $_ -ErrorAction SilentlyContinue;if($running){@{Pid=$_;Started=$running.StartTime.ToUniversalTime().ToString('o')}}})
    [pscustomobject]@{Time=[datetime]::UtcNow.ToString('o');Safe=($issues.Count -eq 0);Issues=@($issues);DesktopProcessCount=$desktop.Count;CodeProcessCount=$code.Count;UnexpectedConnections=@($unexpected|Select-Object OwningProcess,LocalAddress,LocalPort,RemoteAddress,RemotePort,State);UnconfirmedLoopbackConnections=@($unconfirmedLoopback|Select-Object OwningProcess,RemoteAddress,RemotePort,State);PreviewServices=$previewServices;PreviewMonitoredPids=$previewDescendants;PreviewServiceChecks=@($previewChecks);ListenerSource='GetExtendedTcpTable/OWNER_PID_LISTENER/IPv4+IPv6';PreviewListeners=@($listeners|Where-Object {$_.OwningProcess -in $checkedOwners}|Select-Object OwningProcess,LocalAddress,LocalPort,ReportedState);Environments=$environments;OwnedPids=@($pids);OwnedProcesses=$identities;EvidenceDeadlineExceeded=$deadlineExceeded;ReaderTimeoutPids=$readerTimeoutPids;EvidenceReaderElapsedMilliseconds=$readerClock.ElapsedMilliseconds}
}
function Get-GuardRuntimeSafety([ValidateRange(1,30000)][int]$EvidenceBudgetMilliseconds=30000,[ValidateRange(1,10000)][int]$ReaderTimeoutMilliseconds=10000) {
    $clock=[Diagnostics.Stopwatch]::StartNew()
    $snapshot=Get-GuardRuntimeSnapshot -EvidenceBudgetMilliseconds $EvidenceBudgetMilliseconds -ReaderTimeoutMilliseconds $ReaderTimeoutMilliseconds
    # Listener/process/connection enumeration is not atomic. Re-read once only
    # for a loopback-only network mismatch; persistent unknown services still fail.
    $retry=-not $snapshot.Safe -and @($snapshot.Issues|Where-Object {$_ -ne 'UnexpectedRuntimeNetworkPath'}).Count -eq 0 -and
        @($snapshot.UnexpectedConnections).Count -gt 0 -and @($snapshot.UnexpectedConnections|Where-Object {-not (Test-GuardLoopbackAddress $_.RemoteAddress) -or $_.RemotePort -in @(10808,10813)}).Count -eq 0
    $remaining=$EvidenceBudgetMilliseconds-[int]$clock.ElapsedMilliseconds
    if($retry -and $remaining -gt 0){
        $first=[pscustomobject]@{Time=$snapshot.Time;UnexpectedConnections=$snapshot.UnexpectedConnections;PreviewServiceChecks=$snapshot.PreviewServiceChecks;PreviewListeners=$snapshot.PreviewListeners}
        $snapshot=Get-GuardRuntimeSnapshot -EvidenceBudgetMilliseconds $remaining -ReaderTimeoutMilliseconds $ReaderTimeoutMilliseconds
        $snapshot|Add-Member -NotePropertyName LoopbackRecheck -NotePropertyValue $first
    }
    $snapshot
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
