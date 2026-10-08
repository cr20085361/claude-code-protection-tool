[CmdletBinding()]
param([string]$EvidencePath=(Join-Path $PSScriptRoot 'evidence\supervisor-host-fixture-tests.json'))
$ErrorActionPreference='Stop'
# All processes and files belong to a new TEMP fixture. This suite never touches the production proxy/task.
$suite=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeSupervisorHostTests-'+[guid]::NewGuid().ToString('N'))
$buildRoot=Join-Path $suite 'build'
$runtime=Join-Path $buildRoot 'runtime'
$null=New-Item -ItemType Directory -Path $runtime -Force
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$hostExe=Join-Path $runtime 'ClaudeSupervisorHost.exe'
$shellExe=Join-Path $suite 'FixtureShell.exe'
$probeSource=Join-Path $suite 'FixtureShell.cs'
$processes=[Collections.Generic.List[Diagnostics.Process]]::new()
$ownedChildren=[Collections.Generic.List[Diagnostics.Process]]::new()
$results=[Collections.Generic.List[object]]::new()
$shellCode=@'
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;
internal static class FixtureShell {
  [DllImport("kernel32.dll")] private static extern IntPtr GetConsoleWindow();
  [DllImport("kernel32.dll", SetLastError=true)] private static extern bool IsProcessInJob(IntPtr process, IntPtr job, out bool inside);
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] private static extern IntPtr OpenJobObject(uint access,bool inherit,string name);
  [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
  private static readonly JavaScriptSerializer json=new JavaScriptSerializer();
  private static void Write(string path,object value) {
    string temp=path+"."+Guid.NewGuid().ToString("N")+".tmp";
    File.WriteAllText(temp,json.Serialize(value),new UTF8Encoding(false));
    if(File.Exists(path)) File.Replace(temp,path,null); else File.Move(temp,path);
  }
  private static string Arg(string[] args,string name) { for(int i=0;i<args.Length-1;i++) if(args[i]==name) return args[i+1]; return null; }
  private static int Main(string[] args) {
    if(args.Length==3 && args[0]=="--child") {
      IntPtr job=OpenJobObject(4,false,args[2]); bool inJob;
      if(job==IntPtr.Zero) return 92;
      IsProcessInJob(Process.GetCurrentProcess().Handle,job,out inJob);CloseHandle(job);
      Write(args[1],new {Pid=Process.GetCurrentProcess().Id,Started=Process.GetCurrentProcess().StartTime.ToUniversalTime().ToString("o"),ConsoleWindow=GetConsoleWindow().ToInt64(),InOwnedJob=inJob});
      Thread.Sleep(120000); return 0;
    }
    string script=Arg(args,"-File"), root=Path.GetDirectoryName(script), priv=Path.Combine(root,"private");
    var scenario=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(script));
    string mode=(string)scenario["Mode"];
    string jobName="Local\\ClaudeSupervisorWorker-"+Arg(args,"-RunId");
    IntPtr ownJob=OpenJobObject(4,false,jobName);bool inside;
    if(ownJob==IntPtr.Zero) return 93;
    IsProcessInJob(Process.GetCurrentProcess().Handle,ownJob,out inside);CloseHandle(ownJob);
    Write(Path.Combine(priv,"worker-facts.json"),new {Pid=Process.GetCurrentProcess().Id,ConsoleWindow=GetConsoleWindow().ToInt64(),InOwnedJob=inside,RunId=Arg(args,"-RunId"),HostPid=Arg(args,"-HostPid"),HostStarted=Arg(args,"-HostStarted")});
    if(mode=="exit7") { Console.Out.WriteLine("worker-normal-output"); Console.Error.WriteLine("password=fixture-confidential"); Console.Out.WriteLine("Bearer fixture-token");Console.Error.WriteLine("{\"password\":\"fixture-json-secret\"}"); return 7; }
    if(mode=="exit0") return 0;
    if(mode=="hang") { Thread.Sleep(120000); return 0; }
    if(mode=="child") {
      var launch=new ProcessStartInfo(Process.GetCurrentProcess().MainModule.FileName,"--child \""+Path.Combine(priv,"child-facts.json")+"\" \""+jobName+"\"");
      launch.UseShellExecute=false; launch.CreateNoWindow=true; Process.Start(launch);
    }
    var identity=json.Deserialize<Dictionary<string,object>>(File.ReadAllText(Path.Combine(priv,"supervisor-host-identity.json")));
    int ticks=0;
    while(true) {
      var health=new Dictionary<string,object>(identity);
      health["SchemaVersion"]=mode=="wrong-schema"?1:2;
      health["Time"]=DateTime.UtcNow.ToString("o"); health["Status"]="Healthy";
      health["LastSafetyCheck"]=mode=="stale-safety"?DateTime.UtcNow.AddMinutes(-10).ToString("o"):DateTime.UtcNow.ToString("o");
      health["LastEgressCheck"]=mode=="stale-egress"?DateTime.UtcNow.AddMinutes(-10).ToString("o"):DateTime.UtcNow.ToString("o");
      health["LastEgressAttempt"]=DateTime.UtcNow.ToString("o");
      if(mode=="wrong-run") health["RunId"]=Guid.NewGuid().ToString("D");
      if(mode=="upstream-backoff") { health["Status"]="UpstreamUnavailable";health["LastSafetyCheck"]=null;health["LastEgressCheck"]=DateTime.UtcNow.AddHours(-1).ToString("o");health["NextProbe"]=DateTime.UtcNow.AddMinutes(5).ToString("o"); }
      Write(Path.Combine(priv,"supervisor-health.json"),health);
      if((mode=="healthy" || mode=="upstream-backoff") && ticks++>24) return 0;
      Thread.Sleep(100);
    }
  }
}
'@
[IO.File]::WriteAllText($probeSource,$shellCode,[Text.UTF8Encoding]::new($false))
& $csc /nologo /target:winexe /reference:System.Web.Extensions.dll /out:$hostExe (Join-Path $PSScriptRoot 'ClaudeSupervisorHost.cs')
if($LASTEXITCODE -ne 0){throw 'Host .NET Framework compilation failed.'}
& $csc /nologo /target:exe /reference:System.Web.Extensions.dll /out:$shellExe $probeSource
if($LASTEXITCODE -ne 0){throw 'Native shell fixture compilation failed.'}
Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
public static class ClaudeHostWindowProbe {
 public delegate bool Callback(IntPtr h,IntPtr data);
 [DllImport("user32.dll")] private static extern bool EnumWindows(Callback callback,IntPtr data);
 [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr window,out uint pid);
 [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr window);
 public static int VisibleWindows(int[] processes) { int count=0; var ids=new HashSet<int>(processes);EnumWindows(delegate(IntPtr window,IntPtr data){uint pid;GetWindowThreadProcessId(window,out pid);if(ids.Contains((int)pid)&&IsWindowVisible(window))count++;return true;},IntPtr.Zero);return count; }
}
'@
function Write-FixtureJson([string]$Path,$Value){[IO.File]::WriteAllText($Path,($Value|ConvertTo-Json -Depth 30),[Text.UTF8Encoding]::new($false))}
function New-Fixture([string]$Mode,[double]$Timeout=2) {
    $fixture=Join-Path $suite ('fixture-'+$Mode+'-'+[guid]::NewGuid().ToString('N'))
    $null=New-Item -ItemType Directory -Path (Join-Path $fixture 'private') -Force
    $script=Join-Path $fixture 'worker.ps1'
    Write-FixtureJson $script @{Mode=$Mode}
    Write-FixtureJson (Join-Path $fixture 'private\deployment.json') @{Reliability=@{SchemaVersion=2;ShellPath=$shellExe;ShellHash=(Get-FileHash $shellExe).Hash;HostHash=(Get-FileHash $hostExe).Hash;SupervisorScript='worker.ps1';SupervisorHash=(Get-FileHash $script).Hash}}
    Write-FixtureJson (Join-Path $fixture 'private\host-fixture.json') @{Kind='ClaudeSupervisorHostFixture';WatchdogSeconds=$Timeout;PollMilliseconds=50}
    $fixture
}
function Start-FixtureHost([string]$Fixture) {
    $start=[Diagnostics.ProcessStartInfo]::new($hostExe,'--fixture-root "'+$Fixture+'"')
    $start.UseShellExecute=$false;$start.CreateNoWindow=$true
    $p=[Diagnostics.Process]::Start($start);$processes.Add($p);$p
}
function Wait-FixtureFile([string]$Path,[Diagnostics.Process]$HostProcess,[int]$Seconds=10) {
    $limit=[datetime]::UtcNow.AddSeconds($Seconds)
    while(-not (Test-Path -LiteralPath $Path)) {
        if([datetime]::UtcNow -gt $limit -or $HostProcess.HasExited){throw ('Fixture failed to produce '+[IO.Path]::GetFileName($Path))}
        Start-Sleep -Milliseconds 50
    }
    Get-Content -LiteralPath $Path -Raw|ConvertFrom-Json
}
function Wait-FixtureExit([Diagnostics.Process]$HostProcess,[int]$Seconds=10) {
    if(-not $HostProcess.WaitForExit($Seconds*1000)){throw 'Fixture host did not stop within test budget.'}
    $HostProcess.ExitCode
}
function Assert-Fixture([bool]$Condition,[string]$Name,$Details) {
    $results.Add([pscustomobject]@{Name=$Name;Status=if($Condition){'PASS'}else{'FAIL'};Details=$Details})
    if(-not $Condition){throw ('Fixture assertion failed: '+$Name)}
}
try {
    # PE subsystem 2 is WINDOWS_GUI, so Task Scheduler never creates a console for this host.
    $pe=[IO.File]::ReadAllBytes($hostExe);$header=[BitConverter]::ToInt32($pe,60);$subsystem=[BitConverter]::ToUInt16($pe,$header+24+68)
    Assert-Fixture ($subsystem -eq 2) 'WinExeSubsystem' @{Subsystem=$subsystem}
    $f=New-Fixture healthy 2;$p=Start-FixtureHost $f
    $facts=Wait-FixtureFile (Join-Path $f 'private\worker-facts.json') $p
    $identity=Wait-FixtureFile (Join-Path $f 'private\supervisor-host-identity.json') $p
    $visible=[ClaudeHostWindowProbe]::VisibleWindows(@($p.Id,[int]$facts.Pid))
    Assert-Fixture ($facts.ConsoleWindow -eq 0 -and $visible -eq 0 -and $facts.InOwnedJob) 'NoConsoleAndOwnedWorkerJob' @{ConsoleWindow=$facts.ConsoleWindow;VisibleWindows=$visible;WorkerInOwnedJob=$facts.InOwnedJob}
    Assert-Fixture ($facts.RunId -eq $identity.RunId -and [int]$facts.HostPid -eq $p.Id -and $facts.HostStarted -eq $identity.HostStarted) 'IdentityArguments' @{HostPid=$p.Id;WorkerPid=$facts.Pid}
    Assert-Fixture ((Wait-FixtureExit $p) -eq 0) 'HealthyProgressNormalStop' $null
    $f=New-Fixture exit7;$p=Start-FixtureHost $f;$exit=Wait-FixtureExit $p
    $events=@(Get-Content (Join-Path $f 'private\host-events.jsonl')|ForEach-Object {$_|ConvertFrom-Json})
    $logs=(Get-Content (Join-Path $f 'private\supervisor-worker-stdout.log') -Raw)+(Get-Content (Join-Path $f 'private\supervisor-worker-stderr.log') -Raw)
    Assert-Fixture ($exit -eq 7 -and @($events|Where-Object {$_.Kind -eq 'WorkerExited' -and $_.Data.ExitCode -eq 7}).Count -eq 1) 'RawWorkerExitCode' @{HostExitCode=$exit}
    Assert-Fixture ($logs -match 'worker-normal-output' -and $logs -notmatch 'fixture-confidential|fixture-token|fixture-json-secret') 'RedirectedOutputRedaction' @{NormalOutputCaptured=($logs -match 'worker-normal-output');SecretsAbsent=($logs -notmatch 'fixture-confidential|fixture-token|fixture-json-secret')}
    $f=New-Fixture exit7
    [IO.File]::WriteAllText((Join-Path $f 'private\supervisor-worker-stdout.log'),('x'*2097152),[Text.UTF8Encoding]::new($false))
    $p=Start-FixtureHost $f;$null=Wait-FixtureExit $p
    $previous=Join-Path $f 'private\supervisor-worker-stdout.log.previous';$current=Join-Path $f 'private\supervisor-worker-stdout.log'
    Assert-Fixture ((Test-Path $previous) -and (Get-Item $previous).Length -eq 2097152 -and (Get-Item $current).Length -lt 2097152) 'WorkerLogRotationTwoMiB' @{PreviousBytes=(Get-Item $previous).Length;CurrentBytes=(Get-Item $current).Length}
    foreach($mode in @('hang','wrong-run','stale-safety','stale-egress','wrong-schema')) {
        $f=New-Fixture $mode;$p=Start-FixtureHost $f;$timer=[Diagnostics.Stopwatch]::StartNew();$exit=Wait-FixtureExit $p
        $budget=Get-Content (Join-Path $f 'private\supervisor-host-recovery.json') -Raw|ConvertFrom-Json
        Assert-Fixture ($exit -eq 22 -and @($budget.FailureTimes).Count -eq 1 -and $timer.Elapsed.TotalSeconds -lt 8) ('Watchdog-'+$mode) @{ExitCode=$exit;Seconds=[math]::Round($timer.Elapsed.TotalSeconds,2);FailureCount=@($budget.FailureTimes).Count}
    }
    $f=New-Fixture upstream-backoff;$p=Start-FixtureHost $f
    Assert-Fixture ((Wait-FixtureExit $p) -eq 0) 'UpstreamBackoffHealthProgressAccepted' $null
    $f=New-Fixture child 5;$p=Start-FixtureHost $f
    $facts=Wait-FixtureFile (Join-Path $f 'private\worker-facts.json') $p
    $child=Wait-FixtureFile (Join-Path $f 'private\child-facts.json') $p
    $childProcess=Get-Process -Id $child.Pid;$ownedChildren.Add($childProcess)
    $workerProcess=Get-Process -Id $facts.Pid
    Assert-Fixture (-not $child.InOwnedJob -and $child.ConsoleWindow -eq 0) 'DescendantSilentlyBreaksAway' @{ChildInOwnedJob=$child.InOwnedJob;ConsoleWindow=$child.ConsoleWindow}
    $p.Kill();$p.WaitForExit();$workerExited=$workerProcess.WaitForExit(3000)
    Assert-Fixture ($workerExited -and -not $childProcess.HasExited) 'HostCloseKillsWorkerPreservesDetachedChild' @{WorkerExited=$workerExited;DetachedChildAlive=(-not $childProcess.HasExited)}
    $p=Start-FixtureHost $f
    $facts2=Wait-FixtureFile (Join-Path $f 'private\worker-facts.json') $p
    # A forced host termination persists an active run and is charged on next launch.
    Start-Sleep -Milliseconds 300
    $budget=Get-Content (Join-Path $f 'private\supervisor-host-recovery.json') -Raw|ConvertFrom-Json
    Assert-Fixture (@($budget.FailureTimes).Count -eq 1) 'InterruptedHostBudgetPersists' @{FailureCount=@($budget.FailureTimes).Count}
    # Valid maintenance stops only the owned worker, and cannot erase prior failures.
    Write-FixtureJson (Join-Path $f 'private\maintenance.json') @{Until=[datetime]::UtcNow.AddMinutes(1).ToString('o')}
    Assert-Fixture ((Wait-FixtureExit $p) -eq 0) 'MaintenanceStopsNormally' $null
    $budget=Get-Content (Join-Path $f 'private\supervisor-host-recovery.json') -Raw|ConvertFrom-Json
    Assert-Fixture (@($budget.FailureTimes).Count -eq 1) 'MaintenanceDoesNotConsumeOrClearFailureBudget' @{FailureCount=@($budget.FailureTimes).Count}
    $f=New-Fixture exit7
    $exitCodes=@(1..4|ForEach-Object {$p=Start-FixtureHost $f;Wait-FixtureExit $p})
    $budget=Get-Content (Join-Path $f 'private\supervisor-host-recovery.json') -Raw|ConvertFrom-Json
    $next=[datetime]$budget.NextRestart
    Assert-Fixture (($exitCodes -join ',') -eq '7,7,7,21' -and @($budget.FailureTimes).Count -eq 3 -and ($next.ToUniversalTime()-[datetime]::UtcNow).TotalMinutes -gt 4.8) 'CrossHostPersistentThreeFailuresFiveMinuteBackoff' @{ExitCodes=$exitCodes;FailureCount=@($budget.FailureTimes).Count;NextRestart=$budget.NextRestart}
    $f=New-Fixture exit0
    $badShell=Join-Path $f 'invalid-shell.txt';[IO.File]::WriteAllText($badShell,'non-executable fixture')
    $manifestPath=Join-Path $f 'private\deployment.json';$manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json
    $manifest.Reliability.ShellPath=$badShell;$manifest.Reliability.ShellHash=(Get-FileHash $badShell).Hash;Write-FixtureJson $manifestPath $manifest
    $p=Start-FixtureHost $f;$exit=Wait-FixtureExit $p
    $budget=Get-Content (Join-Path $f 'private\supervisor-host-recovery.json') -Raw|ConvertFrom-Json
    Assert-Fixture ($exit -eq 23 -and @($budget.FailureTimes).Count -eq 1) 'NativeWorkerLaunchFailureConsumesPersistentBudget' @{ExitCode=$exit;FailureCount=@($budget.FailureTimes).Count;Reason=$budget.Reason}
    $f=New-Fixture exit7
    Write-FixtureJson (Join-Path $f 'private\maintenance.json') @{Until=[datetime]::UtcNow.AddMinutes(1).ToString('o')}
    $p=Start-FixtureHost $f
    Assert-Fixture ((Wait-FixtureExit $p) -eq 0 -and -not (Test-Path (Join-Path $f 'private\worker-facts.json'))) 'MaintenancePreventsWorkerLaunch' $null
    $f=New-Fixture exit0
    Write-FixtureJson (Join-Path $f 'private\safety-hold.json') @{Reason='fixture-persistent-safety-hold'}
    $p=Start-FixtureHost $f
    Assert-Fixture ((Wait-FixtureExit $p) -eq 0 -and (Test-Path (Join-Path $f 'private\worker-facts.json')) -and (Test-Path (Join-Path $f 'private\safety-hold.json'))) 'SafetyHoldDoesNotBypassOrPreventDiagnosticWorker' $null
    foreach($key in @('ShellHash','HostHash','SupervisorHash')) {
        $f=New-Fixture exit0;$manifestPath=Join-Path $f 'private\deployment.json';$manifest=Get-Content $manifestPath -Raw|ConvertFrom-Json;$manifest.Reliability.$key='0'*64;Write-FixtureJson $manifestPath $manifest
        $p=Start-FixtureHost $f
        Assert-Fixture ((Wait-FixtureExit $p) -eq 20 -and -not (Test-Path (Join-Path $f 'private\worker-facts.json'))) ('FixtureStillRequires-'+$key) $null
    }
    $p=Start-FixtureHost $buildRoot
    Assert-Fixture ((Wait-FixtureExit $p) -eq 20) 'FixtureRejectsInferredProductionRoot' $null
    $evidence=[ordered]@{Time=[datetime]::UtcNow.ToString('o');Status='PASS';Compiler='NET Framework v4.0.30319 csc /target:winexe';FixtureOnly=$true;ProductionProxyTouched=$false;TestCount=$results.Count;Results=@($results);FixtureRoot=$suite}
    $null=New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($EvidencePath))) -Force
    Write-FixtureJson $EvidencePath $evidence
    $evidence|ConvertTo-Json -Depth 10
} catch {
    $evidence=[ordered]@{Time=[datetime]::UtcNow.ToString('o');Status='FAIL';FixtureOnly=$true;ProductionProxyTouched=$false;TestCount=$results.Count;Results=@($results);Error=$_.Exception.Message;FixtureRoot=$suite}
    $null=New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($EvidencePath))) -Force
    Write-FixtureJson $EvidencePath $evidence
    throw
} finally {
    foreach($p in $processes){try{if(-not $p.HasExited){$p.Kill();$null=$p.WaitForExit(3000)}}catch{}}
    foreach($p in $ownedChildren){try{if(-not $p.HasExited){$p.Kill();$null=$p.WaitForExit(3000)}}catch{}}
    # Recovered child facts can include a second detached fixture child. Kill by exact binary path only.
    Get-CimInstance Win32_Process -Filter "Name='FixtureShell.exe'" -ErrorAction SilentlyContinue|Where-Object {$_.ExecutablePath -eq $shellExe}|ForEach-Object {Stop-Process -Id $_.ProcessId -ErrorAction SilentlyContinue}
    foreach($p in $processes){$p.Dispose()};foreach($p in $ownedChildren){$p.Dispose()}
    # Leave the isolated fixture/evidence for inspection; do not perform recursive cleanup here.
}
