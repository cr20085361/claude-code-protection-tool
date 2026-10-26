[CmdletBinding()]
param([string]$LauncherAssembly)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$fixture=Join-Path $PSScriptRoot ('private\health-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixture 'private') | Out-Null
$now=[datetimeoffset]::Parse('2026-10-06T01:00:00Z')
$state=[pscustomobject]@{ExpectedIp='203.0.113.1';Reliability=[pscustomobject]@{HostPath='C:\fixture\runtime\host.exe';ShellPath='C:\fixture\pwsh.exe';SupervisorScript='ClaudeGuard-Supervisor-v2.ps1'}}
$base=@{SchemaVersion=2;Time=$now.ToString('o');RunId='fixture-run';HostPid=10;HostStarted=$now.AddSeconds(-60).ToString('o');SupervisorPid=20;SupervisorStarted=$now.AddSeconds(-60).ToString('o');LastSafetyCheck=$now.AddSeconds(-1).ToString('o');LastEgressCheck=$now.AddSeconds(-1).ToString('o');Status='Healthy';LastVerifiedEgress=@{VerifiedProbeCount=2;CloudflareIp='203.0.113.1';IpifyIp='203.0.113.1'}}
$identity=@{RunId=$base.RunId;HostPid=$base.HostPid;HostStarted=$base.HostStarted;SupervisorPid=$base.SupervisorPid;SupervisorStarted=$base.SupervisorStarted;ShellPath=$state.Reliability.ShellPath;ScriptPath='C:\fixture\ClaudeGuard-Supervisor-v2.ps1'}
$cases=@()
function Add-Case($name,$expected,$change,[bool]$identityOk=$true,[string]$task='Running',[bool]$hold=$false,[string]$expectedKind=''){
    $h=$base|ConvertTo-Json -Depth 5|ConvertFrom-Json
    if($change){& $change $h}
    $script:cases+=@([pscustomobject]@{Name=$name;Expected=$expected;ExpectedKind=$expectedKind;Health=$h;State=$state;Identity=$identity;IdentityOk=$identityOk;TaskState=$task;Hold=$hold;Now=$now.ToString('o')})
}
Add-Case 'fresh-current-run' $true $null
Add-Case 'age-119' $true {param($h)$h.Time=$now.AddSeconds(-119).ToString('o')}
Add-Case 'age-120-inclusive' $true {param($h)$h.Time=$now.AddSeconds(-120).ToString('o')}
Add-Case 'age-121-expired' $false {param($h)$h.Time=$now.AddSeconds(-121).ToString('o')}
Add-Case 'invalid-time' $false {param($h)$h.Time='bad'}
Add-Case 'future-five-seconds' $true {param($h)$h.Time=$now.AddSeconds(5).ToString('o')}
Add-Case 'future-six-seconds' $false {param($h)$h.Time=$now.AddSeconds(6).ToString('o')}
Add-Case 'legacy-health' $false {param($h)$h.SchemaVersion=1}
Add-Case 'worker-missing-or-pid-reused' $false $null $false
Add-Case 'task-stopped-old-proxy-alive' $false $null $true 'Ready'
Add-Case 'starting-is-not-ready' $false {param($h)$h.Status='Starting'}
Add-Case 'checking-is-not-ready' $false {param($h)$h.Status='Checking'}
Add-Case 'previous-run-safety-result' $false {param($h)$h.LastSafetyCheck=$now.AddSeconds(-61).ToString('o')}
Add-Case 'stale-safety-completion' $false {param($h)$h.SupervisorStarted=$now.AddSeconds(-300).ToString('o');$h.LastSafetyCheck=$now.AddSeconds(-121).ToString('o')}
Add-Case 'missing-egress-result' $false {param($h)$h.LastVerifiedEgress=$null}
Add-Case 'wrong-fixed-egress' $false {param($h)$h.LastVerifiedEgress.IpifyIp='203.0.113.2'}
Add-Case 'one-probe-degraded' $true {param($h)$h.Status='ProbeDegraded';$h.LastVerifiedEgress.VerifiedProbeCount=1;$h.LastVerifiedEgress.IpifyIp=''}
Add-Case 'persisted-safety-hold' $false $null $true 'Running' $true
Add-Case 'reported-safety-hold' $false {param($h)$h.Status='SafetyHold'} $true 'Running' $false 'SafetyHold'
Add-Case 'backoff-is-not-ready' $false {param($h)$h.Status='Backoff'}
Add-Case 'old-hold-after-reviewed-maintenance' $false {param($h)$h.Status='SafetyHold'} $false 'Running' $false 'SupervisorUnavailable'
Add-Case 'persisted-hold-with-legacy-health' $false {param($h)$h.SchemaVersion=1} $false 'Ready' $true 'SafetyHold'
Add-Case 'node-pool-second-node' $true {param($h)$h.LastVerifiedEgress.CloudflareIp='203.0.113.2';$h.LastVerifiedEgress.IpifyIp='203.0.113.2'}
Add-Case 'node-pool-switch-between-probes' $true {param($h)$h.LastVerifiedEgress.IpifyIp='203.0.113.2'}
Add-Case 'node-pool-unapproved-egress' $false {param($h)$h.LastVerifiedEgress.IpifyIp='203.0.113.99'}
foreach($case in @($cases|Where-Object Name -like 'node-pool-*')){$case.State=$state|ConvertTo-Json -Depth 10|ConvertFrom-Json;$case.State|Add-Member ExpectedIps @('203.0.113.1','203.0.113.2')}
Add-Case 'upstream-failure-not-ready' $false {param($h)$h.Status='UpstreamUnavailable';$h|Add-Member ConsecutiveFailures 75;$h|Add-Member NextProbe ($now.AddMinutes(4).ToString('o'))}
$results=@()
try {
    $module=Get-Module ClaudeGuard
    $results=& $module {
        param($Fixture,$Cases,$Now)
        $original=$script:Root
        try {
            $script:Root=$Fixture
            foreach($c in $Cases){
                $hold=Get-GuardPath 'private\safety-hold.json'
                if($c.Hold){[IO.File]::WriteAllText($hold,'{}')}elseif(Test-Path -LiteralPath $hold){Remove-Item -LiteralPath $hold}
                $script:FixtureIdentity=$c.IdentityOk
                $r=Get-GuardHealthAssessment -Health $c.Health -State $c.State -NowUtc $Now -TaskState $c.TaskState -IdentityVerifier {return $script:FixtureIdentity}
                if($r.Ready -ne $c.Expected){throw ('PowerShell health case failed: '+$c.Name+' '+$r.Reason)}
                if($c.ExpectedKind -and $r.Kind -ne $c.ExpectedKind){throw ('PowerShell health kind failed: '+$c.Name+' '+$r.Kind)}
                [pscustomobject]@{Name=$c.Name;PowerShellPassed=$true;Expected=$c.Expected;Kind=$r.Kind}
            }
        }finally{$script:Root=$original;Remove-Variable FixtureIdentity -Scope Script -ErrorAction SilentlyContinue}
    } $fixture $cases $now
    $cases|ConvertTo-Json -Depth 10|Set-Content -LiteralPath (Join-Path $fixture 'cases.json') -Encoding utf8
    $source=@'
using System;using System.IO;using System.Web.Script.Serialization;
public class ContractCase {public string Name;public bool Expected;public ClaudeGuardWindow.HealthResult Health;public ClaudeGuardWindow.DeploymentResult State;public ClaudeGuardWindow.HostIdentity Identity;public bool IdentityOk;public string TaskState;public bool Hold;public string Now;}
public class ContractRunner {public static int Main(string[] args){var cases=new JavaScriptSerializer().Deserialize<ContractCase[]>(File.ReadAllText(args[0]));foreach(var c in cases){string failure=ClaudeGuardWindow.ValidateHealth(c.Health,c.State,c.Identity,DateTimeOffset.Parse(c.Now),c.IdentityOk&&c.TaskState=="Running",c.Hold);if((failure==null)!=c.Expected){Console.Error.WriteLine(c.Name+": "+failure);return 1;}}Console.WriteLine("C# health contract cases passed: "+cases.Length);return 0;}}
'@
    $sourcePath=Join-Path $fixture 'ContractRunner.cs';[IO.File]::WriteAllText($sourcePath,$source)
    $compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    $uiDll=Join-Path $fixture 'GuardUI.dll'
    if($LauncherAssembly){
        $LauncherAssembly=[IO.Path]::GetFullPath($LauncherAssembly)
        $assemblyName=[Reflection.AssemblyName]::GetAssemblyName($LauncherAssembly).Name
        $uiDll=Join-Path $fixture ($assemblyName+'.exe')
        Copy-Item -LiteralPath $LauncherAssembly -Destination $uiDll
    }else{
        & $compiler /nologo /target:library /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+$uiDll) (Join-Path $PSScriptRoot 'ClaudeGuardLauncher.cs')
        if($LASTEXITCODE -ne 0){throw 'UI contract assembly compile failed.'}
    }
    $runner=Join-Path $fixture 'ContractRunner.exe'
    & $compiler /nologo /reference:System.Windows.Forms.dll /reference:System.Web.Extensions.dll ('/reference:'+$uiDll) ('/out:'+$runner) $sourcePath
    if($LASTEXITCODE -ne 0){throw 'Contract runner compile failed.'}
    & $runner (Join-Path $fixture 'cases.json')
    if($LASTEXITCODE -ne 0){throw 'C# health contract regression failed.'}
    Write-GuardJson (Join-Path $PSScriptRoot 'evidence\supervisor-health-regression.json') @{Time=(Get-Date -Format o);Passed=$true;FixtureOnly=$true;Cases=$results;CSharpCases=$cases.Count;TestedAssembly=$LauncherAssembly;TestedAssemblyHash=if($LauncherAssembly){Get-GuardHash $LauncherAssembly}else{$null}}
}finally{
    # 删除经过绝对路径范围核验的本脚本隔离目录。
    $full=[IO.Path]::GetFullPath($fixture);$allowed=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'private'))+[IO.Path]::DirectorySeparatorChar
    if(-not $full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase)){throw 'Fixture cleanup outside private refused.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
$results|ConvertTo-Json
