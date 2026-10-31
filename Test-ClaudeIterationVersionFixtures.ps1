[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$checker=Join-Path $PSScriptRoot 'Test-ClaudeIterationVersion.ps1'
$fixture=Join-Path $PSScriptRoot ('private\iteration-version-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixture 'docs'),(Join-Path $fixture 'evidence') -Force|Out-Null
$cases=[Collections.Generic.List[string]]::new()
function Write-FixtureLedger($Ledger){$Ledger|ConvertTo-Json -Depth 15|Set-Content -LiteralPath (Join-Path $fixture '.iteration-version.json') -Encoding utf8}
function Read-FixtureLedger{Get-Content -LiteralPath (Join-Path $fixture '.iteration-version.json') -Raw|ConvertFrom-Json}
function Update-FixtureFingerprint{
    $ledger=Read-FixtureLedger
    $ledger.history[-1]|Add-Member NoteProperty source_fingerprint (& $checker -ProjectRoot $fixture -GetSourceFingerprint) -Force
    Write-FixtureLedger $ledger
}
function Reset-Fixture{
    foreach($name in @('extra.ps1','baseline.json','Build-ClaudeShortcut.ps1','Test-ClaudeIterationVersion.ps1')){Remove-Item -LiteralPath (Join-Path $fixture $name) -ErrorAction SilentlyContinue}
    [IO.File]::WriteAllText((Join-Path $fixture 'ClaudeGuardLauncher.cs'),'[assembly: System.Reflection.AssemblyVersion("1.0.1.0")][assembly: System.Reflection.AssemblyFileVersion("1.0.1.0")] public class F { public const string BuildVersion="v1.0.1"; }')
    [IO.File]::WriteAllText((Join-Path $fixture 'sample.ps1'),'Write-Output "fixture"')
    [IO.File]::WriteAllText((Join-Path $fixture 'AGENTS.md'),'fixture rules')
    [IO.File]::WriteAllText((Join-Path $fixture 'README.md'),'当前源码基线：**v1.0.1 · 第 1 次源码迭代**。')
    [IO.File]::WriteAllText((Join-Path $fixture 'CHANGELOG.md'),"当前版本 **v1.0.1 · 第 1 次源码迭代**。`n`n## v1.0.1 (2026-10-31)`nFixture.")
    [IO.File]::WriteAllText((Join-Path $fixture 'docs\DEPLOYMENT.md'),'当前源码为 v1.0.1，fixture only。')
    Write-FixtureLedger @{schema_version=1;baseline=@{version='v1.0.0'};current_version='v1.0.1';completed_iterations=1;history=@(@{id=[guid]::NewGuid().ToString();from_version='v1.0.0';to_version='v1.0.1';level='patch';summary='fixture';verification='fixture validation';recorded_at=[datetimeoffset]::Now.ToString('o')})}
    Update-FixtureFingerprint
}
function Pass($Name,[scriptblock]$Body){& $Body;$cases.Add($Name)}
function Reject([scriptblock]$Body,[string]$Message){
    try{& $Body|Out-Null}catch{if($_.Exception.Message -notmatch $Message){throw};return}
    throw 'Inconsistent iteration unexpectedly passed.'
}
try {
    Reset-Fixture
    Pass 'consistent-source-ledger-and-documents' {if(-not (& $checker -ProjectRoot $fixture).Passed){throw 'Valid fixture failed'}}
    Pass 'verified-single-iteration-baseline' {
        @{Version='v1.0.0';CompletedIterations=0}|ConvertTo-Json|Set-Content (Join-Path $fixture 'baseline.json')
        if(-not (& $checker -ProjectRoot $fixture -BaselineFile (Join-Path $fixture 'baseline.json')).BaselineVerified){throw 'Baseline not checked'}
    }
    Reset-Fixture
    Pass 'unregistered-source-edit-is-blocked' {[IO.File]::AppendAllText((Join-Path $fixture 'sample.ps1'),' # edited');Reject {& $checker -ProjectRoot $fixture} 'fingerprint'}
    Reset-Fixture
    Pass 'build-blocks-unregistered-source-before-runtime' {
        Copy-Item -LiteralPath $checker,(Join-Path $PSScriptRoot 'Build-ClaudeShortcut.ps1') -Destination $fixture
        Update-FixtureFingerprint
        [IO.File]::WriteAllText((Join-Path $fixture 'extra.ps1'),'new source')
        # 模块和运行状态故意不存在；应在尝试加载它们前由版本门槛拒绝。
        Reject {& (Join-Path $fixture 'Build-ClaudeShortcut.ps1') -CompileOnly} 'fingerprint'
    }
    Reset-Fixture
    Pass 'rule-change-is-included-in-fingerprint' {[IO.File]::AppendAllText((Join-Path $fixture 'AGENTS.md'),' modified');Reject {& $checker -ProjectRoot $fixture} 'fingerprint'}
    Reset-Fixture
    Pass 'history-count-mismatch-is-blocked' {$l=Read-FixtureLedger;$l.completed_iterations=2;Write-FixtureLedger $l;Reject {& $checker -ProjectRoot $fixture} 'history count'}
    Reset-Fixture
    Pass 'duplicate-iteration-id-is-blocked' {
        $l=Read-FixtureLedger;$entry=$l.history[0]|ConvertTo-Json|ConvertFrom-Json;$entry.from_version='v1.0.1';$entry.to_version='v1.0.2';$l.history+=@($entry);$l.completed_iterations=2;$l.current_version='v1.0.2';Write-FixtureLedger $l
        Reject {& $checker -ProjectRoot $fixture} 'unique UUID'
    }
    Reset-Fixture
    Pass 'broken-version-chain-is-blocked' {$l=Read-FixtureLedger;$l.history[0].from_version='v0.9.0';Write-FixtureLedger $l;Reject {& $checker -ProjectRoot $fixture} 'chain'}
    Reset-Fixture
    Pass 'semantic-level-and-target-mismatch-is-blocked' {$l=Read-FixtureLedger;$l.history[0].to_version='v1.1.0';Write-FixtureLedger $l;Reject {& $checker -ProjectRoot $fixture} 'semantic increment'}
    Reset-Fixture
    Pass 'current-version-must-match-history' {$l=Read-FixtureLedger;$l.current_version='v1.0.2';Write-FixtureLedger $l;Reject {& $checker -ProjectRoot $fixture} 'final history'}
    Reset-Fixture
    Pass 'ui-constant-mismatch-is-blocked' {
        $path=Join-Path $fixture 'ClaudeGuardLauncher.cs';[IO.File]::WriteAllText($path,([IO.File]::ReadAllText($path).Replace('BuildVersion="v1.0.1"','BuildVersion="v1.0.0"')));Update-FixtureFingerprint
        Reject {& $checker -ProjectRoot $fixture} 'UI version'
    }
    Reset-Fixture
    Pass 'assembly-metadata-mismatch-is-blocked' {
        $path=Join-Path $fixture 'ClaudeGuardLauncher.cs';[IO.File]::WriteAllText($path,([IO.File]::ReadAllText($path).Replace('AssemblyFileVersion("1.0.1.0")','AssemblyFileVersion("1.0.0.0")')));Update-FixtureFingerprint
        Reject {& $checker -ProjectRoot $fixture} 'assembly metadata'
    }
    Reset-Fixture
    Pass 'readme-current-version-is-checked' {[IO.File]::WriteAllText((Join-Path $fixture 'README.md'),'当前源码基线：**v1.0.0 · 第 1 次源码迭代**。');Reject {& $checker -ProjectRoot $fixture} 'README.md current'}
    Reset-Fixture
    Pass 'changelog-entry-is-required' {[IO.File]::WriteAllText((Join-Path $fixture 'CHANGELOG.md'),'当前版本 **v1.0.1 · 第 1 次源码迭代**。');Reject {& $checker -ProjectRoot $fixture} 'no changelog entry'}
    Reset-Fixture
    Pass 'deployment-document-is-checked' {[IO.File]::WriteAllText((Join-Path $fixture 'docs\DEPLOYMENT.md'),'当前源码为 v1.0.0，fixture。');Reject {& $checker -ProjectRoot $fixture} 'Deployment document'}
    Reset-Fixture
    Pass 'unchanged-iteration-baseline-is-blocked' {
        @{Version='v1.0.1';CompletedIterations=1}|ConvertTo-Json|Set-Content (Join-Path $fixture 'baseline.json')
        Reject {& $checker -ProjectRoot $fixture -BaselineFile (Join-Path $fixture 'baseline.json')} 'advance the baseline'
    }
    Reset-Fixture
    Pass 'timezone-is-required' {$l=Read-FixtureLedger;$l.history[0].recorded_at='2026-10-31T12:00:00';Write-FixtureLedger $l;Reject {& $checker -ProjectRoot $fixture} 'requires a timezone'}
    Reset-Fixture
    Pass 'backfill-retains-historical-completion-time' {
        $l=Read-FixtureLedger;$l.history[0]|Add-Member NoteProperty backfilled $true;$l.history[0]|Add-Member NoteProperty completed_at '2035-01-01T00:00:00+08:00';Write-FixtureLedger $l
        Reject {& $checker -ProjectRoot $fixture} 'historical completion time'
    }
    Reset-Fixture
    Pass 'backfill-needs-evidence' {
        $l=Read-FixtureLedger;$l.history[0]|Add-Member NoteProperty backfilled $true;$l.history[0]|Add-Member NoteProperty completed_at '2026-10-01T00:00:00+08:00';$l.history[0]|Add-Member NoteProperty deployed_version_at_completion 'v1.0.0';$l.history[0]|Add-Member NoteProperty local_evidence @();Write-FixtureLedger $l
        Reject {& $checker -ProjectRoot $fixture} 'inspectable evidence'
    }
    Reset-Fixture
    Pass 'local-evidence-hash-is-verified' {
        $path=Join-Path $fixture 'evidence\proof.json';[IO.File]::WriteAllText($path,'{"Passed":true}')
        $l=Read-FixtureLedger;$l.history[0]|Add-Member NoteProperty local_evidence @(@{path='evidence/proof.json';sha256=(Get-FileHash $path).Hash});Write-FixtureLedger $l
        if(-not (& $checker -ProjectRoot $fixture -VerifyLocalEvidence).LocalEvidenceVerified){throw 'Evidence not verified'}
        [IO.File]::AppendAllText($path,' ');Reject {& $checker -ProjectRoot $fixture -VerifyLocalEvidence} 'evidence hash'
    }
    Reset-Fixture
    Pass 'evidence-cannot-escape-project' {$l=Read-FixtureLedger;$l.history[0]|Add-Member NoteProperty local_evidence @(@{path='../outside.json';sha256='bad'});Write-FixtureLedger $l;Reject {& $checker -ProjectRoot $fixture -VerifyLocalEvidence} 'leaves the project'}
    Reset-Fixture
    Pass 'stale-actual-exe-is-blocked' {Reject {& $checker -ProjectRoot $fixture -LauncherAssembly (Join-Path $PSScriptRoot 'runtime\ClaudeProGuard.exe')} 'Actual launcher EXE version'}
    Reset-Fixture
    Pass 'registered-public-export-retains-deployed-fingerprint' {
        $l=Read-FixtureLedger;$original=$l.history[-1].source_fingerprint.sha256
        [IO.File]::WriteAllText((Join-Path $fixture 'sample.ps1'),'Write-Output "public-example"')
        $l.history[-1]|Add-Member NoteProperty public_source_fingerprint (& $checker -ProjectRoot $fixture -GetSourceFingerprint)
        Write-FixtureLedger $l
        if((& $checker -ProjectRoot $fixture).SourceVariant -ne 'public' -or (Read-FixtureLedger).history[-1].source_fingerprint.sha256 -ne $original){throw 'Public export replaced the deployed fingerprint.'}
    }
    Pass 'public-export-edit-is-blocked' {[IO.File]::AppendAllText((Join-Path $fixture 'sample.ps1'),' # modified');Reject {& $checker -ProjectRoot $fixture} 'fingerprint'}
    Reset-Fixture
    Pass 'unregistered-sanitization-is-blocked' {[IO.File]::WriteAllText((Join-Path $fixture 'sample.ps1'),'Write-Output "public-example"');Reject {& $checker -ProjectRoot $fixture} 'fingerprint'}
    Reset-Fixture
    Pass 'partial-export-hybrid-is-blocked' {
        $l=Read-FixtureLedger
        [IO.File]::WriteAllText((Join-Path $fixture 'sample.ps1'),'Write-Output "public-example"')
        [IO.File]::WriteAllText((Join-Path $fixture 'AGENTS.md'),'public rules')
        $l.history[-1]|Add-Member NoteProperty public_source_fingerprint (& $checker -ProjectRoot $fixture -GetSourceFingerprint);Write-FixtureLedger $l
        [IO.File]::WriteAllText((Join-Path $fixture 'AGENTS.md'),'fixture rules')
        Reject {& $checker -ProjectRoot $fixture} 'fingerprint'
    }
    Reset-Fixture
    Pass 'public-variant-does-not-skip-document-checks' {
        $l=Read-FixtureLedger;[IO.File]::WriteAllText((Join-Path $fixture 'sample.ps1'),'Write-Output "public-example"')
        $l.history[-1]|Add-Member NoteProperty public_source_fingerprint (& $checker -ProjectRoot $fixture -GetSourceFingerprint);Write-FixtureLedger $l
        [IO.File]::WriteAllText((Join-Path $fixture 'README.md'),'stale version')
        Reject {& $checker -ProjectRoot $fixture} 'README.md current'
    }
    $result=@{Passed=$true;FixtureOnly=$true;ProductionProcessesTouched=$false;CaseCount=$cases.Count;Cases=@($cases);Time=[datetimeoffset]::Now.ToString('o')}
    $result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence\iteration-version-regression.json') -Encoding utf8
    $result|ConvertTo-Json -Depth 5
}finally{
    $full=[IO.Path]::GetFullPath($fixture);$allowed=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'private'))+[IO.Path]::DirectorySeparatorChar
    if($full.StartsWith($allowed,[StringComparison]::OrdinalIgnoreCase) -and [IO.Path]::GetFileName($full) -match '^iteration-version-fixture-[0-9a-f]{32}$'){Remove-Item -LiteralPath $full -Recurse -Force}
}
