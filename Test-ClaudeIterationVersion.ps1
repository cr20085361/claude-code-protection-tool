[CmdletBinding()]
param(
    [string]$ProjectRoot=$PSScriptRoot,
    [string]$LauncherAssembly,
    [string]$BaselineFile,
    [ValidateRange(1,100)][int]$ExpectedNewIterations=1,
    [switch]$GetSourceFingerprint,
    [switch]$VerifyLocalEvidence
)
$ErrorActionPreference='Stop'
function Get-IterationSourceFingerprint {
    $files=@(Get-ChildItem -LiteralPath $ProjectRoot -File|Where-Object {$_.Extension -in @('.cs','.ps1','.psm1','.py','.cjs') -or $_.Name -eq 'AGENTS.md'}|Sort-Object Name)
    $lines=@($files|ForEach-Object {$_.Name+'='+((Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant())})
    $bytes=[Text.Encoding]::UTF8.GetBytes(($lines -join "`n")+"`n")
    [pscustomobject]@{algorithm='sha256';scope='root-source-and-AGENTS-v1';sha256=[Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes)).ToLowerInvariant();file_count=$files.Count}
}
function Read-IterationVersion([string]$Value){
    if($Value -notmatch '^v(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$'){throw ('Invalid iteration version: '+$Value)}
    [version]$Value.Substring(1)
}
function Require-Iteration([bool]$Condition,[string]$Message){if(-not $Condition){throw $Message}}
function Test-IterationFingerprint($Expected,$Actual){
    $Expected -and $Expected.scope -ceq $Actual.scope -and $Expected.algorithm -ceq 'sha256' -and
        $Expected.sha256 -cmatch '^[0-9a-f]{64}$' -and $Expected.sha256 -ceq $Actual.sha256 -and $Expected.file_count -eq $Actual.file_count
}
$ProjectRoot=[IO.Path]::GetFullPath($ProjectRoot)
$fingerprint=Get-IterationSourceFingerprint
if($GetSourceFingerprint){return $fingerprint}
$raw=Get-Content -LiteralPath (Join-Path $ProjectRoot '.iteration-version.json') -Raw
$ledger=$raw|ConvertFrom-Json
# ConvertFrom-Json 可自动转换日期，时区要求必须依据原始 JSON 字符串核验。
$document=[Text.Json.JsonDocument]::Parse($raw)
try{
    $dates=@($document.RootElement.GetProperty('history').EnumerateArray()|ForEach-Object {
        $completedElement=[Text.Json.JsonElement]::new()
        [pscustomobject]@{Recorded=$_.GetProperty('recorded_at').GetString();Completed=if($_.TryGetProperty('completed_at',[ref]$completedElement)){$completedElement.GetString()}else{$null}}
    })
}finally{$document.Dispose()}
Require-Iteration ($ledger.schema_version -eq 1) 'Unsupported iteration ledger schema.'
$history=@($ledger.history)
Require-Iteration ($history.Count -gt 0 -and $history.Count -eq $ledger.completed_iterations) 'Iteration history count does not match completed_iterations.'
$expected=$ledger.baseline.version;$ids=[Collections.Generic.HashSet[string]]::new();$entryIndex=0
foreach($entry in $history){
    $parsedId=[guid]::Empty
    Require-Iteration ($ids.Add([string]$entry.id) -and [guid]::TryParse([string]$entry.id,[ref]$parsedId)) 'Iteration IDs must be unique UUIDs.'
    Require-Iteration ($entry.from_version -ceq $expected) 'Iteration version chain is broken.'
    $from=Read-IterationVersion $entry.from_version;$to=Read-IterationVersion $entry.to_version
    $next=switch($entry.level){'patch'{[version]::new($from.Major,$from.Minor,$from.Build+1)}'minor'{[version]::new($from.Major,$from.Minor+1,0)}'major'{[version]::new($from.Major+1,0,0)}default{throw 'Unknown iteration increment level.'}}
    Require-Iteration ($to -eq $next) 'Iteration version does not follow its semantic increment level.'
    Require-Iteration (-not [string]::IsNullOrWhiteSpace($entry.summary) -and -not [string]::IsNullOrWhiteSpace($entry.verification)) 'Iteration summary and verification are required.'
    $recorded=[datetimeoffset]::MinValue
    Require-Iteration ($dates[$entryIndex].Recorded -match '(Z|[+-]\d{2}:\d{2})$' -and [datetimeoffset]::TryParse($dates[$entryIndex].Recorded,[ref]$recorded)) 'Iteration recording time requires a timezone.'
    if($entry.PSObject.Properties['backfilled'] -and $entry.backfilled){
        $completed=[datetimeoffset]::MinValue
        Require-Iteration ($dates[$entryIndex].Completed -match '(Z|[+-]\d{2}:\d{2})$' -and [datetimeoffset]::TryParse($dates[$entryIndex].Completed,[ref]$completed) -and $completed -le $recorded) 'Backfilled entry must retain a valid historical completion time.'
        [void](Read-IterationVersion $entry.deployed_version_at_completion)
        Require-Iteration (@($entry.local_evidence).Count -gt 0) 'Backfilled entry needs inspectable evidence references.'
    }
    if($VerifyLocalEvidence -and $entry.PSObject.Properties['local_evidence']){
        foreach($proof in @($entry.local_evidence)){
            $path=[IO.Path]::GetFullPath((Join-Path $ProjectRoot $proof.path))
            Require-Iteration ($path.StartsWith($ProjectRoot+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) 'Evidence path leaves the project.'
            Require-Iteration ((Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ieq $proof.sha256) 'Local evidence hash differs from the recorded artifact.'
        }
    }
    $expected=$entry.to_version
    $entryIndex++
}
Require-Iteration ($ledger.current_version -ceq $expected) 'Current version differs from the final history entry.'
$version=Read-IterationVersion $ledger.current_version;$assemblyVersion=$version.ToString()+'.0'
$latest=$history[-1]
$sourceVariant='deployed'
$sourceMatches=Test-IterationFingerprint $latest.source_fingerprint $fingerprint
if(-not $sourceMatches -and $latest.PSObject.Properties['public_source_fingerprint']){
    # Explicitly register the complete sanitized export in the NEW iteration;
    # keep the deployed fingerprint and every historical entry unchanged.
    $sourceMatches=Test-IterationFingerprint $latest.public_source_fingerprint $fingerprint
    if($sourceMatches){$sourceVariant='public'}
}
Require-Iteration $sourceMatches 'Source changed without a matching completed iteration fingerprint.'
$source=Get-Content -LiteralPath (Join-Path $ProjectRoot 'ClaudeGuardLauncher.cs') -Raw
foreach($pattern in @('AssemblyVersion\("([^"]+)"\)','AssemblyFileVersion\("([^"]+)"\)')){
    $matches=[regex]::Matches($source,$pattern)
    Require-Iteration ($matches.Count -eq 1 -and $matches[0].Groups[1].Value -ceq $assemblyVersion) 'Launcher assembly metadata differs from iteration version.'
}
$constant=[regex]::Matches($source,'public const string BuildVersion="([^"]+)";')
Require-Iteration ($constant.Count -eq 1 -and $constant[0].Groups[1].Value -ceq $ledger.current_version) 'Launcher UI version differs from iteration version.'
$summary='\*\*'+[regex]::Escape($ledger.current_version)+' · 第 '+$history.Count+' 次源码迭代\*\*'
foreach($name in @('README.md','CHANGELOG.md')){
    $text=Get-Content -LiteralPath (Join-Path $ProjectRoot $name) -Raw
    Require-Iteration ($text -match ('(?m)^当前[^\r\n]*'+$summary)) ($name+' current version/count differs from ledger.')
}
$changelog=Get-Content -LiteralPath (Join-Path $ProjectRoot 'CHANGELOG.md') -Raw
foreach($entry in $history){Require-Iteration ($changelog -match ('(?m)^## '+[regex]::Escape($entry.to_version)+' \(')) 'A completed iteration has no changelog entry.'}
$deployment=Get-Content -LiteralPath (Join-Path $ProjectRoot 'docs\DEPLOYMENT.md') -Raw
Require-Iteration ($deployment -match ('(?m)^当前源码为 '+[regex]::Escape($ledger.current_version)+'[，,]')) 'Deployment document current version differs from ledger.'
if($BaselineFile){
    $before=Get-Content -LiteralPath $BaselineFile -Raw|ConvertFrom-Json
    Require-Iteration ($ledger.completed_iterations -eq $before.CompletedIterations+$ExpectedNewIterations -and $version -gt (Read-IterationVersion $before.Version)) 'Implementation did not advance the baseline iteration version and count.'
    Require-Iteration ($history[$before.CompletedIterations].from_version -ceq $before.Version) 'New history is not appended to the task baseline.'
}
if($LauncherAssembly){
    $exe=[IO.Path]::GetFullPath($LauncherAssembly)
    $info=[Diagnostics.FileVersionInfo]::GetVersionInfo($exe)
    Require-Iteration ($info.FileVersion -ceq $assemblyVersion -and $info.ProductVersion -ceq $assemblyVersion -and [Reflection.AssemblyName]::GetAssemblyName($exe).Version.ToString() -ceq $assemblyVersion) 'Actual launcher EXE version differs from ledger/source.'
}
[pscustomobject]@{Passed=$true;Version=$ledger.current_version;CompletedIterations=$history.Count;SourceFingerprintVerified=$true;SourceVariant=$sourceVariant;BinaryVerified=[bool]$LauncherAssembly;BaselineVerified=[bool]$BaselineFile;LocalEvidenceVerified=[bool]$VerifyLocalEvidence}
