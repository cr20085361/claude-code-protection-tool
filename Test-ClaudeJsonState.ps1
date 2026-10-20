$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeJsonStateTests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $fixture
$checks=[Collections.Generic.List[string]]::new()
try {
    & (Get-Module ClaudeGuard) {
        param($Fixture,$Checks)
        function Require($Ok,$Name){if(-not $Ok){throw $Name};$Checks.Add($Name)}
        $path=Join-Path $Fixture 'state.json'
        Write-GuardJson $path @{Version=1}
        Require ((Read-GuardJson $path).Version -eq 1) 'json-created-and-readable'
        Write-GuardJson $path @{Version=2}
        Require ((Read-GuardJson $path).Version -eq 2) 'json-replaced-and-readable'
        $original=${function:Write-GuardJson}.ToString()
        $call='[IO.File]::Replace($temp,$Path,[NullString]::Value)'
        $injection='if($script:replacementFailures -gt 0){$script:replacementFailures--;throw [IO.IOException]::new("injected native replacement error",($script:replacementCode - 2147024896))};'+$call
        $testWriter=[scriptblock]::Create($original.Replace($call,$injection))
        $script:replacementCode=1175;$script:replacementFailures=2
        & $testWriter $path @{Version=3}
        Require ((Read-GuardJson $path).Version -eq 3 -and $script:replacementFailures -eq 0) 'native-1175-retried-and-published'
        $script:replacementFailures=1000;$watch=[Diagnostics.Stopwatch]::StartNew();$failed=$false
        try{& $testWriter $path @{Version=4}}catch{$failed=$true}
        Require ($failed -and $watch.ElapsedMilliseconds -ge 1900 -and $watch.ElapsedMilliseconds -lt 6000) 'native-1175-retry-budget-bounded'
        Require ((Read-GuardJson $path).Version -eq 3) 'persistent-replacement-failure-preserves-old-state'
        Require (@(Get-ChildItem -LiteralPath $Fixture -Filter '*.tmp').Count -eq 0) 'failed-replacement-cleans-disposable-temporary-file'
        foreach($code in @(1176,1177)){
            $script:replacementCode=$code;$script:replacementFailures=1000;$watch.Restart();$failed=$false
            try{& $testWriter $path @{Version=5}}catch{$failed=$true}
            Require ($failed -and $script:replacementFailures -eq 999 -and $watch.ElapsedMilliseconds -lt 1000) ('unsafe-native-'+$code+'-not-retried')
        }
        $lock=[IO.File]::Open($path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::ReadWrite)
        try{
            $watch.Restart();$failed=$false
            try{Write-GuardJson $path @{Version=6}}catch{$failed=$true}
            Require ($failed -and $watch.ElapsedMilliseconds -ge 1900) 'real-windows-sharing-lock-respects-retry-budget'
            Require (([IO.File]::ReadAllText($path)|ConvertFrom-Json).Version -eq 3) 'real-sharing-failure-preserves-valid-json'
        } finally {$lock.Dispose()}
        Write-GuardJson $path @{Version=7}
        Require ((Read-GuardJson $path).Version -eq 7) 'publication-recovers-after-lock-release'
        Require (@(Get-ChildItem -LiteralPath $Fixture -Filter '*.tmp').Count -eq 0) 'all-temporary-files-cleaned'
    } $fixture $checks
    $result=@{Time=(Get-Date -Format o);Passed=$true;FixtureOnly=$true;Count=$checks.Count;Checks=@($checks)}
    Write-GuardJson (Join-Path $PSScriptRoot 'evidence\json-state-fixture-tests.json') $result
    $result|ConvertTo-Json -Depth 4
} finally {
    $full=[IO.Path]::GetFullPath($fixture);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeJsonStateTests-[0-9a-f]{32}$'){throw 'Unsafe JSON fixture cleanup path.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
