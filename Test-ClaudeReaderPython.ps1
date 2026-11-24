[CmdletBinding()]
param([string]$ResultFile=(Join-Path $PSScriptRoot 'evidence\reader-python-regression.json'))

Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$runtimePath=Join-Path $PSScriptRoot 'ClaudeGuard-Runtime.psm1'
$tokens=$null;$parseErrors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($runtimePath,[ref]$tokens,[ref]$parseErrors)
if($parseErrors.Count){throw ('Runtime parse failed: '+($parseErrors.Message -join '; '))}
$names=@('Get-GuardReaderPythonCandidates','Invoke-GuardReaderPythonProbe','Resolve-GuardReaderPython')
$definitions=@($ast.FindAll({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -in $names},$false))
if($definitions.Count -ne $names.Count){throw 'Reader fixture functions were not found exactly once.'}
$probeSource=($definitions|Where-Object Name -eq 'Invoke-GuardReaderPythonProbe').Extent.Text
$module=New-Module -ScriptBlock ([scriptblock]::Create("Set-StrictMode -Version Latest`n"+($definitions.Extent.Text -join [Environment]::NewLine)))
$fixture=Join-Path $PSScriptRoot ('private\reader-python-fixture-'+[guid]::NewGuid().ToString('N'))
$result=[ordered]@{Time=[datetimeoffset]::UtcNow.ToString('o');Passed=$false;FixtureOnly=$true;NativePythonExecuted=$false;ProductionProcessesTouched=$false;ProductionStateTouched=$false;Cases=@();Error=$null}
try{
    # Empty files are never executed. Only the resolver runs; its process probe
    # and discovery are replaced inside this private dynamic module.
    $pathA=Join-Path $fixture 'fixture-secret-A\python.exe'
    $pathB=Join-Path $fixture 'fixture-secret-B\python.exe'
    $wrongName=Join-Path $fixture 'fixture-secret-other\other.exe'
    $storeAlias=Join-Path $fixture 'WindowsApps\python.exe'
    foreach($path in @($pathA,$pathB,$wrongName,$storeAlias)){
        New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($path)) -Force|Out-Null
        [IO.File]::WriteAllBytes($path,[byte[]]@())
    }
    $result.Cases=@(& $module {
        param($PathA,$PathB,$WrongName,$StoreAlias,$Fixture,$ProbeSource)
        $script:cases=[Collections.Generic.List[object]]::new()
        function Require([bool]$Condition,[string]$Name){
            if(-not $Condition){throw ('Reader regression failed: '+$Name)}
            $script:cases.Add([pscustomobject]@{Name=$Name;Passed=$true})
        }
        function Reset-Fixture([object[]]$Candidates,[object[]]$Steps,[int]$DiscoveryDelay=0){
            $script:fixtureCandidates=@($Candidates);$script:fixtureSteps=@($Steps)
            $script:fixtureCalls=[Collections.Generic.List[object]]::new()
            $script:fixtureDiscoveryCount=0;$script:fixtureDiscoveryDelay=$DiscoveryDelay
        }
        function script:Get-GuardReaderPythonCandidates{
            $script:fixtureDiscoveryCount++
            if($script:fixtureDiscoveryDelay){[Threading.Thread]::Sleep($script:fixtureDiscoveryDelay)}
            $script:fixtureCandidates
        }
        function script:Invoke-GuardReaderPythonProbe([string]$Path,[int]$TimeoutMilliseconds){
            $index=$script:fixtureCalls.Count
            $script:fixtureCalls.Add([pscustomobject]@{Path=$Path;TimeoutMilliseconds=$TimeoutMilliseconds})
            if($index -ge $script:fixtureSteps.Count){throw 'Unexpected extra probe invocation.'}
            $step=$script:fixtureSteps[$index]
            $clock=[Diagnostics.Stopwatch]::StartNew()
            if($step -eq 'UseBudgetThenTimeout'){[Threading.Thread]::Sleep($TimeoutMilliseconds+5);$step='TimedOut'}
            elseif($step -eq 'UseBudgetThenPass'){[Threading.Thread]::Sleep($TimeoutMilliseconds+5);$step='Passed'}
            [pscustomobject]@{
                Outcome=$step;ElapsedMilliseconds=$clock.ElapsedMilliseconds
                ExitCode=$(if($step -eq 'Passed'){0}elseif($step -eq 'NonZeroExit'){42}else{$null})
                NativeErrorCode=$(if($step -eq 'StartFailed'){5}else{$null})
                Path=$Path;Stdout='fixture-secret-token-DO-NOT-LOG'
                Stderr='fixture-secret-error-DO-NOT-LOG';Exception='fixture-secret-exception-DO-NOT-LOG'
            }
        }
        function script:Write-GuardJson{throw 'Resolver must not write production state.'}
        function Run-Fixture([int]$Budget=8000,[switch]$WithoutFailures){
            $failures=@();$resolved=$null;$failure=$null
            $clock=[Diagnostics.Stopwatch]::StartNew()
            try{
                if($WithoutFailures){$resolved=Resolve-GuardReaderPython $Budget}
                else{$resolved=Resolve-GuardReaderPython $Budget ([ref]$failures)}
            }catch{$failure=$_.Exception.Message}
            [pscustomobject]@{Path=$resolved;Error=$failure;Failures=@($failures);ElapsedMilliseconds=$clock.ElapsedMilliseconds;Calls=@($script:fixtureCalls);DiscoveryCount=$script:fixtureDiscoveryCount}
        }

        Reset-Fixture @($PathA,$PathB) @('Passed')
        $r=Run-Fixture
        Require ($r.Path -eq $PathA -and -not $r.Error -and $r.Calls.Count -eq 1) 'first-valid-interpreter-used-without-retry'
        Require ($r.Failures.Count -eq 0) 'successful-probe-is-not-failure-metadata'
        Require ($r.DiscoveryCount -eq 1) 'candidate-discovery-is-per-resolution'

        Reset-Fixture @($PathA) @('TimedOut','Passed')
        $r=Run-Fixture
        Require ($r.Path -eq $PathA -and $r.Calls.Count -eq 2 -and -not $r.Error) 'transient-timeout-retries-successfully'
        Require ($r.Failures.Count -eq 1 -and $r.Failures[0].CandidateIndex -eq 1 -and $r.Failures[0].Round -eq 1 -and $r.Failures[0].Outcome -eq 'TimedOut') 'retry-retains-first-failure-diagnostic'
        Require ($r.Calls[0].TimeoutMilliseconds -gt 0 -and $r.Calls[0].TimeoutMilliseconds -le 1500 -and $r.Calls[1].TimeoutMilliseconds -gt 0 -and $r.Calls[1].TimeoutMilliseconds -le 2250) 'each-round-obeys-its-probe-cap'

        Reset-Fixture @($PathA,$PathB) @('TimedOut','Passed')
        $r=Run-Fixture
        Require ($r.Path -eq $PathB -and $r.Calls.Count -eq 2 -and $r.Calls[0].Path -eq $PathA -and $r.Calls[1].Path -eq $PathB) 'fallback-is-tried-before-retrying-first-interpreter'
        Require ($r.Failures.Count -eq 1 -and $r.Failures[0].Round -eq 1) 'fallback-success-does-not-enter-second-round'

        Reset-Fixture @($PathA,$PathB) @('StartFailed','Passed')
        $r=Run-Fixture
        Require ($r.Path -eq $PathB -and $r.Failures[0].NativeErrorCode -eq 5) 'native-start-failure-falls-back-with-numeric-code'
        Reset-Fixture @($PathA,$PathB) @('NonZeroExit','Passed')
        $r=Run-Fixture
        Require ($r.Path -eq $PathB -and $r.Failures[0].ExitCode -eq 42) 'nonzero-probe-exit-falls-back-with-numeric-code'

        Reset-Fixture @($PathA,$PathB) @('TimedOut','NonZeroExit','TimedOut','StartFailed')
        $r=Run-Fixture
        Require (-not $r.Path -and $r.Error -like 'RuntimeReaderUnavailable:*') 'persistent-failure-remains-unavailable'
        Require ($r.Calls.Count -eq 4 -and ($r.Calls.Path -join '|') -eq (@($PathA,$PathB,$PathA,$PathB) -join '|')) 'persistent-failure-is-bounded-to-two-ordered-rounds'
        Require (($r.Failures.CandidateIndex -join ',') -eq '1,2,1,2' -and ($r.Failures.Round -join ',') -eq '1,1,2,2') 'diagnostics-bind-failure-to-candidate-and-round'
        $safeFields=@('CandidateIndex','Round','Outcome','ElapsedMilliseconds','ExitCode','NativeErrorCode')|Sort-Object
        foreach($failure in $r.Failures){
            $actualFields=@($failure.PSObject.Properties.Name)|Sort-Object
            Require (-not @(Compare-Object $actualFields $safeFields).Count) ('failure-metadata-field-whitelist-'+$failure.CandidateIndex+'-'+$failure.Round)
        }
        $serialized=ConvertTo-Json -InputObject $r.Failures -Depth 5 -Compress
        Require ($serialized -notmatch 'fixture-secret|DO-NOT-LOG|python\.exe|[A-Za-z]:\\' -and $r.Error -notmatch 'fixture-secret|DO-NOT-LOG|python\.exe') 'failure-metadata-and-error-exclude-paths-output-and-exception-text'

        $missing=Join-Path $Fixture 'missing\python.exe'
        Reset-Fixture @('python.exe','\\untrusted.example\share\python.exe',$WrongName,$StoreAlias,$missing,$PathA) @('Passed')
        $r=Run-Fixture
        Require ($r.Path -eq $PathA -and $r.Calls.Count -eq 1 -and $r.Calls[0].Path -eq $PathA) 'unrecognized-alias-relative-unc-wrong-name-and-missing-candidates-never-execute'
        Require (@($r.Failures|Where-Object Outcome -eq 'InvalidCandidate').Count -eq 4 -and @($r.Failures|Where-Object Outcome -eq 'MissingFile').Count -eq 1) 'invalid-and-missing-candidates-have-fixed-diagnostics'
        Require (@($r.Failures|Where-Object Round -ne 0).Count -eq 0 -and ($r.Failures.CandidateIndex -join ',') -eq '1,2,3,4,5') 'skipped-candidates-use-round-zero-and-original-one-based-indices'

        Reset-Fixture @($PathA,$PathA,$PathB) @('TimedOut','Passed')
        $r=Run-Fixture
        Require ($r.Path -eq $PathB -and $r.Calls.Count -eq 2) 'duplicate-discovery-does-not-repeat-first-round-probe'
        Reset-Fixture @() @()
        $r=Run-Fixture
        Require (-not $r.Path -and $r.Error -like 'RuntimeReaderUnavailable:*' -and $r.Calls.Count -eq 0) 'empty-discovery-remains-unavailable-without-probing'
        Require ($r.Failures.Count -eq 1 -and $r.Failures[0].Outcome -eq 'NoCandidate' -and $r.Failures[0].Round -eq 0) 'empty-discovery-is-distinguishable-from-probe-failure'

        Reset-Fixture @($PathA,$PathB) @('UseBudgetThenTimeout')
        $r=Run-Fixture 120
        Require (-not $r.Path -and $r.Error -like 'RuntimeReaderUnavailable:*' -and $r.Calls.Count -eq 1) 'budget-exhaustion-prevents-fallback-and-retry'
        Require ($r.Calls[0].TimeoutMilliseconds -gt 0 -and $r.Calls[0].TimeoutMilliseconds -le 120 -and $r.ElapsedMilliseconds -lt 1500) 'remaining-global-budget-caps-probe-wait'
        Require (@($r.Failures|Where-Object Outcome -eq 'BudgetExhausted').Count -eq 1) 'budget-exhaustion-has-fixed-summary'
        Reset-Fixture @($PathA) @('UseBudgetThenPass')
        $r=Run-Fixture 120
        Require (-not $r.Path -and $r.Error -like 'RuntimeReaderUnavailable:*' -and @($r.Failures|Where-Object Outcome -eq 'BudgetExhausted').Count -eq 1) 'late-success-does-not-bypass-global-budget'
        Reset-Fixture @($PathA) @('Passed') 80
        $r=Run-Fixture 20
        Require (-not $r.Path -and $r.Calls.Count -eq 0 -and @($r.Failures|Where-Object Outcome -eq 'BudgetExhausted').Count -eq 1) 'discovery-time-is-charged-to-global-budget'

        foreach($budget in @(0,8001)){
            Reset-Fixture @($PathA) @('Passed')
            $r=Run-Fixture $budget
            Require (-not $r.Path -and $r.Error -and $r.Calls.Count -eq 0 -and $r.DiscoveryCount -eq 0) ('out-of-range-budget-refused-'+$budget)
        }
        Reset-Fixture @($PathA) @('Passed')
        $r=Run-Fixture -WithoutFailures
        Require ($r.Path -eq $PathA -and -not $r.Error) 'existing-callers-without-diagnostic-ref-still-work'

        # The native probe is not executed by this fixture. These checks protect
        # its isolation flags and CPython 3/x64 attestation while native success
        # is verified separately under the deployed supervisor shell.
        Require ($ProbeSource.Contains("'-I'") -and $ProbeSource.Contains("'-S'") -and $ProbeSource.Contains("'-c'")) 'native-probe-keeps-isolated-no-site-code-invocation'
        Require ($ProbeSource.Contains('sys.implementation.name == "cpython"') -and $ProbeSource.Contains('sys.version_info.major == 3') -and $ProbeSource.Contains('struct.calcsize("P") == 8')) 'native-probe-requires-cpython-three-and-64-bit-pointers'
        @($script:cases)
    } $pathA $pathB $wrongName $storeAlias $fixture $probeSource)
    $result.Passed=$true
}catch{
    $result.Error=$_.Exception.Message
    throw
}finally{
    $parent=[IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'private')).TrimEnd('\')+'\'
    $full=[IO.Path]::GetFullPath($fixture)
    if(-not $full.StartsWith($parent,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^reader-python-fixture-[a-f0-9]{32}$'){
        throw 'Unsafe reader fixture cleanup was refused.'
    }
    if(Test-Path -LiteralPath $full){
        if((Get-Item -LiteralPath $full -Force).Attributes -band [IO.FileAttributes]::ReparsePoint -or @(Get-ChildItem -LiteralPath $full -Force -Recurse|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count){throw 'Reader fixture contains a reparse point.'}
        Remove-Item -LiteralPath $full -Recurse -Force
    }
    if($module){Remove-Module $module -ErrorAction SilentlyContinue}
    $result.Count=@($result.Cases).Count
    $outputParent=[IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($ResultFile))
    if(-not (Test-Path -LiteralPath $outputParent)){New-Item -ItemType Directory -Path $outputParent -Force|Out-Null}
    [IO.File]::WriteAllText($ResultFile,($result|ConvertTo-Json -Depth 6),[Text.UTF8Encoding]::new($false))
}
[pscustomobject]$result|ConvertTo-Json -Depth 6
