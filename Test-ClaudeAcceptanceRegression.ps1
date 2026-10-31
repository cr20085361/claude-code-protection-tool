[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$module=Get-Module ClaudeGuard
$fixture=Join-Path $PSScriptRoot ('private\acceptance-fixture-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path (Join-Path $fixture 'private'),(Join-Path $fixture 'evidence') -Force|Out-Null
$results=@()
try {
    $results=& $module {
        param($Fixture)
        $originalRoot=$script:Root
        $originalDesktop=(Get-Item Function:Get-GuardDesktop).ScriptBlock
        try {
            $script:Root=$Fixture
            $script:TestDesktop=[pscustomobject]@{Version='2.100.0.0';Path='C:\fixture\Claude.exe';Hash='desktop-hash'}
            Set-Item Function:script:Get-GuardDesktop { $script:TestDesktop }
            $runtime=Get-GuardPath 'evidence\local-code-runtime-accepted.json'
            $session=Get-GuardPath 'evidence\test-session-summary.json'
            Write-GuardJson $runtime @{SyntheticFixture=$true}
            Write-GuardJson $session @{SyntheticFixture=$true;EndTurn=$true}
            $acceptance=@{BasicAccepted=$true;AuthenticatedCodeResponseVerified=$true;LocalFileReadVerified=$true;DesktopHash='desktop-hash';CodeHash='code-hash';RuntimeEvidenceFile='evidence\local-code-runtime-accepted.json';TestSessionEvidenceFile='evidence\test-session-summary.json';RuntimeEvidenceHash=(Get-GuardHash $runtime);TestSessionEvidenceHash=(Get-GuardHash $session)}
            $acceptancePath=Get-GuardPath 'evidence\local-code-acceptance.json'
            Write-GuardJson $acceptancePath $acceptance
            $state=@{CodeCoverage='verified';Desktop=@{Version='2.100.0.0';Path='C:\fixture\Claude.exe';Hash='desktop-hash'};CodeGate=@{PayloadHash='code-hash'};LocalCodeAcceptance=@{EvidenceFile='evidence\local-code-acceptance.json';EvidenceHash=(Get-GuardHash $acceptancePath)}}
            $statePath=Get-GuardPath 'private\deployment.json'
            Write-GuardJson $statePath $state
            function Check([string]$Name,[bool]$Expected) {
                $actual=Test-GuardLocalCodeAcceptance
                if($actual -ne $Expected){throw ('Acceptance regression failed: '+$Name)}
                [pscustomobject]@{Case=$Name;Expected=$Expected;Actual=$actual;Passed=$true}
            }
            Check 'matching-current-version' $true
            $script:TestDesktop.Hash='changed';Check 'updated-executable-hash' $false;$script:TestDesktop.Hash='desktop-hash'
            $script:TestDesktop.Version='2.101.0.0';Check 'updated-package-version' $false;$script:TestDesktop.Version='2.100.0.0'
            $script:TestDesktop.Path='C:\fixture\new\Claude.exe';Check 'updated-install-path' $false;$script:TestDesktop.Path='C:\fixture\Claude.exe'
            $state.CodeCoverage='prepared';Write-GuardJson $statePath $state;Check 'prepared-is-not-user-accepted' $false
            $state.CodeCoverage='verified';Write-GuardJson $statePath $state
            Write-GuardJson $runtime @{Changed=$true};Check 'runtime-evidence-tampered' $false
            Write-GuardJson $runtime @{SyntheticFixture=$true}
            Write-GuardJson $session @{Changed=$true};Check 'session-evidence-tampered' $false
            Write-GuardJson $session @{SyntheticFixture=$true;EndTurn=$true}
            $acceptance.CodeHash='changed';Write-GuardJson $acceptancePath $acceptance;Check 'acceptance-evidence-tampered' $false
        } finally {
            Set-Item Function:script:Get-GuardDesktop $originalDesktop
            $script:Root=$originalRoot
            Remove-Variable TestDesktop -Scope Script -ErrorAction SilentlyContinue
        }
    } $fixture
} finally {
    # 只删除本脚本创建的三个文件及空目录，不递归删除。
    foreach($name in @('private\deployment.json','evidence\local-code-runtime-accepted.json','evidence\test-session-summary.json','evidence\local-code-acceptance.json')){Remove-Item -LiteralPath (Join-Path $fixture $name) -ErrorAction SilentlyContinue}
    Remove-Item -LiteralPath (Join-Path $fixture 'private'),(Join-Path $fixture 'evidence'),$fixture -ErrorAction SilentlyContinue
}
Write-GuardJson (Join-Path $PSScriptRoot 'evidence\acceptance-version-regression.json') @{Time=(Get-Date -Format o);FixtureOnly=$true;Cases=$results;Passed=$true}
$results|ConvertTo-Json
