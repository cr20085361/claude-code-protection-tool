[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$d=Get-GuardState
$roots=@(
    (Get-GuardCodeCacheRoots $d.Desktop),
    (Join-Path ([IO.Path]::GetDirectoryName($d.Desktop.Path)) 'resources\preseed\claude-code')
) | ForEach-Object { $_ }
$found=@()
foreach($root in $roots) {
    if(Test-Path -LiteralPath $root) {
        foreach($f in Get-ChildItem -LiteralPath $root -Filter claude.exe -File -Recurse) {
            $found+=@{Path=$f.FullName;Hash=(Get-GuardHash $f.FullName);FileVersion=$f.VersionInfo.FileVersion}
        }
    }
}
$candidatePaths=@($found | ForEach-Object {$_.Path})
$processes=@(Get-CimInstance Win32_Process | Where-Object {$_.ExecutablePath -and $_.ExecutablePath -in $candidatePaths} | Select-Object ProcessId,ParentProcessId,ExecutablePath)
$result=@{Time=(Get-Date -Format o);CacheRoots=$roots;Candidates=$found;RunningCandidateProcesses=$processes;CodeCoverage=$d.CodeCoverage;Accepted=$false;Note='Candidates and static paths do not establish a real Desktop local Code session, inherited settings, or update safety.'}
Write-GuardJson (Get-GuardPath 'evidence\code-runtime-discovery.json') $result
$result | ConvertTo-Json -Depth 8
