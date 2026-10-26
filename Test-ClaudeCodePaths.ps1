[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$project=$PSScriptRoot
Import-Module (Join-Path $project 'ClaudeGuard.psm1') -Force
$fixture=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeCodePaths-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $fixture
$oldApp=$env:APPDATA;$oldLocal=$env:LOCALAPPDATA
$checks=[Collections.Generic.List[string]]::new()
function Require($Condition,$Name){if(-not $Condition){throw ('Code paths regression failed: '+$Name)};$checks.Add($Name)}
try {
    $env:APPDATA=Join-Path $fixture 'Roaming';$env:LOCALAPPDATA=Join-Path $fixture 'Local'
    $desktop=[pscustomobject]@{Family='Claude_fixture'}
    $roots=@(Get-GuardCodeCacheRoots $desktop)
    Require ($roots.Count -eq 3 -and $roots[2] -eq (Join-Path $env:LOCALAPPDATA 'Claude-Data\claude_fixture\claude-code')) 'legacy-and-current-cache-layouts-discovered'
    $rejected=$false;try{Get-GuardCodeCacheRoots ([pscustomobject]@{Family='..\escape'})}catch{$rejected=$true}
    Require $rejected 'package-family-path-traversal-refused'
    # Use the real cache repair, ACL and gate functions with offline firewall substitutes.
    foreach($sourceFile in @('ClaudeGuard.psm1','ClaudeCodeGate.psm1')){
        $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $project $sourceFile),[ref]$null,[ref]$null)
        foreach($name in @('Repair-GuardDesktopCodeCache','Set-CodeCacheGate','Assert-CodeCacheGate','Set-CodeAccessOnlyAcl','Protect-CodeBinary')){
            $definition=$ast.Find({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name},$true)
            if($definition){. ([scriptblock]::Create($definition.Extent.Text))}
        }
    }
    function Import-Module {}
    function Test-GuardAdmin {$true}
    function Get-GuardState {$script:state}
    function Get-GuardPath($Name){Join-Path $fixture $Name}
    $script:firewallPaths=[Collections.Generic.List[string]]::new()
    function Assert-GuardRule($Path){$script:firewallPaths.Add($Path)}
    function Assert-GuardSharedProxyBlock($Path){if($Path -notin $script:firewallPaths){throw 'Shared proxy validation preceded direct egress validation.'}}
    function Assert-GuardFirewall {}
    function Test-CodeCacheGate {}
    function Assert-CodePrepared {}
    $null=New-Item -ItemType Directory -Path (Join-Path $fixture 'private'),(Join-Path $fixture 'evidence')
    $payload=Join-Path $fixture 'private\payload.exe'
    Copy-Item -LiteralPath (Join-Path $env:SystemRoot 'System32\whoami.exe') -Destination $payload
    $archive=Join-Path $fixture 'archive.bin';[IO.File]::WriteAllText($archive,'fixture-metadata')
    $paths=@($roots|ForEach-Object {Join-Path $_ '2.1.304\0123456789ab\claude.exe'})
    $script:state=[pscustomobject]@{UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Desktop=$desktop;CodeCoverage='prepared';CodePaths=$paths;Reliability=@{};CodeGate=[pscustomobject]@{Roots=$roots;Version='2.1.304';CompressedHash='0123456789abcdef';PayloadPath=$payload;PayloadHash=(Get-GuardHash $payload);ArchivePath=$archive;ArchiveHash=(Get-GuardHash $archive)}}
    foreach($root in $roots){$null=New-Item -ItemType Directory -Path $root -Force;Set-CodeCacheGate $root}
    # Reproduce the incident: valid current engine exists, but still inherits execution deny.
    $actual=$paths[2];$null=New-Item -ItemType Directory -Path (Split-Path $actual) -Force;Copy-Item -LiteralPath $payload -Destination $actual
    function Can-Start($Path){try{$p=Start-Process -FilePath $Path -WindowStyle Hidden -PassThru -Wait -RedirectStandardOutput (Join-Path $fixture 'probe.out');return $p.ExitCode -eq 0}catch{return $false}}
    Require (-not (Can-Start $actual)) 'inherited-execution-deny-reproduces-launch-failure'
    Repair-GuardDesktopCodeCache
    Require (Can-Start $actual) 'existing-verified-current-engine-starts-after-repair'
    Require (@($paths|Where-Object {$_ -notin $script:firewallPaths}).Count -eq 0) 'all-cache-paths-validate-firewall-before-allow'
    $unknown=Join-Path (Split-Path $actual) 'unknown.exe';Copy-Item -LiteralPath $payload -Destination $unknown
    Require (-not (Can-Start $unknown)) 'unapproved-neighbour-remains-blocked'
    $acl=Get-Acl -LiteralPath $actual;$acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.WindowsIdentity]::GetCurrent().User,'FullControl','Allow'));Set-CodeAccessOnlyAcl $actual $acl
    [IO.File]::AppendAllText($actual,'tampered');$rejected=$false
    try{Repair-GuardDesktopCodeCache}catch{$rejected=$_.Exception.Message -match 'differs from the approved payload'}
    Require $rejected 'modified-current-engine-refused'
    $result=@{Time=(Get-Date -Format o);Passed=$true;FixtureOnly=$true;Count=$checks.Count;Checks=@($checks)}
    Write-GuardJson (Join-Path $project 'evidence\code-path-fixture-tests.json') $result
    $result|ConvertTo-Json -Depth 4
} finally {
    $env:APPDATA=$oldApp;$env:LOCALAPPDATA=$oldLocal
    $full=[IO.Path]::GetFullPath($fixture);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeCodePaths-[0-9a-f]{32}$'){throw 'Unsafe Code paths fixture cleanup.'}
    foreach($file in Get-ChildItem -LiteralPath $full -Filter *.exe -Recurse -File){
        $acl=[Security.AccessControl.FileSecurity]::new();$acl.SetAccessRuleProtection($true,$false)
        $acl.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.WindowsIdentity]::GetCurrent().User,'FullControl','Allow'))
        Set-CodeAccessOnlyAcl $file.FullName $acl
    }
    Remove-Item -LiteralPath $full -Recurse -Force
}
