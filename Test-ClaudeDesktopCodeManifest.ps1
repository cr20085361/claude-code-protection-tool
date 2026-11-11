$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-DesktopUpdate.psm1') -Force
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeCodeManifestTests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $scratch
$checks=[Collections.Generic.List[string]]::new()
function Require([bool]$Ok,[string]$Name){if(-not $Ok){throw ('Manifest fixture failed: '+$Name)};$checks.Add($Name)}
function New-FixtureArchive([string]$Source){
    $payload=[Text.Encoding]::UTF8.GetBytes($Source)
    $tree=@{files=@{'.vite'=@{files=@{build=@{files=@{'index-fixture.js'=@{size=$payload.Length;offset='0'}}}}}}}
    $json=[Text.Encoding]::UTF8.GetBytes(($tree|ConvertTo-Json -Depth 12 -Compress))
    $header=[byte[]]::new(16)
    [BitConverter]::GetBytes([uint32]4).CopyTo($header,0)
    [BitConverter]::GetBytes([uint32](8+$json.Length)).CopyTo($header,4)
    [BitConverter]::GetBytes([uint32](4+$json.Length)).CopyTo($header,8)
    [BitConverter]::GetBytes([uint32]$json.Length).CopyTo($header,12)
    $path=Join-Path $scratch ([guid]::NewGuid().ToString('N')+'.asar')
    $stream=[IO.File]::Create($path)
    try{$stream.Write($header);$stream.Write($json);$stream.Write($payload)}finally{$stream.Dispose()}
    $path
}
# Preserve vendor JSON's leading version field, as required by the real reader.
$manifestJson='{"version":"2.1.321","baseUrl":"https://downloads.claude.ai/claude-code-releases","manifest":{"version":"2.1.321","platforms":{"win32-x64":{"binary":"claude.exe.zst","checksum":"'+('a'*64)+'"}}}}'
$data="throw new Error('vendor code must never execute');const embedded=JSON.parse('"+$manifestJson+"');"
$policy='const schema={flatKey:"disableAutoUpdates"};'
$legacy='log.info("[CCD-autoupdate] Disabled: MSIX install");'
$offline='log.info("[CCD-autoupdate] Disabled: offline MSIX (preseeded CLI)");'
$modern='async function poll(){if(!flag())return;if(policy().autoUpdate.disabled){once||(once=!0,log.info("[CCD-autoupdate] Disabled by enterprise policy"));return}if(await runtime.hasLocalBinaryOverride())return;await check();}'
# Exercise the actual validation conditions used during maintenance and initial
# preparation, without executing either script's live deployment operations.
$gates=@{}
foreach($name in @('Update-ClaudeGuard.ps1','Prepare-ClaudeCode.ps1')){
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot $name),[ref]$tokens,[ref]$errors)
    $ifs=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.IfStatementAst] -and $n.Extent.Text.StartsWith('if') -and $n.Extent.Text.Contains('$m.codeAutomaticUpdatesControlled')},$true))
    Require ($errors.Count -eq 0 -and $ifs.Count -eq 1) ($name+'-validation-located')
    $gates[$name]=[scriptblock]::Create($ifs[0].Extent.Text)
}
function Test-PolicyCase([string]$Name,[string]$Source,[bool]$Accepted,[string]$Mode){
    $archive=New-FixtureArchive ($data+$Source)
    $raw=& node (Join-Path $PSScriptRoot 'Read-DesktopCodeManifest.cjs') $archive 2>$null
    Require ($LASTEXITCODE -eq 0) ($Name+'-metadata-read-without-execution')
    $m=$raw|ConvertFrom-Json
    Require ($m.codeAutoUpdateControl -ceq $Mode) ($Name+'-control-mode')
    $allowed=$true
    try{$null=Read-ClaudeDesktopUpdateEngine $PSScriptRoot $archive}catch{$allowed=$false}
    Require ($allowed -eq $Accepted) ($Name+'-download-gate')
    foreach($entry in $gates.GetEnumerator()){
        $allowed=$true;try{& $entry.Value}catch{$allowed=$false}
        Require ($allowed -eq $Accepted) ($Name+'-'+$entry.Key+'-gate')
    }
    if($Mode -eq 'enterprise-policy'){Require (-not $m.msixAutomaticCodeUpdatesDisabled) ($Name+'-does-not-claim-all-msix-updates-disabled')}
}
try{
    Test-PolicyCase 'legacy-msix' ($policy+$legacy) $true 'msix-disabled'
    Test-PolicyCase 'online-msix-policy' ($policy+$offline+$modern) $true 'enterprise-policy'
    Test-PolicyCase 'renamed-identifiers' ($policy+$modern.Replace('policy()','a$()').Replace('once','b$').Replace('log.info','c$.info')) $true 'enterprise-policy'
    Test-PolicyCase 'formatted-guard' ($policy+$modern.Replace('){',") {`n").Replace(';',";`n")) $true 'enterprise-policy'
    Test-PolicyCase 'offline-marker-only' ($policy+$offline) $false 'unverified'
    Test-PolicyCase 'enterprise-log-only' ($policy+'log.info("[CCD-autoupdate] Disabled by enterprise policy");') $false 'unverified'
    Test-PolicyCase 'missing-policy-return' ($policy+$modern.Replace(';return}if(await',';}if(await')) $false 'unverified'
    Test-PolicyCase 'inverted-policy' ($policy+$modern.Replace('if(policy().autoUpdate.disabled)','if(!policy().autoUpdate.disabled)')) $false 'unverified'
    Test-PolicyCase 'guard-continues-updating' ($policy+$modern.Replace(';return}if(await',';check();return}if(await')) $false 'unverified'
    Test-PolicyCase 'different-policy-key' ($modern.Replace('.autoUpdate.disabled','.other.disabled')+$policy) $false 'unverified'
    Test-PolicyCase 'policy-schema-missing' $modern $false 'unverified'
    Test-PolicyCase 'legacy-without-desktop-policy' $legacy $false 'msix-disabled'
    foreach($case in @(
        @{Name='untrusted-code-host';Data=$data.Replace('downloads.claude.ai','other.invalid')},
        @{Name='untrusted-code-checksum';Data=$data.Replace(('a'*64),'bad')},
        @{Name='unexpected-code-binary';Data=$data.Replace('claude.exe.zst','other.exe')},
        @{Name='ambiguous-code-manifests';Data=($data+$data)},
        @{Name='missing-code-manifest';Data='throw new Error("must not execute");'}
    )){
        $archive=New-FixtureArchive ($case.Data+$policy+$modern)
        $allowed=$true;try{$null=Read-ClaudeDesktopUpdateEngine $PSScriptRoot $archive}catch{$allowed=$false}
        Require (-not $allowed) ($case.Name+'-refused')
    }
    $result=[ordered]@{Passed=$true;FixtureOnly=$true;ProductionTouched=$false;Count=$checks.Count;Checks=@($checks)}
    $result|ConvertTo-Json -Depth 5
}finally{
    $full=[IO.Path]::GetFullPath($scratch);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeCodeManifestTests-[a-f0-9]{32}$'){throw 'Unsafe manifest fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
