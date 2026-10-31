[CmdletBinding()]
param([switch]$Finalize)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeCodeGate.psm1') -Force
$d=Get-GuardState
if (@(Get-GuardDesktopProcesses).Count) { throw 'Exit Claude before preparing its Code execution gate.' }
Assert-GuardPolicy
if ($Finalize) {
    if (-not (Test-GuardAdmin)) { throw 'Administrator rights required for final Code rules and binary permissions.' }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $d.UserSid) { throw 'Use the same Windows account for elevation.' }
    Install-GuardFirewall
    foreach($path in $d.CodePaths){Protect-CodeBinary $path}
    Test-CodeCacheGate
    $d=Get-GuardState
    $d.CodeCoverage='prepared'
    Write-GuardJson (Get-GuardPath 'private\deployment.json') $d
    Assert-CodePrepared
    Write-GuardJson (Get-GuardPath 'evidence\code-preparation.json') @{Time=(Get-Date -Format o);NetworkProtectionPrepared=$true;RealAuthenticatedSessionVerified=$false;CodeVersion=$d.CodeGate.Version;Paths=$d.CodePaths}
    exit 0
}
if ($d.CodeCoverage -in @('prepared','verified')) { Assert-CodePrepared; exit 0 }
$desktop=Get-GuardDesktop
if ($desktop.Path -ne $d.Desktop.Path -or $desktop.Hash -ne $d.Desktop.Hash) { throw 'Desktop updated before preparation; review new version first.' }
$archive=Join-Path ([IO.Path]::GetDirectoryName($desktop.Path)) 'resources\app.asar'
$manifestText=& node (Join-Path $PSScriptRoot 'Read-DesktopCodeManifest.cjs') $archive
if ($LASTEXITCODE -ne 0) { throw 'Could not read the installed official Code manifest.' }
$m=$manifestText|ConvertFrom-Json
if (-not $m.msixAutomaticCodeUpdatesDisabled -or $m.desktopCodeVersion -notmatch '^\d+\.\d+\.\d+$' -or ([uri]$m.baseUrl).Host -ne 'downloads.claude.ai') { throw 'Unexpected engine/update source; review required.' }
Write-GuardJson (Get-GuardPath 'evidence\desktop-code-manifest.json') $m
$roots=@(Get-GuardCodeCacheRoots $desktop)
$gateBackupPath=Get-GuardPath 'private\code-gate-backup.json'
if (-not (Test-Path $gateBackupPath)) {
    $backup=@()
    foreach($root in $roots){
        if(Test-Path -LiteralPath $root){throw 'Existing Code cache requires review before installing an execution gate.'}
        $backup+=@{Path=$root;Existed=$false;Sddl=$null}
    }
    Write-GuardJson $gateBackupPath @{Roots=$backup;Created=(Get-Date -Format o)}
}
foreach($root in $roots){New-Item -ItemType Directory -Path $root -Force|Out-Null;Set-CodeCacheGate $root}
$compressed=Get-GuardPath 'private\official-code.zst'
$url=$m.baseUrl+'/'+$m.desktopCodeVersion+'/win32-x64/'+$m.platform.binary
Start-GuardProxy
$null=Test-GuardEgress
if (-not (Test-Path $compressed) -or (Get-GuardHash $compressed).ToLowerInvariant() -ne $m.platform.checksum) {
    & (Get-GuardPath 'runtime\network-probe.exe') --silent --show-error --fail --connect-timeout 10 --max-time 600 --proxy $d.ProxyUrl --noproxy '' --output $compressed $url
    if($LASTEXITCODE -ne 0){throw 'Official Code download failed through the dedicated proxy.'}
}
$payload=Get-GuardPath 'private\official-code.exe'
if(Test-Path $payload){Remove-Item -LiteralPath $payload}
$payloadMeta=& node (Join-Path $PSScriptRoot 'Expand-VerifiedCode.cjs') $compressed $payload $m.platform.checksum
if($LASTEXITCODE -ne 0){throw 'Official Code checksum/decompression failed.'}
$payloadMeta=$payloadMeta|ConvertFrom-Json
$paths=@()
foreach($root in $roots){
    $versionDir=Join-Path $root $m.desktopCodeVersion
    New-Item -ItemType Directory -Path $versionDir -Force|Out-Null
    $path=Join-Path $versionDir 'claude.exe'
    if(Test-Path $path){if((Get-GuardHash $path).ToLowerInvariant() -ne $payloadMeta.sha256){throw 'Code cache binary mismatch.'}}else{Copy-Item -LiteralPath $payload -Destination $path}
    [IO.File]::WriteAllText((Join-Path $versionDir '.verified'),$m.platform.checksum,[Text.UTF8Encoding]::new($false))
    Write-GuardJson (Join-Path $versionDir '.payload') @{sha256=$payloadMeta.sha256;size=$payloadMeta.size}
    $paths+=$path
}
$d|Add-Member -NotePropertyName CodeGate -NotePropertyValue @{Schema=1;Roots=$roots;Version=$m.desktopCodeVersion;PayloadHash=$payloadMeta.sha256;ArchivePath=$archive;ArchiveHash=(Get-GuardHash $archive);CompressedHash=$m.platform.checksum} -Force
$d.CodePaths=$paths
$d.CodeCoverage='staged'
Write-GuardJson (Get-GuardPath 'private\deployment.json') $d
Test-CodeCacheGate
Write-Output 'Official pinned Code staged; firewall finalization is required before execution.'
