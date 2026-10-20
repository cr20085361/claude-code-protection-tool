$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-VersionInfo.psm1') -Force
$module=Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard-DesktopUpdate.psm1') -Force -PassThru
$root=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeDesktopUpdateTests-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $root,(Join-Path $root 'private'),(Join-Path $root 'runtime')
$checks=[Collections.Generic.List[string]]::new()
try{
& $module {
param($Root,$Checks,$Project)
$script:FixtureRoot=$Root;$script:FixtureAlive=$true;$script:FixtureMaintenance=$null;$script:FixtureVersion='2.26454.2.0';$script:FixtureReady=$true;$script:FixtureFailure=''
$script:FixtureCalls=[Collections.Generic.List[string]]::new()
$script:RealCacheAssert=${function:Assert-ClaudeDesktopUpdateCodeCache}
$script:RealNativeInstall=${function:Invoke-ClaudeDesktopUpdateNativeInstall}
$script:RealClientsExited=${function:Assert-ClaudeDesktopUpdateClientsExited}
function Require([bool]$Ok,[string]$Name){if(-not $Ok){throw ('Update fixture failed: '+$Name)};$Checks.Add($Name)}
function Reject([scriptblock]$Call,[string]$Name){$denied=$false;try{& $Call|Out-Null}catch{$denied=$true};Require $denied $Name}
function script:Get-GuardMaintenanceLock($Purpose){[Threading.Mutex]::new($false,('Local\UpdateFixture-'+[IO.Path]::GetFileName($script:FixtureRoot)+'-'+$Purpose))}
function script:Test-GuardMaintenanceProcess {$script:FixtureAlive}
function script:Get-GuardMaintenanceSnapshot {[pscustomobject]@{Active=($null -ne $script:FixtureMaintenance -and $script:FixtureMaintenance.Status -eq 'Running');Interrupted=($null -ne $script:FixtureMaintenance -and $script:FixtureMaintenance.Status -eq 'Interrupted');Operation=$script:FixtureMaintenance}}
function script:Get-GuardState {Read-GuardJson (Join-Path $script:FixtureRoot 'private\deployment.json')}
function script:Get-GuardDesktop {[pscustomobject]@{Version=$script:FixtureVersion;Family='Claude_fixture';Path='fixture.exe';Hash='fixture-desktop-hash'}}
function script:Get-ClaudeDesktopUpdateInstalledPackage {[pscustomobject]@{Publisher='fixture-publisher';PackageFamilyName='Claude_fixture'}}
function script:Get-ClaudeDesktopUpdateSignature {[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='O="Anthropic, PBC", C=US'}}}
function script:Read-ClaudeDesktopUpdateEngine {[pscustomobject]@{desktopCodeVersion='2.1.294';baseUrl='https://downloads.claude.ai/claude-code-releases';platform=[pscustomobject]@{checksum=('a'*64);binary='claude.exe.zst'}}}
function script:Assert-ClaudeDesktopUpdateCodeCache {}
function script:Assert-ClaudeDesktopUpdateProtectionReady {if(-not $script:FixtureReady){throw 'protection not ready'}}
function script:Assert-GuardPolicy {if($script:FixtureFailure -eq 'policy'){throw 'policy changed'}}
function script:Assert-GuardCore {param([switch]$ConfigurationOnly);if($script:FixtureFailure -eq 'core'){throw 'Proxy runtime or fixed config changed.'};if($script:FixtureFailure -eq 'proxy-stopped' -and -not $ConfigurationOnly){throw 'Proxy absent or unexpected listeners.'}}
function script:New-GuardMaintenanceOperation($Id){$script:FixtureMaintenance=[pscustomobject]@{ActionId=$Id;Status='Running';Phase='Preparing';WorkerPid=0;DesktopDownloadId=$null;RecoveryRequired=$false;CompletedAt=$null;FailureKind=$null;Reason=$null};$script:FixtureMaintenance}
function script:Set-GuardMaintenanceOperation($Id,$Changes,[switch]$Recovery){foreach($key in $Changes.Keys){$script:FixtureMaintenance|Add-Member -NotePropertyName $key -NotePropertyValue $Changes[$key] -Force};$script:FixtureMaintenance}
function script:Read-GuardMaintenanceOperation($Id){$script:FixtureMaintenance}
function script:Get-GuardMaintenanceAssessment($Operation){[pscustomobject]@{Interrupted=($Operation.Status -eq 'Interrupted');Active=($Operation.Status -eq 'Running')}}
function script:Get-GuardMaintenanceUiResult {[pscustomobject]@{Success=$script:FixtureReady}}
function script:Register-GuardUiAction {}
function script:Set-GuardUiMaintenanceBinding {}
function script:Assert-ClaudeDesktopUpdateClientsExited {if($script:FixtureFailure -eq 'clients' -or ($script:FixtureFailure -eq 'late-clients' -and 'save-before-suspend' -in $script:FixtureCalls)){throw 'clients still active'}}
function script:Test-GuardAdmin {$true}
function script:Get-GuardApprovedShellPath {'fixture-shell'}
function script:Start-GuardMaintenanceAdministrator {throw [ComponentModel.Win32Exception]::new(1223)}
function script:Save-ClaudeDesktopUpdateRollback($Root,$Id,$State){$script:FixtureCalls.Add('save-before-suspend');$null=Set-GuardMaintenanceOperation $Id @{SupervisorSuspended=$true;BackupFile='fixture-backup'}}
function script:Invoke-ClaudeDesktopUpdateNativeInstall($Path){
    $script:FixtureCalls.Add('native-install')
    if($script:FixtureFailure -eq 'install'){throw 'native install failed'}
    if($script:FixtureFailure -in @('in-use','in-use-changed','in-use-rollback')){
        if($script:FixtureFailure -eq 'in-use-changed'){$script:FixtureVersion='2.26455.1.0'}
        throw 'Deployment failed with HRESULT: 0x80073D02 [ActivityId] 4b46accf-5727-0016-96fb-804c2757dd01'
    }
    $script:FixtureVersion='2.26455.1.0'
}
function script:Invoke-ClaudeDesktopUpdateMaintenance($Root,$Id,[switch]$BeforeInstall){
    if($BeforeInstall){
        $script:FixtureCalls.Add('pre-maintenance')
        Require ((Get-ClaudeDesktopUpdateSnapshot $Root).Status -eq 'PreparingProtection' -and $script:FixtureMaintenance.Status -eq 'Running') 'preparation-keeps-one-active-update-operation'
        if($script:FixtureFailure -eq 'pre-maintenance'){throw 'pre-maintenance failed'}
        if($script:FixtureFailure -eq 'pre-rollback'){$script:FixtureMaintenance.RecoveryRequired=$true;throw 'pre-maintenance rollback failed'}
        if($script:FixtureFailure -eq 'pre-unready'){return}
        if($script:FixtureFailure -eq 'pre-package-changed'){[IO.File]::AppendAllText((Read-ClaudeDesktopUpdate $Root).PackageFile,'tampered')}
        $script:FixtureReady=$true;return
    }
    $script:FixtureCalls.Add('maintenance');if($script:FixtureFailure -in @('maintenance','rollback')){throw 'maintenance failed'};$script:FixtureMaintenance.Status='Completed';$script:FixtureMaintenance.CompletedAt=[datetimeoffset]::UtcNow.ToString('o')
}
function script:Restore-GuardMaintenanceBackup {$script:FixtureCalls.Add('restore');if($script:FixtureFailure -in @('rollback','in-use-rollback')){throw 'restore failed'}}
$files=@('ClaudeGuard-DesktopUpdate.psm1','Invoke-ClaudeDesktopUpdate.ps1','ClaudeGuard-VersionInfo.psm1','Read-DesktopCodeManifest.cjs','Expand-VerifiedCode.cjs','Update-ClaudeGuard.ps1','ClaudeGuard.psm1','ClaudeGuard-Lifecycle.ps1','ClaudeGuard-Health.ps1','ClaudeCodeGate.psm1','runtime\ClaudeProGuard.exe')
foreach($name in $files){[IO.File]::WriteAllText((Join-Path $Root $name),'fixture-only')}
Write-GuardJson (Join-Path $Root 'private\deployment.json') @{UserSid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value;Desktop=@{Family='Claude_fixture';Version='2.26454.2.0';Path='fixture.exe';Hash='fixture-desktop-hash'};ProxyUrl='http://127.0.0.1:10818'}
$release=[pscustomobject]@{LatestDesktopVersion='2.26455.1';DownloadUrl=('https://downloads.claude.ai/releases/win32/x64/2.26455.1/Claude-'+('a'*40)+'.msix')}
Reject {Get-ClaudeDesktopUpdateArtifact $Root '../escape'} 'artifact-path-traversal-refused'
Reject {Assert-ClaudeDesktopUpdateUrl ($release.DownloadUrl.Replace('downloads.claude.ai','other.test')) $release.LatestDesktopVersion} 'non-official-source-refused'
Reject {Assert-ClaudeDesktopUpdateUrl $release.DownloadUrl '2.26456.1'} 'release-and-url-version-must-match'
$id=[guid]::NewGuid().ToString('N');$op=New-ClaudeDesktopUpdate $Root $id $release
Require ((Read-ClaudeDesktopUpdate $Root).Id -eq $id) 'canonical-operation-published'
Reject {New-ClaudeDesktopUpdate $Root ([guid]::NewGuid().ToString('N')) $release} 'duplicate-live-download-refused'
[IO.File]::WriteAllBytes(($op.PackageFile+'.part'),(New-Object byte[] 1024))
Require ((Get-ClaudeDesktopUpdateSnapshot $Root).DownloadedBytes -eq 1024) 'download-progress-from-partial-file'
$script:FixtureAlive=$false
Require ((Get-ClaudeDesktopUpdateSnapshot $Root).Status -eq 'Interrupted') 'dead-download-retains-interrupted-evidence'
$script:FixtureAlive=$true
$second=[guid]::NewGuid().ToString('N');$op=New-ClaudeDesktopUpdate $Root $second $release
$null=Set-ClaudeDesktopUpdate $Root $id @{Status='Failed';Message='late old failure'}
Require ((Read-ClaudeDesktopUpdate $Root).Id -eq $second) 'late-old-download-cannot-overwrite-new-operation'
function Build-Package($Path,[string]$Version='2.26455.1.0',[string]$Publisher='fixture-publisher',[string]$Architecture='x64',[string]$Name='Claude'){
    if(Test-Path -LiteralPath $Path){Remove-Item -LiteralPath $Path}
    $zip=[IO.Compression.ZipFile]::Open($Path,[IO.Compression.ZipArchiveMode]::Create)
    try{
        $entry=$zip.CreateEntry('AppxManifest.xml',[IO.Compression.CompressionLevel]::NoCompression);$stream=$entry.Open();$writer=[IO.StreamWriter]::new($stream)
        try{$writer.Write('<Package><Identity Name="'+$Name+'" Publisher="'+$Publisher+'" Version="'+$Version+'" ProcessorArchitecture="'+$Architecture+'"/></Package>')}finally{$writer.Dispose()}
        $entry=$zip.CreateEntry('app/resources/app.asar',[IO.Compression.CompressionLevel]::NoCompression);$stream=$entry.Open();try{$data=New-Object byte[] 4096;$stream.Write($data,0,$data.Length)}finally{$stream.Dispose()}
    }finally{$zip.Dispose()}
}
Build-Package $op.PackageFile
$package=Assert-ClaudeDesktopUpdatePackage $Root $op.PackageFile $release.LatestDesktopVersion
Require ($package.Signature -eq 'Valid' -and $package.CodeVersion -eq '2.1.294') 'signed-package-and-pinned-engine-verified'
Reject {Assert-ClaudeDesktopUpdatePackage $Root $op.PackageFile $release.LatestDesktopVersion ('0'*64)} 'changed-package-hash-refused'
Reject {Assert-ClaudeDesktopUpdatePackage $Root $op.PackageFile '2.26456.1'} 'package-version-mismatch-refused'
foreach($field in @('publisher','architecture','name')){
    switch($field){'publisher'{Build-Package $op.PackageFile -Publisher 'foreign'};'architecture'{Build-Package $op.PackageFile -Architecture 'arm64'};'name'{Build-Package $op.PackageFile -Name 'Other'}}
    Reject {Assert-ClaudeDesktopUpdatePackage $Root $op.PackageFile $release.LatestDesktopVersion} ('package-'+$field+'-mismatch-refused')
}
Build-Package $op.PackageFile
function script:Get-ClaudeDesktopUpdateSignature {[pscustomobject]@{Status='NotSigned';SignerCertificate=$null}}
Reject {Assert-ClaudeDesktopUpdatePackage $Root $op.PackageFile $release.LatestDesktopVersion} 'unsigned-package-refused'
function script:Get-ClaudeDesktopUpdateSignature {[pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='O="Anthropic, PBC", C=US'}}}
$package=Assert-ClaudeDesktopUpdatePackage $Root $op.PackageFile $release.LatestDesktopVersion
$null=Set-ClaudeDesktopUpdate $Root $second @{Status='Ready';PackageHash=$package.Hash;TargetVersion=$package.Version;PackageBytes=$package.Bytes;CodeVersion=$package.CodeVersion;CodePayloadHash=('b'*64);Publisher=$package.Publisher;Signature='Valid'}
$script:FixtureFailure='clients'
Reject {New-ClaudeDesktopUpdateRequest $Root $second} 'running-clients-block-install-before-maintenance-claim'
Require (-not $script:FixtureMaintenance) 'running-clients-do-not-pause-guardian'
$script:FixtureFailure='policy';$script:FixtureReady=$false
Reject {New-ClaudeDesktopUpdateRequest $Root $second} 'real-protection-failure-does-not-use-update-state-to-allow-install'
$script:FixtureFailure='core'
Reject {New-ClaudeDesktopUpdateRequest $Root $second} 'changed-core-configuration-still-blocks-automatic-maintenance'
$script:FixtureFailure='proxy-stopped'
$stoppedRequest=New-ClaudeDesktopUpdateRequest $Root $second
Require ($stoppedRequest.Request.PreparationRequired -and $stoppedRequest.Request.AutoPrepare) 'stopped-proxy-can-enter-reviewed-maintenance-without-listener'
$null=Set-GuardMaintenanceOperation $stoppedRequest.Request.Id @{Status='Failed';Phase='Failed'}
$null=Set-ClaudeDesktopUpdate $Root $second @{Status='Ready';Phase='Ready';MaintenanceId=$null}
$script:FixtureFailure='';$script:FixtureReady=$true;$script:FixtureVersion='2.26455.1.0'
Reject {New-ClaudeDesktopUpdateRequest $Root $second} 'same-version-reinstall-refused'
$script:FixtureVersion='2.26456.1.0'
Reject {New-ClaudeDesktopUpdateRequest $Root $second} 'downgrade-refused'
$script:FixtureVersion='2.26454.2.0'
$request=New-ClaudeDesktopUpdateRequest $Root $second
Require ($script:FixtureMaintenance.Phase -eq 'AwaitingAuthorization' -and (Read-ClaudeDesktopUpdate $Root).MaintenanceId -eq $request.Request.Id) 'request-correlated-before-uac'
$null=Assert-ClaudeDesktopUpdateRequest $Root $request.Request.Id $request.Hash
Require $true 'immutable-request-and-dependencies-verified'
Reject {Assert-ClaudeDesktopUpdateRequest $Root $request.Request.Id ('0'*64)} 'changed-request-refused'
[IO.File]::AppendAllText((Join-Path $Root 'Update-ClaudeGuard.ps1'),'changed')
Reject {Assert-ClaudeDesktopUpdateRequest $Root $request.Request.Id $request.Hash} 'changed-install-dependency-refused'
[IO.File]::WriteAllText((Join-Path $Root 'Update-ClaudeGuard.ps1'),'fixture-only')
$originalTime=$request.Request.CreatedAt;$request.Request.CreatedAt=[datetimeoffset]::UtcNow.AddHours(-2).ToString('o');Write-GuardJson $request.Path $request.Request
Reject {Assert-ClaudeDesktopUpdateRequest $Root $request.Request.Id (Get-GuardHash $request.Path)} 'expired-install-request-refused'
$request.Request.CreatedAt=$originalTime;Write-GuardJson $request.Path $request.Request;$request.Hash=Get-GuardHash $request.Path
Invoke-ClaudeDesktopUpdateInstallation $Root $request.Request.Id $request.Hash
Require ((Read-ClaudeDesktopUpdate $Root).Status -eq 'Completed' -and @($script:FixtureCalls) -join ',' -eq 'save-before-suspend,native-install,maintenance') 'native-install-followed-by-reviewed-maintenance'
Require ($script:FixtureMaintenance.Status -eq 'Completed') 'completion-requires-maintenance-success'
$null=Set-ClaudeDesktopUpdate $Root $second @{Status='Maintaining'};$script:FixtureReady=$false;$script:FixtureAlive=$false
Require ((Get-ClaudeDesktopUpdateSnapshot $Root).Status -eq 'AwaitingReadiness') 'finished-installer-with-unready-guardian-is-not-false-interruption'
$script:FixtureReady=$true;$script:FixtureAlive=$true
Require ((Get-ClaudeDesktopUpdateSnapshot $Root).Status -eq 'Completed') 'current-guardian-readiness-closes-final-result'
$preparationPackagePath=(Read-ClaudeDesktopUpdate $Root $second).PackageFile
$preparationPackageBytes=[IO.File]::ReadAllBytes($preparationPackagePath)
foreach($preFailure in @('','pre-maintenance','pre-unready','pre-package-changed','pre-rollback')){
    $script:FixtureMaintenance=$null;$script:FixtureVersion='2.26454.2.0';$script:FixtureCalls.Clear();$script:FixtureFailure='';$script:FixtureReady=$false
    $null=Set-ClaudeDesktopUpdate $Root $second @{Status='Failed';FailureKind='DesktopUpdateFailed';Message='old 0x80073D02';MaintenanceId=$null}
    $request=New-ClaudeDesktopUpdateRequest $Root $second
    Require ($request.Request.AutoPrepare -and $request.Request.PreparationRequired) 'one-click-request-allows-reviewed-preparation-while-held'
    $script:FixtureFailure=$preFailure
    if($preFailure){
        Reject {Invoke-ClaudeDesktopUpdateInstallation $Root $request.Request.Id $request.Hash} ($preFailure+'-stops-combined-operation')
        Require ('native-install' -notin $script:FixtureCalls) ($preFailure+'-does-not-install-before-preparation-verifies')
        Require ((Read-ClaudeDesktopUpdate $Root).Status -eq $(if($preFailure -eq 'pre-rollback'){'Interrupted'}else{'Failed'})) ($preFailure+'-publishes-terminal-state')
        if($preFailure -eq 'pre-rollback'){
            Require ((Read-ClaudeDesktopUpdate $Root).Status -eq 'Interrupted' -and $script:FixtureMaintenance.RecoveryRequired) 'preparation-rollback-failure-retains-recovery-required'
        }
    }else{
        Invoke-ClaudeDesktopUpdateInstallation $Root $request.Request.Id $request.Hash
        Require ((Read-ClaudeDesktopUpdate $Root).Status -eq 'Completed' -and @($script:FixtureCalls) -join ',' -eq 'pre-maintenance,save-before-suspend,native-install,maintenance') 'one-click-preparation-install-and-post-maintenance-order'
    }
    [IO.File]::WriteAllBytes($preparationPackagePath,$preparationPackageBytes)
}
foreach($failure in @('install','maintenance','rollback')){
    $script:FixtureMaintenance=$null;$script:FixtureVersion='2.26454.2.0';$script:FixtureCalls.Clear();$script:FixtureFailure=''
    $null=Set-ClaudeDesktopUpdate $Root $second @{Status='Ready';MaintenanceId=$null;FailureKind=$null}
    $request=New-ClaudeDesktopUpdateRequest $Root $second;$script:FixtureFailure=$failure
    Reject {Invoke-ClaudeDesktopUpdateInstallation $Root $request.Request.Id $request.Hash} ('injected-'+$failure+'-failure-reported')
    Require ('restore' -in $script:FixtureCalls) ('injected-'+$failure+'-uses-protection-rollback')
    Require ((Read-ClaudeDesktopUpdate $Root).Status -eq $(if($failure -eq 'rollback'){'Interrupted'}else{'Failed'})) ('injected-'+$failure+'-keeps-correct-terminal-state')
}
foreach($failure in @('in-use','in-use-changed','in-use-rollback','late-clients')){
    $script:FixtureMaintenance=$null;$script:FixtureVersion='2.26454.2.0';$script:FixtureCalls.Clear();$script:FixtureFailure=''
    $null=Set-ClaudeDesktopUpdate $Root $second @{Status='Ready';MaintenanceId=$null;FailureKind=$null}
    $request=New-ClaudeDesktopUpdateRequest $Root $second;$script:FixtureFailure=$failure
    Reject {Invoke-ClaudeDesktopUpdateInstallation $Root $request.Request.Id $request.Hash} ($failure+'-reported')
    $failed=Read-ClaudeDesktopUpdate $Root
    if($failure -eq 'in-use'){
        Require ($failed.Status -eq 'Ready' -and $failed.FailureKind -eq 'PackageResourcesInUse' -and $failed.PackageHash -eq $package.Hash) 'in-use-retains-verified-package-for-direct-retry'
        Require (-not $script:FixtureMaintenance.BaselineChanged -and $script:FixtureMaintenance.RollbackRestored) 'unchanged-native-failure-restores-without-false-safety-hold'
        Require ($failed.InstallerActivityId -eq '4b46accf-5727-0016-96fb-804c2757dd01' -and $script:FixtureMaintenance.InstallerErrorDetail -match '80073D02') 'in-use-retains-correlated-windows-diagnostics'
        $script:FixtureFailure='';$request=New-ClaudeDesktopUpdateRequest $Root $second
        Invoke-ClaudeDesktopUpdateInstallation $Root $request.Request.Id $request.Hash
        Require ((Read-ClaudeDesktopUpdate $Root).Status -eq 'Completed') 'in-use-retry-installs-without-redownload'
    }elseif($failure -eq 'in-use-changed'){
        Require ($failed.Status -eq 'Failed' -and $script:FixtureMaintenance.BaselineChanged) 'changed-package-cannot-be-returned-to-ready'
    }elseif($failure -eq 'in-use-rollback'){
        Require ($failed.Status -eq 'Interrupted' -and $script:FixtureMaintenance.RecoveryRequired) 'in-use-rollback-failure-still-requires-recovery'
    }else{
        Require ('native-install' -notin $script:FixtureCalls -and -not $script:FixtureMaintenance.BaselineChanged) 'clients-reopened-after-authorization-block-native-install'
    }
}
$script:NativeParameters=$null
function script:Add-AppxPackage {param($Path,[switch]$ForceTargetApplicationShutdown,$ErrorAction);$script:NativeParameters=$PSBoundParameters}
& $script:RealNativeInstall 'fixture.msix'
Require ($script:NativeParameters.Path -eq 'fixture.msix' -and $script:NativeParameters.ForceTargetApplicationShutdown -and $script:NativeParameters.ErrorAction -eq 'Stop' -and -not $script:NativeParameters.ContainsKey('DeferRegistrationWhenPackagesAreInUse')) 'native-install-shuts-down-target-package-and-requires-synchronous-result'
$record=[Management.Automation.ErrorRecord]::new([Runtime.InteropServices.COMException]::new('localized deployment failure',-2147009278),'DeploymentError',[Management.Automation.ErrorCategory]::NotSpecified,$null)
$record.ErrorDetails=[Management.Automation.ErrorDetails]::new('Get-AppPackageLog -ActivityID 4b46accf-5727-0016-96fb-804c2757dd01')
$failureInfo=Get-ClaudeDesktopUpdateInstallFailure $record
Require ($failureInfo.ResourcesInUse -and $failureInfo.ActivityId -eq '4b46accf-5727-0016-96fb-804c2757dd01') 'localized-hresult-and-error-details-classified'
$script:FixtureFailure='';$script:FixtureVersion='2.26454.2.0';$script:FixtureReady=$true
$script:FixtureMaintenance.Status='Failed'
$null=Set-ClaudeDesktopUpdate $Root $second @{Status='Failed';FailureKind='DesktopUpdateFailed';Message='Deployment failed with HRESULT: 0x80073D02'}
Require ((Get-ClaudeDesktopUpdateSnapshot $Root).Status -eq 'Failed') 'legacy-in-use-failure-needs-new-successful-maintenance'
$script:FixtureMaintenance.Status='Completed';$script:FixtureReady=$false
Require ((Get-ClaudeDesktopUpdateSnapshot $Root).Status -eq 'Failed') 'legacy-in-use-failure-cannot-bypass-current-protection'
$script:FixtureReady=$true
$null=Set-ClaudeDesktopUpdate $Root $second @{PackageHash=('0'*64)}
Require ((Get-ClaudeDesktopUpdateSnapshot $Root).Status -eq 'Failed') 'legacy-retry-revalidates-downloaded-package-hash'
$null=Set-ClaudeDesktopUpdate $Root $second @{PackageHash=$package.Hash}
Require ((Get-ClaudeDesktopUpdateSnapshot $Root).Status -eq 'Ready' -and -not (Read-ClaudeDesktopUpdate $Root).MaintenanceId) 'successful-maintenance-reenables-verified-legacy-download-without-redownload'
function script:Get-CimInstance {param($ClassName);[pscustomobject]@{Name='claude.exe';ProcessId=123}}
Reject {& $script:RealClientsExited} 'real-preflight-still-blocks-active-code-or-desktop'
Remove-Item Function:Get-CimInstance
$script:FixtureFailure='';$script:FixtureVersion='2.26454.2.0';$script:FixtureMaintenance=$null
$null=Set-ClaudeDesktopUpdate $Root $second @{Status='Ready';MaintenanceId=$null;FailureKind=$null}
$source=Get-Content -LiteralPath (Join-Path $Project 'Invoke-ClaudeDesktopUpdate.ps1') -Raw
$source=[regex]::Replace($source,'(?m)^Import-Module .*\r?\n','').Replace('$PSScriptRoot',("'"+$Root.Replace("'","''")+"'")).Replace('exit 0','return').Replace('exit 1','return')
& ([scriptblock]::Create($source)) -Action Install -OperationId $second -CommandId ([guid]::NewGuid().ToString('N'))
$cancelled=Read-ClaudeDesktopUpdate $Root
Require ($cancelled.Status -eq 'Ready' -and $cancelled.FailureKind -eq 'AdministratorCancelled') 'real-coordinator-uac-cancel-preserves-verified-download'
Require ($script:FixtureMaintenance.Status -eq 'Failed' -and -not $script:FixtureMaintenance.WorkerPid) 'uac-cancel-does-not-start-installer'
$compressedHash=(Get-GuardHash (Join-Path $Root 'Update-ClaudeGuard.ps1')).ToLowerInvariant()
$compressed=Join-Path $Root ('private\code-'+$compressedHash+'.zst');$payload=Join-Path $Root ('private\code-'+$compressedHash+'.exe')
Copy-Item -LiteralPath (Join-Path $Root 'Update-ClaudeGuard.ps1') -Destination $compressed
[IO.File]::WriteAllText($payload,'fixture-code-payload')
$cachePackage=[pscustomobject]@{CodeChecksum=$compressedHash};$payloadHash=Get-GuardHash $payload
& $script:RealCacheAssert $Root $cachePackage $payloadHash
Require $true 'cached-code-bound-to-signed-compressed-checksum-and-payload-hash'
Reject {& $script:RealCacheAssert $Root $cachePackage ('0'*64)} 'changed-cached-code-payload-refused'
[IO.File]::AppendAllText($compressed,'changed')
Reject {& $script:RealCacheAssert $Root $cachePackage $payloadHash} 'changed-cached-code-compressed-archive-refused'
Reject {Initialize-ClaudeDesktopUpdateCodeCache $Root ([pscustomobject]@{CodeChecksum='bad'})} 'unexpected-code-cache-metadata-refused'
function script:Get-ClaudeVersionCatalog {[pscustomobject]@{Status='QueryFailed';LastSuccess=$null}}
$before=Get-GuardHash (Join-Path $Root 'private\active-desktop-update.json')
Reject {Start-ClaudeDesktopUpdateDownload $Root ([guid]::NewGuid().ToString('N'))} 'failed-release-query-cannot-start-download'
Require ((Get-GuardHash (Join-Path $Root 'private\active-desktop-update.json')) -eq $before) 'failed-query-does-not-overwrite-verified-download'
$script:FixtureMaintenance=$null
function script:Get-ClaudeVersionCatalog {[pscustomobject]@{Status='Checked';LastSuccess=[pscustomobject]@{LatestDesktopVersion='2.26455.1';DownloadUrl=('https://downloads.claude.ai/releases/win32/x64/2.26455.1/Claude-'+('a'*40)+'.msix')}}}
function script:Invoke-ClaudeDesktopUpdateTransfer($Root,$Operation){Build-Package $Operation.PackageFile}
function script:Initialize-ClaudeDesktopUpdateCodeCache {[pscustomobject]@{Hash=('b'*64);Checksum=('a'*64)}}
$downloadId=[guid]::NewGuid().ToString('N');Start-ClaudeDesktopUpdateDownload $Root $downloadId
Require ((Read-ClaudeDesktopUpdate $Root).Status -eq 'Ready' -and (Read-ClaudeDesktopUpdate $Root).CodePayloadHash -eq ('b'*64)) 'download-becomes-ready-only-after-package-and-code-cache-validation'
function script:Invoke-ClaudeDesktopUpdateTransfer {throw 'fixture transfer interrupted'}
Reject {Start-ClaudeDesktopUpdateDownload $Root ([guid]::NewGuid().ToString('N'))} 'download-transfer-failure-reported'
Require ((Read-ClaudeDesktopUpdate $Root).Status -eq 'Failed') 'download-transfer-failure-preserves-final-evidence'
} $root $checks $PSScriptRoot
$result=@{Passed=$true;FixtureOnly=$true;ProductionTouched=$false;NativeInstallationExecuted=$false;Time=(Get-Date -Format o);Count=$checks.Count;Checks=@($checks)}
$result|ConvertTo-Json -Depth 5|Set-Content -LiteralPath (Join-Path $PSScriptRoot 'evidence\desktop-update-regression.json') -Encoding utf8
$result|ConvertTo-Json -Depth 5
}finally{
    $full=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeDesktopUpdateTests-[a-f0-9]{32}$'){throw 'Unsafe update fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
