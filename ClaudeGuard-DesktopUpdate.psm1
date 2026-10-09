Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function Get-ClaudeDesktopUpdateArtifact([string]$Root,[string]$Id,[string]$Kind='Operation') {
    if($Id -notmatch '^[a-f0-9]{32}$'){throw '更新操作身份无效。'}
    $name=switch($Kind){'Operation'{'desktop-update-'+$Id+'.json'};'Package'{'desktop-package-'+$Id+'.msix'};'Request'{'desktop-install-'+$Id+'.json'};default{throw '更新文件类型无效。'}}
    $private=Join-Path ([IO.Path]::GetFullPath($Root)) 'private'
    if((Get-Item -LiteralPath $private).Attributes -band [IO.FileAttributes]::ReparsePoint){throw '更新目录不能是重解析点。'}
    $path=Join-Path $private $name
    if(Test-Path -LiteralPath $path){if((Get-Item -LiteralPath $path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw '更新文件不能是重解析点。'}}
    $path
}
function Invoke-ClaudeDesktopUpdateLocked([scriptblock]$Action){
    $mutex=Get-GuardMaintenanceLock 'DesktopUpdateRecord';$held=$false
    try{try{$held=$mutex.WaitOne(15000)}catch [Threading.AbandonedMutexException]{$held=$true};if(-not $held){throw '更新状态正在写入，请稍候。'};& $Action}finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
function Read-ClaudeDesktopUpdate([string]$Root,[string]$Id='') {
    $path=if($Id){Get-ClaudeDesktopUpdateArtifact $Root $Id}else{Join-Path $Root 'private\active-desktop-update.json'}
    if(-not (Test-Path -LiteralPath $path)){return $null}
    $op=Read-GuardJson $path
    if($op.SchemaVersion -ne 1 -or $op.Id -notmatch '^[a-f0-9]{32}$' -or ($Id -and $op.Id -ne $Id)){throw '更新状态身份无效。'}
    if(-not $Id){$canonical=Get-ClaudeDesktopUpdateArtifact $Root $op.Id;if(Test-Path -LiteralPath $canonical){$op=Read-GuardJson $canonical;if($op.SchemaVersion -ne 1 -or $op.Id -ne [IO.Path]::GetFileNameWithoutExtension($canonical).Substring(15)){throw '更新状态关联无效。'}}}
    if($op.Status -notin @('Downloading','Verifying','PreparingInstall','PreparingProtection','Ready','AwaitingAuthorization','Installing','Maintaining','AwaitingReadiness','Completed','Failed','Interrupted') -or $op.PackageFile -ne (Get-ClaudeDesktopUpdateArtifact $Root $op.Id 'Package')){throw '更新阶段或安装包路径无效。'}
    $op
}
function Set-ClaudeDesktopUpdate([string]$Root,[string]$Id,[Collections.IDictionary]$Changes) {
    Invoke-ClaudeDesktopUpdateLocked {
        $op=Read-ClaudeDesktopUpdate $Root $Id;if(-not $op){throw '更新操作记录缺失。'}
        foreach($key in $Changes.Keys){$op|Add-Member -NotePropertyName $key -NotePropertyValue $Changes[$key] -Force}
        $op.UpdatedAt=[datetimeoffset]::UtcNow.ToString('o')
        Write-GuardJson (Get-ClaudeDesktopUpdateArtifact $Root $Id) $op
        $active=Read-ClaudeDesktopUpdate $Root
        if($active -and $active.Id -eq $Id){Write-GuardJson (Join-Path $Root 'private\active-desktop-update.json') $op}
        $op
    }
}
function New-ClaudeDesktopUpdate([string]$Root,[string]$Id,$Release) {
    Invoke-ClaudeDesktopUpdateLocked {
        $old=Get-ClaudeDesktopUpdateSnapshot $Root
        if($old -and ($old.Status -in @('Downloading','Verifying','PreparingInstall','PreparingProtection','AwaitingAuthorization','Installing','Maintaining','AwaitingReadiness') -or ($old.Status -eq 'Interrupted' -and $old.MaintenanceId))){throw '已有更新正在进行或等待恢复，请接续原操作。'}
        $self=[Diagnostics.Process]::GetCurrentProcess()
        $op=[ordered]@{SchemaVersion=1;Id=$Id;Status='Downloading';Phase='Downloading';StartedAt=[datetimeoffset]::UtcNow.ToString('o');UpdatedAt=[datetimeoffset]::UtcNow.ToString('o');CompletedAt=$null;WorkerPid=$PID;WorkerStarted=$self.StartTime.ToUniversalTime().ToString('o');WorkerPath=$self.MainModule.FileName;TargetVersion=$Release.LatestDesktopVersion;DownloadUrl=$Release.DownloadUrl;PackageFile=(Get-ClaudeDesktopUpdateArtifact $Root $Id 'Package');PackageHash=$null;PackageBytes=0;CodeVersion=$null;Publisher=$null;Signature=$null;MaintenanceId=$null;FailureKind=$null;Message='正在下载官方安装包，可继续使用当前 Claude。'}
        Write-GuardJson (Get-ClaudeDesktopUpdateArtifact $Root $Id) $op
        Write-GuardJson (Join-Path $Root 'private\active-desktop-update.json') $op
        [pscustomobject]$op
    }
}
function Get-ClaudeDesktopUpdateSnapshot([string]$Root) {
    $op=Read-ClaudeDesktopUpdate $Root;if(-not $op){return $null}
    # 兼容旧入口的 0x80073D02 失败记录。完成新的受控维护后重新核验旧下载，
    # 而非将旧“失败”状态永久锁死或要求重复下载。
    if($op.Status -eq 'Failed' -and $op.FailureKind -eq 'DesktopUpdateFailed' -and $op.Message -match '(?i)0x80073D02'){
        try{$op=Resume-ClaudeDesktopUpdateVerifiedPackage $Root $op}catch{}
    }
    if($op.MaintenanceId -and $op.Status -in @('AwaitingAuthorization','PreparingProtection','Installing','Maintaining','Interrupted','AwaitingReadiness')){
        $m=Read-GuardMaintenanceOperation $op.MaintenanceId
        if($m -and $m.Status -eq 'Completed'){
            $r=Get-GuardMaintenanceUiResult $m
            if($r.Success){$op=Set-ClaudeDesktopUpdate $Root $op.Id @{Status='Completed';Phase='Completed';CompletedAt=$m.CompletedAt;Message='更新安装与版本维护完成，后台守护已核验。';FailureKind=$null}}
            else{$op=Set-ClaudeDesktopUpdate $Root $op.Id @{Status='AwaitingReadiness';Phase='Verifying';Message='安装与迁移已完成，当前守护就绪尚未确认，请重新检查。';FailureKind='SupervisorUnavailable'}}
        }elseif($m -and $m.Status -eq 'Failed' -and -not $m.RecoveryRequired){
            $op=Set-ClaudeDesktopUpdate $Root $op.Id @{Status='Failed';Phase='Failed';CompletedAt=$m.CompletedAt;FailureKind=$m.FailureKind;Message=$m.Reason}
        }elseif($m -and ((Get-GuardMaintenanceAssessment $m).Interrupted -or $m.RecoveryRequired)){
            $op=Set-ClaudeDesktopUpdate $Root $op.Id @{Status='Interrupted';Phase='Interrupted';FailureKind='MaintenanceInterrupted';Message='更新中断，需要同账号管理员恢复。请点击“维护版本”。'}
        }
    }
    if($op.Status -in @('Downloading','Verifying','PreparingInstall','PreparingProtection','AwaitingAuthorization','Installing','Maintaining') -and -not (Test-GuardMaintenanceProcess $op.WorkerPid $op.WorkerStarted $op.WorkerPath)){
        if($op.Status -eq 'PreparingInstall' -and -not $op.MaintenanceId){$op=Set-ClaudeDesktopUpdate $Root $op.Id @{Status='Ready';Phase='Ready';FailureKind='InstallPrecondition';Message='安装准备已中止，已核验安装包保留，可重试。'}}
        else{$op=Set-ClaudeDesktopUpdate $Root $op.Id @{Status='Interrupted';Phase='Interrupted';FailureKind='UpdateInterrupted';Message=$(if($op.MaintenanceId){'更新中断，需要恢复。请点击“维护版本”。'}else{'下载已中断，可重新下载；未改变已安装版本。'})}}
    }
    $bytes=$op.PackageBytes;$partial=$op.PackageFile+'.part'
    if($op.Status -eq 'Downloading' -and (Test-Path -LiteralPath $partial)){$bytes=(Get-Item -LiteralPath $partial).Length}
    $op|Add-Member -NotePropertyName DownloadedBytes -NotePropertyValue $bytes -Force
    $op
}
function Assert-ClaudeDesktopUpdateUrl([string]$Url,[string]$Version) {
    $headers="HTTP/1.1 307 Temporary Redirect`r`nLocation: $Url`r`n"
    $release=ConvertFrom-ClaudeVersionHeaders $headers
    if((ConvertTo-ClaudeVersion $release.LatestDesktopVersion) -ne (ConvertTo-ClaudeVersion $Version)){throw '下载地址与发布版本不一致。'}
}
function Get-ClaudeDesktopUpdateInstalledPackage {
    $p=@(Get-AppxPackage -Name Claude)
    $state=Get-GuardState
    if($p.Count -ne 1 -or $p[0].PackageFamilyName -ne $state.Desktop.Family){throw '当前客户端包身份无法确认。'}
    $p[0]
}
function Get-ClaudeDesktopUpdateSignature([string]$Path){Get-AuthenticodeSignature -LiteralPath $Path}
function Read-ClaudeDesktopUpdateEngine([string]$Root,[string]$Archive) {
    $text=& node (Join-Path $Root 'Read-DesktopCodeManifest.cjs') $Archive 2>$null
    if($LASTEXITCODE -ne 0 -or -not $text){throw '安装包配套 Code 元数据无法核验。'}
    $m=$text|ConvertFrom-Json
    if(-not $m.msixAutomaticCodeUpdatesDisabled -or -not $m.desktopUpdatePolicySupported){throw '该包的更新策略兼容性需要另外核对。'}
    $m
}
function Assert-ClaudeDesktopUpdatePackage([string]$Root,[string]$Path,[string]$Version,[string]$ExpectedHash='') {
    if(-not (Test-Path -LiteralPath $Path -PathType Leaf) -or (Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint){throw '安装包路径无效。'}
    $size=(Get-Item -LiteralPath $Path).Length
    if($size -lt 1024 -or $size -gt 1073741824){throw '安装包大小超出约定范围。'}
    $hash=Get-GuardHash $Path
    if($ExpectedHash -and $hash -ne $ExpectedHash){throw '安装包下载后发生变化，已拒绝安装。'}
    $signature=Get-ClaudeDesktopUpdateSignature $Path
    if($signature.Status.ToString() -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O="?Anthropic, PBC"?[, ]'){throw '官方安装包签名核验失败。'}
    $installed=Get-ClaudeDesktopUpdateInstalledPackage
    $zip=[IO.Compression.ZipFile]::OpenRead($Path);$archive=$Path+'.asar-check'
    try{
        $manifests=@($zip.Entries|Where-Object {$_.FullName -eq 'AppxManifest.xml'})
        $engines=@($zip.Entries|Where-Object {$_.FullName -eq 'app/resources/app.asar'})
        if($manifests.Count -ne 1 -or $manifests[0].Length -gt 65536 -or $engines.Count -ne 1 -or $engines[0].Length -gt 536870912){throw '安装包结构超出当前兼容范围。'}
        $settings=[Xml.XmlReaderSettings]::new();$settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit;$settings.XmlResolver=$null
        $stream=$manifests[0].Open();$reader=[Xml.XmlReader]::Create($stream,$settings)
        try{$xml=[Xml.XmlDocument]::new();$xml.XmlResolver=$null;$xml.Load($reader)}finally{$reader.Dispose();$stream.Dispose()}
        $identity=$xml.SelectSingleNode('/*[local-name()="Package"]/*[local-name()="Identity"]')
        if(-not $identity -or $identity.GetAttribute('Name') -ne 'Claude' -or $identity.GetAttribute('ProcessorArchitecture') -ne 'x64' -or $identity.GetAttribute('Publisher') -ne $installed.Publisher -or (ConvertTo-ClaudeVersion $identity.GetAttribute('Version')) -ne (ConvertTo-ClaudeVersion $Version)){throw '安装包名称、发行方、架构或版本不匹配。'}
        [IO.Compression.ZipFileExtensions]::ExtractToFile($engines[0],$archive,$true)
        $engine=Read-ClaudeDesktopUpdateEngine $Root $archive
        [pscustomobject]@{Version=$identity.GetAttribute('Version');Hash=$hash;Bytes=$size;Publisher=$identity.GetAttribute('Publisher');CodeVersion=$engine.desktopCodeVersion;Signature='Valid';CodeChecksum=$engine.platform.checksum;CodeBaseUrl=$engine.baseUrl;CodeBinary=$engine.platform.binary}
    }finally{$zip.Dispose();if(Test-Path -LiteralPath $archive){Remove-Item -LiteralPath $archive}}
}
function Initialize-ClaudeDesktopUpdateCodeCache([string]$Root,$Package) {
    if($Package.CodeChecksum -notmatch '^[a-f0-9]{64}$' -or $Package.CodeBinary -ne 'claude.exe.zst' -or $Package.CodeVersion -notmatch '^\d+\.\d+\.\d+$' -or $Package.CodeBaseUrl -notmatch '^https://downloads\.claude\.ai/claude-code-releases(?:/rc/[a-f0-9]{40})?$'){throw '配套 Code 下载元数据不符合约定。'}
    $state=Get-GuardState
    $compressed=Join-Path $Root ('private\code-'+$Package.CodeChecksum+'.zst')
    $payload=Join-Path $Root ('private\code-'+$Package.CodeChecksum+'.exe')
    if(-not (Test-Path -LiteralPath $compressed)){
        if(Test-Path -LiteralPath (Join-Path $Root 'private\safety-hold.json')){throw '安全暂停期间不能下载配套 Code。'}
        $partial=$compressed+'.part'
        & (Join-Path $Root 'runtime\network-probe.exe') --silent --show-error --fail --proto '=https' --proxy $state.ProxyUrl --noproxy '' --connect-timeout 10 --max-time 600 --max-filesize 536870912 --output $partial ($Package.CodeBaseUrl+'/'+$Package.CodeVersion+'/win32-x64/'+$Package.CodeBinary) 2>$null
        if($LASTEXITCODE -ne 0 -or (Get-GuardHash $partial).ToLowerInvariant() -ne $Package.CodeChecksum){throw '配套 Code 下载未完成或官方校验值不一致。'}
        [IO.File]::Move($partial,$compressed)
    }
    if((Get-GuardHash $compressed).ToLowerInvariant() -ne $Package.CodeChecksum){throw '配套 Code 压缩载荷发生变化。'}
    $known=Test-Path -LiteralPath $payload
    if($known -and $state.CodeGate.CompressedHash -eq $Package.CodeChecksum -and $state.CodeGate.Version -eq $Package.CodeVersion -and (Get-GuardHash $payload).ToLowerInvariant() -eq $state.CodeGate.PayloadHash.ToLowerInvariant()){
        return [pscustomobject]@{Hash=(Get-GuardHash $payload);Checksum=$Package.CodeChecksum}
    }
    $temporary=Join-Path $Root ('private\code-'+$Package.CodeChecksum+'-'+[guid]::NewGuid().ToString('N')+'.exe')
    try{
        $null=& node (Join-Path $Root 'Expand-VerifiedCode.cjs') $compressed $temporary $Package.CodeChecksum 2>$null
        if($LASTEXITCODE -ne 0){throw '配套 Code 解压与校验失败。'}
        $signature=Get-ClaudeDesktopUpdateSignature $temporary
        if($signature.Status.ToString() -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O="?Anthropic, PBC"?[, ]'){throw '配套 Code 官方签名核验失败。'}
        $hash=Get-GuardHash $temporary
        if($known){if((Get-GuardHash $payload) -ne $hash){throw '已缓存配套 Code 与官方压缩载荷不一致。'}}else{[IO.File]::Move($temporary,$payload)}
        [pscustomobject]@{Hash=$hash;Checksum=$Package.CodeChecksum}
    }finally{if(Test-Path -LiteralPath $temporary){Remove-Item -LiteralPath $temporary}}
}
function Assert-ClaudeDesktopUpdateCodeCache([string]$Root,$Package,[string]$Hash) {
    if($Hash -notmatch '^[A-Fa-f0-9]{64}$' -or $Package.CodeChecksum -notmatch '^[a-f0-9]{64}$'){throw '配套 Code 校验身份无效。'}
    if((Get-GuardHash (Join-Path $Root ('private\code-'+$Package.CodeChecksum+'.zst'))).ToLowerInvariant() -ne $Package.CodeChecksum -or (Get-GuardHash (Join-Path $Root ('private\code-'+$Package.CodeChecksum+'.exe'))) -ne $Hash){throw '下载后的配套 Code 载荷发生变化。'}
}
function Assert-ClaudeDesktopUpdateProtectionReady {
    Assert-GuardPolicy;Assert-GuardFirewall;Assert-GuardCore
    if(-not (Get-GuardSupervisorSnapshot).Ready){throw '当前防护尚未就绪，请先完成版本维护或恢复。'}
}
function Invoke-ClaudeDesktopUpdateTransfer([string]$Root,$Operation) {
    Assert-ClaudeDesktopUpdateUrl $Operation.DownloadUrl $Operation.TargetVersion
    $state=Get-GuardState
    if($state.ProxyUrl -ne 'http://127.0.0.1:10818'){throw '专用代理配置发生变化。'}
    $partial=$Operation.PackageFile+'.part';$header=$Operation.PackageFile+'.headers'
    try{
        & (Join-Path $Root 'runtime\network-probe.exe') --silent --show-error --fail --proto '=https' --proxy $state.ProxyUrl --noproxy '' --connect-timeout 10 --max-time 900 --max-filesize 1073741824 --dump-header $header --output $partial $Operation.DownloadUrl 2>$null
        if($LASTEXITCODE -ne 0){throw '官方安装包下载未完成，可重新下载。'}
        $h=[IO.File]::ReadAllText($header)
        $status=@([regex]::Matches($h,'(?m)^HTTP/\S+\s+(\d{3})'))
        $length=@([regex]::Matches($h,'(?im)^content-length:\s*(\d+)\s*$'))
        if(-not $status.Count -or $status[-1].Groups[1].Value -ne '200' -or $length.Count -ne 1 -or [long]$length[0].Groups[1].Value -ne (Get-Item -LiteralPath $partial).Length){throw '下载响应或完整长度无法确认。'}
        [IO.File]::Move($partial,$Operation.PackageFile,$true)
    }finally{if(Test-Path -LiteralPath $header){Remove-Item -LiteralPath $header}}
}
function Start-ClaudeDesktopUpdateDownload([string]$Root,[string]$Id) {
    $catalog=Get-ClaudeVersionCatalog $Root (Get-GuardState) -CheckUpdates -Force
    if($catalog.Status -ne 'Checked' -or -not $catalog.LastSuccess){throw '尚未取得当前官方发布，不能下载。'}
    Assert-ClaudeDesktopUpdateUrl $catalog.LastSuccess.DownloadUrl $catalog.LastSuccess.LatestDesktopVersion
    $m=Get-GuardMaintenanceSnapshot;if($m.Active -or $m.Interrupted -or ($m.Operation -and $m.Operation.RecoveryRequired)){throw '请先完成或恢复已有版本维护。'}
    $op=New-ClaudeDesktopUpdate $Root $Id $catalog.LastSuccess
    try{
        Invoke-ClaudeDesktopUpdateTransfer $Root $op
        $null=Set-ClaudeDesktopUpdate $Root $Id @{Status='Verifying';Phase='Verifying';Message='下载完成，正在核验官方签名、包身份和配套 Code。'}
        $package=Assert-ClaudeDesktopUpdatePackage $Root $op.PackageFile $op.TargetVersion
        $null=Set-ClaudeDesktopUpdate $Root $Id @{Message='正在核验并缓存官方配套 Code，安装中断时可接续恢复。'}
        $code=Initialize-ClaudeDesktopUpdateCodeCache $Root $package
        $null=Set-ClaudeDesktopUpdate $Root $Id @{Status='Ready';Phase='Ready';PackageHash=$package.Hash;PackageBytes=$package.Bytes;TargetVersion=$package.Version;CodeVersion=$package.CodeVersion;CodeChecksum=$code.Checksum;CodePayloadHash=$code.Hash;Publisher=$package.Publisher;Signature='Valid';Message='官方安装包及配套 Code 已核验。安装前请完全退出 Claude 和本地 Code。';FailureKind=$null}
    }catch{$null=Set-ClaudeDesktopUpdate $Root $Id @{Status='Failed';Phase='Failed';FailureKind='DownloadOrVerificationFailed';Message=$_.Exception.Message;CompletedAt=[datetimeoffset]::UtcNow.ToString('o')};throw}
}
function Assert-ClaudeDesktopUpdateClientsExited {
    if(@(Get-CimInstance Win32_Process|Where-Object {$_.Name -ieq 'claude.exe'}).Count){throw '请完全退出 Claude 和本地 Code，再点击“安装并维护”。'}
}
function Test-ClaudeDesktopUpdatePreparationRequired {
    # 自动维护仍须遵守原账号、代理策略和核心文件边界。
    Assert-GuardPolicy;Assert-GuardCore
    try{Assert-ClaudeDesktopUpdateProtectionReady;return $false}catch{return $true}
}
function New-ClaudeDesktopUpdateRequest([string]$Root,[string]$Id) {
    $op=Invoke-ClaudeDesktopUpdateLocked {
        $ready=Read-ClaudeDesktopUpdate $Root $Id
        $retry=$ready -and $ready.Status -eq 'Failed' -and $ready.FailureKind -in @('DesktopUpdateFailed','PackageResourcesInUse','InstallPrecondition') -and $ready.Signature -eq 'Valid' -and $ready.PackageHash -match '^[A-Fa-f0-9]{64}$'
        if(-not $ready -or ($ready.Status -ne 'Ready' -and -not $retry)){throw '请先下载并核验官方安装包，或等待已有安装准备完成。'}
        $self=[Diagnostics.Process]::GetCurrentProcess()
        Set-ClaudeDesktopUpdate $Root $Id @{Status='PreparingInstall';Phase='PreparingInstall';WorkerPid=$PID;WorkerStarted=$self.StartTime.ToUniversalTime().ToString('o');WorkerPath=$self.MainModule.FileName;Message='正在核对退出状态及安装条件，请等待。';FailureKind=$null}
    }
    $claimed=$null
    try{
    Assert-ClaudeDesktopUpdateClientsExited
    $prepare=Test-ClaudeDesktopUpdatePreparationRequired
    $current=Get-GuardDesktop
    if((ConvertTo-ClaudeVersion $op.TargetVersion) -le (ConvertTo-ClaudeVersion $current.Version)){throw '当前安装版本无需升级，已拒绝重装或降级。'}
    $package=Assert-ClaudeDesktopUpdatePackage $Root $op.PackageFile $op.TargetVersion $op.PackageHash
    Assert-ClaudeDesktopUpdateCodeCache $Root $package $op.CodePayloadHash
    $state=Get-GuardState
    if([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -ne $state.UserSid){throw '更新需要原 Windows 账号。'}
    $maintenanceId=[guid]::NewGuid().ToString('N')
    $files=@('ClaudeGuard-DesktopUpdate.psm1','Invoke-ClaudeDesktopUpdate.ps1','ClaudeGuard-VersionInfo.psm1','Read-DesktopCodeManifest.cjs','Expand-VerifiedCode.cjs','Update-ClaudeGuard.ps1','ClaudeGuard.psm1','ClaudeGuard-Lifecycle.ps1','ClaudeGuard-Health.ps1','ClaudeCodeGate.psm1','runtime\ClaudeProGuard.exe')
    $request=[ordered]@{SchemaVersion=1;Id=$maintenanceId;DownloadId=$Id;CreatedAt=[datetimeoffset]::UtcNow.ToString('o');UserSid=$state.UserSid;BaselineHash=(Get-GuardHash (Join-Path $Root 'private\deployment.json'));PackageFile=$op.PackageFile;PackageHash=$package.Hash;TargetVersion=$package.Version;CodeVersion=$package.CodeVersion;CodePayloadHash=$op.CodePayloadHash;Publisher=$package.Publisher;Scripts=@($files|ForEach-Object {@{Name=$_;Hash=(Get-GuardHash (Join-Path $Root $_))}})}
    $path=Get-ClaudeDesktopUpdateArtifact $Root $maintenanceId 'Request'
    $request.AutoPrepare=$true;$request.PreparationRequired=$prepare
    Write-GuardJson $path $request
    $null=New-GuardMaintenanceOperation $maintenanceId
    $claimed=$maintenanceId
    Register-GuardUiAction $maintenanceId 'Update';Set-GuardUiMaintenanceBinding $maintenanceId $maintenanceId
    $null=Set-GuardMaintenanceOperation $maintenanceId @{Phase='AwaitingAuthorization';DesktopDownloadId=$Id}
    $self=[Diagnostics.Process]::GetCurrentProcess()
    $null=Set-ClaudeDesktopUpdate $Root $Id @{Status='AwaitingAuthorization';Phase='AwaitingAuthorization';MaintenanceId=$maintenanceId;WorkerPid=$PID;WorkerStarted=$self.StartTime.ToUniversalTime().ToString('o');WorkerPath=$self.MainModule.FileName;Message='等待同账号 Windows 管理员授权；之后自动完成必要维护、安装和防护核验。'}
    [pscustomobject]@{Path=$path;Hash=(Get-GuardHash $path);Request=[pscustomobject]$request}
    }catch{
        if($claimed){$null=Set-GuardMaintenanceOperation $claimed @{Status='Failed';Phase='Failed';FailureKind='InstallPrecondition';Reason=$_.Exception.Message}}
        $null=Set-ClaudeDesktopUpdate $Root $Id @{Status='Ready';Phase='Ready';MaintenanceId=$null;FailureKind='InstallPrecondition';Message=$_.Exception.Message}
        throw
    }
}
function Assert-ClaudeDesktopUpdateRequest([string]$Root,[string]$Id,[string]$Hash) {
    $path=Get-ClaudeDesktopUpdateArtifact $Root $Id 'Request'
    if((Get-GuardHash $path) -ne $Hash){throw '已确认的更新请求发生变化。'}
    $r=Read-GuardJson $path;$state=Get-GuardState
    if($r.SchemaVersion -ne 1 -or $r.Id -ne $Id -or $r.UserSid -ne $state.UserSid -or $r.UserSid -ne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -or (Get-GuardHash (Join-Path $Root 'private\deployment.json')) -ne $r.BaselineHash){throw '更新请求与账号或防护基线不一致。'}
    $age=([datetimeoffset]::UtcNow-([datetimeoffset]$r.CreatedAt)).TotalSeconds
    if($age -lt 0 -or $age -gt 3600){throw '更新请求已过期。'}
    if($r.PackageFile -ne (Get-ClaudeDesktopUpdateArtifact $Root $r.DownloadId 'Package')){throw '更新安装包路径不一致。'}
    $allowed=@('ClaudeGuard-DesktopUpdate.psm1','Invoke-ClaudeDesktopUpdate.ps1','ClaudeGuard-VersionInfo.psm1','Read-DesktopCodeManifest.cjs','Expand-VerifiedCode.cjs','Update-ClaudeGuard.ps1','ClaudeGuard.psm1','ClaudeGuard-Lifecycle.ps1','ClaudeGuard-Health.ps1','ClaudeCodeGate.psm1','runtime\ClaudeProGuard.exe')
    if(@(Compare-Object @($r.Scripts.Name|Sort-Object) @($allowed|Sort-Object)).Count){throw '更新请求依赖范围不一致。'}
    foreach($s in $r.Scripts){if((Get-GuardHash (Join-Path $Root $s.Name)) -ne $s.Hash){throw '已确认的更新脚本发生变化。'}}
    $op=Read-GuardMaintenanceOperation $Id
    if(-not $op -or $op.Status -ne 'Running' -or $op.DesktopDownloadId -ne $r.DownloadId -or (Read-GuardMaintenanceOperation).ActionId -ne $Id){throw '更新维护操作关联失效。'}
    $package=Assert-ClaudeDesktopUpdatePackage $Root $r.PackageFile $r.TargetVersion $r.PackageHash
    Assert-ClaudeDesktopUpdateCodeCache $Root $package $r.CodePayloadHash
    $r
}
function Invoke-ClaudeDesktopUpdateNativeInstall([string]$Path){
    # 主窗口退出后，MSIX 仍可能有后台服务/包活动。由 Windows 只关闭目标包，
    # 避免按进程名结束其他程序，也不能用延迟注册冒充安装完成。
    Add-AppxPackage -Path $Path -ForceTargetApplicationShutdown -ErrorAction Stop
}
function Get-ClaudeDesktopUpdateInstallFailure([Management.Automation.ErrorRecord]$Record) {
    $detail=$Record.Exception.Message
    if($Record.ErrorDetails -and $Record.ErrorDetails.Message){$detail+="`n"+$Record.ErrorDetails.Message}
    $inUse=$detail -match '(?i)0x80073D02'
    $exception=$Record.Exception
    while($exception){
        if($exception.HResult -eq -2147009278){$inUse=$true}
        $exception=$exception.InnerException
    }
    $activity=[regex]::Match($detail,'(?i)(?:\[ActivityId\]|-ActivityID)\s*([a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12})')
    [pscustomobject]@{ResourcesInUse=$inUse;ErrorCode=$(if($inUse){'0x80073D02'}else{$null});ActivityId=$(if($activity.Success){$activity.Groups[1].Value}else{$null});Detail=$detail}
}
function Test-ClaudeDesktopUpdateBaselineUnchanged([string]$Root,$Request) {
    if((Get-GuardHash (Join-Path $Root 'private\deployment.json')) -ne $Request.BaselineHash){return $false}
    $before=(Get-GuardState).Desktop;$actual=Get-GuardDesktop
    foreach($key in @('Version','Path','Hash','Family')){
        if(-not $before.PSObject.Properties[$key] -or -not $actual.PSObject.Properties[$key] -or -not $before.$key -or $before.$key -ne $actual.$key){return $false}
    }
    $true
}
function Resume-ClaudeDesktopUpdateVerifiedPackage([string]$Root,$Operation) {
    $maintenance=Get-GuardMaintenanceSnapshot
    if($maintenance.Active -or $maintenance.Interrupted -or -not $maintenance.Operation -or $maintenance.Operation.Status -ne 'Completed' -or -not (Get-GuardMaintenanceUiResult $maintenance.Operation).Success){return $Operation}
    Assert-ClaudeDesktopUpdateProtectionReady
    $baseline=[pscustomobject]@{BaselineHash=(Get-GuardHash (Join-Path $Root 'private\deployment.json'))}
    if(-not (Test-ClaudeDesktopUpdateBaselineUnchanged $Root $baseline) -or (ConvertTo-ClaudeVersion $Operation.TargetVersion) -le (ConvertTo-ClaudeVersion (Get-GuardDesktop).Version)){return $Operation}
    $package=Assert-ClaudeDesktopUpdatePackage $Root $Operation.PackageFile $Operation.TargetVersion $Operation.PackageHash
    Assert-ClaudeDesktopUpdateCodeCache $Root $package $Operation.CodePayloadHash
    Invoke-ClaudeDesktopUpdateLocked {
        $current=Read-ClaudeDesktopUpdate $Root $Operation.Id
        if($current.Status -ne 'Failed' -or $current.UpdatedAt -ne $Operation.UpdatedAt -or -not (Test-ClaudeDesktopUpdateBaselineUnchanged $Root $baseline)){return $current}
        Set-ClaudeDesktopUpdate $Root $Operation.Id @{Status='Ready';Phase='Ready';MaintenanceId=$null;FailureKind='PackageResourcesInUse';Message='上次安装因 Claude 后台资源占用失败。当前版本维护已完成，原官方包及配套 Code 已重新核验；完全退出 Claude 和本地 Code 后可点击“安装并维护”重试。';CompletedAt=$null}
    }
}
function Save-ClaudeDesktopUpdateRollback([string]$Root,[string]$Id,$State) {
    $task=Get-ScheduledTask -TaskName $State.Reliability.TaskName
    Assert-GuardSupervisorTask $task $State
    $taskPath=Join-Path $Root ('private\upgrade-task-'+$Id+'.xml')
    [IO.File]::WriteAllText($taskPath,(Export-ScheduledTask -TaskName $State.Reliability.TaskName),[Text.UTF8Encoding]::new($false))
    $backupPath=Join-Path $Root ('private\upgrade-backup-'+$Id+'.json')
    Write-GuardJson $backupPath @{Deployment=$State;Firewall=(Read-GuardJson (Join-Path $Root 'private\firewall.json'));WasEnabled=[bool]$task.Settings.Enabled;WasRunning=($task.State.ToString() -eq 'Running');CodeAcls=@($State.CodePaths|Where-Object {Test-Path -LiteralPath $_}|ForEach-Object {@{Path=$_;Sddl=(Get-Acl -LiteralPath $_).Sddl}})}
    $restore=@{Path=$taskPath;Hash=(Get-GuardHash $taskPath);WasEnabled=[bool]$task.Settings.Enabled;WasRunning=($task.State.ToString() -eq 'Running')}
    $null=Set-GuardMaintenanceOperation $Id @{BackupFile=$backupPath;BackupHash=(Get-GuardHash $backupPath);TaskBackup=$taskPath;TaskBackupHash=$restore.Hash;DesktopTaskSnapshot=$restore;SupervisorSuspended=$true}
    $null=Suspend-GuardSupervisorTask -State $State -TimeoutSeconds 30
}
function Invoke-ClaudeDesktopUpdateMaintenance([string]$Root,[string]$Id,[switch]$BeforeInstall) {
    $self=[Diagnostics.Process]::GetCurrentProcess()
    $null=Set-GuardMaintenanceOperation $Id @{Phase='Preparing';CoordinatorPid=$PID;CoordinatorStarted=$self.StartTime.ToUniversalTime().ToString('o');CoordinatorPath=$self.MainModule.FileName}
    $text=& (Join-Path $Root 'Update-ClaudeGuard.ps1') -OperationId $Id
    if(-not $text){throw '安装后维护候选未生成。'}
    $stage=$text|ConvertFrom-Json
    $result=Join-Path $Root ('private\upgrade-result-'+[guid]::NewGuid().ToString('N')+'.json')
    $stageId=(Read-GuardJson $stage.StageFile).Id
    $null=Set-GuardMaintenanceOperation $Id @{Phase='AwaitingAuthorization';StageId=$stageId;StageFile=$stage.StageFile;StageHash=$stage.StageHash;ResultFile=$result}
    & (Join-Path $Root 'Update-ClaudeGuard.ps1') -Install -StageFile $stage.StageFile -StageHash $stage.StageHash -ResultFile $result -OperationId $Id -ContinueDesktopUpdate:$BeforeInstall
    $m=Read-GuardMaintenanceOperation $Id
    if($BeforeInstall){
        $migration=Read-GuardJson $result
        $state=Get-GuardState
        if(-not $migration.Success -or $migration.ActionId -ne $Id -or $migration.StageId -ne $stageId -or $migration.DesktopVersion -ne $state.Desktop.Version -or $migration.CodeVersion -ne $state.CodeGate.Version -or $m.Status -ne 'Running'){throw '安装前自动维护未完成，安装尚未执行。'}
        Assert-ClaudeDesktopUpdateProtectionReady
        $null=Set-GuardMaintenanceOperation $Id @{Phase='PreparingInstall';PreparationResultFile=$result;StageId=$null;StageFile=$null;StageHash=$null;ResultFile=$null;BackupFile=$null;BackupHash=$null;TaskBackup=$null;TaskBackupHash=$null;ProxyBackup=$null;ProxyBackupHash=$null;DesktopTaskSnapshot=$null;SupervisorSuspended=$false;BaselineChanged=$false}
        return
    }
    if($m.Status -ne 'Completed' -or -not (Get-GuardMaintenanceUiResult $m).Success){throw '安装后维护尚未成功完成。'}
}
function Invoke-ClaudeDesktopUpdateInstallation([string]$Root,[string]$Id,[string]$RequestHash) {
    if(-not (Test-GuardAdmin)){throw '需要同账号管理员授权。'}
    $r=Assert-ClaudeDesktopUpdateRequest $Root $Id $RequestHash
    $mutex=Get-GuardMaintenanceLock 'Install';$held=$false;$suspended=$false;$migrationStarted=$false
    $installBaseline=$r
    try{
        try{$held=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$held=$true};if(-not $held){throw '已有安装进程正在运行。'}
        $self=[Diagnostics.Process]::GetCurrentProcess()
        $null=Set-GuardMaintenanceOperation $Id @{WorkerPid=$PID;WorkerStarted=$self.StartTime.ToUniversalTime().ToString('o');WorkerPath=$self.MainModule.FileName;Phase='Migrating'}
        Assert-ClaudeDesktopUpdateClientsExited
        if((ConvertTo-ClaudeVersion $r.TargetVersion) -le (ConvertTo-ClaudeVersion (Get-GuardDesktop).Version)){throw '安装前版本已变化，拒绝重装或降级。'}
        if(Test-ClaudeDesktopUpdatePreparationRequired){
            if(-not (Get-GuardLifecycleValue $r 'AutoPrepare' $false)){throw '安装前防护需要维护，请重新发起安装。'}
            $null=Set-ClaudeDesktopUpdate $Root $r.DownloadId @{Status='PreparingProtection';Phase='PreparingProtection';WorkerPid=$PID;WorkerStarted=$self.StartTime.ToUniversalTime().ToString('o');WorkerPath=$self.MainModule.FileName;Message='正在自动恢复并核验安装前防护，完成后直接安装，请等待。'}
            Invoke-ClaudeDesktopUpdateMaintenance $Root $Id -BeforeInstall
            $installBaseline=[pscustomobject]@{BaselineHash=(Get-GuardHash (Join-Path $Root 'private\deployment.json'))}
            foreach($s in $r.Scripts){if((Get-GuardHash (Join-Path $Root $s.Name)) -ne $s.Hash){throw '自动维护期间更新脚本发生变化。'}}
            $package=Assert-ClaudeDesktopUpdatePackage $Root $r.PackageFile $r.TargetVersion $r.PackageHash
            Assert-ClaudeDesktopUpdateCodeCache $Root $package $r.CodePayloadHash
            Assert-ClaudeDesktopUpdateClientsExited
            if((ConvertTo-ClaudeVersion $r.TargetVersion) -le (ConvertTo-ClaudeVersion (Get-GuardDesktop).Version)){throw '自动维护后版本已变化，拒绝重装或降级。'}
        }
        Assert-ClaudeDesktopUpdateProtectionReady
        $null=Set-ClaudeDesktopUpdate $Root $r.DownloadId @{Status='Installing';Phase='Installing';WorkerPid=$PID;WorkerStarted=$self.StartTime.ToUniversalTime().ToString('o');WorkerPath=$self.MainModule.FileName;Message='正在安装官方客户端，后台守护暂时暂停。'}
        $suspended=$true;Save-ClaudeDesktopUpdateRollback $Root $Id (Get-GuardState)
        # 授权与暂停守护期间可能又启动客户端，安装前重新检查活动会话。
        Assert-ClaudeDesktopUpdateClientsExited
        $null=Set-GuardMaintenanceOperation $Id @{BaselineChanged=$true}
        Invoke-ClaudeDesktopUpdateNativeInstall $r.PackageFile
        $actual=Get-GuardDesktop
        if((ConvertTo-ClaudeVersion $actual.Version) -ne (ConvertTo-ClaudeVersion $r.TargetVersion) -or $actual.Family -ne (Get-GuardState).Desktop.Family){throw '安装后实际包身份或版本不一致。'}
        $null=Set-ClaudeDesktopUpdate $Root $r.DownloadId @{Status='Maintaining';Phase='Maintaining';Message='客户端已安装，正在迁移并核验版本防护。'}
        $migrationStarted=$true
        Invoke-ClaudeDesktopUpdateMaintenance $Root $Id
        $null=Set-ClaudeDesktopUpdate $Root $r.DownloadId @{Status='Completed';Phase='Completed';CompletedAt=[datetimeoffset]::UtcNow.ToString('o');Message='更新安装与版本维护完成，后台守护已核验。';FailureKind=$null}
    }catch{
        $failure=Get-ClaudeDesktopUpdateInstallFailure $_;$reason=$failure.Detail;$restored=$false;$unchanged=$false
        $prior=Read-GuardMaintenanceOperation $Id
        $existingRecovery=[bool](Get-GuardLifecycleValue $prior 'RecoveryRequired' $false)
        if(-not $suspended){$restored=[bool](Get-GuardLifecycleValue $prior 'RollbackRestored' $false)}
        # 安装结果未知时仍保留保守暂停；只有程序身份、哈希和防护基线均未变
        # 才撤销“基线变化”标记，防止资源占用失败造成不必要的永久安全暂停。
        if(-not $migrationStarted){try{$unchanged=Test-ClaudeDesktopUpdateBaselineUnchanged $Root $installBaseline}catch{}}
        if($unchanged -and -not $existingRecovery){$null=Set-GuardMaintenanceOperation $Id @{BaselineChanged=$false} -Recovery}
        if($suspended){try{Restore-GuardMaintenanceBackup (Read-GuardMaintenanceOperation $Id);$restored=$true}catch{}}
        $needsRecovery=$existingRecovery -or ($suspended -and -not $restored)
        $retry=$failure.ResourcesInUse -and $unchanged -and $restored -and -not $needsRecovery
        $kind=if($failure.ResourcesInUse){'PackageResourcesInUse'}else{'DesktopUpdateFailed'}
        $message=if($retry){'Windows 仍报告 Claude 后台资源占用（0x80073D02）。旧版及防护已恢复，官方包已保留；完全退出 Claude 和本地 Code 后可再次点击“安装并维护”。'}else{'更新未完成：'+$reason+' 请点击“维护版本”恢复或重新核验。'}
        if($retry -and $failure.ActivityId){$message+=' 诊断 ID：'+$failure.ActivityId}
        $status=if($needsRecovery){'Interrupted'}else{'Failed'}
        $null=Set-GuardMaintenanceOperation $Id @{Status=$status;Phase=$status;RecoveryRequired=$needsRecovery;RollbackRestored=$restored;FailureKind=$kind;Reason=$message;InstallerErrorCode=$failure.ErrorCode;InstallerActivityId=$failure.ActivityId;InstallerErrorDetail=$failure.Detail} -Recovery
        $updateStatus=if($retry){'Ready'}else{$status}
        $null=Set-ClaudeDesktopUpdate $Root $r.DownloadId @{Status=$updateStatus;Phase=$updateStatus;FailureKind=$kind;Message=$message;CompletedAt=[datetimeoffset]::UtcNow.ToString('o');InstallerErrorCode=$failure.ErrorCode;InstallerActivityId=$failure.ActivityId}
        throw
    }finally{if($held){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
Export-ModuleMember -Function *-ClaudeDesktopUpdate*
