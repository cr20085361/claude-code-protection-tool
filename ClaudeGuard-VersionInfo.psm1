Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'

function ConvertTo-ClaudeVersion([string]$Value) {
    if($Value -notmatch '^\d+\.\d+\.\d+(?:\.\d+)?$'){throw 'Invalid version.'}
    $v=[version]$Value
    [version]::new($v.Major,$v.Minor,$v.Build,[Math]::Max(0,$v.Revision))
}
function Get-ClaudeVersionDecision([string]$Latest,[string]$Installed) {
    $a=ConvertTo-ClaudeVersion $Latest;$b=ConvertTo-ClaudeVersion $Installed
    if($a -gt $b){'Available'}elseif($a -eq $b){'Current'}else{'Ahead'}
}
function ConvertFrom-ClaudeVersionHeaders([string]$Headers) {
    if($Headers.Length -gt 65536){throw 'Official response too large.'}
    $status=@([regex]::Matches($Headers,'(?m)^HTTP/\S+\s+(\d{3})'))
    $location=@([regex]::Matches($Headers,'(?im)^location:\s*(\S+)\s*$'))
    if(-not $status.Count -or [int]$status[-1].Groups[1].Value -notin @(301,302,303,307,308) -or $location.Count -ne 1){throw 'Official redirect not available.'}
    $u=[uri]$location[0].Groups[1].Value
    if($u.Scheme -ne 'https' -or $u.Host -ne 'downloads.claude.ai' -or $u.Port -ne 443 -or $u.UserInfo -or $u.Query -or $u.Fragment -or $u.AbsolutePath -notmatch '^/releases/win32/x64/(\d+\.\d+\.\d+)/Claude-(?:[a-f0-9]{40}|[a-f0-9]{64})\.msix$'){throw 'Official update source changed.'}
    $version=$Matches[1];$null=ConvertTo-ClaudeVersion $version
    [pscustomobject]@{LatestDesktopVersion=$version;DownloadUrl=$u.AbsoluteUri;SourceUrl='https://claude.ai/api/desktop/win32/x64/msix/latest/redirect'}
}
function Invoke-ClaudeVersionCatalogRequest([string]$Probe,[string]$Proxy) {
    if($Proxy -ne 'http://127.0.0.1:10818'){throw 'Unapproved proxy.'}
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$Probe;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    foreach($a in @('--silent','--show-error','--dump-header','-','--output','NUL','--max-filesize','65536','--connect-timeout','8','--max-time','20','--proxy',$Proxy,'--noproxy','','https://claude.ai/api/desktop/win32/x64/msix/latest/redirect')){$info.ArgumentList.Add($a)}
    $p=[Diagnostics.Process]::new();$p.StartInfo=$info
    try{
        if(-not $p.Start()){throw 'Query could not start.'}
        $output=$p.StandardOutput.ReadToEndAsync();$errors=$p.StandardError.ReadToEndAsync()
        if(-not $p.WaitForExit(24000)){try{$p.Kill()}catch{};throw 'Query timed out.'}
        if($p.ExitCode -ne 0){throw 'Official query unavailable.'}
        ConvertFrom-ClaudeVersionHeaders $output.GetAwaiter().GetResult()
    }finally{$p.Dispose()}
}
function Get-ClaudeVersionCatalog([string]$Root,$State,[switch]$CheckUpdates,[switch]$Force,[datetimeoffset]$Now=[datetimeoffset]::UtcNow) {
    $path=Join-Path $Root 'private\version-update-status.json'
    $previous=$null
    if(Test-Path -LiteralPath $path){
        try{
            $previous=Read-GuardJson $path
            if($previous.SchemaVersion -ne 1 -or @(@('Status','CheckedAt','LastSuccess','FailureKind')|Where-Object {-not $previous.PSObject.Properties[$_]}).Count -or $previous.Status -notin @('Checked','QueryFailed')){throw 'Invalid query cache.'}
            $null=[datetimeoffset]$previous.CheckedAt
            if($previous.LastSuccess){$null=ConvertTo-ClaudeVersion $previous.LastSuccess.LatestDesktopVersion;$null=[datetimeoffset]$previous.LastSuccess.CheckedAt}
        }catch{$previous=$null}
    }
    if(-not $CheckUpdates){if($previous){return $previous};return [pscustomobject]@{SchemaVersion=1;Status='NotChecked';CheckedAt=$null;LastSuccess=$null;FailureKind=$null}}
    if($previous -and -not $Force){
        $age=($Now-([datetimeoffset]$previous.CheckedAt)).TotalSeconds
        $ttl=if($previous.Status -eq 'QueryFailed'){900}else{21600}
        if($age -ge 0 -and $age -lt $ttl){return $previous}
    }
    $deferred=Test-Path -LiteralPath (Join-Path $Root 'private\safety-hold.json')
    $opPath=Join-Path $Root 'private\active-version-maintenance.json'
    if(Test-Path -LiteralPath $opPath){
        try{$op=Read-GuardJson $opPath;$deferred=$deferred -or $op.Status -in @('Running','Interrupted') -or $op.RecoveryRequired}catch{$deferred=$true}
    }
    if($deferred){return [pscustomobject]@{SchemaVersion=1;Status='Deferred';CheckedAt=$null;LastSuccess=$(if($previous){$previous.LastSuccess}else{$null});FailureKind='MaintenanceOrSafetyHold'}}
    $bytes=[Text.Encoding]::UTF8.GetBytes([IO.Path]::GetFullPath($Root).ToLowerInvariant())
    $sha=[Security.Cryptography.SHA256]::Create()
    try{$key=([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-','')}finally{$sha.Dispose()}
    $mutex=[Threading.Mutex]::new($false,('Local\ClaudeVersionQuery-'+$key));$locked=$false
    try {
        try{$locked=$mutex.WaitOne(0)}catch [Threading.AbandonedMutexException]{$locked=$true}
        if(-not $locked){return [pscustomobject]@{SchemaVersion=1;Status='Checking';CheckedAt=$null;LastSuccess=$(if($previous){$previous.LastSuccess}else{$null});FailureKind=$null}}
        $record=[ordered]@{SchemaVersion=1;Status='QueryFailed';CheckedAt=$Now.ToString('o');LastSuccess=$(if($previous){$previous.LastSuccess}else{$null});FailureKind='OfficialSourceUnavailable'}
        try{
            $found=Invoke-ClaudeVersionCatalogRequest (Join-Path $Root 'runtime\network-probe.exe') $State.ProxyUrl
            $record.Status='Checked';$record.FailureKind=$null
            $record.LastSuccess=@{CheckedAt=$Now.ToString('o');LatestDesktopVersion=$found.LatestDesktopVersion;SourceUrl=$found.SourceUrl;DownloadUrl=$found.DownloadUrl}
        }catch{}
        Write-GuardJson $path $record
        [pscustomobject]$record
    }finally{if($locked){$mutex.ReleaseMutex()};$mutex.Dispose()}
}
function Get-ClaudeVersionFileIdentity($Process) {
    $start=$null
    try{
        $p=Get-Process -Id $Process.ProcessId -ErrorAction Stop
        if(-not $p.Path){throw 'Running process identity unreadable.'}
        if($p.Path -ne $Process.ExecutablePath){return $null}
        $start=$p.StartTime.ToUniversalTime().ToString('o')
        # CIM 启动时间只有微秒精度；之后仍用原生启动时间再次排除 PID 复用。
        if($Process.CreationDate -and [Math]::Abs(([datetimeoffset]$Process.CreationDate).UtcDateTime.Ticks-$p.StartTime.ToUniversalTime().Ticks) -gt 10){return $null}
        $file=Get-Item -LiteralPath $p.Path
        $version=$file.VersionInfo.FileVersion
        if($version -match '^([0-9]+\.[0-9]+\.[0-9]+)(?:\.0)?$'){$version=$Matches[1]}else{$version=$null}
        $hash=Get-GuardHash $p.Path
        $again=Get-Process -Id $Process.ProcessId -ErrorAction Stop
        if($again.StartTime.ToUniversalTime().Ticks -ne $p.StartTime.ToUniversalTime().Ticks -or $again.Path -ne $p.Path){return $null}
        [pscustomobject]@{Version=$version;Hash=$hash;StartedAt=$start}
    }catch{
        # 读取失败不能变成“未运行”；仅在 CIM 再次确认同一进程后返回未确认身份。
        try{
            $live=Get-CimInstance Win32_Process -Filter ('ProcessId='+[int]$Process.ProcessId) -ErrorAction Stop
            if($live -and $live.ExecutablePath -eq $Process.ExecutablePath -and $Process.CreationDate -and $live.CreationDate -eq $Process.CreationDate){
                return [pscustomobject]@{Version=$null;Hash=$null;StartedAt=$start}
            }
        }catch{}
        $null
    }
}
function Get-ClaudeVersionRuntime($State,$Processes,[scriptblock]$FileReader={param($p)Get-ClaudeVersionFileIdentity $p},[bool]$DesktopMatchesApproved=$true) {
    $roots=@($State.CodeGate.Roots|ForEach-Object {[IO.Path]::GetFullPath($_).TrimEnd('\')+'\'})
    $byPid=@{};foreach($p in $Processes){$byPid[[string]$p.ProcessId]=$p}
    $result=@()
    foreach($p in $Processes){
        if(-not $p.ExecutablePath -or [IO.Path]::GetFileName($p.ExecutablePath) -ine 'claude.exe'){continue}
        if(-not @($roots|Where-Object {$p.ExecutablePath.StartsWith($_,[StringComparison]::OrdinalIgnoreCase)}).Count){continue}
        $file=& $FileReader $p
        if(-not $file){continue}
        $owner=$false;$next=[string]$p.ParentProcessId;$seen=@{}
        for($i=0;$i -lt 32 -and $byPid.ContainsKey($next) -and -not $seen.ContainsKey($next);$i++){
            $seen[$next]=$true;$parent=$byPid[$next]
            if($parent.ExecutablePath -eq $State.Desktop.Path){$owner=$true;break}
            $next=[string]$parent.ParentProcessId
        }
        $approved=$p.ExecutablePath -in @($State.CodePaths) -and $file.Hash -eq $State.CodeGate.PayloadHash -and $file.Version -eq $State.CodeGate.Version
        $identity=if(-not $file.Version){'Unreadable'}elseif(-not $approved){'Unreviewed'}elseif(-not $owner -or -not $DesktopMatchesApproved){'UnknownOrigin'}else{'Approved'}
        $result+=[pscustomobject]@{Pid=$p.ProcessId;StartedAt=$file.StartedAt;Version=$file.Version;Identity=$identity}
    }
    $result
}
function Get-ClaudeVersionSnapshot([string]$Root,[switch]$CheckUpdates,[switch]$Force) {
    $state=Get-GuardState
    $installed=$null;$engine=$null;$installedMatches=$false
    try{
        $installed=Get-GuardDesktop
        $manifest=& node (Join-Path $Root 'Read-DesktopCodeManifest.cjs') (Join-Path (Split-Path $installed.Path) 'resources\app.asar') 2>$null
        if($LASTEXITCODE -eq 0 -and $manifest){$engine=($manifest|ConvertFrom-Json).desktopCodeVersion}
        $installedMatches=$installed.Path -eq $state.Desktop.Path -and $installed.Hash -eq $state.Desktop.Hash -and $installed.Version -eq $state.Desktop.Version -and $engine -eq $state.CodeGate.Version
    }catch{}
    $runtime=@(Get-ClaudeVersionRuntime $state @(Get-CimInstance Win32_Process) -DesktopMatchesApproved $installedMatches)
    $catalog=Get-ClaudeVersionCatalog $Root $state -CheckUpdates:$CheckUpdates -Force:$Force
    $decision=$null
    if($catalog.LastSuccess -and $installed){try{$decision=Get-ClaudeVersionDecision $catalog.LastSuccess.LatestDesktopVersion $installed.Version}catch{}}
    $toolVersion=$null
    try{$toolVersion=(Read-GuardJson (Join-Path $Root '.iteration-version.json')).current_version}catch{}
    [pscustomobject]@{SchemaVersion=1;ObservedAt=[datetimeoffset]::UtcNow.ToString('o');InstalledDesktopVersion=$(if($installed){$installed.Version}else{$null});InstalledCodeVersion=$engine;ApprovedDesktopVersion=$state.Desktop.Version;ApprovedCodeVersion=$state.CodeGate.Version;InstalledMatchesApproved=$installedMatches;Runtime=$runtime;RuntimeState=$(if($runtime.Count){'Running'}else{'NotRunning'});Catalog=$catalog;UpdateDecision=$decision;ToolVersion=$toolVersion}
}
Export-ModuleMember -Function *-ClaudeVersion*
