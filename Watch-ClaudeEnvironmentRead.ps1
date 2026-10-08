[CmdletBinding()]
param([ValidateRange(10,900)][int]$Seconds=120)
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$state=Get-GuardState
$python=Join-Path $env:LOCALAPPDATA 'Programs\Python\Python311\python.exe'
$deadline=[datetime]::UtcNow.AddSeconds($Seconds)
$seen=@{};$records=@()
$resultPath=Get-GuardPath 'evidence\runtime-environment-native-diagnostic.json'
do {
    $targets=@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in (@($state.Desktop.Path)+@($state.CodePaths)) -and $_.CommandLine -notmatch '--type='})
    foreach($target in $targets){
        $process=$null;$reader=$null
        try {
            $process=Get-Process -Id $target.ProcessId -ErrorAction Stop;$null=$process.Handle
            if($process.Path -ne $target.ExecutablePath){continue}
            $key=[string]$process.Id+':'+$process.StartTime.ToUniversalTime().Ticks
            if($seen[$key]){continue};$seen[$key]=$true
            $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$python;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
            $info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $info.ArgumentList.Add((Join-Path $PSScriptRoot 'Read-ClaudeProcessEnvironment.py'));$info.ArgumentList.Add([string]$process.Id)
            $reader=[Diagnostics.Process]::new();$reader.StartInfo=$info;$timer=[Diagnostics.Stopwatch]::StartNew();$null=$reader.Start()
            $output=$reader.StandardOutput.ReadToEndAsync();$stderr=$reader.StandardError.ReadToEndAsync()
            $timedOut=-not $reader.WaitForExit(10000);if($timedOut){$reader.Kill();$null=$reader.WaitForExit(1000)}
            $record=[ordered]@{Time=[datetime]::UtcNow.ToString('o');Pid=$process.Id;Kind=if($target.ExecutablePath -eq $state.Desktop.Path){'Desktop'}else{'Code'};Started=$process.StartTime.ToUniversalTime().ToString('o');ExitedDuringRead=$process.HasExited;ExitCode=$reader.ExitCode;ElapsedMs=$timer.ElapsedMilliseconds;TimedOut=$timedOut;FailureClass=$null;ComparisonIssues=@()}
            $errorText=$stderr.GetAwaiter().GetResult()
            foreach($known in @('Approved process cannot be opened for read-only evidence.','Process environment evidence unavailable.','Process basic information unavailable.','Process path could not be verified.','Environment terminator was not found.','Refusing environment read outside approved Claude paths.')){if($errorText.Contains($known)){$record.FailureClass=$known}}
            if($reader.ExitCode -eq 0){$comparison=$output.GetAwaiter().GetResult()|ConvertFrom-Json;$record.ComparisonIssues=@('ConfigDirMatches','HttpProxyMatches','HttpsProxyMatches','AllProxyMatches','NoProxyOnlyLoopback','TlsVerificationEnabled'|Where-Object {$comparison.$_ -ne $true})}
            $records+=[pscustomobject]$record
            $records|ConvertTo-Json -Depth 5|Set-Content -LiteralPath $resultPath -Encoding utf8
        }catch { }finally {if($reader){$reader.Dispose()};if($process){$process.Dispose()}}
    }
    Start-Sleep -Milliseconds 500
}while([datetime]::UtcNow -lt $deadline)
[pscustomobject]@{Captured=$records.Count;Failures=@($records|Where-Object ExitCode -ne 0).Count;ResultPath=$resultPath}|ConvertTo-Json
