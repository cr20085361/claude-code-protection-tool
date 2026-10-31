[CmdletBinding()]
param([switch]$CompileOnly)
$ErrorActionPreference='Stop'
$versionCheck=& (Join-Path $PSScriptRoot 'Test-ClaudeIterationVersion.ps1')
if(-not $versionCheck.Passed){throw 'Iteration version consistency check failed.'}
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -Force
$d=Get-GuardState
$pwsh=Get-GuardApprovedShellPath
Add-Type -AssemblyName System.Drawing
$icon=[Drawing.Icon]::ExtractAssociatedIcon((Get-GuardDesktop).Path)
try{$stream=[IO.File]::Create((Get-GuardPath 'runtime\claude-guard.ico'));try{$icon.Save($stream)}finally{$stream.Dispose()}}finally{$icon.Dispose()}
$compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$exe=Get-GuardPath 'runtime\ClaudeProGuard.exe'
$hostExe=Get-GuardPath 'runtime\ClaudeSupervisorHost.exe'
if(@(Get-CimInstance Win32_Process|Where-Object {$_.ExecutablePath -in @($exe,$hostExe)}).Count){throw 'Stop the safety launcher and owned supervisor host before compiling their executables.'}
& $compiler /nologo /target:winexe /platform:x64 /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/win32icon:'+(Get-GuardPath 'runtime\claude-guard.ico')) ('/out:'+$exe) (Join-Path $PSScriptRoot 'ClaudeGuardLauncher.cs')
if($LASTEXITCODE -ne 0){throw 'GUI launcher compilation failed.'}
& $compiler /nologo /target:winexe /platform:x64 /reference:System.Web.Extensions.dll ('/out:'+$hostExe) (Join-Path $PSScriptRoot 'ClaudeSupervisorHost.cs')
if($LASTEXITCODE -ne 0){throw 'Supervisor host compilation failed.'}
if($CompileOnly){[pscustomobject]@{LauncherPath=$exe;LauncherHash=(Get-GuardHash $exe);HostPath=$hostExe;HostHash=(Get-GuardHash $hostExe);ShellPath=$pwsh};return}
$desktop=[Environment]::GetFolderPath('Desktop')
$shortcutPath=Join-Path $desktop 'Claude Pro（安全入口）.lnk'
$shell=New-Object -ComObject WScript.Shell
$shortcut=$shell.CreateShortcut($shortcutPath)
$shortcut.TargetPath=$exe;$shortcut.WorkingDirectory=$PSScriptRoot;$shortcut.IconLocation=(Get-GuardPath 'runtime\claude-guard.ico')
$shortcut.Description='后台检查固定出口、防火墙和 Code 执行门槛后打开 Claude Pro。'
$shortcut.Save()
$readback=$shell.CreateShortcut($shortcutPath)
if($readback.TargetPath -ne $exe -or $readback.WorkingDirectory -ne $PSScriptRoot){throw 'Desktop shortcut verification failed.'}
Write-GuardJson (Get-GuardPath 'evidence\desktop-shortcut.json') @{Time=(Get-Date -Format o);Path=$shortcutPath;Target=$readback.TargetPath;WorkingDirectory=$readback.WorkingDirectory;TargetHash=(Get-GuardHash $exe);ConsoleSubsystem=$false;VerifiedByShortcutReadback=$true;ActualDoubleClickVerified=$false}
Write-Output $shortcutPath
