# Run an existing project's ordinary development command with the same scoped
# process environment that Claude passes to development servers it starts itself.
[CmdletBinding()]
param(
    [Parameter(Mandatory,Position=0)][string]$FilePath,
    [Parameter(Position=1)][string[]]$ArgumentList=@()
)
$ErrorActionPreference='Stop'
$principal=[Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
if($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw '请使用普通权限的 PowerShell 启动本地预览。'}
$command=Get-Command $FilePath -CommandType Application,ExternalScript -ErrorAction Stop | Select-Object -First 1
Import-Module (Join-Path $PSScriptRoot 'ClaudeGuard.psm1') -DisableNameChecking
$environment=New-GuardDesktopEnvironment (Get-GuardState)
$previous=@{}
try{
    foreach($key in $environment.Keys){
        $previous[$key]=[Environment]::GetEnvironmentVariable($key,'Process')
        [Environment]::SetEnvironmentVariable($key,$environment[$key],'Process')
    }
    & $command.Source @ArgumentList
    if($command.CommandType -eq 'Application'){exit $LASTEXITCODE}
}finally{
    foreach($key in $previous.Keys){[Environment]::SetEnvironmentVariable($key,$previous[$key],'Process')}
}
