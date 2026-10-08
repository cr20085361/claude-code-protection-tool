$ErrorActionPreference='Stop'
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeVersionWindow-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $scratch|Out-Null
$runner=Join-Path $scratch 'Runner.cs'
$source=@'
using System;using System.Drawing;using System.Reflection;using System.Collections.Generic;using System.IO;using System.Web.Script.Serialization;using System.Windows.Forms;
public static class VersionWindowRunner {
 static List<string> checks=new List<string>();
 static T Field<T>(object o,string name){return (T)o.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(o);}
 static void Require(bool ok,string name){if(!ok)throw new Exception(name);checks.Add(name);}
 [STAThread] public static int Main(string[] args){
  Application.EnableVisualStyles();using(var w=new ClaudeGuardWindow(args[0],"unused")){
   w.PreviewOnly=true;w.ShowInTaskbar=false;w.StartPosition=FormStartPosition.Manual;w.Location=new Point(-30000,-30000);w.Show();Application.DoEvents();
   var status=Field<Label>(w,"status");var health=Field<Label>(w,"networkHealth");status.Text="original-action";health.Text="original-health";
   var info=new ClaudeGuardWindow.VersionResult{SchemaVersion=1,InstalledDesktopVersion="2.26454.2.0",InstalledCodeVersion="2.1.293",ApprovedCodeVersion="2.1.293",InstalledMatchesApproved=true,Runtime=new ClaudeGuardWindow.RuntimeVersion[0],ToolVersion="v1.2.0",Catalog=new ClaudeGuardWindow.CatalogResult{Status="Checked",LastSuccess=new ClaudeGuardWindow.PublishedVersion{CheckedAt=DateTimeOffset.UtcNow.ToString("o"),LatestDesktopVersion="2.26454.2"}},UpdateDecision="Current"};
   w.RenderVersionInfo(info);Application.DoEvents();
   Require(Field<Label>(w,"installedVersions").Text.Contains("2.26454.2.0")&&Field<Label>(w,"installedVersions").Text.Contains("2.1.293"),"native-installed-and-approved-versions-visible");
   Require(Field<Label>(w,"runtimeVersions").Text=="本地 Code：未运行。","native-not-running-is-not-installed-version");
   info.Runtime=new[]{new ClaudeGuardWindow.RuntimeVersion{Version="2.1.293",Identity="Approved"}};w.RenderVersionInfo(info);
   Require(Field<Label>(w,"runtimeVersions").Text.Contains("2.1.293（已核准进程）"),"native-running-approved-engine");
   info.Runtime[0].Identity="Unreviewed";w.RenderVersionInfo(info);
   Require(Field<Label>(w,"runtimeVersions").ForeColor==Color.FromArgb(145,99,20),"native-unreviewed-engine-is-amber");
   info.Runtime[0].Identity="Unreadable";info.Runtime[0].Version=null;w.RenderVersionInfo(info);
   Require(Field<Label>(w,"runtimeVersions").Text.Contains("运行版本未确认")&&!Field<Label>(w,"runtimeVersions").Text.Contains("未运行"),"native-unreadable-running-engine-is-not-absent");
   info.UpdateDecision="Available";info.Catalog.LastSuccess.LatestDesktopVersion="2.26455.1";w.RenderVersionInfo(info);
   Require(Field<Label>(w,"updateStatus").Text.Contains("发现新版 Desktop 2.26455.1"),"native-new-release-prompt");
   info.Catalog.Status="QueryFailed";w.RenderVersionInfo(info);
   Require(Field<Label>(w,"updateStatus").Text.Contains("暂未取得")&&Field<Label>(w,"updateStatus").Text.Contains("上次"),"native-query-failure-retains-last-check");
   Require(status.Text=="original-action"&&health.Text=="original-health"&&Field<Button>(w,"launch").Enabled,"version-failure-does-not-change-health-or-start-controls");
   info.Catalog.Status="Checked";info.Catalog.LastSuccess.CheckedAt=DateTimeOffset.UtcNow.AddDays(-2).ToString("o");w.RenderVersionInfo(info);
   Require(Field<Label>(w,"updateStatus").Text.StartsWith("上次检查"),"native-stale-result-labelled-as-history");
   info.Catalog.Status="Deferred";w.RenderVersionInfo(info);
   Require(Field<Label>(w,"updateStatus").Text.Contains("维护或安全暂停"),"native-query-deferred-during-maintenance");
   Require(Field<Button>(w,"checkUpdates").Text=="检查新版"&&Field<Label>(w,"entryVersion").Text.Contains("v1.2.0"),"native-check-button-and-tool-version");
   File.WriteAllText(args[1],new JavaScriptSerializer().Serialize(new{Passed=true,NativeWindow=true,ProductionTouched=false,Count=checks.Count,Checks=checks}));w.Close();
  }return 0;
 }
}
'@
[IO.File]::WriteAllText($runner,$source,[Text.UTF8Encoding]::new($false))
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$dll=Join-Path $scratch 'GuardUI.dll';$exe=Join-Path $scratch 'Runner.exe';$result=Join-Path $PSScriptRoot 'evidence\version-window-regression.json'
try {
    & $csc /nologo /target:library /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+$dll) (Join-Path $PSScriptRoot 'ClaudeGuardLauncher.cs')
    if($LASTEXITCODE){throw 'UI library compilation failed.'}
    & $csc /nologo /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/reference:'+$dll) ('/out:'+$exe) $runner
    if($LASTEXITCODE){throw 'Window runner compilation failed.'}
    & $exe $scratch $result
    if($LASTEXITCODE){throw 'Native version window fixture failed.'}
    Get-Content -LiteralPath $result -Raw
}finally{
    $full=[IO.Path]::GetFullPath($scratch);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeVersionWindow-[a-f0-9]{32}$'){throw 'Unsafe window fixture cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
