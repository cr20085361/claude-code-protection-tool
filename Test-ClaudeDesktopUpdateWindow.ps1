$ErrorActionPreference='Stop'
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeUpdateWindow-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $scratch,(Join-Path $scratch 'private')
$source=@'
using System;using System.Drawing;using System.IO;using System.Reflection;using System.Collections.Generic;using System.Web.Script.Serialization;using System.Windows.Forms;
public class UpdateWindowRunner {
 static List<string> checks=new List<string>();static T Field<T>(object o,string n){return (T)o.GetType().GetField(n,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(o);}
 static void Require(bool ok,string name){if(!ok)throw new Exception(name);checks.Add(name);}
 static ClaudeGuardWindow.VersionResult Info(){return new ClaudeGuardWindow.VersionResult{SchemaVersion=1,InstalledDesktopVersion="2.26454.2.0",InstalledCodeVersion="2.1.293",ApprovedCodeVersion="2.1.293",InstalledMatchesApproved=true,Runtime=new ClaudeGuardWindow.RuntimeVersion[0],ToolVersion="v1.3.0",UpdateDecision="Current",Catalog=new ClaudeGuardWindow.CatalogResult{Status="Checked",LastSuccess=new ClaudeGuardWindow.PublishedVersion{CheckedAt=DateTimeOffset.UtcNow.ToString("o"),LatestDesktopVersion="2.26454.2"}}};}
 [STAThread]public static int Main(string[] args){try{return Run(args);}catch(Exception e){Console.WriteLine(e.GetType().Name+": "+e.Message);if(e.InnerException!=null)Console.WriteLine(e.InnerException.GetType().Name+": "+e.InnerException.Message);return 1;}}
 public static int Run(string[] args){
  Application.EnableVisualStyles();
  foreach(float scale in new[]{1f,1.25f,1.5f,2f})using(var w=new ClaudeGuardWindow(args[0],"unused")){
   w.PreviewOnly=true;w.ShowInTaskbar=false;w.StartPosition=FormStartPosition.Manual;w.Location=new Point(-30000,-30000);w.Show();w.Scale(new SizeF(scale,scale));Application.DoEvents();
   var status=Field<Label>(w,"status");foreach(string n in new[]{"launch","check","login","report","maintenance"}){var b=Field<Button>(w,n);Require(status.Bottom<b.Top,"status-does-not-cover-"+n+"-at-"+scale);}
   foreach(string n in new[]{"launch","check","login","report","maintenance","checkUpdates","downloadUpdates","installUpdates"}){var b=Field<Button>(w,n);Require(w.DisplayRectangle.Contains(b.Bounds),"complete-scrollable-"+n+"-bounds-at-"+scale);}
   w.RenderVersionInfo(Info());Require(Field<Button>(w,"downloadUpdates").Enabled,"fresh-release-allows-package-download-at-"+scale);
   w.Close();
  }
  using(var w=new ClaudeGuardWindow(args[0],"unused")){
   w.PreviewOnly=true;w.ShowInTaskbar=false;w.StartPosition=FormStartPosition.Manual;w.Location=new Point(-30000,-30000);w.Show();Application.DoEvents();w.RenderVersionInfo(Info());
   var launch=Field<Button>(w,"launch");var status=Field<Label>(w,"status");status.Text="original-main-status";
   var d=new ClaudeGuardWindow.DesktopUpdateResult{SchemaVersion=1,Id=new string('a',32),Status="Downloading",TargetVersion="2.26455.1.0",PackageBytes=20*1048576,Message="Downloading"};
   w.RenderDesktopUpdate(d);Require(!Field<Button>(w,"downloadUpdates").Enabled&&!Field<Button>(w,"installUpdates").Enabled&&launch.Enabled&&status.Text=="original-main-status","download-does-not-pause-current-use-or-overwrite-main-result");
   Require(Field<Label>(w,"downloadStatus").Text.Contains("20.0 MB"),"download-progress-visible");
   d.Status="Ready";w.RenderDesktopUpdate(d);Require(Field<Button>(w,"installUpdates").Enabled,"verified-newer-package-allows-install");
   Field<Button>(w,"check").Enabled=false;w.RenderDesktopUpdate(d);Require(Field<Button>(w,"installUpdates").Enabled,"held-check-button-does-not-force-separate-maintenance");Field<Button>(w,"check").Enabled=true;
   d.Status="Failed";d.FailureKind="DesktopUpdateFailed";d.Signature="Valid";d.PackageHash=new string('a',64);w.RenderDesktopUpdate(d);Require(Field<Button>(w,"installUpdates").Enabled&&Field<Label>(w,"downloadStatus").Text.Contains("自动恢复"),"verified-failed-package-allows-one-click-recovery-and-install");
   d.Signature=null;w.RenderDesktopUpdate(d);Require(!Field<Button>(w,"installUpdates").Enabled,"unverified-failed-download-cannot-install");d.Status="Ready";d.FailureKind=null;
   d.TargetVersion="2.26454.2.0";w.RenderDesktopUpdate(d);Require(!Field<Button>(w,"installUpdates").Enabled&&Field<Label>(w,"downloadStatus").Text.Contains("无需升级"),"current-package-does-not-offer-reinstall");
   d.TargetVersion="2.26455.1.0";d.Status="Installing";d.MaintenanceId=new string('b',32);d.Message="正在安装";w.RenderDesktopUpdate(d);Require(!Field<Button>(w,"installUpdates").Enabled&&!Field<Button>(w,"downloadUpdates").Enabled,"native-install-blocks-duplicate-actions");
   d.Status="PreparingProtection";d.Message="自动恢复防护";w.RenderDesktopUpdate(d);Require(!Field<Button>(w,"installUpdates").Enabled&&!Field<Button>(w,"downloadUpdates").Enabled,"automatic-preparation-blocks-duplicate-actions");
   w.RenderClientState(true,false);Require(launch.Text=="Claude 已打开","actual-running-process-shows-open");
   status.Text="Claude 已打开。";status.ForeColor=Color.FromArgb(24,106,65);w.RenderClientState(false,false);Require(launch.Text=="打开 Claude"&&!status.Text.Contains("已打开"),"manual-client-exit-clears-button-and-stale-success-message");
   w.RenderClientState(false,true);Require(launch.Text=="更新进行中","installation-with-exited-client-shows-update-in-progress");
   w.RenderClientState(false,false);Require(launch.Text=="打开 Claude","finished-update-with-exited-client-shows-open-action");
   d.Status="AwaitingReadiness";d.Message="守护就绪尚未确认";w.RenderDesktopUpdate(d);Require(!Field<Button>(w,"installUpdates").Enabled&&Field<Label>(w,"downloadStatus").Text.Contains("尚未确认"),"finished-installer-awaits-current-guardian");
   d.Status="Completed";d.Message="更新安装与版本维护完成";w.RenderDesktopUpdate(d);Require(Field<Label>(w,"downloadStatus").ForeColor==Color.FromArgb(24,106,65),"completed-update-is-green");
   d.Status="Interrupted";d.Message="需要恢复";w.RenderDesktopUpdate(d);Require(!Field<Button>(w,"downloadUpdates").Enabled&&!Field<Button>(w,"installUpdates").Enabled,"interrupted-install-requires-recovery");
   var json=new JavaScriptSerializer();d.Status="PreparingInstall";d.MaintenanceId=null;var self=System.Diagnostics.Process.GetCurrentProcess();d.WorkerPid=self.Id;d.WorkerStarted=self.StartTime.ToUniversalTime().ToString("o");d.WorkerPath=self.MainModule.FileName;d.PackageFile=Path.Combine(args[0],"private","desktop-package-"+d.Id+".msix");File.WriteAllText(Path.Combine(args[0],"private","active-desktop-update.json"),json.Serialize(d));
   Require((bool)w.GetType().GetMethod("ResumeDesktopUpdateOnOpen",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(w,new object[0]),"reopen-during-install-preparation-blocks-auto-start");
   d.Status="PreparingProtection";d.MaintenanceId=new string('b',32);File.WriteAllText(Path.Combine(args[0],"private","active-desktop-update.json"),json.Serialize(d));Require((bool)w.GetType().GetMethod("ResumeDesktopUpdateOnOpen",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(w,new object[0]),"reopen-during-automatic-maintenance-resumes-same-update");
   d.Status="Downloading";d.MaintenanceId=null;File.WriteAllText(Path.Combine(args[0],"private","active-desktop-update.json"),json.Serialize(d));Require(!(bool)w.GetType().GetMethod("ResumeDesktopUpdateOnOpen",BindingFlags.Instance|BindingFlags.NonPublic).Invoke(w,new object[0]),"reopen-during-download-keeps-normal-start-flow");
  File.Delete(Path.Combine(args[0],"private","active-desktop-update.json"));w.Close();
  }
  using(var w=new ClaudeGuardWindow(args[0],"unused")){
   w.PreviewOnly=true;w.ShowInTaskbar=false;w.StartPosition=FormStartPosition.Manual;w.Location=new Point(-30000,-30000);w.Show();Application.DoEvents();
   string fakePath=Path.Combine(args[0],"runtime","Claude.exe");File.WriteAllText(Path.Combine(args[0],"private","deployment.json"),new JavaScriptSerializer().Serialize(new {Desktop=new {Path=fakePath}}));
   string closeFile=Path.Combine(args[0],"close-fixture-client.txt");
   using(var fake=System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(fakePath){Arguments="\""+closeFile+"\"",UseShellExecute=false,CreateNoWindow=true})){
    try{
     Require(fake.WaitForInputIdle(5000)&&!fake.HasExited,"fixture-client-started-with-native-window");
     var refresh=w.GetType().GetMethod("RefreshClientState",BindingFlags.Instance|BindingFlags.NonPublic);refresh.Invoke(w,new object[0]);Require(Field<Button>(w,"launch").Text=="Claude 已打开","native-process-identity-updates-launch-button");
     File.WriteAllText(closeFile,"close");Require(fake.WaitForExit(5000),"fixture-client-manually-closed");refresh.Invoke(w,new object[0]);Require(Field<Button>(w,"launch").Text=="打开 Claude","native-process-exit-refreshes-launch-button");
    }finally{if(!fake.HasExited){fake.Kill();fake.WaitForExit(5000);}}
   }
   w.Close();
  }
  File.WriteAllText(args[1],new JavaScriptSerializer().Serialize(new{Passed=true,NativeWindows=true,ProductionTouched=false,Count=checks.Count,Checks=checks}));return 0;
 }
}
'@
$runner=Join-Path $scratch 'Runner.cs';[IO.File]::WriteAllText($runner,$source,[Text.UTF8Encoding]::new($false))
$null=New-Item -ItemType Directory -Path (Join-Path $scratch 'runtime')
$client=Join-Path $scratch 'Client.cs'
[IO.File]::WriteAllText($client,'using System;using System.IO;using System.Drawing;using System.Windows.Forms;public static class Client{[STAThread]public static void Main(string[] args){var form=new Form{ShowInTaskbar=false,StartPosition=FormStartPosition.Manual,Location=new Point(-30000,-30000),Size=new Size(100,100)};var timer=new Timer{Interval=50};timer.Tick+=delegate{if(File.Exists(args[0])){timer.Stop();form.Close();}};timer.Start();Application.Run(form);}}',[Text.UTF8Encoding]::new($false))
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$dll=Join-Path $scratch 'UI.dll';$exe=Join-Path $scratch 'Runner.exe';$result=Join-Path $PSScriptRoot 'evidence\desktop-update-window-regression.json'
try{
    & $csc /nologo /target:winexe /reference:System.Windows.Forms.dll /reference:System.Drawing.dll ('/out:'+(Join-Path $scratch 'runtime\Claude.exe')) $client
    if($LASTEXITCODE){throw 'Fixture client compile failed.'}
    & $csc /nologo /target:library /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+$dll) (Join-Path $PSScriptRoot 'ClaudeGuardLauncher.cs')
    if($LASTEXITCODE){throw 'Update window compile failed.'}
    & $csc /nologo /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/reference:'+$dll) ('/out:'+$exe) $runner
    if($LASTEXITCODE){throw 'Update window runner compile failed.'}
    & $exe $scratch $result
    if($LASTEXITCODE){throw 'Update window regression failed.'}
    Get-Content -LiteralPath $result -Raw
}finally{
    $full=[IO.Path]::GetFullPath($scratch);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeUpdateWindow-[a-f0-9]{32}$'){throw 'Unsafe update window cleanup.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
