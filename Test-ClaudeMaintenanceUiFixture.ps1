[CmdletBinding()]
param()
$ErrorActionPreference='Stop'
$root=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeMaintenanceUi-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path (Join-Path $root 'runtime'),(Join-Path $root 'private'),(Join-Path $root 'evidence')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'private\launcher-paths.txt') -Destination (Join-Path $root 'private')
$bridge=@'
param($Action,$ActionId,$ResultFile)
if($Action -eq 'Start'){[IO.File]::WriteAllText((Join-Path $PSScriptRoot 'fixture-auto-start.txt'),'Start')}
[IO.File]::WriteAllText($ResultFile,(@{ActionId=$ActionId;Success=$true;SupervisorVerified=$true;Message='fixture startup complete'}|ConvertTo-Json),[Text.UTF8Encoding]::new($false))
'@
[IO.File]::WriteAllText((Join-Path $root 'ClaudeGuard-UiBridge.ps1'),$bridge,[Text.UTF8Encoding]::new($false))
$source=@'
using System;using System.IO;using System.Diagnostics;using System.Drawing;using System.Collections.Generic;using System.Windows.Forms;using System.Web.Script.Serialization;
public static class UiFixtureRunner {
 static string root,path,started;static int pid;static int step;static string id=new string('a',32),stage=new string('b',32);static ClaudeGuardWindow window;static Timer timer;static JavaScriptSerializer json=new JavaScriptSerializer();static List<string> checks=new List<string>();static Exception failure;
 static void Save(string name,object value){string p=Path.Combine(root,name),tmp=p+".tmp";File.WriteAllText(tmp,json.Serialize(value));if(File.Exists(p))File.Replace(tmp,p,null);else File.Move(tmp,p);}
 static Dictionary<string,object> Record(string status,string phase,int worker,bool canonicalOnly=false){
  var m=new Dictionary<string,object>{{"SchemaVersion",1},{"ActionId",id},{"StageId",stage},{"Status",status},{"Phase",phase},{"StartedAt",started},{"CoordinatorPid",pid},{"CoordinatorStarted",started},{"CoordinatorPath",path},{"WorkerPid",worker},{"WorkerStarted",started},{"WorkerPath",path},{"RecoveryRequired",false},{"ResultFile",Path.Combine(root,"private","upgrade-result-"+id+".json")}};
  Save("private/maintenance-operation-"+id+".json",m);if(!canonicalOnly)Save("private/active-version-maintenance.json",m);return m;
 }
 static void Open(){window=new ClaudeGuardWindow(root,File.ReadAllText(Path.Combine(root,"private","launcher-paths.txt")).Trim());window.ShowInTaskbar=false;window.StartPosition=FormStartPosition.Manual;window.Location=new Point(-30000,-30000);window.Show();}
 static string Label(){foreach(Control c in window.Controls)if(c is Label && c.Top==100)return c.Text;throw new Exception("status label missing");}
 static Button Button(string text){foreach(Control c in window.Controls)if(c is Button && c.Text==text)return (Button)c;throw new Exception("button missing");}
 static Color LabelColor(){foreach(Control c in window.Controls)if(c is Label && c.Top==100)return c.ForeColor;throw new Exception("status label missing");}
 static void Require(bool ok,string name){if(!ok)throw new Exception(name+"; label="+Label());checks.Add(name);}
 static void Healthy(){
  string stamp=DateTimeOffset.UtcNow.ToString("o");string run=Guid.NewGuid().ToString();
  Save("private/deployment.json",new {ExpectedIp="203.0.113.1",Desktop=new {Version="fixture-desktop",Path="fixture"},CodeGate=new {Version="fixture-code"},Reliability=new {HostPath=path,ShellPath=path,SupervisorScript="ClaudeGuard-Supervisor-v2.ps1"}});
  Save("private/supervisor-host-identity.json",new {RunId=run,HostPid=pid,HostStarted=started,SupervisorPid=pid,SupervisorStarted=started,ShellPath=path,ScriptPath=Path.Combine(root,"ClaudeGuard-Supervisor-v2.ps1")});
  Save("private/supervisor-health.json",new {SchemaVersion=2,Time=stamp,Status="Healthy",RunId=run,HostPid=pid,HostStarted=started,SupervisorPid=pid,SupervisorStarted=started,LastSafetyCheck=stamp,LastEgressCheck=stamp,LastVerifiedEgress=new {VerifiedProbeCount=2,CloudflareIp="203.0.113.1",IpifyIp="203.0.113.1"}});
  Save("private/upgrade-result-"+id+".json",new {Success=true,ActionId=id,StageId=stage,DesktopVersion="fixture-desktop",CodeVersion="fixture-code"});
 }
 [STAThread]public static int Main(string[] args){
  root=args[0];var self=Process.GetCurrentProcess();path=self.MainModule.FileName;pid=self.Id;started=self.StartTime.ToUniversalTime().ToString("o");
  Application.EnableVisualStyles();Record("Running","Migrating",0);Open();
  timer=new Timer();timer.Interval=2800;
  timer.Tick+=delegate{try{
   if(step==0){Require(Label().Contains("暂时暂停")&&LabelColor()==Color.FromArgb(145,99,20),"native-planned-pause-is-amber");Require(!Button("打开 Claude").Enabled&&!Button("维护版本").Enabled,"native-maintenance-blocks-duplicate-and-start");window.Close();Open();}
   if(step==1){Require(!File.Exists(Path.Combine(root,"fixture-auto-start.txt"))&&Label().Contains("暂时暂停"),"native-close-reopen-resumes-without-auto-start");Record("Running","Migrating",999999);}
   if(step==2){Require(Label().Contains("维护中断")&&Button("维护版本").Enabled&&!Button("打开 Claude").Enabled,"native-dead-worker-offers-recovery");Record("Running","Migrating",0);Save("private/safety-hold.json",new {Reason="fixture actual hold"});}
   if(step==3){Require(Label().Contains("网络防护已暂停")&&LabelColor()==Color.FromArgb(163,59,42),"native-real-hold-overrides-maintenance");File.Delete(Path.Combine(root,"private","safety-hold.json"));Healthy();Record("Completed","Completed",0,true);}
   if(step==4){Require(Label().Contains("版本维护完成")&&Label().Contains("fixture-code")&&LabelColor()==Color.FromArgb(24,106,65),"native-canonical-terminal-and-current-health-show-green");Require(Button("打开 Claude").Enabled,"native-success-enables-protected-start");window.Close();timer.Stop();Application.ExitThread();}
   step++;
  }catch(Exception ex){failure=ex;timer.Stop();if(window!=null)window.Close();Application.ExitThread();}};
  timer.Start();Application.Run();Save("evidence/native-ui-fixture.json",new {Passed=failure==null,NativeWindow=true,ProductionTouched=false,Checks=checks,Error=failure==null?null:failure.ToString()});if(failure!=null){Console.Error.WriteLine(failure);return 1;}Console.WriteLine("Native maintenance window fixture: "+checks.Count+" cases passed");return 0;
 }
}
'@
$runner=Join-Path $root 'Runner.cs';[IO.File]::WriteAllText($runner,$source,[Text.UTF8Encoding]::new($false))
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$dll=Join-Path $root 'runtime\GuardUI.dll';$exe=Join-Path $root 'runtime\UiFixtureRunner.exe'
try {
& $csc /nologo /target:library /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+$dll) (Join-Path $PSScriptRoot 'ClaudeGuardLauncher.cs')
if($LASTEXITCODE){throw 'Native fixture UI compile failed.'}
& $csc /nologo /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/reference:'+$dll) ('/out:'+$exe) $runner
if($LASTEXITCODE){throw 'Native fixture runner compile failed.'}
& $exe $root
if($LASTEXITCODE){throw 'Native maintenance window fixture failed.'}
Copy-Item -LiteralPath (Join-Path $root 'evidence\native-ui-fixture.json') -Destination (Join-Path $PSScriptRoot 'evidence\maintenance-native-ui-fixture.json')
}finally{
$full=[IO.Path]::GetFullPath($root);$temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath())
if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeMaintenanceUi-[0-9a-f]{32}$'){throw 'Unsafe UI fixture cleanup path.'}
Remove-Item -LiteralPath $full -Recurse -Force
}
