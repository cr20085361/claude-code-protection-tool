[CmdletBinding()]
param(
    [string]$LauncherAssembly,
    [string]$ReportFile = (Join-Path $PSScriptRoot 'evidence\status-consistency-window-regression.json')
)
$ErrorActionPreference='Stop'
$scratch=Join-Path ([IO.Path]::GetTempPath()) ('ClaudeStatusConsistency-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path (Join-Path $scratch 'runtime'),(Join-Path $scratch 'private')
$ReportFile=[IO.Path]::GetFullPath($ReportFile)
$null=New-Item -ItemType Directory -Path ([IO.Path]::GetDirectoryName($ReportFile)) -Force
$source=@'
using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Reflection;
using System.Collections.Generic;
using System.Web.Script.Serialization;
using System.Windows.Forms;
public static class StatusConsistencyRunner {
 static readonly List<string> checks=new List<string>();
 static readonly JavaScriptSerializer json=new JavaScriptSerializer();
 static string root,processPath,processStarted;
 static int processId;
 static readonly string operationId=new string('a',32);
 static readonly string recoveryId=new string('d',32),recoveryStage=new string('e',32),updateId=new string('b',32);
 static T Field<T>(object value,string name){return (T)value.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).GetValue(value);}
 static void SetField(object value,string name,object fieldValue){value.GetType().GetField(name,BindingFlags.Instance|BindingFlags.NonPublic).SetValue(value,fieldValue);}
 static object Invoke(object value,string name,params object[] args){return value.GetType().GetMethod(name,BindingFlags.Instance|BindingFlags.NonPublic).Invoke(value,args);}
 static void Require(bool condition,string name){if(!condition)throw new Exception(name);checks.Add(name);}
 static string Label(ClaudeGuardWindow window,string name){return Field<Label>(window,name).Text;}
 static void Save(string name,object value){File.WriteAllText(Path.Combine(root,"private",name),json.Serialize(value));}
 static void Clear(){foreach(string name in Directory.GetFiles(Path.Combine(root,"private"),"*.json"))File.Delete(name);}
 static ClaudeGuardWindow Open(){
  var window=new ClaudeGuardWindow(root,"unused-fixture-shell");
  // No backend scripts exist in this root. PreviewOnly suppresses dispatch; stop
  // observer timers so every transition below is driven by the test itself.
  window.PreviewOnly=true;window.ShowInTaskbar=false;window.StartPosition=FormStartPosition.Manual;window.Location=new Point(-30000,-30000);window.Show();
  foreach(string name in new[]{"healthTimer","versionTimer","riskWatchTimer"})Field<System.Windows.Forms.Timer>(window,name).Stop();
  Application.DoEvents();return window;
 }
 static ClaudeGuardWindow.RiskScoreResult LowRisk(){return new ClaudeGuardWindow.RiskScoreResult{Score=11,Grade="A",Threshold=20,GateEnabled=true,PassedGate=true,DynamicWatchEnabled=true,WatchIntervalSeconds=25,RuntimeEnforcementMode="AutoHealAndWarn",RuntimeStatus="WithinGate",TopRisks=new[]{"fixture risk (+3)"}};}
 static void Score(ClaudeGuardWindow window){Invoke(window,"ApplyRiskScoreView",LowRisk());}
 static void NetworkFix(ClaudeGuardWindow window,bool success){Invoke(window,"RenderNetworkFixResult",new ClaudeGuardWindow.UiResult{Success=success,Message="fixture network repair failed",RiskScore=LowRisk()});}
 static void Refresh(ClaudeGuardWindow window){Invoke(window,"RefreshNetworkHealth");}
 static void Maintenance(string status,string phase,bool live,string reason){Save("active-version-maintenance.json",new ClaudeGuardWindow.MaintenanceResult{SchemaVersion=1,ActionId=operationId,Status=status,Phase=phase,StartedAt=processStarted,CoordinatorPid=live?processId:999999,CoordinatorStarted=processStarted,CoordinatorPath=processPath,Reason=reason,FailureKind=status=="Failed"?"MaintenanceFailed":null,SupervisorSuspended=phase=="Migrating"});}
 static void Healthy(){
  string stamp=DateTimeOffset.UtcNow.ToString("o"),run=Guid.NewGuid().ToString();
  Save("deployment.json",new ClaudeGuardWindow.DeploymentResult{ExpectedIp="203.0.113.1",Desktop=new ClaudeGuardWindow.DesktopResult{Version="fixture-desktop",Path=Path.Combine(root,"runtime","fixture-client.exe")},CodeGate=new ClaudeGuardWindow.CodeResult{Version="fixture-code"},Reliability=new ClaudeGuardWindow.ReliabilityResult{HostPath=processPath,ShellPath=processPath,SupervisorScript="ClaudeGuard-Supervisor-v2.ps1"}});
  Save("supervisor-host-identity.json",new ClaudeGuardWindow.HostIdentity{RunId=run,HostPid=processId,HostStarted=processStarted,SupervisorPid=processId,SupervisorStarted=processStarted,ShellPath=processPath,ScriptPath=Path.GetFullPath(Path.Combine(Path.GetDirectoryName(processPath),"..","ClaudeGuard-Supervisor-v2.ps1"))});
  Save("supervisor-health.json",new ClaudeGuardWindow.HealthResult{SchemaVersion=2,Time=stamp,Status="Healthy",RunId=run,HostPid=processId,HostStarted=processStarted,SupervisorPid=processId,SupervisorStarted=processStarted,LastSafetyCheck=stamp,LastEgressCheck=stamp,LastVerifiedEgress=new ClaudeGuardWindow.EgressResult{VerifiedProbeCount=2,CloudflareIp="203.0.113.1",IpifyIp="203.0.113.1"}});
 }
 static ClaudeGuardWindow.VersionResult VersionInfo(){return new ClaudeGuardWindow.VersionResult{SchemaVersion=1,InstalledDesktopVersion="5.11492.5.0",InstalledCodeVersion="2.1.325",ApprovedCodeVersion="2.1.321",InstalledMatchesApproved=false,Runtime=new ClaudeGuardWindow.RuntimeVersion[0],ToolVersion=ClaudeGuardWindow.BuildVersion,UpdateDecision="Current",Catalog=new ClaudeGuardWindow.CatalogResult{Status="Checked",LastSuccess=new ClaudeGuardWindow.PublishedVersion{CheckedAt=DateTimeOffset.UtcNow.ToString("o"),LatestDesktopVersion="5.11492.5"}}};}
 static T Read<T>(string name){return json.Deserialize<T>(File.ReadAllText(Path.Combine(root,"private",name)));}
 static ClaudeGuardWindow.VersionResult RecoveredInfo(){var info=VersionInfo();info.ApprovedCodeVersion=info.InstalledCodeVersion;info.InstalledMatchesApproved=true;return info;}
 static ClaudeGuardWindow.DesktopUpdateResult HistoricalUpdate(){return new ClaudeGuardWindow.DesktopUpdateResult{SchemaVersion=1,Id=updateId,Status="Failed",TargetVersion="5.11492.5.0",MaintenanceId=operationId,CompletedAt=DateTimeOffset.UtcNow.AddMinutes(-10).ToString("o"),PackageFile=Path.Combine(root,"private","desktop-package-"+updateId+".msix"),FailureKind="DesktopUpdateFailed",Signature="Valid",PackageHash=new string('c',64),Message="historical failed update"};}
 static void RecoveryFixtures(){
  Healthy();var deployment=Read<ClaudeGuardWindow.DeploymentResult>("deployment.json");deployment.Desktop.Version="5.11492.5.0";deployment.CodeGate.Version="2.1.325";Save("deployment.json",deployment);
  var maintenance=new ClaudeGuardWindow.MaintenanceResult{SchemaVersion=1,ActionId=recoveryId,StageId=recoveryStage,Status="Completed",Phase="Completed",CompletedAt=DateTimeOffset.UtcNow.AddMinutes(-1).ToString("o"),ResultFile=Path.Combine(root,"private","upgrade-result-"+recoveryId+".json")};
  Save("active-version-maintenance.json",maintenance);Save("maintenance-operation-"+recoveryId+".json",maintenance);
  Save("upgrade-result-"+recoveryId+".json",new ClaudeGuardWindow.MigrationResult{Success=true,ActionId=recoveryId,StageId=recoveryStage,DesktopVersion="5.11492.5.0",CodeVersion="2.1.325"});
  Save("active-desktop-update.json",HistoricalUpdate());
 }
 static bool ShowsRecovered(ClaudeGuardWindow window){return Label(window,"downloadStatus").Contains("后续防护维护已完成");}
 static void ObserveRecovery(ClaudeGuardWindow window){window.RenderVersionInfo(RecoveredInfo());Refresh(window);Invoke(window,"RefreshDesktopUpdate");}
 static void SaveRecoveryOperation(ClaudeGuardWindow.MaintenanceResult maintenance){Save("active-version-maintenance.json",maintenance);Save("maintenance-operation-"+recoveryId+".json",maintenance);}
 static void AssertHold(ClaudeGuardWindow window,string suffix){
  Require(!Field<Button>(window,"launch").Enabled&&!Field<Button>(window,"login").Enabled&&Field<Button>(window,"maintenance").Enabled,"persistent-hold-blocks-start-and-offers-maintenance-"+suffix);
  Require(Label(window,"riskSummaryLabel").Contains("防护暂停")&&!Label(window,"riskSummaryLabel").Contains("允许启动"),"low-score-never-overrides-persistent-hold-"+suffix);
  Require(Label(window,"networkHealth").Contains("启动已禁用")&&!Label(window,"networkHealth").Contains("专用网络已关闭"),"hold-does-not-claim-unobserved-network-shutdown-"+suffix);
 }
 static void Run(){
  Clear();using(var window=Open()){
   Score(window);
   Require(Label(window,"riskCheckedLabel").Contains("时间待确认"),"legacy-score-has-no-invented-check-time");
   var sample=LowRisk();sample.Time="2026-11-15T09:10:11+00:00";Invoke(window,"ApplyRiskScoreView",sample);
   string timeText="最近评分检查 "+DateTimeOffset.Parse(sample.Time).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");
   Require(Label(window,"riskCheckedLabel")==timeText,"score-uses-sample-local-time");
   var late=LowRisk();late.Time="2026-11-15T09:05:11Z";Invoke(window,"ApplyRiskScoreView",late);Refresh(window);
   Require(Label(window,"riskCheckedLabel")==timeText,"late-old-score-and-health-tick-preserve-latest-time");
   Require(Label(window,"riskSummaryLabel").Contains("评分门槛通过")&&!Label(window,"riskSummaryLabel").Contains("允许启动"),"passed-score-alone-is-not-launch-authorization");
   Require(Label(window,"riskSummaryLabel").Contains("待核验"),"passed-score-retains-pending-protection-state");
  }
  foreach(bool scoreFirst in new[]{true,false}){
   Clear();using(var window=Open()){
    Save("safety-hold.json",new {Reason="Interrupted maintenance recovered; reviewed maintenance is required before protected launch."});
    if(scoreFirst){Score(window);Refresh(window);}else{Refresh(window);Score(window);}
    AssertHold(window,scoreFirst?"score-first":"hold-first");
    string heldMessage=Label(window,"status");var lateRisk=LowRisk();lateRisk.RuntimeStatus="TerminatedOnBreach";lateRisk.TerminatedProtectedProcesses=true;lateRisk.RuntimeAlertMessage="fixture late runtime alert";
    Invoke(window,"ApplyRiskScoreView",lateRisk);
    Require(Label(window,"status")==heldMessage&&Label(window,"riskSummaryLabel").Contains("防护暂停")&&!Field<Button>(window,"launch").Enabled,"late-runtime-alert-cannot-replace-hold-or-reenable-start-"+scoreFirst);
    Score(window);
    File.Delete(Path.Combine(root,"private","safety-hold.json"));Healthy();Refresh(window);
    Require(Field<Button>(window,"launch").Enabled&&Field<Button>(window,"login").Enabled,"verified-healthy-recovery-restores-actions-"+scoreFirst);
    Require(!Label(window,"riskSummaryLabel").Contains("防护暂停")&&!Label(window,"networkHealth").Contains("防护已暂停")&&!Label(window,"status").Contains("异常"),"healthy-recovery-clears-stale-hold-"+scoreFirst);
    Require(Label(window,"riskSummaryLabel").Contains("评分门槛通过")&&!Label(window,"riskSummaryLabel").Contains("允许启动")&&Label(window,"networkHealth").Contains("后台守护健康"),"recovery-keeps-score-and-guardian-evidence-distinct-"+scoreFirst);
   }
  }
  foreach(bool scoreFirst in new[]{true,false}){
   Clear();using(var window=Open()){
    Maintenance("Running","Migrating",true,null);
    if(scoreFirst){Score(window);Refresh(window);}else{Refresh(window);Score(window);}
    Require(!Field<Button>(window,"launch").Enabled&&!Field<Button>(window,"maintenance").Enabled,"live-maintenance-disables-start-and-duplicate-maintenance-"+scoreFirst);
    Require(Label(window,"riskSummaryLabel").Contains("版本维护中")&&!Label(window,"riskSummaryLabel").Contains("允许启动"),"low-score-cannot-authorize-start-during-maintenance-"+scoreFirst);
    Maintenance("Interrupted","Migrating",false,null);Refresh(window);Score(window);
    Require(!Field<Button>(window,"launch").Enabled&&Field<Button>(window,"maintenance").Enabled,"interrupted-maintenance-offers-recovery-"+scoreFirst);
    Require(Label(window,"riskSummaryLabel").Contains("维护中断")&&!Label(window,"riskSummaryLabel").Contains("允许启动"),"low-score-cannot-authorize-start-after-interruption-"+scoreFirst);
   }
  }
  Clear();using(var window=Open()){
   Maintenance("Failed","Failed",false,"版本维护失败：Desktop cache repair timed out.");
   Save("safety-hold.json",new {Reason="Interrupted maintenance recovered; reviewed maintenance is required before protected launch."});
   Refresh(window);
   Require(Label(window,"status").Contains("缓存")&&Label(window,"status").Contains("超时")&&Label(window,"status").Contains("维护版本"),"persistent-hold-explains-cache-repair-timeout-and-recovery");
   Require(!Label(window,"status").Contains("未找到可运行的 64 位 Python"),"cache-timeout-is-not-misreported-as-missing-python");
  }
  foreach(string state in new[]{"hold","maintenance","interrupted"}){
   Clear();using(var window=Open()){
    if(state=="hold")Save("safety-hold.json",new {Reason="fixture persistent hold"});
    else Maintenance(state=="maintenance"?"Running":"Interrupted","Migrating",state=="maintenance",null);
    Refresh(window);string originalStatus=Label(window,"status");
    foreach(bool success in new[]{true,false}){
     NetworkFix(window,success);
     Require(Label(window,"status")==originalStatus&&!Field<Button>(window,"launch").Enabled,"network-repair-result-cannot-override-"+state+"-"+success);
     Require(!Label(window,"riskSummaryLabel").Contains("允许启动")&&!Label(window,"status").Contains("现在可"),"network-repair-does-not-authorize-launch-during-"+state+"-"+success);
    }
   }
  }
  Clear();using(var window=Open()){
   NetworkFix(window,true);
   Require(Label(window,"status").Contains("评分门槛通过")&&Label(window,"status").Contains("后台守护")&&Label(window,"status").Contains("核验")&&!Label(window,"status").Contains("现在可"),"network-repair-success-still-requires-current-guardian-verification");
   NetworkFix(window,false);
   Require(Label(window,"status").Contains("fixture network repair failed")&&Field<Label>(window,"status").ForeColor!=Color.FromArgb(24,106,65)&&!Label(window,"riskSummaryLabel").Contains("允许启动"),"failed-network-repair-is-not-upgraded-to-success-by-passed-score");
   Healthy();Refresh(window);NetworkFix(window,true);
   Require(Label(window,"status").Contains("核验")&&!Label(window,"status").Contains("现在可"),"network-repair-success-retains-verification-at-next-launch");
  }
  Clear();using(var window=Open()){
   window.RenderVersionInfo(VersionInfo());
   var update=new ClaudeGuardWindow.DesktopUpdateResult{SchemaVersion=1,Id=new string('b',32),Status="Failed",TargetVersion="5.11492.5.0",MaintenanceId=operationId,FailureKind="DesktopUpdateFailed",Signature="Valid",PackageHash=new string('c',64),Message="更新未完成：RuntimeReaderUnavailable: 未找到可运行的 64 位 Python 3。"};
   window.RenderDesktopUpdate(update);string text=Label(window,"downloadStatus");
   Require(text.Contains("客户端已安装")&&text.Contains("防护维护未完成")&&text.Contains("维护版本"),"installed-client-with-failed-migration-points-to-maintenance");
   Require(!Field<Button>(window,"installUpdates").Enabled&&!text.Contains("点击“安装并维护”"),"equal-version-failed-migration-does-not-instruct-disabled-reinstall");
   update.TargetVersion="5.11493.1.0";window.RenderDesktopUpdate(update);
   Require(Field<Button>(window,"installUpdates").Enabled&&Label(window,"downloadStatus").Contains("自动恢复"),"newer-verified-package-keeps-recovery-and-install-path");
   update.Signature=null;window.RenderDesktopUpdate(update);
   Require(!Field<Button>(window,"installUpdates").Enabled,"unverified-failed-package-remains-ineligible-for-install");
  }
  foreach(bool interrupted in new[]{false,true}){
   Clear();using(var window=Open()){
    Maintenance(interrupted?"Interrupted":"Running","Migrating",!interrupted,null);Refresh(window);
    Require(!Field<Button>(window,"launch").Enabled&&Field<bool>(window,"maintenanceControlsHeld"),"old-maintenance-holds-actions-before-cross-id-completion-"+interrupted);
    RecoveryFixtures();window.RenderVersionInfo(RecoveredInfo());
    Require(Field<string>(window,"observedMaintenanceId")==operationId&&!Field<Button>(window,"launch").Enabled,"new-running-state-is-deliberately-unobserved-"+interrupted);
    Refresh(window);
    Require(Field<Button>(window,"launch").Enabled&&Field<Button>(window,"check").Enabled&&Field<Button>(window,"maintenance").Enabled,"verified-cross-id-completion-restores-maintenance-held-actions-"+interrupted);
    Require(Label(window,"status").Contains("版本维护完成")&&!Field<bool>(window,"maintenanceControlsHeld")&&Field<string>(window,"observedMaintenanceId")==null,"verified-cross-id-completion-clears-old-observation-once-"+interrupted);
    Field<Label>(window,"status").Text="fixture later user-visible result";Refresh(window);
    Require(Label(window,"status")=="fixture later user-visible result","completed-maintenance-does-not-overwrite-later-results-repeatedly-"+interrupted);
   }
  }
  foreach(string mutation in new[]{"result-failed","result-action","result-stage","result-code","missing-canonical","canonical-schema","canonical-action","health-stale","health-missing","same-id-health-stale","action-busy"}){
   Clear();using(var window=Open()){
    Maintenance("Running","Migrating",true,null);Refresh(window);RecoveryFixtures();window.RenderVersionInfo(RecoveredInfo());
    var r=Read<ClaudeGuardWindow.MigrationResult>("upgrade-result-"+recoveryId+".json");var h=Read<ClaudeGuardWindow.HealthResult>("supervisor-health.json");
    switch(mutation){
     case "result-failed":r.Success=false;Save("upgrade-result-"+recoveryId+".json",r);break;
     case "result-action":r.ActionId=operationId;Save("upgrade-result-"+recoveryId+".json",r);break;
     case "result-stage":r.StageId=operationId;Save("upgrade-result-"+recoveryId+".json",r);break;
     case "result-code":r.CodeVersion="2.1.321";Save("upgrade-result-"+recoveryId+".json",r);break;
     case "missing-canonical":File.Delete(Path.Combine(root,"private","maintenance-operation-"+recoveryId+".json"));break;
     case "canonical-schema":var schemaRecord=Read<ClaudeGuardWindow.MaintenanceResult>("active-version-maintenance.json");schemaRecord.SchemaVersion=2;Save("maintenance-operation-"+recoveryId+".json",schemaRecord);break;
     case "canonical-action":var actionRecord=Read<ClaudeGuardWindow.MaintenanceResult>("active-version-maintenance.json");actionRecord.ActionId=operationId;Save("maintenance-operation-"+recoveryId+".json",actionRecord);break;
     case "same-id-health-stale":var m=Read<ClaudeGuardWindow.MaintenanceResult>("active-version-maintenance.json");m.ActionId=operationId;r.ActionId=operationId;Save("active-version-maintenance.json",m);Save("maintenance-operation-"+operationId+".json",m);Save("upgrade-result-"+recoveryId+".json",r);goto case "health-stale";
     case "health-stale":h.Time=DateTimeOffset.UtcNow.AddMinutes(-5).ToString("o");Save("supervisor-health.json",h);break;
     case "health-missing":File.Delete(Path.Combine(root,"private","supervisor-health.json"));break;
     case "action-busy":SetField(window,"actionBusy",true);break;
    }
    Refresh(window);
    Require(!Field<Button>(window,"launch").Enabled&&!Field<Button>(window,"check").Enabled&&!Label(window,"status").Contains("版本维护完成"),"unverified-or-busy-completion-never-restores-actions-"+mutation);
    Require(Field<bool>(window,"maintenanceControlsHeld"),"maintenance-control-hold-survives-unverified-completion-"+mutation);
    if(mutation=="health-stale" || mutation=="same-id-health-stale" || mutation=="health-missing")Require(Label(window,"status").Contains("维护完成记录已取得")&&Label(window,"status").Contains("待核验")&&!Label(window,"status").Contains("迁移")&&!Label(window,"networkHealth").Contains("暂停"),"recorded-completion-with-pending-health-clears-stale-migration-message-"+mutation);
    if(mutation=="action-busy")Require(Label(window,"status").Contains("等待当前操作")&&!Label(window,"networkHealth").Contains("暂停"),"busy-completion-shows-waiting-result-instead-of-stale-migration");
    SetField(window,"actionBusy",false);RecoveryFixtures();window.RenderVersionInfo(RecoveredInfo());Refresh(window);
    Require(Field<Button>(window,"launch").Enabled&&Label(window,"status").Contains("版本维护完成"),"fresh-valid-result-resumes-after-temporary-completion-block-"+mutation);
   }
  }
  Clear();RecoveryFixtures();using(var window=Open()){
   string historical=File.ReadAllText(Path.Combine(root,"private","active-desktop-update.json"));ObserveRecovery(window);
   Require(ShowsRecovered(window)&&Label(window,"downloadStatus").Contains("上方守护"),"later-verified-maintenance-resolves-historical-failure-with-current-health-reference");
   Require(!Field<Button>(window,"installUpdates").Enabled,"resolved-same-version-history-does-not-enable-reinstallation");
   Require(File.ReadAllText(Path.Combine(root,"private","active-desktop-update.json"))==historical,"recovered-display-keeps-historical-failed-record-unchanged");
   Require(Field<string>(window,"observedMaintenanceId")==null,"recovered-history-does-not-depend-on-one-shot-observed-maintenance-id");
   Save("safety-hold.json",new {Reason="later hold"});Invoke(window,"RefreshDesktopUpdate");
   Require(!ShowsRecovered(window),"new-persisted-hold-withdraws-recovery-before-observer-tick");Refresh(window);
   Require(!ShowsRecovered(window)&&!Field<Button>(window,"launch").Enabled,"observed-hold-preserves-start-block-and-withdrawn-history");
   File.Delete(Path.Combine(root,"private","safety-hold.json"));Healthy();var d=Read<ClaudeGuardWindow.DeploymentResult>("deployment.json");d.Desktop.Version="5.11492.5.0";d.CodeGate.Version="2.1.325";Save("deployment.json",d);Refresh(window);
   Require(ShowsRecovered(window),"verified-healthy-recovery-repaints-history-immediately");
   Invoke(window,"ShowGuardWarning","fixture guardian pending");
   Require(!ShowsRecovered(window),"pending-protection-state-immediately-withdraws-recovered-history");Refresh(window);
   Require(ShowsRecovered(window),"current-health-revalidation-restores-recovery-display");
   var version=RecoveredInfo();version.InstalledCodeVersion="2.1.326";window.RenderVersionInfo(version);
   Require(!ShowsRecovered(window),"new-installed-code-observation-withdraws-old-recovery");window.RenderVersionInfo(RecoveredInfo());
   version=RecoveredInfo();version.ApprovedCodeVersion="2.1.321";window.RenderVersionInfo(version);
   Require(!ShowsRecovered(window),"new-approved-code-observation-withdraws-old-recovery");window.RenderVersionInfo(RecoveredInfo());
   version=RecoveredInfo();version.InstalledMatchesApproved=false;window.RenderVersionInfo(version);
   Require(!ShowsRecovered(window),"same-version-path-or-hash-mismatch-withdraws-old-recovery");window.RenderVersionInfo(RecoveredInfo());
   version=RecoveredInfo();version.InstalledDesktopVersion="5.11493.1.0";window.RenderVersionInfo(version);
   Require(!ShowsRecovered(window),"new-installed-desktop-observation-withdraws-old-recovery");
  }
  using(var window=Open()){ObserveRecovery(window);Require(ShowsRecovered(window),"reopened-entry-rebuilds-recovery-from-durable-verified-records");}
  foreach(string mutation in new[]{"missing-canonical","failed-canonical","older-completion","missing-completion-time","same-operation","missing-stage","missing-result","bad-result-name","result-failed","result-action","result-stage","result-desktop","result-code","deployment-desktop","deployment-code","old-update-time-missing","health-stale","health-hold","health-identity"}){
   Clear();RecoveryFixtures();using(var window=Open()){
    ObserveRecovery(window);Require(ShowsRecovered(window),"recovery-precondition-before-"+mutation);
    var m=Read<ClaudeGuardWindow.MaintenanceResult>("active-version-maintenance.json");var r=Read<ClaudeGuardWindow.MigrationResult>("upgrade-result-"+recoveryId+".json");var d=Read<ClaudeGuardWindow.DeploymentResult>("deployment.json");var h=Read<ClaudeGuardWindow.HealthResult>("supervisor-health.json");var update=Read<ClaudeGuardWindow.DesktopUpdateResult>("active-desktop-update.json");
    switch(mutation){
     case "missing-canonical":File.Delete(Path.Combine(root,"private","maintenance-operation-"+recoveryId+".json"));break;
     case "failed-canonical":m.Status="Failed";Save("maintenance-operation-"+recoveryId+".json",m);break;
     case "older-completion":m.CompletedAt=DateTimeOffset.UtcNow.AddMinutes(-20).ToString("o");SaveRecoveryOperation(m);break;
     case "missing-completion-time":m.CompletedAt=null;SaveRecoveryOperation(m);break;
     case "same-operation":update.MaintenanceId=recoveryId;Save("active-desktop-update.json",update);break;
     case "missing-stage":m.StageId=null;r.StageId=null;SaveRecoveryOperation(m);Save("upgrade-result-"+recoveryId+".json",r);break;
     case "missing-result":File.Delete(m.ResultFile);break;
     case "bad-result-name":m.ResultFile=Path.Combine(root,"private","unrelated-result.json");Save("unrelated-result.json",r);SaveRecoveryOperation(m);break;
     case "result-failed":r.Success=false;Save("upgrade-result-"+recoveryId+".json",r);break;
     case "result-action":r.ActionId=operationId;Save("upgrade-result-"+recoveryId+".json",r);break;
     case "result-stage":r.StageId=operationId;Save("upgrade-result-"+recoveryId+".json",r);break;
     case "result-desktop":r.DesktopVersion="5.11490.1.0";Save("upgrade-result-"+recoveryId+".json",r);break;
     case "result-code":r.CodeVersion="2.1.321";Save("upgrade-result-"+recoveryId+".json",r);break;
     case "deployment-desktop":d.Desktop.Version="5.11490.1.0";Save("deployment.json",d);break;
     case "deployment-code":d.CodeGate.Version="2.1.321";Save("deployment.json",d);break;
     case "old-update-time-missing":update.CompletedAt=null;Save("active-desktop-update.json",update);break;
     case "health-stale":h.Time=DateTimeOffset.UtcNow.AddMinutes(-5).ToString("o");Save("supervisor-health.json",h);break;
     case "health-hold":h.Status="SafetyHold";Save("supervisor-health.json",h);break;
     case "health-identity":h.HostStarted=DateTimeOffset.UtcNow.AddYears(-1).ToString("o");Save("supervisor-health.json",h);break;
    }
    Invoke(window,"RefreshDesktopUpdate");Require(!ShowsRecovered(window),"incomplete-or-mismatched-evidence-never-resolves-history-"+mutation);
   }
  }
  Clear();
 }
 [STAThread]public static int Main(string[] args){
  root=args[0];using(var self=Process.GetCurrentProcess()){processPath=self.MainModule.FileName;processId=self.Id;processStarted=self.StartTime.ToUniversalTime().ToString("o");}
  Application.EnableVisualStyles();Exception failure=null;
  try{Run();}catch(Exception error){failure=error;Console.Error.WriteLine(error);}
  var assembly=typeof(ClaudeGuardWindow).Assembly;
  File.WriteAllText(args[1],json.Serialize(new{Passed=failure==null,NativeWindow=true,PreviewOnly=true,ProductionTouched=false,BuildVersion=ClaudeGuardWindow.BuildVersion,AssemblyVersion=assembly.GetName().Version.ToString(),AssemblySha256=args[2],Count=checks.Count,Checks=checks,Error=failure==null?null:failure.ToString()}));
  Console.WriteLine("Native status consistency window: "+checks.Count+" checks passed; "+(failure==null?"PASSED":"FAILED"));return failure==null?0:1;
 }
}
'@
$runner=Join-Path $scratch 'Runner.cs'
[IO.File]::WriteAllText($runner,$source,[Text.UTF8Encoding]::new($false))
$csc=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
$exe=Join-Path $scratch 'runtime\StatusConsistencyRunner.exe'
try {
    if($LauncherAssembly){
        $actual=(Resolve-Path -LiteralPath $LauncherAssembly).ProviderPath
        $assembly=Join-Path $scratch ('runtime\'+[IO.Path]::GetFileName($actual))
        Copy-Item -LiteralPath $actual -Destination $assembly
    }else{
        $assembly=Join-Path $scratch 'runtime\StatusConsistencyUI.dll'
        & $csc /nologo /target:library /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/out:'+$assembly) (Join-Path $PSScriptRoot 'ClaudeGuardLauncher.cs')
        if($LASTEXITCODE){throw 'Status consistency UI compilation failed.'}
    }
    $assemblyHash=(Get-FileHash -LiteralPath $assembly -Algorithm SHA256).Hash
    & $csc /nologo /reference:System.Windows.Forms.dll /reference:System.Drawing.dll /reference:System.Web.Extensions.dll ('/reference:'+$assembly) ('/out:'+$exe) $runner
    if($LASTEXITCODE){throw 'Status consistency runner compilation failed.'}
    & $exe $scratch $ReportFile $assemblyHash
    if($LASTEXITCODE){throw 'Native status consistency window regression failed; see report.'}
    Get-Content -LiteralPath $ReportFile -Raw
}finally{
    $full=[IO.Path]::GetFullPath($scratch)
    $temp=[IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')+'\'
    if(-not $full.StartsWith($temp,[StringComparison]::OrdinalIgnoreCase) -or [IO.Path]::GetFileName($full) -notmatch '^ClaudeStatusConsistency-[0-9a-f]{32}$'){throw 'Unsafe status consistency fixture cleanup path.'}
    Remove-Item -LiteralPath $full -Recurse -Force
}
