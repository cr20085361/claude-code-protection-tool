using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Threading;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

public sealed class ClaudeGuardWindow : Form {
    static string ReadSharedText(string path) {
        var retry=Stopwatch.StartNew();
        while(true) {
            try {
                using(var stream=new FileStream(path,FileMode.Open,FileAccess.Read,FileShare.ReadWrite|FileShare.Delete))
                using(var reader=new StreamReader(stream)) return reader.ReadToEnd();
            } catch(IOException ex) {
                int code=ex.HResult&65535;
                if(retry.ElapsedMilliseconds>=500 || (code!=2 && code!=3 && code!=32 && code!=33))throw;
                Thread.Sleep(10);
            }
        }
    }
    readonly Label status = new Label();
    readonly Button launch = new Button();
    readonly Button check = new Button();
    readonly Button report = new Button();
    readonly Button login = new Button();
    readonly Button maintenance = new Button();
    readonly Label networkHealth = new Label();
    readonly Label installedVersions = new Label();
    readonly Label runtimeVersions = new Label();
    readonly Label updateStatus = new Label();
    readonly Label entryVersion = new Label();
    readonly Button checkUpdates = new Button();
    readonly Button downloadUpdates = new Button();
    readonly Button installUpdates = new Button();
    readonly Label downloadStatus = new Label();
    bool updateDispatchBusy;
    bool officialDownloadReady;
    string installedDesktopVersion;
    string desktopCommandError;
    readonly System.Windows.Forms.Timer versionTimer = new System.Windows.Forms.Timer();
    bool versionBusy;
    DateTimeOffset nextCatalogCheck=DateTimeOffset.MinValue;
    readonly System.Windows.Forms.Timer healthTimer = new System.Windows.Forms.Timer();
    readonly string root;
    readonly string shell;
    readonly JavaScriptSerializer json = new JavaScriptSerializer();
    string activeActionId;
    string lastSuccessMessage;
    bool guardWarning;
    bool actionBusy;
    string observedMaintenanceId;
    string activeActionKind;
    DateTimeOffset maintenanceRequestStarted;
    public bool PreviewOnly;
    public bool MaintenanceViewOnly;
    public ClaudeGuardWindow(string projectRoot, string pwsh) {
        root=projectRoot; shell=pwsh;
        Text="Claude Pro · 安全入口"; ClientSize=new Size(660,498);
        AutoScroll=true;AutoScrollMinSize=new Size(640,490);
        FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false; StartPosition=FormStartPosition.CenterScreen;
        Font=new Font("Microsoft YaHei UI",10); BackColor=Color.FromArgb(247,249,252);
        var title=new Label { Text="Claude Pro", Font=new Font("Microsoft YaHei UI",19,FontStyle.Bold), Location=new Point(24,20), AutoSize=true };
        var hint=new Label { Text="双击入口后，自动检查连接并打开 Claude。",Location=new Point(26,64),AutoSize=true,ForeColor=Color.FromArgb(70,79,91) };
        status.SetBounds(26,100,608,80); status.Text="正在检查专用网络和防护配置……";
        launch.Text="打开 Claude"; launch.SetBounds(26,188,120,38);
        check.Text="重新检查"; check.SetBounds(156,188,110,38);
        login.Text="登录链接";login.SetBounds(276,188,110,38);
        report.Text="查看说明"; report.SetBounds(396,188,112,38);
        maintenance.Text="维护版本";maintenance.SetBounds(518,188,112,38);
        launch.Click+=async delegate { await RunAction("Start"); };
        check.Click+=async delegate { await RunAction("Check"); };
        maintenance.Click+=async delegate { await RunAction("Update"); };
        report.Click+=delegate { Process.Start(new ProcessStartInfo(Path.Combine(root,"一键使用说明.txt")){UseShellExecute=true}); };
        login.Click+=async delegate {
            using(var prompt=new Form {Text="专用登录浏览器",ClientSize=new Size(488,150),StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false}){
                var label=new Label{Text="粘贴 Claude 提供的官方登录链接或邮件登录链接：",AutoSize=true,Location=new Point(16,18)};
                var input=new TextBox{Location=new Point(16,50),Width=452};
                var open=new Button{Text="打开专用浏览器",Location=new Point(310,95),Width=158,DialogResult=DialogResult.OK};
                prompt.Controls.AddRange(new Control[]{label,input,open});prompt.AcceptButton=open;
                if(prompt.ShowDialog(this)==DialogResult.OK){
                    File.WriteAllText(Path.Combine(root,"private","login-link.json"),json.Serialize(new {Url=input.Text.Trim()}));
                    await RunAction("Login");
                }
            }
        };
        var footer=new Label {Text="专用网络由后台守护恢复；软件升级通过“维护版本”核验。",Location=new Point(26,242),AutoSize=true,ForeColor=Color.FromArgb(70,79,91)};
        networkHealth.SetBounds(26,266,608,24); networkHealth.Font=new Font("Microsoft YaHei UI",9);networkHealth.Text="后台守护状态待确认。";
        Controls.AddRange(new Control[]{title,hint,status,launch,check,login,report,maintenance,footer,networkHealth});
        var divider=new Label{BackColor=Color.FromArgb(219,225,231),Location=new Point(26,300),Size=new Size(608,1)};
        installedVersions.SetBounds(26,312,608,23);installedVersions.Text="正在读取 Desktop 和配套 Code 版本……";installedVersions.AutoEllipsis=true;
        runtimeVersions.SetBounds(26,338,608,23);runtimeVersions.Text="本地 Code：运行版本待确认。";runtimeVersions.AutoEllipsis=true;
        updateStatus.SetBounds(26,370,480,46);updateStatus.Font=new Font("Microsoft YaHei UI",9);updateStatus.Text="官方版本尚未检查。";
        checkUpdates.SetBounds(518,370,112,38);checkUpdates.Text="检查新版";
        checkUpdates.Click+=async delegate {await RefreshVersionInfo(true,true);};
        downloadStatus.SetBounds(26,418,352,46);downloadStatus.Font=new Font("Microsoft YaHei UI",9);downloadStatus.Text="尚未下载官方安装包。";
        downloadUpdates.SetBounds(390,420,116,38);downloadUpdates.Text="下载官方包";downloadUpdates.Enabled=false;
        installUpdates.SetBounds(518,420,112,38);installUpdates.Text="安装并维护";installUpdates.Enabled=false;
        downloadUpdates.Click+=async delegate {await RunDesktopUpdate("Download");};
        installUpdates.Click+=async delegate {await RunDesktopUpdate("Install");};
        entryVersion.SetBounds(26,468,608,22);entryVersion.Font=new Font("Microsoft YaHei UI",8);entryVersion.ForeColor=Color.FromArgb(90,99,110);
        entryVersion.Text="入口运行时每 6 小时检查新版，由你决定何时更新。";
        Controls.AddRange(new Control[]{divider,installedVersions,runtimeVersions,updateStatus,checkUpdates,downloadStatus,downloadUpdates,installUpdates,entryVersion});
        healthTimer.Interval=2000;healthTimer.Tick+=delegate { RefreshNetworkHealth();RefreshDesktopUpdate(); };healthTimer.Start();
        versionTimer.Interval=10000;versionTimer.Tick+=async delegate {if(!PreviewOnly)await RefreshVersionInfo(false,DateTimeOffset.UtcNow>=nextCatalogCheck);};versionTimer.Start();
        FormClosed+=delegate {healthTimer.Stop();healthTimer.Dispose();versionTimer.Stop();versionTimer.Dispose();};
        var iconPath=Path.Combine(root,"runtime","claude-guard.ico"); if(File.Exists(iconPath)) Icon=new Icon(iconPath);
        Shown+=async delegate { if(!PreviewOnly) {var versions=RefreshVersionInfo(false,true);if(ResumeMaintenanceOnOpen() || ResumeDesktopUpdateOnOpen())RefreshNetworkHealth();else if(MaintenanceViewOnly){status.Text="请完全退出 Claude 和本地 Code 后，点击“维护版本”。";RefreshNetworkHealth();}else await RunAction("Start");await versions;} };
    }
    public void RenderVersionInfo(VersionResult info) {
        if(info==null || info.SchemaVersion!=1)throw new InvalidDataException("版本观察记录无效。");
        installedDesktopVersion=info.InstalledDesktopVersion;
        DateTimeOffset catalogTime;
        officialDownloadReady=info.Catalog!=null && info.Catalog.Status=="Checked" && info.Catalog.LastSuccess!=null && DateTimeOffset.TryParse(info.Catalog.LastSuccess.CheckedAt,out catalogTime) && catalogTime<=DateTimeOffset.UtcNow && DateTimeOffset.UtcNow-catalogTime<=TimeSpan.FromHours(6);
        installedVersions.Text="Desktop "+(info.InstalledDesktopVersion??"未确认")+" · 配套 Code "+(info.InstalledCodeVersion??"未确认")+" · 已核准 Code "+(info.ApprovedCodeVersion??"未确认");
        installedVersions.ForeColor=info.InstalledMatchesApproved?Color.FromArgb(70,79,91):Color.FromArgb(145,99,20);
        if(info.Runtime==null || info.Runtime.Length==0){runtimeVersions.Text="本地 Code：未运行。";runtimeVersions.ForeColor=Color.FromArgb(70,79,91);}
        else {
            var values=new System.Collections.Generic.List<string>();bool approved=true;
            foreach(var p in info.Runtime) {
                string label=p.Identity=="Unreadable"?"运行版本未确认":(p.Version??"未知版本")+"（"+(p.Identity=="Approved"?"已核准进程":p.Identity=="UnknownOrigin"?"来源待确认":"未核准进程")+"）";
                if(!values.Contains(label))values.Add(label);if(p.Identity!="Approved")approved=false;
            }
            runtimeVersions.Text="本地 Code 运行中："+String.Join("、",values.ToArray());runtimeVersions.ForeColor=approved?Color.FromArgb(70,79,91):Color.FromArgb(145,99,20);
        }
        updateStatus.ForeColor=Color.FromArgb(70,79,91);var catalog=info.Catalog;
        if(catalog==null || catalog.Status=="NotChecked")updateStatus.Text="官方版本尚未检查；点击“检查新版”。";
        else if(catalog.Status=="Checking")updateStatus.Text="另一项新版检查正在进行，请稍候。";
        else if(catalog.Status=="Deferred")updateStatus.Text="维护或安全暂停期间暂不检查新版。";
        else if(catalog.Status=="QueryFailed") {
            updateStatus.Text="暂未取得官方更新信息；"+(catalog.LastSuccess==null?"稍后可重新检查。":"上次查到 Desktop "+catalog.LastSuccess.LatestDesktopVersion+"。");
            updateStatus.ForeColor=Color.FromArgb(145,99,20);
        } else if(catalog.LastSuccess!=null) {
            DateTimeOffset checkedAt;string time=DateTimeOffset.TryParse(catalog.LastSuccess.CheckedAt,out checkedAt)?checkedAt.ToLocalTime().ToString("MM-dd HH:mm"):"时间未确认";
            bool fresh=DateTimeOffset.TryParse(catalog.LastSuccess.CheckedAt,out checkedAt) && DateTimeOffset.UtcNow>=checkedAt && DateTimeOffset.UtcNow-checkedAt<=TimeSpan.FromHours(6);
            string result=info.UpdateDecision=="Available"?"发现新版 Desktop "+catalog.LastSuccess.LatestDesktopVersion+"，可安排更新。":info.UpdateDecision=="Current"?"未发现当前渠道的新版本。":info.UpdateDecision=="Ahead"?"本机版本高于官方当前发布，可能存在渠道差异。":"已取得发布版本，当前安装版本尚未确认。";
            updateStatus.Text=(fresh?"官方检查 "+time+"：":"上次检查 "+time+"：")+result;
            if(info.UpdateDecision=="Available" || info.UpdateDecision=="Ahead")updateStatus.ForeColor=Color.FromArgb(145,99,20);
        } else updateStatus.Text="官方更新记录尚未确认，请重新检查。";
        entryVersion.Text="安全入口 "+(info.ToolVersion??"版本未确认")+" · 入口运行时每 6 小时检查新版；由你决定何时更新。";
        RefreshDesktopUpdate();
    }
    DesktopUpdateResult ReadDesktopUpdate() {
        var path=Path.Combine(root,"private","active-desktop-update.json");if(!File.Exists(path))return null;
        var d=new JavaScriptSerializer().Deserialize<DesktopUpdateResult>(ReadSharedText(path));
        Guid id;if(d==null || d.SchemaVersion!=1 || !Guid.TryParseExact(d.Id,"N",out id))throw new InvalidDataException("更新记录身份无效。");
        var canonical=Path.Combine(root,"private","desktop-update-"+d.Id+".json");
        if(File.Exists(canonical)){var saved=new JavaScriptSerializer().Deserialize<DesktopUpdateResult>(ReadSharedText(canonical));if(saved==null || saved.SchemaVersion!=1 || saved.Id!=d.Id)throw new InvalidDataException("更新关联无效。");d=saved;}
        if(d.PackageFile!=Path.Combine(root,"private","desktop-package-"+d.Id+".msix"))throw new InvalidDataException("更新文件路径无效。");
        if(IsDesktopUpdateActive(d) && d.Status!="AwaitingReadiness" && !ProcessMatches(d.WorkerPid,d.WorkerStarted,d.WorkerPath)){d.Status="Interrupted";d.Message=String.IsNullOrEmpty(d.MaintenanceId)?"下载已中断，可重新下载；未改变已安装版本。":"更新中断，需要恢复。请点击“维护版本”。";}
        if(d.Status=="Downloading" && File.Exists(d.PackageFile+".part"))d.PackageBytes=new FileInfo(d.PackageFile+".part").Length;
        return d;
    }
    static bool IsDesktopUpdateActive(DesktopUpdateResult d){return d!=null && (d.Status=="Downloading" || d.Status=="Verifying" || d.Status=="PreparingInstall" || d.Status=="AwaitingAuthorization" || d.Status=="Installing" || d.Status=="Maintaining" || d.Status=="AwaitingReadiness");}
    bool ResumeDesktopUpdateOnOpen(){try{var d=ReadDesktopUpdate();RefreshDesktopUpdate();return d!=null && (d.Status=="PreparingInstall" || (!String.IsNullOrEmpty(d.MaintenanceId) && (IsDesktopUpdateActive(d) || d.Status=="Interrupted")));}catch{status.Text="更新记录暂时无法确认，请查看说明并恢复维护。";return true;}}
    public void RenderDesktopUpdate(DesktopUpdateResult d) {
        bool active=IsDesktopUpdateActive(d);bool repair=d!=null && d.Status=="Interrupted" && !String.IsNullOrEmpty(d.MaintenanceId);
        downloadUpdates.Enabled=!updateDispatchBusy && officialDownloadReady && !active && !repair && maintenance.Enabled && check.Enabled;
        Version target,current;bool newer=d!=null && Version.TryParse(d.TargetVersion,out target) && Version.TryParse(installedDesktopVersion,out current) && new Version(target.Major,target.Minor,target.Build,Math.Max(0,target.Revision))>new Version(current.Major,current.Minor,current.Build,Math.Max(0,current.Revision));
        installUpdates.Enabled=!updateDispatchBusy && d!=null && d.Status=="Ready" && newer && maintenance.Enabled && check.Enabled;
        downloadStatus.ForeColor=Color.FromArgb(70,79,91);
        if(d==null){if(!updateDispatchBusy)downloadStatus.Text=desktopCommandError??"尚未下载官方安装包。";return;}
        if(d.Status=="Downloading")downloadStatus.Text="正在下载 Desktop "+d.TargetVersion+"：已取得 "+(d.PackageBytes/1048576.0).ToString("F1")+" MB。";
        else if(d.Status=="Ready")downloadStatus.Text=d.FailureKind!=null?d.Message:(newer?"官方包已核验：Desktop "+d.TargetVersion+"。\n完全退出 Claude 和本地 Code 后安装。":"官方包已核验，当前版本无需升级。");
        else downloadStatus.Text=d.Message??"正在观察更新操作。";
        if(active || repair || d.Status=="Failed" || d.FailureKind!=null)downloadStatus.ForeColor=Color.FromArgb(145,99,20);
        if(d.Status=="Completed")downloadStatus.ForeColor=Color.FromArgb(24,106,65);
        if(!active && desktopCommandError!=null){downloadStatus.Text=desktopCommandError;downloadStatus.ForeColor=Color.FromArgb(145,99,20);}
    }
    void RefreshDesktopUpdate(){try{RenderDesktopUpdate(ReadDesktopUpdate());}catch{downloadUpdates.Enabled=installUpdates.Enabled=false;downloadStatus.Text="更新记录暂时无法确认，请查看本地说明。";downloadStatus.ForeColor=Color.FromArgb(163,59,42);}}
    async Task RunDesktopUpdate(string action) {
        if(updateDispatchBusy || IsDisposed)return;
        var current=ReadDesktopUpdate();string id=action=="Install"?(current==null?null:current.Id):Guid.NewGuid().ToString("N");if(id==null)return;
        string commandId=Guid.NewGuid().ToString("N");desktopCommandError=null;updateDispatchBusy=true;downloadUpdates.Enabled=installUpdates.Enabled=false;downloadStatus.Text=action=="Download"?"正在确认官方发布并准备下载……":"正在核对退出状态和安装条件……";
        try{
            string failure=await Task.Run(delegate {
                var psi=new ProcessStartInfo(shell){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root,Arguments="-NoProfile -ExecutionPolicy Bypass -File \""+Path.Combine(root,"Invoke-ClaudeDesktopUpdate.ps1")+"\" -Action "+action+" -OperationId "+id+" -CommandId "+commandId};
                using(var p=Process.Start(psi)){
                    var watch=Stopwatch.StartNew();
                    do{
                        var receipt=Path.Combine(root,"private","desktop-command-"+commandId+".json");
                        if(File.Exists(receipt)){var result=new JavaScriptSerializer().Deserialize<DesktopCommandResult>(ReadSharedText(receipt));if(result.CommandId==commandId)return result.Message;}
                        try{var op=ReadDesktopUpdate();if(op!=null && op.Id==id && (action=="Download" || op.WorkerPid==p.Id || IsDesktopUpdateActive(op)))return null;}catch{}
                        if(p.HasExited)return "更新操作未能开始，请重新检查后重试。";
                        Thread.Sleep(200);
                    }while(watch.Elapsed.TotalSeconds<45);
                    return "仍在准备更新，稍后将接续显示结果。";
                }
            });
            if(IsDisposed)return;desktopCommandError=failure;RefreshDesktopUpdate();
        }catch{desktopCommandError="更新操作未能启动，请查看说明。";}
        finally{updateDispatchBusy=false;if(!IsDisposed){RefreshDesktopUpdate();RefreshNetworkHealth();}}
    }
    async Task RefreshVersionInfo(bool force,bool query) {
        if(versionBusy || IsDisposed || (actionBusy && activeActionKind=="Update"))return;
        versionBusy=true;checkUpdates.Enabled=false;
        if(query)updateStatus.Text="正在检查官方新版，请稍候……";
        try {
            var info=await Task.Run(delegate {
                var psi=new ProcessStartInfo(shell){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root,RedirectStandardOutput=true,RedirectStandardError=true,
                    Arguments="-NoProfile -ExecutionPolicy Bypass -File \""+Path.Combine(root,"Get-ClaudeVersionInfo.ps1")+"\""+(query?" -CheckUpdates":"")+(force?" -Force":"")};
                using(var p=Process.Start(psi)) {
                    var output=p.StandardOutput.ReadToEndAsync();var errors=p.StandardError.ReadToEndAsync();
                    if(!p.WaitForExit(40000)){if(!p.HasExited)p.Kill();throw new InvalidOperationException("版本观察超时。");}
                    if(p.ExitCode!=0)throw new InvalidOperationException("版本观察尚未完成。");
                    return new JavaScriptSerializer().Deserialize<VersionResult>(output.GetAwaiter().GetResult());
                }
            });
            if(IsDisposed)return;
            RenderVersionInfo(info);
            if(query)nextCatalogCheck=DateTimeOffset.UtcNow.AddMinutes(info.Catalog!=null && (info.Catalog.Status=="Deferred" || info.Catalog.Status=="Checking")?1:info.Catalog!=null && info.Catalog.Status=="QueryFailed"?15:360);
        } catch {if(!IsDisposed){updateStatus.Text="版本观察暂未完成，稍后可点击“检查新版”。";updateStatus.ForeColor=Color.FromArgb(145,99,20);if(query)nextCatalogCheck=DateTimeOffset.UtcNow.AddMinutes(15);}}
        finally{versionBusy=false;if(!IsDisposed)checkUpdates.Enabled=true;}
    }
    MaintenanceResult ReadMaintenance() {
        var path=Path.Combine(root,"private","active-version-maintenance.json");
        if(!File.Exists(path))return null;
        var m=json.Deserialize<MaintenanceResult>(ReadSharedText(path));
        Guid id;if(m==null || m.SchemaVersion!=1 || m.ActionId==null || m.ActionId.Length!=32 || !Guid.TryParseExact(m.ActionId,"N",out id))throw new InvalidDataException("维护记录身份无效。");
        var canonical=Path.Combine(root,"private","maintenance-operation-"+m.ActionId+".json");
        if(File.Exists(canonical)){
            var record=json.Deserialize<MaintenanceResult>(ReadSharedText(canonical));
            if(record==null || record.SchemaVersion!=1 || record.ActionId!=m.ActionId)throw new InvalidDataException("维护记录关联无效。");
            m=record;
        }
        return m;
    }
    bool ResumeMaintenanceOnOpen() {
        try {var m=ReadMaintenance();if(m==null)return false;
            if(m.Status=="Running" || m.Status=="Interrupted" || m.RecoveryRequired){observedMaintenanceId=m.ActionId;return true;}
            return false;
        }catch{observedMaintenanceId="unreadable";return true;}
    }
    public static MaintenanceView AssessMaintenance(MaintenanceResult m,DateTimeOffset now,bool ownerAlive,bool held) {
        var v=new MaintenanceView();if(m==null)return v;
        if(held){v.Held=true;v.Message="网络防护已暂停，请退出 Claude 后进行版本维护。";return v;}
        if(m.Status=="Completed"){v.Completed=true;return v;}
        if(m.Status=="Failed" && !m.RecoveryRequired){v.Failed=true;v.Message=m.Reason??"版本维护失败，请查看维护记录。";return v;}
        if(m.RecoveryRequired || m.Status=="Interrupted" || !ownerAlive){v.BlockStart=true;v.Recover=true;v.Message="维护中断，需要恢复。请点击“维护版本”，通过同账号管理员授权恢复后再重试。";return v;}
        v.BlockStart=true;v.Observe=true;
        DateTimeOffset started;
        if(DateTimeOffset.TryParse(m.WorkerPid>0?m.WorkerStarted:m.StartedAt,out started) && (now-started).TotalSeconds>(m.WorkerPid>0?600:660)){
            v.Message="维护仍在进行，暂未取得最终结果。\n请等待，关闭重开入口可接续观察。";return v;
        }
        switch(m.Phase){
            case "Preparing":v.Message="正在准备并核验官方版本。\n下载或校验完成后将请求 Windows 管理员授权。";break;
            case "AwaitingAuthorization":v.Message="等待 Windows 管理员授权。\n请核对授权窗口；尚未收到取消或完成结果。";break;
            case "Migrating":v.Message="版本维护中，后台守护暂时暂停。\n正在迁移规则和本地 Code 防护，请等待。";break;
            case "Restarting":case "Verifying":v.Message="正在恢复并核验守护。\n当次守护和固定出口通过后，维护才算完成。";break;
            case "Recovering":v.Message="正在恢复中断的维护。\n恢复完成后需要重新核验版本防护。";break;
            default:v.Message="版本维护正在进行，请等待最终结果。";break;
        }
        return v;
    }
    bool RenderMaintenance(bool held,out MaintenanceResult m) {
        m=ReadMaintenance();if(m==null)return false;
        DateTimeOffset began;
        bool relevant=m.ActionId==observedMaintenanceId || (activeActionKind=="Update" && m.Status=="Running" && (!DateTimeOffset.TryParse(m.StartedAt,out began) || began>=maintenanceRequestStarted));
        if(!relevant && (m.Status=="Running" || m.Status=="Interrupted" || m.RecoveryRequired))relevant=true;
        if(!relevant)return false;
        observedMaintenanceId=m.ActionId;
        bool live=m.WorkerPid>0?ProcessMatches(m.WorkerPid,m.WorkerStarted,m.WorkerPath):ProcessMatches(m.CoordinatorPid,m.CoordinatorStarted,m.CoordinatorPath);
        var view=AssessMaintenance(m,DateTimeOffset.UtcNow,live,held);
        if(view.Held){
            status.Text=view.Message;status.ForeColor=Color.FromArgb(163,59,42);
            networkHealth.Text=view.Message;networkHealth.ForeColor=status.ForeColor;
            if(!actionBusy){launch.Enabled=check.Enabled=login.Enabled=false;maintenance.Enabled=!live;}
            guardWarning=false;return true;
        }
        if(view.BlockStart){
            if(!actionBusy){launch.Enabled=check.Enabled=login.Enabled=false;maintenance.Enabled=view.Recover;}
            status.Text=view.Message;status.ForeColor=view.Recover?Color.FromArgb(163,59,42):Color.FromArgb(145,99,20);
            networkHealth.Text=view.Recover?"维护中断，等待同账号管理员恢复。":(m.Phase=="Migrating" || m.SupervisorSuspended?"版本维护中，后台守护暂时暂停。":"正在等待版本维护完成。");
            networkHealth.ForeColor=status.ForeColor;guardWarning=false;return true;
        }
        if(!actionBusy)launch.Enabled=check.Enabled=login.Enabled=maintenance.Enabled=true;
        if(view.Failed){status.Text=view.Message;status.ForeColor=Color.FromArgb(163,59,42);guardWarning=false;}
        return false;
    }
    void RenderMaintenanceCompletion(MaintenanceResult m,HealthResult h,DeploymentResult d,bool ready) {
        if(m==null || m.ActionId!=observedMaintenanceId || m.Status!="Completed" || !ready || String.IsNullOrEmpty(m.ResultFile))return;
        try {
            string expected=Path.Combine(root,"private");
            if(!String.Equals(Path.GetDirectoryName(Path.GetFullPath(m.ResultFile)),expected,StringComparison.OrdinalIgnoreCase))return;
            var r=json.Deserialize<MigrationResult>(ReadSharedText(m.ResultFile));
            if(r==null || !r.Success || r.ActionId!=m.ActionId || r.StageId!=m.StageId || d.Desktop==null || d.CodeGate==null || r.DesktopVersion!=d.Desktop.Version || r.CodeVersion!=d.CodeGate.Version)return;
            status.Text="版本维护完成。\nDesktop "+r.DesktopVersion+" / Code "+r.CodeVersion+"。\n后台守护及固定出口检查通过；点击“打开 Claude”继续。";
            status.ForeColor=Color.FromArgb(24,106,65);lastSuccessMessage=status.Text;guardWarning=false;
            // 只在完成时接续一次；后续启动/检查自行维护其操作结果。
            observedMaintenanceId=null;
        }catch{}
    }
    void RefreshNetworkHealth() {
        try {
            MaintenanceResult operation;
            bool persistedHold=File.Exists(Path.Combine(root,"private","safety-hold.json"));
            if(RenderMaintenance(persistedHold,out operation))return;
            var path=Path.Combine(root,"private","supervisor-health.json");
            if(!File.Exists(path)) { ShowGuardWarning("后台守护状态尚未取得，正在等待自动恢复。");return;}
            var health=new JavaScriptSerializer().Deserialize<HealthResult>(ReadSharedText(path));
            var deployment=json.Deserialize<DeploymentResult>(ReadSharedText(Path.Combine(root,"private","deployment.json")));
            var identity=json.Deserialize<HostIdentity>(ReadSharedText(Path.Combine(root,"private","supervisor-host-identity.json")));
            if(File.Exists(Path.Combine(root,"private","safety-hold.json")) || (health!=null && health.Status=="SafetyHold")) {
                networkHealth.Text="网络防护已暂停，请退出 Claude 后进行版本维护。";networkHealth.ForeColor=Color.FromArgb(163,59,42);
                if(check.Enabled){status.Text="后台守护发现防护异常，专用网络已暂停。\n请完全退出 Claude 后点击“维护版本”，核验通过再使用。";status.ForeColor=Color.FromArgb(163,59,42);}
                return;
            }
            bool identities=health!=null && deployment!=null && deployment.Reliability!=null &&
                ProcessMatches(health.HostPid,health.HostStarted,deployment.Reliability.HostPath) &&
                ProcessMatches(health.SupervisorPid,health.SupervisorStarted,deployment.Reliability.ShellPath);
            string failure=ValidateHealth(health,deployment,identity,DateTimeOffset.UtcNow,identities,File.Exists(Path.Combine(root,"private","safety-hold.json")));
            if(failure!=null && (health==null || health.Status!="SafetyHold")){ShowGuardWarning(failure);return;}
            RenderMaintenanceCompletion(operation,health,deployment,failure==null);
            networkHealth.ForeColor=Color.FromArgb(163,59,42);
            switch(health.Status) {
                case "Healthy": networkHealth.Text="后台守护健康，固定出口检查通过。";networkHealth.ForeColor=Color.FromArgb(24,106,65);RestoreGuardMessage();break;
                case "ProbeDegraded": networkHealth.Text="一个检测站暂不可用，另一站已确认固定出口。";networkHealth.ForeColor=Color.FromArgb(145,99,20);RestoreGuardMessage();break;
                case "SafetyHold":
                    networkHealth.Text="网络防护已暂停，请退出 Claude 后进行版本维护。";
                    if(check.Enabled){status.Text="后台守护发现防护异常，专用网络已暂停。\n请完全退出 Claude 后点击“维护版本”，核验通过再使用。";status.ForeColor=Color.FromArgb(163,59,42);launch.Text="打开 Claude";}
                    break;
                case "UpstreamUnavailable": networkHealth.Text="固定节点暂不可达，守护正在退避重试。";break;
                case "UpgradeRequired": networkHealth.Text="Claude 版本已变化，请退出客户端后进行版本维护。";break;
                case "InterfaceUnavailable": networkHealth.Text="绑定网卡不可用，请等待原网络恢复或重新核验。";break;
                case "Maintenance": networkHealth.Text="专用组件正在维护，请等待核验完成。";break;
                case "Backoff": networkHealth.Text="专用代理反复退出，守护将在退避后重试。";break;
                default: networkHealth.Text="后台防护检查尚未通过，请重新检查并查看说明。";break;
            }
        } catch {ShowGuardWarning("后台状态暂时无法确认，正在等待自动恢复。");}
    }
    void ShowGuardWarning(string reason) {
        networkHealth.Text=reason;networkHealth.ForeColor=Color.FromArgb(163,59,42);
        try {
            var recoveryPath=Path.Combine(root,"private","supervisor-host-recovery.json");
            if(File.Exists(recoveryPath)) {
                var recovery=json.Deserialize<RecoveryResult>(ReadSharedText(recoveryPath));DateTimeOffset next;
                if(recovery!=null && DateTimeOffset.TryParse(recovery.NextRestart,out next) && next>DateTimeOffset.UtcNow)
                    networkHealth.Text="恢复正在退避，下次重试 "+next.ToLocalTime().ToString("HH:mm:ss")+"。请重新检查。";
            }
        } catch {}
        if(check.Enabled) {
            guardWarning=true;
            status.Text=IsClaudeOpen()?"Claude 已打开；后台守护正在恢复。\n当前会话保留，恢复完成后状态会自动更新。":"后台守护正在恢复，尚不能确认防护准备完成。\n请等待自动恢复或点击“重新检查”。";
            status.ForeColor=Color.FromArgb(145,99,20);
        }
    }
    void RestoreGuardMessage() {
        if(guardWarning && check.Enabled) {guardWarning=false;status.Text=lastSuccessMessage??(IsClaudeOpen()?"Claude 已打开。后台守护已恢复，固定出口检查通过。":"后台守护已恢复。点击“打开 Claude”继续。");status.ForeColor=Color.FromArgb(24,106,65);}
    }
    bool IsClaudeOpen() {
        try {
            var d=json.Deserialize<DeploymentResult>(ReadSharedText(Path.Combine(root,"private","deployment.json")));
            foreach(var p in Process.GetProcessesByName("Claude")) {using(p){try{if(p.MainModule.FileName.Equals(d.Desktop.Path,StringComparison.OrdinalIgnoreCase))return true;}catch{}}}
        } catch {} return false;
    }
    [DllImport("kernel32.dll",SetLastError=true)] static extern IntPtr OpenProcess(uint access,bool inherit,int pid);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool QueryFullProcessImageName(IntPtr h,uint flags,StringBuilder name,ref uint length);
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool GetProcessTimes(IntPtr h,out long created,out long exited,out long kernel,out long user);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    public static bool ProcessMatches(int pid,string started,string path) {
        DateTimeOffset time;if(pid<=0 || String.IsNullOrEmpty(path) || !DateTimeOffset.TryParse(started,out time))return false;
        IntPtr h=OpenProcess(0x1000,false,pid);if(h==IntPtr.Zero)return false;
        try {long created,exited,kernel,user;uint length=32768;var name=new StringBuilder((int)length);
            return GetProcessTimes(h,out created,out exited,out kernel,out user) && exited==0 && created==time.UtcDateTime.ToFileTimeUtc() && QueryFullProcessImageName(h,0,name,ref length) && name.ToString().Equals(path,StringComparison.OrdinalIgnoreCase);
        } catch {return false;}finally{CloseHandle(h);}
    }
    public static bool SameTime(string a,string b) {DateTimeOffset x,y;return DateTimeOffset.TryParse(a,out x) && DateTimeOffset.TryParse(b,out y) && x.UtcDateTime.Ticks==y.UtcDateTime.Ticks;}
    public static string ValidateHealth(HealthResult h,DeploymentResult d,HostIdentity identity,DateTimeOffset now,bool identities,bool held) {
        DateTimeOffset stamp,safety,egress,started;
        if(held)return "网络防护已暂停，请退出 Claude 后进行维护。";
        if(h==null || h.SchemaVersion!=2 || !DateTimeOffset.TryParse(h.Time,out stamp))return "后台守护状态尚未取得，正在等待自动恢复。";
        double age=(now-stamp).TotalSeconds;if(age < -5 || age>120)return "后台守护状态已过期，正在等待自动恢复。";
        if(!identities || identity==null || d==null || d.Reliability==null || String.IsNullOrEmpty(h.RunId) ||
            identity.RunId!=h.RunId || identity.HostPid!=h.HostPid || !SameTime(identity.HostStarted,h.HostStarted) || identity.SupervisorPid!=h.SupervisorPid || !SameTime(identity.SupervisorStarted,h.SupervisorStarted) ||
            identity.ShellPath!=d.Reliability.ShellPath || !String.Equals(identity.ScriptPath,Path.GetFullPath(Path.Combine(Path.GetDirectoryName(d.Reliability.HostPath),"..",d.Reliability.SupervisorScript)),StringComparison.OrdinalIgnoreCase))
            return "后台守护已停止或身份未确认，正在等待自动恢复。";
        if(h.Status=="SafetyHold")return "网络防护已暂停，请退出 Claude 后进行维护。";
        if(h.Status!="Healthy" && h.Status!="ProbeDegraded")return "后台守护检查尚未完成："+h.Status+"。请重新检查。";
        if(!DateTimeOffset.TryParse(h.SupervisorStarted,out started) || !DateTimeOffset.TryParse(h.LastSafetyCheck,out safety) || !DateTimeOffset.TryParse(h.LastEgressCheck,out egress) ||
            safety<started || egress<started || (now-safety).TotalSeconds < -5 || (now-safety).TotalSeconds>120 || (now-egress).TotalSeconds < -5 || (now-egress).TotalSeconds>120)
            return "本次守护检查未完成或已过期，正在等待恢复。";
        var e=h.LastVerifiedEgress;if(e==null || e.VerifiedProbeCount<1 ||
            (!String.IsNullOrEmpty(e.CloudflareIp) && e.CloudflareIp!=d.ExpectedIp) || (!String.IsNullOrEmpty(e.IpifyIp) && e.IpifyIp!=d.ExpectedIp) ||
            (e.CloudflareIp!=d.ExpectedIp && e.IpifyIp!=d.ExpectedIp))return "本次固定出口尚未确认，请重新检查。";
        return null;
    }
    async Task RunAction(string action) {
        if(actionBusy)return;
        actionBusy=true;activeActionKind=action;if(action=="Update")maintenanceRequestStarted=DateTimeOffset.UtcNow;else observedMaintenanceId=null;
        string actionId=Guid.NewGuid().ToString("N");activeActionId=actionId;guardWarning=false;
        launch.Enabled=check.Enabled=login.Enabled=maintenance.Enabled=false;
        status.ForeColor=Color.FromArgb(70,79,91); status.Text=action=="Update"?"正在核验官方版本和防护配置……\nWindows 提示管理员授权时，请核对后允许。":"正在检查连接，请稍候……\n检查通过才会打开 Claude。";
        try {
            var result=await Task.Run(delegate {
                string resultFile=Path.Combine(root,"private","ui-result-"+Guid.NewGuid().ToString("N")+".json");
                var psi=new ProcessStartInfo(shell);
                psi.Arguments="-NoProfile -ExecutionPolicy Bypass -File \""+Path.Combine(root,"ClaudeGuard-UiBridge.ps1")+"\" -Action "+action+" -ActionId "+actionId+" -ResultFile \""+resultFile+"\"";
                psi.WorkingDirectory=root; psi.UseShellExecute=false; psi.CreateNoWindow=true;
                try {
                    using(var p=Process.Start(psi)) {
                        if(action=="Update") {
                            // 维护进程独立于窗口存活；只结束观察，不能终止管理员迁移。
                            if(!p.WaitForExit(1320000))return new UiResult{ActionId=actionId,Pending=true,Message="维护仍在进行，暂未取得最终结果。关闭重开入口可接续观察。"};
                        }else if(!p.WaitForExit(180000)){if(!p.HasExited)p.Kill();throw new InvalidOperationException("后台检查尚未完成，暂时无法确认启动状态。");}
                        if(!File.Exists(resultFile)) throw new InvalidOperationException("后台检查无法完成，请查看说明。");
                        var parsed=json.Deserialize<UiResult>(ReadSharedText(resultFile));
                        if(parsed==null || parsed.ActionId!=actionId || (parsed.Success && !parsed.SupervisorVerified) || (p.ExitCode!=0 && parsed.Success)) throw new InvalidOperationException("后台结果不一致。");
                        return parsed;
                    }
                } finally {
                    if(File.Exists(resultFile)) File.Delete(resultFile);
                }
            });
            if(IsDisposed)return;
            if(result.OperationId!=null)observedMaintenanceId=result.OperationId;
            status.Text=result.Message;
            status.ForeColor=result.Success?Color.FromArgb(24,106,65):(result.Pending?Color.FromArgb(145,99,20):Color.FromArgb(163,59,42));
            if(result.Success) {lastSuccessMessage=result.Message;RunApiDiagnostic(actionId);}
            if(result.Success && action=="Start") { launch.Text="Claude 已打开"; }
        } catch { status.Text="安全检查未能完成，暂时无法确认启动状态。\n请查看说明后重新检查。";status.ForeColor=Color.FromArgb(163,59,42); }
        finally {actionBusy=false;activeActionKind=null;if(!IsDisposed){launch.Enabled=check.Enabled=login.Enabled=maintenance.Enabled=true;RefreshNetworkHealth();}}
    }
    async void RunApiDiagnostic(string actionId) {
        try {
            var result=await Task.Run(delegate {
                string file=Path.Combine(root,"private","ui-result-"+Guid.NewGuid().ToString("N")+".json");
                try {var psi=new ProcessStartInfo(shell){UseShellExecute=false,CreateNoWindow=true,WorkingDirectory=root,Arguments="-NoProfile -ExecutionPolicy Bypass -File \""+Path.Combine(root,"ClaudeGuard-UiBridge.ps1")+"\" -Action Diagnose -ActionId "+actionId+" -ResultFile \""+file+"\""};
                    using(var p=Process.Start(psi)){if(!p.WaitForExit(30000)){if(!p.HasExited)p.Kill();return null;}return File.Exists(file)?new JavaScriptSerializer().Deserialize<UiResult>(ReadSharedText(file)):null;}
                } finally {if(File.Exists(file))File.Delete(file);}
            });
            if(IsDisposed || activeActionId!=actionId || guardWarning || result==null || result.ActionId!=actionId)return;
            if(result.ApiTransport!=null && result.ApiTransport.CurlExitCode!=0 && check.Enabled) {
                lastSuccessMessage+=(" 官方 API 的无账号诊断暂未通过，真实会话可用性待确认。");status.Text=lastSuccessMessage;
            }
        } catch {}
    }
    public class UiResult {public bool Pending {get;set;}public string OperationId {get;set;} public bool Success {get;set;} public string Message {get;set;} public bool SessionVerified {get;set;} public bool SupervisorVerified {get;set;} public string ActionId {get;set;} public ApiResult ApiTransport {get;set;} }
    public class ApiResult {public int CurlExitCode {get;set;}}
    public class HealthResult { public int SchemaVersion {get;set;} public string Time {get;set;} public string Status {get;set;} public string RunId {get;set;} public int HostPid {get;set;} public string HostStarted {get;set;} public int SupervisorPid {get;set;} public string SupervisorStarted {get;set;} public string LastSafetyCheck {get;set;} public string LastEgressCheck {get;set;} public EgressResult LastVerifiedEgress {get;set;} }
    public class EgressResult {public int VerifiedProbeCount {get;set;}public string CloudflareIp {get;set;}public string IpifyIp {get;set;}}
    public class HostIdentity {public string RunId {get;set;} public int HostPid {get;set;} public string HostStarted {get;set;} public int SupervisorPid {get;set;} public string SupervisorStarted {get;set;}public string ShellPath {get;set;}public string ScriptPath {get;set;}}
    public class DeploymentResult {public ReliabilityResult Reliability {get;set;}public DesktopResult Desktop {get;set;}public CodeResult CodeGate {get;set;}public string ExpectedIp {get;set;}}
    public class DesktopResult {public string Path {get;set;}public string Version {get;set;}}
    public class CodeResult {public string Version {get;set;}}
    public class ReliabilityResult {public string HostPath {get;set;}public string ShellPath {get;set;}public string SupervisorScript {get;set;}}
    public class MaintenanceResult {public int SchemaVersion {get;set;}public string ActionId {get;set;}public string StageId {get;set;}public string ResultFile {get;set;}public string Status {get;set;}public string Phase {get;set;}public string StartedAt {get;set;}public string CompletedAt {get;set;}public int CoordinatorPid {get;set;}public string CoordinatorStarted {get;set;}public string CoordinatorPath {get;set;}public int WorkerPid {get;set;}public string WorkerStarted {get;set;}public string WorkerPath {get;set;}public bool RecoveryRequired {get;set;}public bool SupervisorSuspended {get;set;}public string Reason {get;set;}}
    public class MaintenanceView {public bool BlockStart;public bool Observe;public bool Recover;public bool Completed;public bool Failed;public bool Held;public string Message;}
    public class MigrationResult {public bool Success {get;set;}public string ActionId {get;set;}public string StageId {get;set;}public string DesktopVersion {get;set;}public string CodeVersion {get;set;}}
    public class RecoveryResult {public string NextRestart {get;set;}public string Reason {get;set;}}
    public class VersionResult {public int SchemaVersion {get;set;}public string InstalledDesktopVersion {get;set;}public string InstalledCodeVersion {get;set;}public string ApprovedCodeVersion {get;set;}public bool InstalledMatchesApproved {get;set;}public RuntimeVersion[] Runtime {get;set;}public CatalogResult Catalog {get;set;}public string UpdateDecision {get;set;}public string ToolVersion {get;set;}}
    public class RuntimeVersion {public string Version {get;set;}public string Identity {get;set;}}
    public class CatalogResult {public string Status {get;set;}public string CheckedAt {get;set;}public PublishedVersion LastSuccess {get;set;}}
    public class PublishedVersion {public string CheckedAt {get;set;}public string LatestDesktopVersion {get;set;}}
    public class DesktopUpdateResult {public int SchemaVersion {get;set;}public string Id {get;set;}public string Status {get;set;}public string TargetVersion {get;set;}public string PackageFile {get;set;}public long PackageBytes {get;set;}public string MaintenanceId {get;set;}public string Message {get;set;}public string FailureKind {get;set;}public int WorkerPid {get;set;}public string WorkerStarted {get;set;}public string WorkerPath {get;set;}}
    public class DesktopCommandResult {public string CommandId {get;set;}public string Message {get;set;}}
}
public static class Launcher {
    [STAThread] public static int Main(string[] args) {
        Application.EnableVisualStyles(); Application.SetCompatibleTextRenderingDefault(false);
        string root=Path.GetDirectoryName(Path.GetDirectoryName(Application.ExecutablePath));
        var lines=File.ReadAllLines(Path.Combine(root,"private","launcher-paths.txt"));
        var window=new ClaudeGuardWindow(root,lines[0]);
        if(args.Length==2 && args[0]=="--render-preview") {
            window.PreviewOnly=true; window.ShowInTaskbar=false; window.StartPosition=FormStartPosition.Manual; window.Location=new Point(-30000,-30000);window.Show();Application.DoEvents();
            using(var image=new Bitmap(window.Width,window.Height)){window.DrawToBitmap(image,new Rectangle(0,0,window.Width,window.Height));image.Save(args[1]);}
            window.Dispose();return 0;
        }
        if(args.Length==1 && args[0]=="--maintenance")window.MaintenanceViewOnly=true;
        bool created;
        using(var single=new Mutex(true,"Local\\ClaudeProGuardLauncher-v1",out created)){
            if(!created){MessageBox.Show("安全入口已在运行，请切换到该窗口。","Claude Pro",MessageBoxButtons.OK,MessageBoxIcon.Information);return 0;}
            Application.Run(window);
        }
        return 0;
    }
}
