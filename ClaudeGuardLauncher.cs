using System;
using System.Diagnostics;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.IO;
using System.Threading;
using System.Text;
using System.Runtime.InteropServices;
using System.Threading.Tasks;
using System.Web.Script.Serialization;
using System.Windows.Forms;

[assembly: System.Reflection.AssemblyVersion("1.7.2.0")]
[assembly: System.Reflection.AssemblyFileVersion("1.7.2.0")]

public sealed class ClaudeGuardWindow : Form {
    public const string BuildVersion="v1.7.2";
    static readonly Color CanvasBg=Color.FromArgb(244,246,249);
    static readonly Color CardBg=Color.White;
    static readonly Color CardBorder=Color.FromArgb(226,232,240);
    static readonly Color TextPrimary=Color.FromArgb(15,23,42);
    static readonly Color TextSecondary=Color.FromArgb(71,85,105);
    static readonly Color TextMuted=Color.FromArgb(100,116,139);
    static readonly Color BrandTeal=Color.FromArgb(15,118,110);
    static readonly Color BrandIndigo=Color.FromArgb(37,99,235);
    static readonly Color NeutralBtnBg=Color.FromArgb(248,250,252);
    static readonly Color NeutralBtnBorder=Color.FromArgb(203,213,225);
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
    readonly Label toolBuildVersion = new Label();
    readonly Button checkUpdates = new Button();
    readonly Button downloadUpdates = new Button();
    readonly Button installUpdates = new Button();
    readonly Label downloadStatus = new Label();
    readonly Button networkEnvButton = new Button();
    readonly Label riskBadgeLabel = new Label();
    readonly Label riskSummaryLabel = new Label();
    readonly CheckBox gateToggle = new CheckBox();
    readonly NumericUpDown thresholdInput = new NumericUpDown();
    readonly ComboBox runtimeModeBox = new ComboBox();
    readonly Button quickFixButton = new Button();
    readonly Button refreshScoreButton = new Button();
    bool suppressGateEvents;
    bool riskWatchBusy;
    bool updateDispatchBusy;
    bool officialDownloadReady;
    string installedDesktopVersion;
    string desktopCommandError;
    bool? lastDesktopOpen;
    readonly System.Windows.Forms.Timer versionTimer = new System.Windows.Forms.Timer();
    bool versionBusy;
    DateTimeOffset nextCatalogCheck=DateTimeOffset.MinValue;
    readonly System.Windows.Forms.Timer healthTimer = new System.Windows.Forms.Timer();
    readonly System.Windows.Forms.Timer riskWatchTimer = new System.Windows.Forms.Timer();
    readonly string root;
    readonly string shell;
    readonly JavaScriptSerializer json = new JavaScriptSerializer();
    string activeActionId;
    string lastSuccessMessage;
    bool guardWarning;
    bool heldControls;
    bool actionBusy;
    string observedMaintenanceId;
    string activeActionKind;
    DateTimeOffset maintenanceRequestStarted;
    public bool PreviewOnly;
    public bool StatusViewOnly;
    bool maintenanceViewOnly;
    public bool MaintenanceViewOnly {
        get { return maintenanceViewOnly; }
        set { maintenanceViewOnly=value; Text="Claude Pro · "+(value?"版本维护 ":"安全入口 ")+BuildVersion; }
    }
    static GraphicsPath CreateRoundRectPath(Rectangle rect, int radius) {
        var path = new GraphicsPath();
        int d = Math.Max(2, radius * 2);
        if (d > rect.Width) d = rect.Width;
        if (d > rect.Height) d = rect.Height;
        path.AddArc(rect.X, rect.Y, d, d, 180, 90);
        path.AddArc(rect.Right - d, rect.Y, d, d, 270, 90);
        path.AddArc(rect.Right - d, rect.Bottom - d, d, d, 0, 90);
        path.AddArc(rect.X, rect.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }
    static void DrawCard(Graphics g, Rectangle rect, Color accentTop) {
        if (rect.Width < 20 || rect.Height < 20) return;
        int r = Math.Max(6, Math.Min(12, rect.Height / 10));
        using (var path = CreateRoundRectPath(rect, r))
        using (var fill = new SolidBrush(CardBg))
        using (var border = new Pen(CardBorder, 1f)) {
            g.FillPath(fill, path);
            if (!accentTop.IsEmpty) {
                var clipState = g.Save();
                g.SetClip(path);
                using (var bar = new SolidBrush(accentTop)) {
                    g.FillRectangle(bar, rect.X, rect.Y, rect.Width, 3);
                }
                g.Restore(clipState);
            }
            g.DrawPath(border, path);
        }
    }
    static void StylePrimaryButton(Button b, Color bg) {
        b.FlatStyle = FlatStyle.Flat;
        b.BackColor = bg;
        b.ForeColor = Color.White;
        b.FlatAppearance.BorderSize = 0;
        b.FlatAppearance.MouseOverBackColor = Color.FromArgb(Math.Max(0, bg.R - 12), Math.Max(0, bg.G - 12), Math.Max(0, bg.B - 12));
        b.Cursor = Cursors.Hand;
    }
    static void StyleSecondaryButton(Button b) {
        b.FlatStyle = FlatStyle.Flat;
        b.BackColor = NeutralBtnBg;
        b.ForeColor = TextPrimary;
        b.FlatAppearance.BorderSize = 1;
        b.FlatAppearance.BorderColor = NeutralBtnBorder;
        b.FlatAppearance.MouseOverBackColor = Color.FromArgb(241, 245, 249);
        b.Cursor = Cursors.Hand;
    }
    static void StyleAccentOutlineButton(Button b, Color accent) {
        b.FlatStyle = FlatStyle.Flat;
        b.BackColor = Color.FromArgb(239, 246, 255);
        b.ForeColor = accent;
        b.FlatAppearance.BorderSize = 1;
        b.FlatAppearance.BorderColor = Color.FromArgb(191, 219, 254);
        b.FlatAppearance.MouseOverBackColor = Color.FromArgb(219, 234, 254);
        b.Cursor = Cursors.Hand;
    }
    protected override void OnPaint(PaintEventArgs e) {
        base.OnPaint(e);
        var g = e.Graphics;
        g.SmoothingMode = SmoothingMode.AntiAlias;
        int marginX = Math.Max(16, status.Left - 18);
        int cardW = Math.Max(200, ClientSize.Width - marginX * 2);
        int padY = Math.Max(10, (launch.Top - status.Bottom) + 6);
        // Card 1: Guard & Launch (encloses status..networkHealth directly owned by Form)
        int c1Top = Math.Max(4, status.Top - 16);
        int c1Bottom = Math.Max(c1Top + 40, networkHealth.Bottom + 14);
        DrawCard(g, new Rectangle(marginX, c1Top, cardW, c1Bottom - c1Top), status.ForeColor);
        // Card 2: Desktop & Code versions / updates
        int c2Top = Math.Max(c1Bottom + 8, installedVersions.Top - 12);
        int c2Bottom = Math.Max(c2Top + 40, entryVersion.Bottom + 12);
        DrawCard(g, new Rectangle(marginX, c2Top, cardW, c2Bottom - c2Top), Color.Empty);
        // Card 3: Network Risk Gate & Optimization
        int c3Top = Math.Max(c2Bottom + 8, riskSummaryLabel.Top - 12);
        int c3Bottom = Math.Max(c3Top + 40, networkEnvButton.Bottom + 12);
        DrawCard(g, new Rectangle(marginX, c3Top, cardW, c3Bottom - c3Top), BrandIndigo);
    }
    public ClaudeGuardWindow(string projectRoot, string pwsh) {
        root=projectRoot; shell=pwsh;
        SetStyle(ControlStyles.OptimizedDoubleBuffer | ControlStyles.AllPaintingInWmPaint | ControlStyles.UserPaint, true);
        Text="Claude Pro · 安全入口 "+BuildVersion; ClientSize=new Size(700,616);
        AutoScroll=true;AutoScrollMinSize=new Size(680,600);
        FormBorderStyle=FormBorderStyle.FixedDialog; MaximizeBox=false; StartPosition=FormStartPosition.CenterScreen;
        Font=new Font("Microsoft YaHei UI",9.5f); BackColor=CanvasBg; ForeColor=TextPrimary;
        var title=new Label { Text="Claude Pro", Font=new Font("Microsoft YaHei UI",18,FontStyle.Bold), Location=new Point(26,18), AutoSize=true, BackColor=CanvasBg, ForeColor=TextPrimary };
        var hint=new Label { Text="固定节点守护与非 TUN 网络风险门禁 · 双击安全检查后启动",Location=new Point(28,53),AutoSize=true,Font=new Font("Microsoft YaHei UI",8.75f),ForeColor=TextMuted,BackColor=CanvasBg };
        riskBadgeLabel.Text="风险评分 -- · 门限 ≤ 20";riskBadgeLabel.SetBounds(376,22,184,26);
        riskBadgeLabel.Font=new Font("Microsoft YaHei UI",8.5f,FontStyle.Bold);
        riskBadgeLabel.TextAlign=ContentAlignment.MiddleCenter;
        riskBadgeLabel.BackColor=Color.FromArgb(241,245,249);riskBadgeLabel.ForeColor=TextSecondary;
        riskBadgeLabel.Cursor=Cursors.Hand;
        riskBadgeLabel.Click+=delegate { ShowNetworkEnvDialog(); };
        toolBuildVersion.Text="安全入口 "+BuildVersion;toolBuildVersion.SetBounds(568,22,108,26);
        toolBuildVersion.Font=new Font("Microsoft YaHei UI",8.5f,FontStyle.Bold);
        toolBuildVersion.TextAlign=ContentAlignment.MiddleCenter;
        toolBuildVersion.BackColor=Color.FromArgb(226,232,240);toolBuildVersion.ForeColor=TextPrimary;

        status.SetBounds(42,100,616,74); status.Text="正在检查专用网络、风险评分和防护配置……";
        status.Font=new Font("Microsoft YaHei UI",10f); status.BackColor=CardBg; status.ForeColor=TextPrimary;
        status.TextChanged+=delegate { Invalidate(); };
        status.ForeColorChanged+=delegate { Invalidate(); };

        launch.Text="打开 Claude"; launch.SetBounds(42,186,134,36); launch.Font=new Font("Microsoft YaHei UI",9.5f,FontStyle.Bold);
        check.Text="重新检查"; check.SetBounds(186,186,108,36);
        login.Text="登录链接";login.SetBounds(304,186,108,36);
        report.Text="查看说明"; report.SetBounds(422,186,108,36);
        maintenance.Text="维护版本";maintenance.SetBounds(540,186,118,36);
        StylePrimaryButton(launch, BrandTeal);
        StyleSecondaryButton(check);
        StyleSecondaryButton(login);
        StyleSecondaryButton(report);
        StyleSecondaryButton(maintenance);
        launch.Click+=async delegate { await RunAction("Start"); };
        check.Click+=async delegate { await RunAction("Check"); };
        maintenance.Click+=async delegate { await RunAction("Update"); };
        report.Click+=delegate { Process.Start(new ProcessStartInfo(Path.Combine(root,"一键使用说明.txt")){UseShellExecute=true}); };
        login.Click+=async delegate {
            using(var prompt=new Form {Text="专用登录浏览器",ClientSize=new Size(488,150),StartPosition=FormStartPosition.CenterParent,FormBorderStyle=FormBorderStyle.FixedDialog,MaximizeBox=false,MinimizeBox=false,BackColor=CanvasBg,Font=new Font("Microsoft YaHei UI",9.5f)}){
                var label=new Label{Text="粘贴 Claude 提供的官方登录链接或邮件登录链接：",AutoSize=true,Location=new Point(16,18),BackColor=CanvasBg};
                var input=new TextBox{Location=new Point(16,50),Width=452};
                var open=new Button{Text="打开专用浏览器",Location=new Point(310,95),Width=158,Height=34,DialogResult=DialogResult.OK};
                StylePrimaryButton(open, BrandTeal);
                prompt.Controls.AddRange(new Control[]{label,input,open});prompt.AcceptButton=open;
                if(prompt.ShowDialog(this)==DialogResult.OK){
                    File.WriteAllText(Path.Combine(root,"private","login-link.json"),json.Serialize(new {Url=input.Text.Trim()}));
                    await RunAction("Login");
                }
            }
        };
        var footer=new Label {Text="专用节点由后台持续检查；节点池自动选择可用连接。",Location=new Point(42,236),AutoSize=true,Font=new Font("Microsoft YaHei UI",8.5f),ForeColor=TextMuted,BackColor=CardBg};
        networkHealth.SetBounds(42,258,616,22); networkHealth.Font=new Font("Microsoft YaHei UI",9f);networkHealth.Text="后台守护状态待确认。";networkHealth.BackColor=CardBg;
        Controls.AddRange(new Control[]{title,hint,riskBadgeLabel,toolBuildVersion,status,launch,check,login,report,maintenance,footer,networkHealth});

        installedVersions.SetBounds(42,320,616,22);installedVersions.Text="正在读取 Desktop 和配套 Code 版本……";installedVersions.AutoEllipsis=true;installedVersions.BackColor=CardBg;
        runtimeVersions.SetBounds(42,346,616,22);runtimeVersions.Text="本地 Code：运行版本待确认。";runtimeVersions.AutoEllipsis=true;runtimeVersions.BackColor=CardBg;
        updateStatus.SetBounds(42,378,486,38);updateStatus.Font=new Font("Microsoft YaHei UI",9f);updateStatus.Text="官方版本尚未检查。";updateStatus.BackColor=CardBg;
        checkUpdates.SetBounds(540,378,118,34);checkUpdates.Text="检查新版";StyleSecondaryButton(checkUpdates);
        checkUpdates.Click+=async delegate {await RefreshVersionInfo(true,true);};
        downloadStatus.SetBounds(42,424,366,38);downloadStatus.Font=new Font("Microsoft YaHei UI",9f);downloadStatus.Text="尚未下载官方安装包。";downloadStatus.BackColor=CardBg;
        downloadUpdates.SetBounds(420,424,110,34);downloadUpdates.Text="下载官方包";downloadUpdates.Enabled=false;StyleSecondaryButton(downloadUpdates);
        installUpdates.SetBounds(540,424,118,34);installUpdates.Text="安装并维护";installUpdates.Enabled=false;StyleAccentOutlineButton(installUpdates, BrandIndigo);
        downloadUpdates.Click+=async delegate {await RunDesktopUpdate("Download");};
        installUpdates.Click+=async delegate {await RunDesktopUpdate("Install");};
        entryVersion.SetBounds(42,466,616,18);entryVersion.Font=new Font("Microsoft YaHei UI",8f);entryVersion.ForeColor=TextMuted;entryVersion.BackColor=CardBg;
        entryVersion.Text="入口运行时每 6 小时检查新版，由你决定何时更新。";

        riskSummaryLabel.SetBounds(42,514,616,24);riskSummaryLabel.Font=new Font("Microsoft YaHei UI",9f,FontStyle.Bold);riskSummaryLabel.ForeColor=TextPrimary;riskSummaryLabel.BackColor=CardBg;riskSummaryLabel.AutoEllipsis=true;
        riskSummaryLabel.Text="非 TUN 网络风险门禁：等待首次检测（低于门限方可启动 Claude）。";
        gateToggle.Text="启用门限 ≤";gateToggle.Location=new Point(42,553);gateToggle.AutoSize=true;gateToggle.Checked=true;gateToggle.BackColor=CardBg;gateToggle.ForeColor=TextSecondary;
        thresholdInput.SetBounds(134,550,52,25);thresholdInput.Minimum=0;thresholdInput.Maximum=100;thresholdInput.Value=20;
        runtimeModeBox.DropDownStyle=ComboBoxStyle.DropDownList;runtimeModeBox.Font=new Font("Microsoft YaHei UI",8.5f);runtimeModeBox.SetBounds(194,550,122,25);
        runtimeModeBox.Items.AddRange(new object[]{"动态:自愈+告警","动态:超限停Claude","动态:仅预警","动态:关闭"});runtimeModeBox.SelectedIndex=0;
        quickFixButton.SetBounds(324,548,114,32);quickFixButton.Text="一键防泄露修复";StylePrimaryButton(quickFixButton, Color.FromArgb(22,163,74));
        refreshScoreButton.SetBounds(446,548,86,32);refreshScoreButton.Text="重测评分";StyleSecondaryButton(refreshScoreButton);
        networkEnvButton.SetBounds(540,548,118,32);networkEnvButton.Text="网络优化";StyleAccentOutlineButton(networkEnvButton, BrandIndigo);
        gateToggle.CheckedChanged+=async delegate { if(!suppressGateEvents && !PreviewOnly) await SaveRiskGateConfigAsync(); };
        thresholdInput.ValueChanged+=async delegate { if(!suppressGateEvents && !PreviewOnly) await SaveRiskGateConfigAsync(); };
        runtimeModeBox.SelectedIndexChanged+=async delegate { if(!suppressGateEvents && !PreviewOnly) await SaveRiskGateConfigAsync(); };
        quickFixButton.Click+=async delegate { await RunQuickNetworkFixAsync(); };
        refreshScoreButton.Click+=async delegate { await RefreshRiskScoreAsync(false); };
        networkEnvButton.Click+=delegate { ShowNetworkEnvDialog(); };

        Controls.AddRange(new Control[]{installedVersions,runtimeVersions,updateStatus,checkUpdates,downloadStatus,downloadUpdates,installUpdates,entryVersion,riskSummaryLabel,gateToggle,thresholdInput,runtimeModeBox,quickFixButton,refreshScoreButton,networkEnvButton});
        healthTimer.Interval=2000;healthTimer.Tick+=delegate { RefreshClientState();RefreshNetworkHealth();RefreshDesktopUpdate(); };healthTimer.Start();
        versionTimer.Interval=10000;versionTimer.Tick+=async delegate {if(!PreviewOnly)await RefreshVersionInfo(false,DateTimeOffset.UtcNow>=nextCatalogCheck);};versionTimer.Start();
        riskWatchTimer.Interval=25000;riskWatchTimer.Tick+=async delegate {if(!PreviewOnly)await PollRuntimeRiskWatchAsync();};riskWatchTimer.Start();
        FormClosed+=delegate {healthTimer.Stop();healthTimer.Dispose();versionTimer.Stop();versionTimer.Dispose();riskWatchTimer.Stop();riskWatchTimer.Dispose();};
        var iconPath=Path.Combine(root,"runtime","claude-guard.ico"); if(File.Exists(iconPath)) Icon=new Icon(iconPath);
        Shown+=async delegate { if(!PreviewOnly) {
            var versions=RefreshVersionInfo(false,true);var scoreTask=RefreshRiskScoreAsync(false);
            bool resume=ResumeMaintenanceOnOpen() || ResumeDesktopUpdateOnOpen();
            if(StatusViewOnly)guardWarning=true;
            if(MaintenanceViewOnly)status.Text="请完全退出 Claude 和本地 Code 后，点击“维护版本”。";
            RefreshNetworkHealth();
            if(!resume && !StatusViewOnly && !MaintenanceViewOnly && !heldControls)await RunAction("Start");
            await versions;await scoreTask;
        }};
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
        if(String.IsNullOrEmpty(d.PackageFile) || !String.Equals(Path.GetFullPath(d.PackageFile),Path.GetFullPath(Path.Combine(root,"private","desktop-package-"+d.Id+".msix")),StringComparison.OrdinalIgnoreCase))throw new InvalidDataException("更新文件路径无效。");
        if(IsDesktopUpdateActive(d) && d.Status!="AwaitingReadiness" && !ProcessMatches(d.WorkerPid,d.WorkerStarted,d.WorkerPath)){d.Status="Interrupted";d.Message=String.IsNullOrEmpty(d.MaintenanceId)?"下载已中断，可重新下载；未改变已安装版本。":"更新中断，需要恢复。请点击“维护版本”。";}
        if(d.Status=="Downloading" && File.Exists(d.PackageFile+".part"))d.PackageBytes=new FileInfo(d.PackageFile+".part").Length;
        return d;
    }
    static bool IsDesktopUpdateActive(DesktopUpdateResult d){return d!=null && (d.Status=="Downloading" || d.Status=="Verifying" || IsDesktopInstallationActive(d));}
    static bool IsDesktopInstallationActive(DesktopUpdateResult d){return d!=null && (d.Status=="PreparingInstall" || d.Status=="PreparingProtection" || d.Status=="AwaitingAuthorization" || d.Status=="Installing" || d.Status=="Maintaining" || d.Status=="AwaitingReadiness");}
    static bool IsDesktopUpdateRetryable(DesktopUpdateResult d){return d!=null && (d.Status=="Ready" || (d.Status=="Failed" && (d.FailureKind=="DesktopUpdateFailed" || d.FailureKind=="PackageResourcesInUse" || d.FailureKind=="InstallPrecondition") && d.Signature=="Valid" && d.PackageHash!=null && System.Text.RegularExpressions.Regex.IsMatch(d.PackageHash,"\\A[A-Fa-f0-9]{64}\\z")));}
    bool ResumeDesktopUpdateOnOpen(){try{var d=ReadDesktopUpdate();RefreshDesktopUpdate();return d!=null && (d.Status=="PreparingInstall" || (!String.IsNullOrEmpty(d.MaintenanceId) && (IsDesktopUpdateActive(d) || d.Status=="Interrupted")));}catch{status.Text="更新记录暂时无法确认，请查看说明并恢复维护。";return true;}}
    public void RenderDesktopUpdate(DesktopUpdateResult d) {
        bool active=IsDesktopUpdateActive(d);bool repair=d!=null && d.Status=="Interrupted" && !String.IsNullOrEmpty(d.MaintenanceId);
        downloadUpdates.Enabled=!updateDispatchBusy && officialDownloadReady && !active && !repair && maintenance.Enabled && check.Enabled;
        Version target,current;bool newer=d!=null && Version.TryParse(d.TargetVersion,out target) && Version.TryParse(installedDesktopVersion,out current) && new Version(target.Major,target.Minor,target.Build,Math.Max(0,target.Revision))>new Version(current.Major,current.Minor,current.Build,Math.Max(0,current.Revision));
        installUpdates.Enabled=!updateDispatchBusy && !actionBusy && IsDesktopUpdateRetryable(d) && newer && maintenance.Enabled;
        downloadStatus.ForeColor=Color.FromArgb(70,79,91);
        if(d==null){if(!updateDispatchBusy)downloadStatus.Text=desktopCommandError??"尚未下载官方安装包。";return;}
        if(d.Status=="Downloading")downloadStatus.Text="正在下载 Desktop "+d.TargetVersion+"：已取得 "+(d.PackageBytes/1048576.0).ToString("F1")+" MB。";
        else if(d.Status=="Ready")downloadStatus.Text=d.FailureKind!=null?d.Message:(newer?"官方包已核验：Desktop "+d.TargetVersion+"。\n完全退出 Claude 和本地 Code 后安装。":"官方包已核验，当前版本无需升级。");
        else if(IsDesktopUpdateRetryable(d))downloadStatus.Text="上次安装未完成，官方包已保留。\n点击“安装并维护”自动恢复并继续更新。";
        else downloadStatus.Text=d.Message??"正在观察更新操作。";
        if(active || repair || d.Status=="Failed" || d.FailureKind!=null)downloadStatus.ForeColor=Color.FromArgb(145,99,20);
        if(d.Status=="Completed")downloadStatus.ForeColor=Color.FromArgb(24,106,65);
        if(!active && desktopCommandError!=null){downloadStatus.Text=desktopCommandError;downloadStatus.ForeColor=Color.FromArgb(145,99,20);}
    }
    void RefreshDesktopUpdate(){try{var d=ReadDesktopUpdate();RenderDesktopUpdate(d);RenderClientState(IsClaudeOpen(),updateDispatchBusy || IsDesktopInstallationActive(d));}catch{downloadUpdates.Enabled=installUpdates.Enabled=false;downloadStatus.Text="更新记录暂时无法确认，请查看本地说明。";downloadStatus.ForeColor=Color.FromArgb(163,59,42);}}
    public void RenderClientState(bool desktopOpen,bool installing) {
        launch.Text=installing?"更新进行中":activeActionKind=="Start"?"正在核验启动":desktopOpen?"Claude 已打开":"打开 Claude";
        if(desktopOpen && lastDesktopOpen==false && !installing && !PreviewOnly){
            var _=PollRuntimeRiskWatchAsync();
        }
        if(!desktopOpen && lastDesktopOpen==true && !installing && !actionBusy && !guardWarning && check.Enabled && status.ForeColor==Color.FromArgb(24,106,65) && status.Text.Contains("Claude 已打开")){
            lastSuccessMessage="Claude 已退出。点击“打开 Claude”继续。";status.Text=lastSuccessMessage;
        }
        lastDesktopOpen=desktopOpen;
    }
    void RefreshClientState(){try{RenderClientState(IsClaudeOpen(),updateDispatchBusy || IsDesktopInstallationActive(ReadDesktopUpdate()));}catch{launch.Text="状态待确认";}}
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
        finally{updateDispatchBusy=false;if(!IsDisposed){RefreshClientState();RefreshDesktopUpdate();RefreshNetworkHealth();}}
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
        if(held && (m.Status!="Running" || !ownerAlive)){v.Held=true;v.Message="网络防护已暂停，请退出 Claude 后进行版本维护。";return v;}
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
            case "PreparingInstall":v.Message="安装前维护已完成。\n正在接续安装，无需再次点击。";break;
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
            ShowSafetyHold(null,m);return true;
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
    void ShowSafetyHold(string healthReason,MaintenanceResult operation) {
        string reason=healthReason??"";
        try {
            var record=json.Deserialize<RecoveryResult>(ReadSharedText(Path.Combine(root,"private","safety-hold.json")));
            if(record!=null && !String.IsNullOrWhiteSpace(record.Reason))reason=record.Reason;
        }catch{}
        string detail="守护检测到防护配置或运行状态异常。";
        if(operation!=null && operation.Status=="Failed" && operation.FailureKind=="RuntimeReaderUnavailable")
            detail="运行检查需要可用的 64 位 Python 3。请先安装或修复 Python。";
        else if(reason.Contains("RuntimeReaderUnavailable"))detail="未找到可运行的 64 位 Python 3。请先安装或修复 Python。";
        else if(reason.Contains("RuntimeEnvironmentUnreadable"))detail="守护无法核验 Claude 的运行环境。请确认 64 位 Python 3 可用，并用同一 Windows 账号打开入口。";
        else if(reason.Contains("RuntimeEnvironmentMismatch"))detail="Claude 的运行环境与核准配置不符。";
        else if(reason.Contains("UnexpectedRuntimeNetworkPath") || reason.Contains("Fixed egress mismatch"))detail="守护发现未经核准的网络连接或出口。";
        status.Text=detail+"\n退出 Claude 和本地 Code 后，点击“维护版本”重新核验并恢复防护。";
        status.ForeColor=Color.FromArgb(163,59,42);networkHealth.ForeColor=status.ForeColor;
        networkHealth.Text="防护已暂停，专用网络已关闭。";lastSuccessMessage=null;guardWarning=true;heldControls=true;
        launch.Enabled=check.Enabled=login.Enabled=false;maintenance.Enabled=!actionBusy;
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
            if(persistedHold){ShowSafetyHold(null,operation);return;}
            var path=Path.Combine(root,"private","supervisor-health.json");
            if(!File.Exists(path)) { ShowGuardWarning("后台守护状态尚未取得，正在等待自动恢复。");return;}
            var health=new JavaScriptSerializer().Deserialize<HealthResult>(ReadSharedText(path));
            if(health!=null && health.Status=="SafetyHold"){ShowSafetyHold(health.Reason,operation);return;}
            var deployment=json.Deserialize<DeploymentResult>(ReadSharedText(Path.Combine(root,"private","deployment.json")));
            var identity=json.Deserialize<HostIdentity>(ReadSharedText(Path.Combine(root,"private","supervisor-host-identity.json")));
            bool identities=health!=null && deployment!=null && deployment.Reliability!=null &&
                ProcessMatches(health.HostPid,health.HostStarted,deployment.Reliability.HostPath) &&
                ProcessMatches(health.SupervisorPid,health.SupervisorStarted,deployment.Reliability.ShellPath);
            string failure=ValidateHealth(health,deployment,identity,DateTimeOffset.UtcNow,identities,File.Exists(Path.Combine(root,"private","safety-hold.json")));
            if(failure!=null){ShowGuardWarning(failure);return;}
            if(heldControls && !actionBusy){heldControls=false;launch.Enabled=check.Enabled=login.Enabled=maintenance.Enabled=true;}
            RenderMaintenanceCompletion(operation,health,deployment,failure==null);
            networkHealth.ForeColor=Color.FromArgb(163,59,42);
            switch(health.Status) {
                case "Healthy": networkHealth.Text=deployment.ExpectedIps!=null?"后台守护健康，已核准节点池（"+deployment.ExpectedIps.Length+" 条）出口检查通过。":"后台守护健康，固定出口检查通过。";networkHealth.ForeColor=Color.FromArgb(24,106,65);RestoreGuardMessage();break;
                case "ProbeDegraded": networkHealth.Text="一个检测站暂不可用，另一站已确认固定出口。";networkHealth.ForeColor=Color.FromArgb(145,99,20);RestoreGuardMessage();break;
                case "UpstreamUnavailable": networkHealth.Text="固定节点暂不可达，守护正在退避重试。";break;
                case "UpgradeRequired": networkHealth.Text="Claude 版本已变化，请退出客户端后进行版本维护。";break;
                case "InterfaceUnavailable": networkHealth.Text="绑定网卡不可用，请等待原网络恢复或重新核验。";break;
                case "Maintenance": networkHealth.Text="专用组件正在维护，请等待核验完成。";break;
                case "Backoff": networkHealth.Text="专用代理启动重试过于频繁，守护将在退避后重试。";break;
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
            status.Text=reason+"\n"+(IsClaudeOpen()?"当前会话保留；恢复后状态会自动更新。":"检查通过后才能打开 Claude。恢复后可重新检查。");
            status.ForeColor=Color.FromArgb(163,59,42);
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
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr window);
    [DllImport("user32.dll")] static extern bool ShowWindowAsync(IntPtr window,int command);
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr window);
    public static bool TryActivateWindow(int pid) {
        try {using(var p=Process.GetProcessById(pid)){
            IntPtr handle=p.MainWindowHandle;if(handle==IntPtr.Zero)return false;
            if(IsIconic(handle))ShowWindowAsync(handle,9);
            return SetForegroundWindow(handle);
        }}catch{return false;}
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
        if(h.Status=="UpstreamUnavailable" || (h.Status=="Checking" && h.ConsecutiveFailures>0)) {
            DateTimeOffset next;
            string retry=DateTimeOffset.TryParse(h.NextProbe,out next) && next>now?"下次重试 "+next.ToLocalTime().ToString("HH:mm:ss")+"。":"后台正在重试。";
            return "固定节点连接检查失败，"+retry+"请检查节点服务和网络。";
        }
        if(h.Status=="Backoff")return "专用代理启动重试过于频繁，后台正在退避重试。";
        if(h.Status=="InterfaceUnavailable")return "绑定网卡不可用，请恢复原网络后重新检查。";
        if(h.Status=="UpgradeRequired")return "Claude 版本已变化，请退出客户端后进行版本维护。";
        if(h.Status!="Healthy" && h.Status!="ProbeDegraded")return "后台守护检查尚未完成，正在等待自动恢复。";
        if(!DateTimeOffset.TryParse(h.SupervisorStarted,out started) || !DateTimeOffset.TryParse(h.LastSafetyCheck,out safety) || !DateTimeOffset.TryParse(h.LastEgressCheck,out egress) ||
            safety<started || egress<started || (now-safety).TotalSeconds < -5 || (now-safety).TotalSeconds>120 || (now-egress).TotalSeconds < -5 || (now-egress).TotalSeconds>120)
            return "本次守护检查未完成或已过期，正在等待恢复。";
        string[] expected=d.ExpectedIps??new string[]{d.ExpectedIp};
        var e=h.LastVerifiedEgress;if(expected.Length==0 || Array.Exists(expected,delegate(string ip){System.Net.IPAddress parsed;return !System.Net.IPAddress.TryParse(ip,out parsed);}) || e==null || e.VerifiedProbeCount<1 ||
            (!String.IsNullOrEmpty(e.CloudflareIp) && Array.IndexOf(expected,e.CloudflareIp)<0) || (!String.IsNullOrEmpty(e.IpifyIp) && Array.IndexOf(expected,e.IpifyIp)<0) ||
            (Array.IndexOf(expected,e.CloudflareIp)<0 && Array.IndexOf(expected,e.IpifyIp)<0))return "本次核准节点出口尚未确认，请重新检查。";
        return null;
    }
    async Task RunAction(string action) {
        if(actionBusy)return;
        actionBusy=true;activeActionKind=action;if(action=="Update")maintenanceRequestStarted=DateTimeOffset.UtcNow;else observedMaintenanceId=null;
        string actionId=Guid.NewGuid().ToString("N");activeActionId=actionId;guardWarning=false;
        launch.Enabled=check.Enabled=login.Enabled=maintenance.Enabled=false;
        lastSuccessMessage=null;
        status.ForeColor=Color.FromArgb(70,79,91); status.Text=action=="Update"?"正在核验官方版本和防护配置……\nWindows 提示管理员授权时，请核对后允许。":action=="Start"?"正在检查专用网络与客户端运行环境……\n核验本次启动后会显示结果。":"正在核验专用网络和防护状态……";
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
                        if(parsed==null || parsed.ActionId!=actionId || (parsed.Success && (!parsed.SupervisorVerified || (action=="Start" && (!parsed.RuntimeVerified || parsed.DesktopPid.GetValueOrDefault()<=0)))) || (p.ExitCode!=0 && parsed.Success)) throw new InvalidOperationException("后台结果不一致。");
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
            if(result.RiskScore!=null)ApplyRiskScoreView(result.RiskScore);
            if(result.FailureKind=="NetworkRiskBlocked")status.Text=result.Message+"\n请点击下方“一键防泄露修复”或调高门限后再次打开。";
            if(result.Success) {
                lastSuccessMessage=result.Message;RunApiDiagnostic(actionId);
                if(action=="Start")TryActivateWindow(result.DesktopPid.Value);
            }
            RefreshClientState();
        } catch { status.Text="安全检查未能完成，暂时无法确认启动状态。\n请查看说明后重新检查。";status.ForeColor=Color.FromArgb(163,59,42); }
        finally {actionBusy=false;activeActionKind=null;if(!IsDisposed){launch.Enabled=check.Enabled=login.Enabled=maintenance.Enabled=true;RefreshClientState();RefreshNetworkHealth();RefreshDesktopUpdate();}}
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
    static string RuntimeModeFromIndex(int idx) {
        switch(idx) {
            case 1: return "StrictTerminate";
            case 2: return "WarnOnly";
            case 3: return "Disabled";
            default: return "AutoHealAndWarn";
        }
    }
    static int RuntimeModeToIndex(string mode) {
        if(mode=="StrictTerminate")return 1;
        if(mode=="WarnOnly")return 2;
        if(mode=="Disabled")return 3;
        return 0;
    }
    void ApplyRiskScoreView(RiskScoreResult risk) {
        if(risk==null || IsDisposed)return;
        suppressGateEvents=true;
        try {
            gateToggle.Checked=risk.GateEnabled;
            int t=Math.Max(0,Math.Min(100,risk.Threshold));
            if((int)thresholdInput.Value!=t)thresholdInput.Value=t;
            thresholdInput.Enabled=risk.GateEnabled;
            int mIdx=RuntimeModeToIndex(risk.RuntimeEnforcementMode);
            if(runtimeModeBox.SelectedIndex!=mIdx)runtimeModeBox.SelectedIndex=mIdx;
            if(risk.WatchIntervalSeconds>=10 && risk.WatchIntervalSeconds<=300 && riskWatchTimer.Interval!=risk.WatchIntervalSeconds*1000){
                riskWatchTimer.Interval=risk.WatchIntervalSeconds*1000;
            }
        } finally { suppressGateEvents=false; }
        string gateDesc=risk.GateEnabled?("门限 ≤ "+risk.Threshold):"门禁关";
        riskBadgeLabel.Text=String.Format("风险 {0} · {1} | {2}",risk.Score,risk.Grade??"--",gateDesc);
        if(!risk.GateEnabled) {
            riskBadgeLabel.BackColor=Color.FromArgb(241,245,249);
            riskBadgeLabel.ForeColor=TextSecondary;
        } else if(risk.PassedGate) {
            riskBadgeLabel.BackColor=Color.FromArgb(220,252,231);
            riskBadgeLabel.ForeColor=Color.FromArgb(24,106,65);
        } else {
            riskBadgeLabel.BackColor=Color.FromArgb(254,226,226);
            riskBadgeLabel.ForeColor=Color.FromArgb(163,59,42);
        }
        string topDesc=(risk.TopRisks!=null && risk.TopRisks.Length>0)?(" | 扣分: "+String.Join("、",risk.TopRisks)):"";
        if(!String.IsNullOrEmpty(risk.RuntimeAlertMessage) && (risk.RuntimeStatus=="AutoHealed" || risk.RuntimeStatus=="Breached" || risk.RuntimeStatus=="TerminatedOnBreach" || risk.RuntimeStatus=="DegradedWithinGate")) {
            riskSummaryLabel.Text=risk.RuntimeAlertMessage;
        } else {
            string stateLabel=risk.GateEnabled?(risk.PassedGate?(risk.DynamicWatchEnabled?"允许启动 · 动态巡检中":"允许启动"):"超出门限 "+risk.Threshold+"，已拦截启动"):"门禁关闭";
            riskSummaryLabel.Text=String.Format("非 TUN 风险分: {0} / 100 ({1} 级) · {2}{3}",risk.Score,risk.Grade??"--",stateLabel,topDesc);
        }
        riskSummaryLabel.ForeColor=(!risk.GateEnabled || risk.PassedGate)?(risk.Score<=8 || risk.RuntimeStatus=="AutoHealed"?Color.FromArgb(24,106,65):TextPrimary):Color.FromArgb(163,59,42);
        if(risk.TerminatedProtectedProcesses && !actionBusy) {
            status.Text=risk.RuntimeAlertMessage+"\n请点击下方“一键防泄露修复”恢复网络环境后再重新打开 Claude。";
            status.ForeColor=Color.FromArgb(163,59,42);
            RefreshClientState();
        } else if(risk.RuntimeStatus=="Breached" && IsClaudeOpen() && !actionBusy) {
            status.Text=risk.RuntimeAlertMessage+"\n当前 Claude 仍在运行，建议立即点击下方“一键防泄露修复”消除暴露风险！";
            status.ForeColor=Color.FromArgb(163,59,42);
        }
        Invalidate();
    }
    async Task PollRuntimeRiskWatchAsync() {
        if(riskWatchBusy || actionBusy || updateDispatchBusy || IsDisposed || PreviewOnly)return;
        if(runtimeModeBox.SelectedIndex==3)return;
        riskWatchBusy=true;
        try {
            var res=await RunNetworkEnvBridge("NetworkEnvRuntimeWatch","Auto",null,false,-1,null,null);
            if(!IsDisposed && res!=null && res.RiskScore!=null)ApplyRiskScoreView(res.RiskScore);
        } catch {} finally { riskWatchBusy=false; }
    }
    async Task RefreshRiskScoreAsync(bool checkConnectivity) {
        try {
            refreshScoreButton.Enabled=false;
            var res=await RunNetworkEnvBridge("NetworkEnvRuntimeWatch","Auto",null,checkConnectivity,-1,null,null);
            if(!IsDisposed && res!=null && res.RiskScore!=null)ApplyRiskScoreView(res.RiskScore);
        } catch {} finally { if(!IsDisposed)refreshScoreButton.Enabled=true; }
    }
    async Task SaveRiskGateConfigAsync() {
        try {
            string mode=RuntimeModeFromIndex(runtimeModeBox.SelectedIndex);
            var res=await RunNetworkEnvBridge("NetworkEnvSetGate","Auto",null,false,(int)thresholdInput.Value,gateToggle.Checked,mode);
            if(!IsDisposed && res!=null && res.RiskScore!=null)ApplyRiskScoreView(res.RiskScore);
        } catch {}
    }
    async Task RunQuickNetworkFixAsync() {
        quickFixButton.Enabled=false;refreshScoreButton.Enabled=false;
        try {
            var res=await RunNetworkEnvBridge("NetworkEnvAutoFix","Auto",null,false,-1,null,null);
            if(IsDisposed)return;
            if(res!=null) {
                if(res.RiskScore!=null)ApplyRiskScoreView(res.RiskScore);
                if(!res.Success && !actionBusy) {
                    status.Text=String.IsNullOrEmpty(res.Message)?"一键防泄露修复未完成，请点击“网络优化”查看详情。":res.Message;
                    status.ForeColor=res.FailureKind=="AdministratorCancelled"?Color.FromArgb(145,99,20):Color.FromArgb(163,59,42);
                } else if(res.RiskScore!=null && res.RiskScore.PassedGate && !actionBusy) {
                    status.Text="已完成一键防泄露修复，当前风险评分 "+res.RiskScore.Score+" / 100 ("+res.RiskScore.Grade+" 级)，已低于门限 "+res.RiskScore.Threshold+"。\n请重启已打开的浏览器；现在可点击“打开 Claude”。";
                    status.ForeColor=Color.FromArgb(24,106,65);
                } else if(res.RiskScore!=null && !res.RiskScore.PassedGate && !actionBusy) {
                    status.Text="已写入防泄露策略，当前风险分 "+res.RiskScore.Score+" / 100 仍高于门限 "+res.RiskScore.Threshold+"，请点“网络优化”查看其余风险项。";
                    status.ForeColor=Color.FromArgb(145,99,20);
                }
            }
        } catch {} finally { if(!IsDisposed){quickFixButton.Enabled=true;refreshScoreButton.Enabled=true;} }
    }
    async Task<UiResult> RunNetworkEnvBridge(string action, string proxyMode, string targetUrl, bool checkConnectivity, int threshold, bool? gateEnabled, string runtimeMode) {
        return await Task.Run(delegate {
            string file = Path.Combine(root, "private", "ui-result-" + Guid.NewGuid().ToString("N") + ".json");
            try {
                var sb = new StringBuilder();
                sb.Append("-NoProfile -ExecutionPolicy Bypass -File \"").Append(Path.Combine(root, "ClaudeGuard-UiBridge.ps1")).Append("\"");
                sb.Append(" -Action ").Append(action);
                sb.Append(" -ActionId ").Append(Guid.NewGuid().ToString("N"));
                sb.Append(" -ResultFile \"").Append(file).Append("\"");
                if (!String.IsNullOrEmpty(proxyMode)) sb.Append(" -ProxyMode ").Append(proxyMode);
                if (!String.IsNullOrEmpty(targetUrl)) sb.Append(" -TargetUrl \"").Append(targetUrl.Replace("\"", "")).Append("\"");
                if (checkConnectivity) sb.Append(" -CheckConnectivity");
                if (threshold >= 0) sb.Append(" -Threshold ").Append(threshold);
                if (gateEnabled.HasValue) sb.Append(" -GateEnabled ").Append(gateEnabled.Value ? "True" : "False");
                if (!String.IsNullOrEmpty(runtimeMode)) sb.Append(" -RuntimeEnforcementMode ").Append(runtimeMode);
                var psi = new ProcessStartInfo(shell) {
                    UseShellExecute = false,
                    CreateNoWindow = true,
                    WorkingDirectory = root,
                    Arguments = sb.ToString()
                };
                using (var p = Process.Start(psi)) {
                    if (!p.WaitForExit(120000)) {
                        if (!p.HasExited) p.Kill();
                        return new UiResult { Success = false, Message = "网络环境操作超时，请稍后重试。" };
                    }
                    if (!File.Exists(file)) return new UiResult { Success = false, Message = "未取得网络环境检查结果。" };
                    return new JavaScriptSerializer().Deserialize<UiResult>(ReadSharedText(file));
                }
            } finally {
                if (File.Exists(file)) File.Delete(file);
            }
        });
    }
    void ShowNetworkEnvDialog() {
        using (var dlg = new Form {
            Text = "非 TUN 网络环境评分与优化 · " + BuildVersion,
            ClientSize = new Size(808, 560),
            StartPosition = FormStartPosition.CenterParent,
            FormBorderStyle = FormBorderStyle.FixedDialog,
            MaximizeBox = false,
            MinimizeBox = false,
            Font = new Font("Microsoft YaHei UI", 9.5f),
            BackColor = CanvasBg,
            ForeColor = TextPrimary
        }) {
            var scoreCard = new Panel {
                Location = new Point(18, 16),
                Size = new Size(772, 92),
                BackColor = CardBg,
                BorderStyle = BorderStyle.FixedSingle
            };
            var bigScore = new Label {
                Text = "--",
                Location = new Point(16, 12),
                Size = new Size(72, 48),
                Font = new Font("Microsoft YaHei UI", 24f, FontStyle.Bold),
                ForeColor = BrandIndigo,
                TextAlign = ContentAlignment.MiddleCenter
            };
            var gradePill = new Label {
                Text = "评级 --",
                Location = new Point(16, 62),
                Size = new Size(72, 22),
                Font = new Font("Microsoft YaHei UI", 8.5f, FontStyle.Bold),
                BackColor = Color.FromArgb(241, 245, 249),
                ForeColor = TextSecondary,
                TextAlign = ContentAlignment.MiddleCenter
            };
            var scoreHeadline = new Label {
                Text = "正在检测非 TUN 网络环境评分与门禁状态……",
                Location = new Point(102, 16),
                Size = new Size(654, 24),
                Font = new Font("Microsoft YaHei UI", 10.5f, FontStyle.Bold),
                ForeColor = TextPrimary,
                AutoEllipsis = true
            };
            var modeLabel = new Label { Text = "代理:", Location = new Point(102, 52), AutoSize = true, ForeColor = TextSecondary };
            var modeBox = new ComboBox { Location = new Point(144, 48), Width = 96, DropDownStyle = ComboBoxStyle.DropDownList };
            modeBox.Items.AddRange(new object[] { "Auto", "Dedicated", "Shared" });
            modeBox.SelectedIndex = 0;
            var urlLabel = new Label { Text = "检测页:", Location = new Point(250, 52), AutoSize = true, ForeColor = TextSecondary };
            var urlBox = new ComboBox { Location = new Point(304, 48), Width = 264, DropDownStyle = ComboBoxStyle.DropDown };
            urlBox.Items.AddRange(new object[] { "https://ipkk.com/claude-ip-check", "https://claude.ai", "https://chatgpt.com" });
            urlBox.Text = "https://ipkk.com/claude-ip-check";
            var connCheck = new CheckBox { Text = "实测连通性", Location = new Point(580, 50), AutoSize = true, ForeColor = TextSecondary };
            var btnRefresh = new Button { Text = "刷新评分", Location = new Point(682, 46), Size = new Size(78, 30) };
            StyleAccentOutlineButton(btnRefresh, BrandIndigo);
            scoreCard.Controls.AddRange(new Control[] { bigScore, gradePill, scoreHeadline, modeLabel, modeBox, urlLabel, urlBox, connCheck, btnRefresh });

            var breakdownList = new ListView {
                Location = new Point(18, 120),
                Size = new Size(772, 198),
                View = View.Details,
                FullRowSelect = true,
                GridLines = true,
                BackColor = CardBg,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Microsoft YaHei UI", 9f)
            };
            breakdownList.Columns.Add("状态", 62);
            breakdownList.Columns.Add("检查维度", 140);
            breakdownList.Columns.Add("扣分", 54);
            breakdownList.Columns.Add("详情与优化建议", 492);

            var outputBox = new TextBox {
                Location = new Point(18, 328),
                Size = new Size(772, 130),
                Multiline = true,
                ReadOnly = true,
                ScrollBars = ScrollBars.Vertical,
                BackColor = CardBg,
                BorderStyle = BorderStyle.FixedSingle,
                Font = new Font("Consolas", 9f),
                ForeColor = TextSecondary,
                Text = "正在运行非 TUN 基线与评分分析，请稍候……"
            };

            var btnAutoFix = new Button { Text = "一键修复防泄露", Location = new Point(18, 468), Size = new Size(132, 34) };
            var btnEnablePolicy = new Button { Text = "仅写浏览器策略", Location = new Point(158, 468), Size = new Size(124, 34) };
            var btnRestorePolicy = new Button { Text = "还原策略", Location = new Point(290, 468), Size = new Size(88, 34) };
            var btnSafeBrowser = new Button { Text = "打开隔离检测浏览器", Location = new Point(386, 468), Size = new Size(156, 34) };
            var btnCliTerminal = new Button { Text = "打开 CLI 代理终端", Location = new Point(18, 510), Size = new Size(146, 34) };
            var btnCliUserSet = new Button { Text = "写入用户级 CLI 代理", Location = new Point(172, 510), Size = new Size(158, 34) };
            var btnCliUserClear = new Button { Text = "清除用户级 CLI 代理", Location = new Point(338, 510), Size = new Size(158, 34) };
            var btnRuntimeWatch = new Button { Text = "立即动态巡检", Location = new Point(504, 510), Size = new Size(124, 34) };
            var btnClose = new Button { Text = "关闭", Location = new Point(698, 510), Size = new Size(92, 34), DialogResult = DialogResult.Cancel };
            StylePrimaryButton(btnAutoFix, Color.FromArgb(22, 163, 74));
            StyleSecondaryButton(btnEnablePolicy);
            StyleSecondaryButton(btnRestorePolicy);
            StyleAccentOutlineButton(btnSafeBrowser, BrandIndigo);
            StyleSecondaryButton(btnCliTerminal);
            StyleSecondaryButton(btnCliUserSet);
            StyleSecondaryButton(btnCliUserClear);
            StyleAccentOutlineButton(btnRuntimeWatch, BrandTeal);
            StyleSecondaryButton(btnClose);

            var actionButtons = new Button[] { btnRefresh, btnAutoFix, btnEnablePolicy, btnRestorePolicy, btnSafeBrowser, btnCliTerminal, btnCliUserSet, btnCliUserClear, btnRuntimeWatch };
            Action<bool> setBusy = delegate(bool busy) {
                foreach (var b in actionButtons) b.Enabled = !busy;
            };
            Action<RiskScoreResult> renderDialogRisk = delegate(RiskScoreResult risk) {
                if (risk == null) return;
                bigScore.Text = risk.Score.ToString();
                gradePill.Text = "评级 " + (risk.Grade ?? "--");
                if (risk.PassedGate) {
                    bigScore.ForeColor = Color.FromArgb(24, 106, 65);
                    gradePill.BackColor = Color.FromArgb(220, 252, 231);
                    gradePill.ForeColor = Color.FromArgb(24, 106, 65);
                } else {
                    bigScore.ForeColor = Color.FromArgb(163, 59, 42);
                    gradePill.BackColor = Color.FromArgb(254, 226, 226);
                    gradePill.ForeColor = Color.FromArgb(163, 59, 42);
                }
                string headline = risk.Summary ?? "";
                if (!String.IsNullOrEmpty(risk.RuntimeAlertMessage)) headline = risk.RuntimeAlertMessage + " | " + headline;
                scoreHeadline.Text = headline;
                breakdownList.BeginUpdate();
                breakdownList.Items.Clear();
                if (risk.Breakdown != null) {
                    foreach (var item in risk.Breakdown) {
                        var row = new ListViewItem(item.Status ?? "");
                        row.SubItems.Add(item.Label ?? "");
                        row.SubItems.Add(item.Points > 0 ? "+" + item.Points : "0");
                        string detail = item.Detail ?? "";
                        if (!String.IsNullOrEmpty(item.FixHint) && item.Points > 0) detail += " [建议: " + item.FixHint + "]";
                        row.SubItems.Add(detail);
                        if (item.Status == "Risk") row.ForeColor = Color.FromArgb(163, 59, 42);
                        else if (item.Status == "Warn") row.ForeColor = Color.FromArgb(145, 99, 20);
                        else if (item.Status == "Pass") row.ForeColor = Color.FromArgb(24, 106, 65);
                        else row.ForeColor = TextMuted;
                        breakdownList.Items.Add(row);
                    }
                }
                breakdownList.EndUpdate();
                ApplyRiskScoreView(risk);
            };
            Func<string, Task> invokeAction = async delegate(string act) {
                setBusy(true);
                try {
                    var res = await RunNetworkEnvBridge(act, Convert.ToString(modeBox.SelectedItem), urlBox.Text.Trim(), connCheck.Checked, -1, null, null);
                    if (!dlg.IsDisposed) {
                        string msg = (res != null && !String.IsNullOrEmpty(res.Message)) ? res.Message : "操作已完成。";
                        outputBox.Text = msg.Replace("\r\n", "\n").Replace("\n", Environment.NewLine);
                        if (res != null && res.RiskScore != null) renderDialogRisk(res.RiskScore);
                    }
                } catch (Exception ex) {
                    if (!dlg.IsDisposed) outputBox.Text = "执行异常：" + ex.Message;
                } finally {
                    if (!dlg.IsDisposed) setBusy(false);
                }
            };

            btnRefresh.Click += async delegate { await invokeAction("NetworkEnvCheck"); };
            btnAutoFix.Click += async delegate { await invokeAction("NetworkEnvAutoFix"); };
            btnEnablePolicy.Click += async delegate { await invokeAction("NetworkEnvEnablePolicy"); };
            btnRestorePolicy.Click += async delegate { await invokeAction("NetworkEnvRestorePolicy"); };
            btnSafeBrowser.Click += async delegate { await invokeAction("NetworkEnvLaunchSafeBrowser"); };
            btnCliTerminal.Click += async delegate { await invokeAction("NetworkEnvCliTerminal"); };
            btnCliUserSet.Click += async delegate { await invokeAction("NetworkEnvCliEnable"); };
            btnCliUserClear.Click += async delegate { await invokeAction("NetworkEnvCliClear"); };
            btnRuntimeWatch.Click += async delegate { await invokeAction("NetworkEnvRuntimeWatch"); };

            dlg.Controls.AddRange(new Control[] {
                scoreCard, breakdownList, outputBox,
                btnAutoFix, btnEnablePolicy, btnRestorePolicy, btnSafeBrowser,
                btnCliTerminal, btnCliUserSet, btnCliUserClear, btnRuntimeWatch, btnClose
            });
            dlg.Shown += async delegate { await invokeAction("NetworkEnvCheck"); };
            dlg.ShowDialog(this);
        }
    }
    public class UiResult {public bool Pending {get;set;}public string OperationId {get;set;} public bool Success {get;set;} public string Message {get;set;} public bool SessionVerified {get;set;} public bool SupervisorVerified {get;set;} public bool RuntimeVerified {get;set;} public int? DesktopPid {get;set;} public string FailureKind {get;set;} public string ActionId {get;set;} public ApiResult ApiTransport {get;set;} public RiskScoreResult RiskScore {get;set;} }
    public class RiskScoreResult {public int Score {get;set;} public string Grade {get;set;} public int Threshold {get;set;} public bool GateEnabled {get;set;} public bool PassedGate {get;set;} public bool DynamicWatchEnabled {get;set;} public int WatchIntervalSeconds {get;set;} public bool AutoHealOnDegrade {get;set;} public string RuntimeEnforcementMode {get;set;} public string RuntimeStatus {get;set;} public string RuntimeAlertMessage {get;set;} public string[] AutoHealedItems {get;set;} public string[] DegradedItems {get;set;} public bool TerminatedProtectedProcesses {get;set;} public int TerminatedProcessCount {get;set;} public string[] TopRisks {get;set;} public string Summary {get;set;} public RiskBreakdownItem[] Breakdown {get;set;} }
    public class RiskBreakdownItem {public string Id {get;set;} public string Label {get;set;} public int Points {get;set;} public int MaxPoints {get;set;} public string Status {get;set;} public string Detail {get;set;} public string FixHint {get;set;} }
    public class ApiResult {public int CurlExitCode {get;set;}}
    public class HealthResult { public int SchemaVersion {get;set;} public string Time {get;set;} public string Status {get;set;} public string Reason {get;set;} public string RunId {get;set;} public int HostPid {get;set;} public string HostStarted {get;set;} public int SupervisorPid {get;set;} public string SupervisorStarted {get;set;} public string LastSafetyCheck {get;set;} public string LastEgressCheck {get;set;} public EgressResult LastVerifiedEgress {get;set;} public int ConsecutiveFailures {get;set;} public string NextProbe {get;set;} }
    public class EgressResult {public int VerifiedProbeCount {get;set;}public string CloudflareIp {get;set;}public string IpifyIp {get;set;}}
    public class HostIdentity {public string RunId {get;set;} public int HostPid {get;set;} public string HostStarted {get;set;} public int SupervisorPid {get;set;} public string SupervisorStarted {get;set;}public string ShellPath {get;set;}public string ScriptPath {get;set;}}
    public class DeploymentResult {public ReliabilityResult Reliability {get;set;}public DesktopResult Desktop {get;set;}public CodeResult CodeGate {get;set;}public string ExpectedIp {get;set;}public string[] ExpectedIps {get;set;}}
    public class DesktopResult {public string Path {get;set;}public string Version {get;set;}}
    public class CodeResult {public string Version {get;set;}}
    public class ReliabilityResult {public string HostPath {get;set;}public string ShellPath {get;set;}public string SupervisorScript {get;set;}}
    public class MaintenanceResult {public int SchemaVersion {get;set;}public string ActionId {get;set;}public string StageId {get;set;}public string ResultFile {get;set;}public string Status {get;set;}public string Phase {get;set;}public string StartedAt {get;set;}public string CompletedAt {get;set;}public int CoordinatorPid {get;set;}public string CoordinatorStarted {get;set;}public string CoordinatorPath {get;set;}public int WorkerPid {get;set;}public string WorkerStarted {get;set;}public string WorkerPath {get;set;}public bool RecoveryRequired {get;set;}public bool SupervisorSuspended {get;set;}public string Reason {get;set;}public string FailureKind {get;set;}}
    public class MaintenanceView {public bool BlockStart;public bool Observe;public bool Recover;public bool Completed;public bool Failed;public bool Held;public string Message;}
    public class MigrationResult {public bool Success {get;set;}public string ActionId {get;set;}public string StageId {get;set;}public string DesktopVersion {get;set;}public string CodeVersion {get;set;}}
    public class RecoveryResult {public string NextRestart {get;set;}public string Reason {get;set;}}
    public class VersionResult {public int SchemaVersion {get;set;}public string InstalledDesktopVersion {get;set;}public string InstalledCodeVersion {get;set;}public string ApprovedCodeVersion {get;set;}public bool InstalledMatchesApproved {get;set;}public RuntimeVersion[] Runtime {get;set;}public CatalogResult Catalog {get;set;}public string UpdateDecision {get;set;}public string ToolVersion {get;set;}}
    public class RuntimeVersion {public string Version {get;set;}public string Identity {get;set;}}
    public class CatalogResult {public string Status {get;set;}public string CheckedAt {get;set;}public PublishedVersion LastSuccess {get;set;}}
    public class PublishedVersion {public string CheckedAt {get;set;}public string LatestDesktopVersion {get;set;}}
    public class DesktopUpdateResult {public int SchemaVersion {get;set;}public string Id {get;set;}public string Status {get;set;}public string TargetVersion {get;set;}public string PackageFile {get;set;}public long PackageBytes {get;set;}public string MaintenanceId {get;set;}public string Message {get;set;}public string FailureKind {get;set;}public string Signature {get;set;}public string PackageHash {get;set;}public int WorkerPid {get;set;}public string WorkerStarted {get;set;}public string WorkerPath {get;set;}}
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
        if(args.Length==1 && args[0]=="--status")window.StatusViewOnly=true;
        bool created;
        using(var single=new Mutex(true,"Local\\ClaudeProGuardLauncher-v1",out created)){
            if(!created){
                using(var self=Process.GetCurrentProcess()){
                    foreach(var other in Process.GetProcessesByName(self.ProcessName)){using(other){
                        try{if(other.Id!=self.Id && other.SessionId==self.SessionId &&
                            String.Equals(other.MainModule.FileName,Application.ExecutablePath,StringComparison.OrdinalIgnoreCase)){
                            ClaudeGuardWindow.TryActivateWindow(other.Id);break;
                        }}catch{}
                    }}
                }
                window.Dispose();return 0;
            }
            Application.Run(window);
        }
        return 0;
    }
}
