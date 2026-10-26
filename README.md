# Claude Code Protection Tool

面向 **Windows x64、Claude Desktop 及其本地 Code 会话**的桌面安全入口。项目提供专用代理、防火墙与执行门禁核验、后台守护、版本显示，以及官方 Desktop 和配套 Code 的受控更新。

当前源码基线：**v1.3.3 · 第 9 次源码迭代**。采用 [MIT 许可证](LICENSE)。本工具与 Anthropic 无隶属关系，不保证账号不受限制，也不改变服务的支持地区或使用政策。

本次源码同步包含 **2026-10-26 修复**：Desktop 3.x Code 缓存路径、未建立本机连接的守护误判、Xray 双节点兼容、入口出口状态误报和更新记录路径大小写问题。编译版本号仍为 v1.3.3，未另建 Release；具体证据及边界见 [验证记录](docs/VALIDATION.md)。

## 能力

- 启动前核对当前安装版本、签名、程序哈希、代理策略、防火墙及当次守护就绪状态。
- 为 Desktop 和其指定版本的本地 Code 使用独立配置与专用代理；检测异常时暂停受保护启动，保留可核查的原因。
- 独立后台宿主托管守护，提供有限恢复、异常退避、固定出口检查及日志脱敏。关闭入口不等于退出 Desktop/Code。
- 支持经核准的 Xray VLESS Reality 节点池，按连接检测选择可用节点，并核对出口白名单；保留旧 sing-box 单节点配置兼容性。节点须单独导入并核验，不会自动信任共享代理中的所有节点。
- 显示已安装 Desktop、该包配套 Code、已核准 Code，以及实际观察到的本地 Code 运行版本。
- 查询官方 Windows x64 MSIX 当前发布，下载并核验官方包及配套 Code；更高版本才允许安装，安装后接续防护迁移和守护核验。
- 保存维护操作身份和最终结果，支持入口关闭重开接续，区分等待、明确授权取消、中断、失败和完成。

v1.3.2 将必要的安装前维护、官方包安装和安装后防护核验接入同一次“安装并维护”操作，无需先手动维护再回来安装；健康状态下直接安装。入口按实际进程刷新“Claude 已打开 / 打开 Claude”，安装期间显示“更新进行中”。资源占用失败仍保留已核验包供重试。

这里管理的是 **Desktop 内嵌元数据指定版本的本地 Code**。独立 CLI、SSH、WSL、云端会话及其他设备不属于当前观察和保护范围。

## 仓库边界

这是经过公开边界整理的源码仓库。账号凭据、节点配置、浏览器数据、部署状态、安装包、编译程序和原始验收记录均在本机保留，不随 GitHub 源码同步发布。

`ClaudeGuard.psm1` 初始化段使用 `192.0.2.10` 与 `C:\Example\v2rayN` 示例。它们不是可用节点，不能直接照搬运行。[PUBLICATION.json](PUBLICATION.json) 记录首次 v1.3.0 导出的历史校验值及六处示例替换；后续源码修复以当前 Git 提交及 [验证记录](docs/VALIDATION.md) 为准。本机私有初始化配置和 Python 路径适配未同步到公开源码。

本仓库目前提供源码及开发者说明，**不是已经验收的通用一键安装包**。首次在其他机器部署，需要审查初始化参数、现有代理/策略、Code 缓存和防火墙，按 [部署说明](docs/DEPLOYMENT.md) 分阶段验收。不要把另一台机器的 `private` 目录复制过来使用。

## 环境与源码检查

需要 Windows x64、PowerShell 7.4 或更新版本、Node.js，以及 Windows 自带 .NET Framework C# 编译器。涉及进程环境读取的现场诊断还需要 Python 3。正式部署还需要官方 Claude Desktop、经本机核验的代理程序和同账号管理员授权。

克隆仓库后，在 PowerShell 7 中运行只使用隔离夹具的检查：

```powershell
git clone https://github.com/cr20085361/claude-code-protection-tool.git
Set-Location claude-code-protection-tool
New-Item -ItemType Directory -Path evidence,private -Force | Out-Null
pwsh -NoProfile -File .\Test-ClaudeDesktopUpdate.ps1
pwsh -NoProfile -File .\Test-ClaudeMaintenance.ps1
pwsh -NoProfile -File .\Test-ClaudeSupervisorHealth.ps1
pwsh -NoProfile -File .\Test-ClaudeLifecycle.ps1
pwsh -NoProfile -File .\Test-ClaudeVersionInfo.ps1
pwsh -NoProfile -File .\Test-ClaudeNodePool.ps1
```

上述检查运行临时夹具和编译测试程序，不执行真实 MSIX 安装或生产防火墙迁移。原生窗口夹具和真实桌面、网络、管理员测试另见 [验证记录与边界](docs/VALIDATION.md)。其他 `Test-*Native*`、恢复和故障注入脚本可能操作已部署的专用组件，不应批量运行全部测试脚本。

## 主要模块

| 模块 | 职责 |
|---|---|
| `ClaudeGuardLauncher.cs`、`ClaudeGuard-UiBridge.ps1` | Windows Forms 入口、启动与检查、维护进度 |
| `ClaudeGuard.psm1`、`ClaudeCodeGate.psm1` | 部署状态、代理策略、防火墙和 Code 执行门禁 |
| `ClaudeGuard-Lifecycle.ps1`、`ClaudeGuard-Health.ps1` | 操作关联、任务生命周期及当次守护就绪契约 |
| `ClaudeSupervisorHost.cs`、`ClaudeGuard-Supervisor-v2.ps1` | 独立宿主、守护、有限恢复及持久退避 |
| `ClaudeGuard-Runtime.psm1`、`Read-ClaudeProcessEnvironment.py` | 受保护进程身份、环境比较及连接核验 |
| `ClaudeGuard-VersionInfo.psm1`、`Get-ClaudeVersionInfo.ps1` | 安装和运行版本观察、官方发布查询 |
| `ClaudeGuard-DesktopUpdate.psm1`、`Invoke-ClaudeDesktopUpdate.ps1` | 官方包和配套 Code 下载核验、安装及维护接续 |
| `Update-ClaudeGuard.ps1` | 版本防护迁移、备份、回滚与恢复 |
| `Read-DesktopCodeManifest.cjs`、`Expand-VerifiedCode.cjs` | 读取官方包内元数据、验证并解压配套 Code |

版本沿革见 [CHANGELOG.md](CHANGELOG.md) 和 [.iteration-version.json](.iteration-version.json)。[PUBLICATION.json](PUBLICATION.json) 保留首次 v1.3.0 公开同步的历史校验值，后续修改不再与该快照逐字节一致。未创建安装包或 Release。

## 反馈与贡献

提交问题时请说明 Windows、Desktop/Code 和工具版本、操作步骤及脱敏后的状态提示。不要上传 `private`、浏览器用户目录、OAuth 链接、验证码、原始进程环境、节点订阅或含账号信息的日志。

修改核心安全门禁、生命周期、更新或回滚逻辑时，请提供对应隔离回归；真实桌面和跨机器结果分别报告，未运行的项目保留 `NOT_RUN`。
