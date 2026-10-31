# 项目工作约定

## 迭代版本

- 本项目每次完成并验证通过的实现迭代都递增版本并追加一条 `.iteration-version.json` 记录；一次任务中的文件修改、失败重试及重复测试合计一次。只读排查、提问和纯说明勘误不递增。是否创建 Release 或 Git 标签不影响源码迭代登记。
- 开始实现前记录当前 `current_version`、`completed_iterations`、工作区既有改动及部署身份；将基线保存在本机 `private` 或 `evidence`。完成时默认新增一条，修复和工程治理使用 patch、新增兼容产品能力使用 minor、破坏兼容的变化使用 major。
- 使用 `$iteration-versioning`。若技能没有自动出现在清单中，读取 `$CODEX_HOME/skills/iteration-versioning/SKILL.md`；`CODEX_HOME` 未设置时读取 `~/.codex/skills/iteration-versioning/SKILL.md`。本文件的版本要求独立生效，不因技能缺失而略过。
- 同步台账、`ClaudeGuardLauncher.cs` 的 `BuildVersion` / AssemblyVersion / AssemblyFileVersion、README 当前版本、CHANGELOG 当前版本及对应条目、部署文档当前版本。保持台账历史 ID、原始内容和顺序；`PUBLICATION.json` 是首次公开快照，不随当前版本改写。
- 历史补登记仅在证据足够时进行：分别记录真实完成时间与本次登记时间，设置 `backfilled=true`，保留当时实际 EXE 版本，并引用证据；不能声称当时编译、发布过追溯分配的版本。
- 最后一条迭代记录保存 `source_fingerprint`。根目录源码和本文件的指纹变化而版本未登记时，版本检查必须失败；更新指纹应随新迭代追加记录，不得借更新旧指纹掩盖漏增版本。
- 公开脱敏导出可在同一条新迭代中另存 `public_source_fingerprint`，保留部署指纹及全部历史原文。检查只接受两份完整且精确匹配的已登记源码；未登记脱敏、混合副本或任一副本的后续改动仍须拒绝。Git 存档保留源码原始字节，避免换行转换破坏指纹。

## 完成与构建检查

- 交付前运行 `Test-ClaudeIterationVersion.ps1`。普通迭代同时传入 `-BaselineFile <本轮基线>`，默认要求版本前进且次数增加 1；仅经用户要求的历史补登记可指定已核实的 `-ExpectedNewIterations`。
- 编译后运行 `Test-ClaudeIterationVersion.ps1 -LauncherAssembly <实际 EXE>`，再核对安装后的 EXE 和真实窗口版本。`Test-ClaudeVersionWindow.ps1` 验证窗口显示，`Test-ClaudeSupervisorHealth.ps1 -LauncherAssembly <实际 EXE>` 验证健康契约。根据实际改动补充相关隔离回归，不批量运行生产故障注入脚本。
- 台账、源文件常量、当前文档、源码指纹或实际交付 EXE 不一致时，不能宣称迭代完成。验证失败保留明确状态和证据；不得仅更改界面数字或降低检查要求。
- 构建入口 `Build-ClaudeShortcut.ps1` 先执行源码版本一致性检查。版本检查脚本和测试本身也是源码，修改后纳入本轮指纹。

## 保持当前代理连续运行

- 只涉及版本、文档和入口时，保留代理、守护 RunId、代理配置、防火墙和部署核准状态。避免调用会停止计划任务整棵进程树的维护路径。
- `Build-ClaudeShortcut.ps1` 会同时构建宿主，且要求宿主停止；当前任务只更新入口时，使用 C# 编译器把 `ClaudeGuardLauncher.cs` 编译到 `private` 候选目录，保留现有图标，验证候选后只关闭、备份、原子替换入口 EXE，再以 `--status` 重开。代理和宿主均不重启。
- 对照修改前的代理 PID、启动时间、守护 RunId 和受保护文件哈希，并检查当次健康状态。候选或替换失败时恢复入口备份，不修改代理来绕过版本问题。
- `private`、`runtime`、`evidence` 中的本机原始材料不公开；保留用户已有未提交改动。完成后报告版本、迭代次数、实际 EXE/UI 核验和代理连续性结果。
