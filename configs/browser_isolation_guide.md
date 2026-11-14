# 不开 TUN 模式下压低浏览器风控评分操作指南（阶段一 & 阶段二）

## 阶段一：抹平 TUN 分差（31 分 → ≤13 分）

在不开全局 TUN 虚拟网卡时，Windows 系统代理仅接管 HTTP/HTTPS TCP 流量，浏览器原生 WebRTC STUN UDP 探测与内置 DoH 可能绕过代理暴露中国真实 IP 或国内 DNS。

1. **开启防泄露策略（支持一键备份与还原）**：
   - 在「Claude Pro 安全入口」点击底部的 **「网络优化」 → 「开启防泄露策略」**；或运行：
     ```powershell
     pwsh -NoProfile -File .\Set-ClaudeWebRtcPolicy.ps1 -Enable
     ```
   - 写入的用户级策略位于 `HKCU:\Software\Policies\Google\Chrome` 与 `HKCU:\Software\Policies\Microsoft\Edge`：
     - `WebRtcIPHandling = "disable_non_proxied_udp"`（禁止未走代理的物理网卡 UDP 探测）
     - `DnsOverHttpsMode = "off"`（禁止内置 DoH 绕过代理）
     - `BuiltInDnsClientEnabled = 0`（禁用内置异步 DNS 解析器）
   - 若要随时还原：`pwsh -NoProfile -File .\Set-ClaudeWebRtcPolicy.ps1 -Restore`。

2. **使用显式 SOCKS5 隔离浏览器**：
   - 点击 **「打开隔离检测浏览器」** 或运行：
     ```powershell
     pwsh -NoProfile -File .\Start-ClaudeSafeBrowser.ps1 -Url https://ipkk.com/claude-ip-check
     ```
   - 该启动器使用 `--proxy-server=socks5://127.0.0.1:<Port>`（使 Chromium 将域名解析交由 SOCKS5 远端代理完成）、`--disable-quic`、`--lang=en-US` 与独立缓存目录 `browser-safe-profile/`。
   - **关于 10818 与 10808 的差异**：
     - 若代理端口开启了 UDP 转发（如本机 `10808`），WebRTC STUN 会通过 SOCKS5 UDP 返回 **VPS 出口 IP**（完全等效于开启 TUN）。
     - 若代理端口为 `udp=false`（如 `10818` 专用守护默认配置），`disable_non_proxied_udp` 会直接阻断 STUN 泄露真实 IP，同样消除 18 分 WebRTC 受限地区扣分。

---

## 阶段二：消除时区与字体弱线索（13 分 → 2~5 分 A+ 极低风险）

`ipkk.com` 检测中剩余约 11 分扣分通常来自：
1. 浏览器时区（`UTC+8`）与美国/海外 VPS 所在国家不一致；
2. Windows 系统预装的 `SimHei`、`SimSun`、`Microsoft YaHei` 等 20 种常见中文字体。

### 方式 A：轻量本地增强（Windows 宿主机）
- 仅在专用隔离浏览器 `browser-safe-profile` 中搭配时区校准（例如切换系统时区至 VPS 所在地区，或使用仅作用于隔离窗口的时区扩展），避免影响日常账号。

### 方式 B：彻底 0 中文字体容器浏览器（Docker `linuxserver/chromium`）
若本机已安装 Docker Desktop，可启动一个**完全无中文字体且时区对齐 VPS**的独立浏览器容器，只映射本地代理端口即可达到 2~5 分（A+）：

```yaml
# docker-compose.yml 参考（以美西洛杉矶 VPS、本机代理端口 10808 为例）
services:
  claude-browser:
    image: lscr.io/linuxserver/chromium:latest
    container_name: claude-safe-browser
    security_opt:
      - seccomp:unconfined
    environment:
      - PUID=1000
      - PGID=1000
      - TZ=America/Los_Angeles
      - CHROME_CLI=--proxy-server=socks5://host.docker.internal:10808 --proxy-bypass-list=localhost;127.0.0.1 --disable-quic --lang=en-US
    ports:
      - "127.0.0.1:3000:3000"
    shm_size: "1gb"
    restart: unless-stopped
```

> 注：若使用 `host.docker.internal:10808`，需在对应共享代理客户端中仅在必要时允许局域网/Docker 网段连接，切勿将代理端口暴露到公网。

---

## 阶段三：Claude Code / Codex 终端代理与出口稳定性要点

1. **禁止节点自动测速切换 (`url-test`)**：`claude.ai`、`anthropic.com`、`openai.com`、`chatgpt.com` 必须绑定固定单一出口节点，避免会话/OAuth 期间出口 IP 跳变触发账号风控。
2. **终端 CLI 注入代理**：独立终端中的 `claude` 与 `codex` 默认不读取 Windows 系统代理，推荐使用：
   ```powershell
   # 启动已注入代理的 claude 或 codex
   pwsh -NoProfile -File .\Set-ClaudeCliProxy.ps1 -Scope Launch -Command claude -Verify
   pwsh -NoProfile -File .\Set-ClaudeCliProxy.ps1 -Scope Launch -Command codex -Verify
   ```
   或直接打印 PowerShell 环境变量片段并在当前终端执行：
   ```powershell
   pwsh -NoProfile -File .\Set-ClaudeCliProxy.ps1 -PrintSnippet
   ```
