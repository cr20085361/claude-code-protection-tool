#!/usr/bin/env bash
# VPS 服务端网络环境检查与非 TUN 优化脚本（默认仅做只读检查；传 --apply 才写入系统调优）
# 适用于 Debian / Ubuntu 等主流 Linux VPS（Claude / Codex / 代理节点通用）
set -euo pipefail

APPLY=0
if [[ "${1:-}" == "--apply" ]]; then
  APPLY=1
fi

echo "=== 1. TCP 拥塞控制与队列检查 ==="
cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "unknown")
qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "unknown")
echo "当前 tcp_congestion_control=$cc | default_qdisc=$qdisc"

if [[ "$APPLY" -eq 1 ]]; then
  if [[ "$EUID" -ne 0 ]]; then
    echo "错误：--apply 需要 root 权限。" >&2
    exit 1
  fi
  modprobe tcp_bbr 2>/dev/null || true
  cat >/etc/sysctl.d/99-claude-bbr.conf <<'EOF'
net.core.default_qdisc=fq
net.ipv4.tcp_congestion_control=bbr
EOF
  sysctl --system >/dev/null
  echo "已应用 BBR + fq：$(sysctl -n net.ipv4.tcp_congestion_control) / $(sysctl -n net.core.default_qdisc)"
else
  if [[ "$cc" != "bbr" || "$qdisc" != "fq" ]]; then
    echo "提示：建议开启 BBR + fq（可传 --apply 自动配置），以降低 TLS 握手延迟。"
  fi
fi

echo ""
echo "=== 2. VPS DNS 配置检查 (/etc/resolv.conf) ==="
grep -E '^nameserver' /etc/resolv.conf || echo "未在 /etc/resolv.conf 找到 nameserver"
echo "提示：确保代理出站使用干净的海外 DNS（如 1.1.1.1 / 8.8.8.8），避免 VPS 自身解析污染或地区异常。"

echo ""
echo "=== 3. IPv4 / IPv6 出站核验 ==="
v4=$(curl -4 -s --max-time 6 https://api.ipify.org || echo "unavailable")
v6=$(curl -6 -s --max-time 6 https://api64.ipify.org || echo "unavailable")
echo "公网 IPv4: $v4"
echo "公网 IPv6: $v6"
if [[ "$v6" != "unavailable" ]]; then
  echo "提示：VPS 存在公网 IPv6；若仅希望使用干净 IPv4 出口，建议在 Xray/sing-box 出站设置 ForceIPv4 / UseIPv4 并屏蔽 ::/0。"
fi

echo ""
echo "=== 4. UDP 出站转发检查 (STUN / WebRTC 代理必备) ==="
if command -v python3 >/dev/null 2>&1; then
  python3 - <<'PY'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
try:
    # 发送最小 DNS 查询包到 1.1.1.1:53 验证 VPS UDP 出站是否未被防火墙拦截
    pkt = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
    s.sendto(pkt, ("1.1.1.1", 53))
    data, _ = s.recvfrom(512)
    print(f"VPS UDP 出站探测成功 (收到 {len(data)} 字节响应)")
except Exception as e:
    print(f"VPS UDP 出站探测失败: {e}（请检查云安全组或本机防火墙 UDP 出站规则）")
finally:
    s.close()
PY
else
  echo "跳过 UDP 探测（未安装 python3）。"
fi

echo ""
echo "=== 5. 建议核查项（仅参考） ==="
echo "1) 使用真实家宽/静态住宅落地（或 Xray dialerProxy 链式代理）可进一步降低机房 ASN (is_idc) 风控。"
echo "2) 确保 Claude / Anthropic / OpenAI 域名走固定单一出口节点，勿使用自动测速切换节点。"
