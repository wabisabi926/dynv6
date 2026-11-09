package main

import (
	"net"
	"strings"
)

// vpnInterfaceHint 识别 Tailscale/WireGuard/OpenVPN/Clash 等虚拟网卡。
// 只用于提示：如果启用了出口节点，探测到的公网 IP 可能是出口 IP，而不是家庭宽带 IP。
func vpnInterfaceHint() string {
	ifs, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 {
			continue
		}
		name := strings.ToLower(ifc.Name)
		for _, kw := range []string{"tailscale", "wireguard", "openvpn", "clash", "tun", "vpn"} {
			if strings.Contains(name, kw) {
				return ifc.Name
			}
		}
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ip, _, err := net.ParseCIDR(a.String())
			if err != nil || ip == nil {
				continue
			}
			if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
				return ifc.Name + "（100.64/10）"
			}
		}
	}
	return ""
}
