//go:build linux

package platform

import (
	"bufio"
	"encoding/binary"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	procRoutePath = "/proc/net/route"
	procARPPath   = "/proc/net/arp"
	resolvPath    = "/etc/resolv.conf"
	// systemd-resolved lists the real upstream servers here, while
	// /etc/resolv.conf only points at its 127.0.0.53 stub.
	resolvedPath = "/run/systemd/resolve/resolv.conf"

	rtfUp      = 0x1
	rtfGateway = 0x2
)

func DiscoverNetworkInfo() (NetworkInfo, error) {
	var info NetworkInfo

	route, err := os.ReadFile(procRoutePath)
	if err != nil {
		return info, err
	}
	gw, ifname, ok := parseDefaultRoute(string(route))
	if !ok {
		return info, nil
	}
	info.GatewayIP = gw
	info.InterfaceName = ifname

	if iface, err := net.InterfaceByName(ifname); err == nil {
		info.InterfaceIndex = uint32(iface.Index)
		info.IsVPN = isVPNInterface(ifname, iface.Flags)
		info.LocalIP = firstIPv4(iface)
	}
	info.GatewayMAC = ResolveMAC(gw)

	info.SystemResolvers = readResolvers()
	return info, nil
}

func readResolvers() []string {
	// Prefer the real upstreams when systemd-resolved is in charge.
	if data, err := os.ReadFile(resolvedPath); err == nil {
		if r := parseResolvConf(string(data)); len(r) > 0 {
			return r
		}
	}
	data, err := os.ReadFile(resolvPath)
	if err != nil {
		return nil
	}
	return parseResolvConf(string(data))
}

// parseDefaultRoute returns the gateway and interface of the lowest-metric
// default route in /proc/net/route text.
func parseDefaultRoute(table string) (net.IP, string, bool) {
	var (
		bestGW     net.IP
		bestIf     string
		bestMetric = -1
	)
	sc := bufio.NewScanner(strings.NewReader(table))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 8 || f[1] != "00000000" || f[7] != "00000000" {
			continue
		}
		flags, err := strconv.ParseUint(f[3], 16, 32)
		if err != nil || flags&rtfUp == 0 || flags&rtfGateway == 0 {
			continue
		}
		gw, err := parseHexIPv4(f[2])
		if err != nil || gw.IsUnspecified() {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		if bestMetric < 0 || metric < bestMetric {
			bestMetric, bestGW, bestIf = metric, gw, f[0]
		}
	}
	return bestGW, bestIf, bestGW != nil
}

// /proc/net/route stores addresses as host-order hex of a little-endian word.
func parseHexIPv4(s string) (net.IP, error) {
	v, err := strconv.ParseUint(s, 16, 32)
	if err != nil {
		return nil, err
	}
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, uint32(v))
	return net.IP(b), nil
}

// parseResolvConf returns the IPv4 nameservers listed in resolv.conf text,
// skipping loopback stubs.
func parseResolvConf(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 2 || f[0] != "nameserver" {
			continue
		}
		ip := net.ParseIP(f[1])
		if ip == nil || ip.To4() == nil || ip.IsLoopback() || ip.IsUnspecified() {
			continue
		}
		out = append(out, ip.String())
	}
	return out
}

// parseARPTable finds the MAC for ip in /proc/net/arp text.
func parseARPTable(table, ip string) string {
	sc := bufio.NewScanner(strings.NewReader(table))
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 4 || f[0] != ip {
			continue
		}
		// Flags 0x0 means an incomplete entry.
		if f[2] == "0x0" || f[3] == "00:00:00:00:00:00" {
			return ""
		}
		return strings.ToUpper(f[3])
	}
	return ""
}

func ResolveMAC(ip net.IP) string {
	ip4 := ip.To4()
	if ip4 == nil {
		return ""
	}
	data, err := os.ReadFile(procARPPath)
	if err != nil {
		return ""
	}
	return parseARPTable(string(data), ip4.String())
}

func firstIPv4(iface *net.Interface) net.IP {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil
	}
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok && n.IP.To4() != nil {
			return n.IP.To4()
		}
	}
	return nil
}

func isVPNInterface(name string, flags net.Flags) bool {
	if flags&net.FlagPointToPoint != 0 {
		return true
	}
	for _, p := range []string{"tun", "tap", "wg", "ppp", "ipsec", "tailscale", "zt"} {
		if strings.HasPrefix(name, p) {
			return true
		}
	}
	return false
}
