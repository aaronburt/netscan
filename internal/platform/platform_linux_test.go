//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"net"
)

func fixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestParseDefaultRoutePicksLowestMetric(t *testing.T) {
	gw, ifname, ok := parseDefaultRoute(fixture(t, "route"))
	if !ok || gw.String() != "172.17.0.1" || ifname != "eth0" {
		t.Fatalf("got %v %q %v", gw, ifname, ok)
	}
}

func TestParseDefaultRouteNone(t *testing.T) {
	if _, _, ok := parseDefaultRoute("Iface\tDestination\n"); ok {
		t.Fatal("expected no default route")
	}
}

func TestParseResolvConf(t *testing.T) {
	got := parseResolvConf(fixture(t, "resolv.conf"))
	want := []string{"1.1.1.1", "192.168.1.1"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v, want %v", got, want)
	}
}

func TestParseARPTable(t *testing.T) {
	arp := fixture(t, "arp")
	if got := parseARPTable(arp, "172.17.0.1"); got != "02:42:AC:11:00:01" {
		t.Fatalf("got %q", got)
	}
	if got := parseARPTable(arp, "172.17.0.9"); got != "" {
		t.Fatalf("incomplete entry should be empty, got %q", got)
	}
	if got := parseARPTable(arp, "10.0.0.1"); got != "" {
		t.Fatalf("missing entry should be empty, got %q", got)
	}
}

func TestIsVPNInterface(t *testing.T) {
	if !isVPNInterface("wg0", 0) || !isVPNInterface("tun0", 0) || !isVPNInterface("x", net.FlagPointToPoint) {
		t.Fatal("expected vpn")
	}
	if isVPNInterface("eth0", net.FlagUp) {
		t.Fatal("eth0 is not a vpn")
	}
}

func TestSingleInstance(t *testing.T) {
	t.Setenv("XDG_RUNTIME_DIR", t.TempDir())
	first, ok, err := AcquireSingleInstance(`Local\NetScan.Test`)
	if err != nil || !ok {
		t.Fatalf("first acquire: ok=%v err=%v", ok, err)
	}
	if _, ok, err := AcquireSingleInstance(`Local\NetScan.Test`); err != nil || ok {
		t.Fatalf("second acquire should be refused: ok=%v err=%v", ok, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	again, ok, err := AcquireSingleInstance(`Local\NetScan.Test`)
	if err != nil || !ok {
		t.Fatalf("reacquire after close: ok=%v err=%v", ok, err)
	}
	again.Close()
}

func echoReply(t *testing.T, id, seq int) []byte {
	t.Helper()
	b, err := (&icmp.Message{Type: ipv4.ICMPTypeEchoReply, Body: &icmp.Echo{ID: id, Seq: seq}}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// quoted builds the original IP header + 8 echo bytes an ICMP error carries.
func quoted(id, seq int) []byte {
	b := make([]byte, 28)
	b[0], b[9] = 0x45, 1
	b[20] = byte(ipv4.ICMPTypeEcho)
	b[24], b[25] = byte(id>>8), byte(id)
	b[26], b[27] = byte(seq>>8), byte(seq)
	return b
}

func TestClassifyReply(t *testing.T) {
	from := net.ParseIP("9.9.9.9")
	id := int(icmpID)

	if r, ok := classifyReply(echoReply(t, id, 7), from, 7, true); !ok || !r.OK || !r.Reached {
		t.Fatalf("echo reply: %+v %v", r, ok)
	}
	if _, ok := classifyReply(echoReply(t, id, 8), from, 7, true); ok {
		t.Fatal("wrong seq must be ignored")
	}
	if _, ok := classifyReply(echoReply(t, id+1, 7), from, 7, true); ok {
		t.Fatal("wrong id must be ignored on raw sockets")
	}
	if _, ok := classifyReply(echoReply(t, id+1, 7), from, 7, false); !ok {
		t.Fatal("ping sockets rewrite the id, so it must not be checked")
	}

	te, _ := (&icmp.Message{Type: ipv4.ICMPTypeTimeExceeded, Body: &icmp.TimeExceeded{Data: quoted(id, 7)}}).Marshal(nil)
	if r, ok := classifyReply(te, from, 7, true); !ok || !r.TTLExpired || !r.Reached || !r.ReplyIP.Equal(from) {
		t.Fatalf("time exceeded: %+v %v", r, ok)
	}
	if _, ok := classifyReply(te, from, 9, true); ok {
		t.Fatal("time exceeded for another probe must be ignored")
	}

	du, _ := (&icmp.Message{Type: ipv4.ICMPTypeDestinationUnreachable, Code: 1, Body: &icmp.DstUnreach{Data: quoted(id, 7)}}).Marshal(nil)
	if r, ok := classifyReply(du, from, 7, true); !ok || r.OK || r.ErrorMessage != "unreachable" {
		t.Fatalf("unreachable: %+v %v", r, ok)
	}
	if _, ok := classifyReply([]byte{1, 2}, from, 7, true); ok {
		t.Fatal("garbage must be ignored")
	}
}

func TestSendEchoLoopback(t *testing.T) {
	res, err := SendEcho(net.ParseIP("127.0.0.1"), 0, 2e9, 1)
	if err != nil {
		t.Skipf("no icmp privileges: %v", err)
	}
	if !res.OK {
		t.Fatalf("loopback echo failed: %+v", res)
	}
}

func TestSendEchoRejectsIPv6(t *testing.T) {
	if _, err := SendEcho(net.ParseIP("::1"), 0, 1e9, 1); err == nil {
		t.Fatal("expected error")
	}
}
