package probe_test

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/aaronburt/netscan/internal/probe"
	"github.com/miekg/dns"
)

func TestProbeTCP(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer ln.Close()

	addr := ln.Addr().String()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	targetOK := probe.Target{
		ID:      21,
		Layer:   probe.LayerWANTCP,
		Address: addr,
	}
	resOK := probe.ProbeTCP(targetOK, 1*time.Second, 1)
	if !resOK.Reached || !resOK.OK {
		t.Fatalf("expected reached=true and ok=true, got reached=%v ok=%v err=%s", resOK.Reached, resOK.OK, resOK.ErrCode)
	}

	targetRefused := probe.Target{
		ID:      22,
		Layer:   probe.LayerWANTCP,
		Address: "127.0.0.1:65534",
	}
	resRefused := probe.ProbeTCP(targetRefused, 500*time.Millisecond, 2)
	if !resRefused.Reached {
		t.Fatalf("expected reached=true on connection refused, got %v", resRefused.Reached)
	}
	if resRefused.OK {
		t.Fatalf("expected ok=false on connection refused")
	}
	if resRefused.ErrCode != probe.ErrRefused {
		t.Fatalf("expected ErrRefused, got %s", resRefused.ErrCode)
	}
}

func TestProbeDNS(t *testing.T) {
	pc, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen udp: %v", err)
	}
	defer pc.Close()

	server := &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			m := new(dns.Msg)
			m.SetReply(r)
			q := r.Question[0].Name
			if q == "error.test." {
				m.Rcode = dns.RcodeServerFailure
			} else {
				rr, _ := dns.NewRR(fmt.Sprintf("%s 3600 IN A 1.2.3.4", q))
				m.Answer = append(m.Answer, rr)
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() {
		_ = server.ActivateAndServe()
	}()
	defer server.Shutdown()

	time.Sleep(50 * time.Millisecond)

	dnsAddr := pc.LocalAddr().String()

	targetOK := probe.Target{
		ID:      31,
		Layer:   probe.LayerDNS,
		Address: dnsAddr,
	}
	resOK := probe.ProbeDNS(targetOK, "example.com", 1*time.Second, 1)
	if !resOK.Reached || !resOK.OK {
		t.Fatalf("expected reached=true and ok=true, got reached=%v ok=%v err=%s", resOK.Reached, resOK.OK, resOK.ErrCode)
	}

	targetFail := probe.Target{
		ID:      32,
		Layer:   probe.LayerDNS,
		Address: dnsAddr,
	}
	resFail := probe.ProbeDNS(targetFail, "error.test", 1*time.Second, 2)
	if !resFail.Reached {
		t.Fatalf("expected reached=true for SERVFAIL, got %v", resFail.Reached)
	}
	if resFail.OK {
		t.Fatalf("expected ok=false for SERVFAIL")
	}
	if resFail.ErrCode != probe.ErrDNSRCode {
		t.Fatalf("expected ErrDNSRCode, got %s", resFail.ErrCode)
	}
}

func TestProbeHTTP(t *testing.T) {
	ts204 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	defer ts204.Close()

	target204 := probe.Target{
		ID:       51,
		Layer:    probe.LayerHTTP,
		Address:  ts204.URL,
		Expected: http.StatusNoContent,
	}
	res204 := probe.ProbeHTTP(target204, 1*time.Second, 1, "test")
	if !res204.Reached || !res204.OK {
		t.Fatalf("expected reached=true ok=true for 204, got reached=%v ok=%v err=%s", res204.Reached, res204.OK, res204.ErrCode)
	}

	ts200 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("PrefixMatchedContent"))
	}))
	defer ts200.Close()

	target200 := probe.Target{
		ID:         52,
		Layer:      probe.LayerHTTP,
		Address:    ts200.URL,
		Expected:   http.StatusOK,
		BodyPrefix: "PrefixMatched",
	}
	res200 := probe.ProbeHTTP(target200, 1*time.Second, 2, "test")
	if !res200.Reached || !res200.OK {
		t.Fatalf("expected reached=true ok=true for 200 prefix match, got reached=%v ok=%v err=%s", res200.Reached, res200.OK, res200.ErrCode)
	}

	targetMismatch := probe.Target{
		ID:         53,
		Layer:      probe.LayerHTTP,
		Address:    ts200.URL,
		Expected:   http.StatusOK,
		BodyPrefix: "WrongPrefix",
	}
	resMismatch := probe.ProbeHTTP(targetMismatch, 1*time.Second, 3, "test")
	if !resMismatch.Reached {
		t.Fatalf("expected reached=true for body mismatch, got %v", resMismatch.Reached)
	}
	if resMismatch.OK {
		t.Fatalf("expected ok=false for body mismatch")
	}
	if resMismatch.ErrCode != probe.ErrHTTPUnexpected {
		t.Fatalf("expected ErrHTTPUnexpected, got %s", resMismatch.ErrCode)
	}
}

func TestProbeICMPLoopback(t *testing.T) {
	target := probe.Target{
		ID:      1,
		Layer:   probe.LayerGateway,
		Address: "127.0.0.1",
	}
	res := probe.ProbeICMP(target, 1*time.Second, 1)
	if !res.Reached || !res.OK {
		t.Logf("ICMP loopback returned reached=%v ok=%v err=%s err_text=%s", res.Reached, res.OK, res.ErrCode, res.ErrText)
	}
}
