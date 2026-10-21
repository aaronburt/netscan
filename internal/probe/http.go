package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"strings"
	"time"
)

func ProbeHTTP(target Target, timeout time.Duration, seq uint64, version string) ProbeResult {
	sendUTC := time.Now().UTC().UnixMilli()
	sendMono := time.Now().UnixNano()

	var dnsStart, connStart, tlsStart, reqStart time.Time
	var dnsUS, tcpUS, tlsUS, ttfbUS int64

	trace := &httptrace.ClientTrace{
		DNSStart: func(_ httptrace.DNSStartInfo) { dnsStart = time.Now() },
		DNSDone: func(_ httptrace.DNSDoneInfo) {
			if !dnsStart.IsZero() {
				dnsUS = time.Since(dnsStart).Microseconds()
			}
		},
		ConnectStart: func(_, _ string) { connStart = time.Now() },
		ConnectDone: func(_, _ string, _ error) {
			if !connStart.IsZero() {
				tcpUS = time.Since(connStart).Microseconds()
			}
		},
		TLSHandshakeStart: func() { tlsStart = time.Now() },
		TLSHandshakeDone: func(_ tls.ConnectionState, _ error) {
			if !tlsStart.IsZero() {
				tlsUS = time.Since(tlsStart).Microseconds()
			}
		},
		WroteRequest: func(_ httptrace.WroteRequestInfo) { reqStart = time.Now() },
		GotFirstResponseByte: func() {
			if !reqStart.IsZero() {
				ttfbUS = time.Since(reqStart).Microseconds()
			}
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	reqCtx := httptrace.WithClientTrace(ctx, trace)
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, target.Address, nil)
	if err != nil {
		return ProbeResult{
			TargetID:    target.ID,
			Target:      target,
			Seq:         seq,
			SendTimeUTC: sendUTC,
			SendMonoNS:  sendMono,
			Reached:     false,
			OK:          false,
			ErrCode:     ErrOther,
			ErrText:     err.Error(),
		}
	}

	ua := "NetScan/" + version
	if version == "" {
		ua = "NetScan/0.1.0"
	}
	req.Header.Set("User-Agent", ua)

	transport := &http.Transport{
		DisableKeepAlives: true,
		Proxy:             nil,
		DialContext: (&net.Dialer{
			Timeout: timeout,
		}).DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	start := time.Now()
	resp, err := client.Do(req)
	duration := time.Since(start)

	res := ProbeResult{
		TargetID:    target.ID,
		Target:      target,
		Seq:         seq,
		SendTimeUTC: sendUTC,
		SendMonoNS:  sendMono,
		RTTUS:       duration.Microseconds(),
		Duration:    duration,
		DNSUS:       dnsUS,
		TCPUS:       tcpUS,
		TLSUS:       tlsUS,
		TTFBUS:      ttfbUS,
	}

	if err != nil {
		res.Reached = false
		res.OK = false

		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			res.ErrCode = ErrTimeout
			return res
		}

		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			res.ErrCode = ErrOSDNS
			res.ErrText = dnsErr.Error()
			return res
		}

		var certErr *tls.CertificateVerificationError
		if errors.As(err, &certErr) {
			res.Reached = true
			res.ErrCode = ErrTLS
			res.ErrText = certErr.Error()
			return res
		}

		errStr := strings.ToLower(err.Error())
		if strings.Contains(errStr, "timeout") || strings.Contains(errStr, "deadline exceeded") {
			res.ErrCode = ErrTimeout
			return res
		}
		if strings.Contains(errStr, "tls") || strings.Contains(errStr, "certificate") || strings.Contains(errStr, "handshake failure") {
			res.Reached = true
			res.ErrCode = ErrTLS
			res.ErrText = err.Error()
			return res
		}
		if strings.Contains(errStr, "no such host") || strings.Contains(errStr, "server failure") {
			res.ErrCode = ErrOSDNS
			res.ErrText = err.Error()
			return res
		}
		if strings.Contains(errStr, "refused") {
			res.Reached = true
			res.ErrCode = ErrRefused
			return res
		}

		res.ErrCode = ErrOther
		res.ErrText = err.Error()
		return res
	}
	defer resp.Body.Close()

	res.Reached = true
	res.HTTPStatus = resp.StatusCode

	bodyBytes, _ := io.ReadAll(io.LimitReader(resp.Body, 1024))
	bodyStr := string(bodyBytes)

	expectedStatus := target.Expected
	if expectedStatus == 0 {
		expectedStatus = http.StatusNoContent
	}

	if resp.StatusCode != expectedStatus {
		res.OK = false
		res.ErrCode = ErrHTTPUnexpected
		res.ErrText = resp.Status
		return res
	}

	if target.BodyPrefix != "" && !strings.HasPrefix(bodyStr, target.BodyPrefix) {
		res.OK = false
		res.ErrCode = ErrHTTPUnexpected
		res.ErrText = "body prefix mismatch"
		return res
	}

	res.OK = true
	return res
}
