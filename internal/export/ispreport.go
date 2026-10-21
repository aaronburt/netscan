package export

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/store"
)

func GenerateISPReport(
	w io.Writer,
	meta ExportMeta,
	events []detector.Event,
	stats store.StatsSummary,
	gwIP, ispHopIP string,
) error {
	fromLocal := time.UnixMilli(meta.FromMS).Local().Format(time.RFC3339)
	toLocal := time.UnixMilli(meta.ToMS).Local().Format(time.RFC3339)

	var b strings.Builder

	b.WriteString("================================================================================\n")
	b.WriteString("                          NETSCAN ISP EVIDENCE REPORT                           \n")
	b.WriteString("================================================================================\n\n")

	b.WriteString("1. REPORT METADATA\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString(fmt.Sprintf("Report Period:      %s to %s\n", fromLocal, toLocal))
	b.WriteString(fmt.Sprintf("Generated At:       %s\n", meta.GeneratedAt))
	b.WriteString(fmt.Sprintf("NetScan Version:    %s\n", meta.AppVersion))
	b.WriteString(fmt.Sprintf("Network Label:      %s\n", meta.NetworkLabel))
	b.WriteString(fmt.Sprintf("Default Gateway:    %s\n", gwIP))
	b.WriteString(fmt.Sprintf("ISP First Hop:      %s\n\n", ispHopIP))

	b.WriteString("2. MONITORING COVERAGE & UPTIME\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString(fmt.Sprintf("Coverage Ratio:     %.1f%% of selected period\n", stats.CoveragePct))
	b.WriteString(fmt.Sprintf("Total Loss Ratio:   %.2f%% across all targets\n", stats.TotalLossPct))
	b.WriteString(fmt.Sprintf("Total Outages (7d): %d verified incidents\n", stats.Outages7D))
	b.WriteString(fmt.Sprintf("Total Blips (7d):   %d micro-drops (<2s)\n\n", stats.Blips7D))

	var ispEvents []detector.Event
	var localEvents []detector.Event
	var latencyEvents []detector.Event

	for _, e := range events {
		if (e.Flags & detector.EventFlagPostResume) != 0 {
			localEvents = append(localEvents, e)
			continue
		}
		if (e.Flags & detector.EventFlagVPN) != 0 {
			localEvents = append(localEvents, e)
			continue
		}

		switch e.Classification {
		case detector.ClassISPEdge, detector.ClassWAN, detector.ClassDNSSystem:
			ispEvents = append(ispEvents, e)
		case detector.ClassLinkDown, detector.ClassGateway:
			localEvents = append(localEvents, e)
		case detector.ClassLatencyLocal, detector.ClassLatencyWAN:
			latencyEvents = append(latencyEvents, e)
		default:
			ispEvents = append(ispEvents, e)
		}
	}

	b.WriteString("3. ISP-ATTRIBUTABLE INCIDENTS (LAN VERIFIED OPERATIONAL)\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	if len(ispEvents) == 0 {
		b.WriteString("No upstream ISP-attributable outages recorded during this period.\n\n")
	} else {
		b.WriteString(fmt.Sprintf("%-24s %-12s %-10s %-12s %-10s\n", "Start Time", "Duration", "Class", "Gateway OK", "Uncertainty"))
		b.WriteString(strings.Repeat("-", 80) + "\n")
		for _, e := range ispEvents {
			startStr := time.UnixMilli(e.StartMS).Local().Format("2006-01-02 15:04:05")
			durStr := "ongoing"
			if e.DurationMS != nil {
				durStr = fmt.Sprintf("%.1fs", float64(*e.DurationMS)/1000.0)
			}
			uncertStr := fmt.Sprintf("±%.1fs", float64(e.StartUncertMS)/1000.0)
			gwStr := fmt.Sprintf("%.1f%%", e.GatewayOKPct)

			b.WriteString(fmt.Sprintf("%-24s %-12s %-10s %-12s %-10s\n",
				startStr, durStr, string(e.Classification), gwStr, uncertStr))
		}
		b.WriteString("\nNote: Gateway OK indicates local Wi-Fi / Ethernet router remained responsive\n")
		b.WriteString("during the drop, demonstrating failure occurred upstream on the ISP link.\n\n")
	}

	b.WriteString("4. LOCAL NETWORK / SYSTEM EVENTS (EXCLUDED FROM ISP METRICS)\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	if len(localEvents) == 0 {
		b.WriteString("No local link or router drops recorded during this period.\n\n")
	} else {
		for _, e := range localEvents {
			startStr := time.UnixMilli(e.StartMS).Local().Format("2006-01-02 15:04:05")
			durStr := "ongoing"
			if e.DurationMS != nil {
				durStr = fmt.Sprintf("%.1fs", float64(*e.DurationMS)/1000.0)
			}
			b.WriteString(fmt.Sprintf("- %s: %s (%s, Gateway reachable: %.1f%%)\n",
				startStr, durStr, string(e.Classification), e.GatewayOKPct))
		}
		b.WriteString("\n")
	}

	b.WriteString("5. MEASUREMENT METHODOLOGY & SPECIFICATION\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString("1. High-Frequency Staggered Polling: 1000ms healthy interval, 500ms suspect mode.\n")
	b.WriteString("2. Multi-Protocol Quorum: An outage requires concurrent failure across multiple\n")
	b.WriteString("   independent tier-1 anycast targets (1.1.1.1, 8.8.8.8, 9.9.9.9).\n")
	b.WriteString("3. ICMP Loss Confirmation: ICMP loss is verified with TCP port 443 handshakes\n")
	b.WriteString("   to differentiate ICMP rate-limiting from actual transport outages.\n")
	b.WriteString("4. Fault Isolation: Unprivileged Win32 IcmpSendEcho2 to local router verifies\n")
	b.WriteString("   local LAN health independently of external WAN routing.\n")
	b.WriteString("================================================================================\n")

	_, err := w.Write([]byte(b.String()))
	return err
}
