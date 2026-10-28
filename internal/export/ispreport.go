package export

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/aaronburt/netscan/internal/config"
	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/store"
)

func GenerateISPReport(
	w io.Writer,
	meta ExportMeta,
	events []detector.Event,
	stats store.StatsSummary,
	profiles []store.ProfileUse,
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
	b.WriteString(fmt.Sprintf("Total Blips (7d):   %d brief probe failures (not outages)\n\n", stats.Blips7D))

	var ispEvents []detector.Event
	var localEvents []detector.Event
	var latencyEvents []detector.Event
	var blipEvents []detector.Event

	for _, e := range events {
		if e.Kind == detector.EventKindBlip {
			blipEvents = append(blipEvents, e)
			continue
		}
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

	b.WriteString("3. MONITORING PROFILE\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	writeProfileUse(&b, profiles)

	b.WriteString("4. ISP-ATTRIBUTABLE INCIDENTS (LAN VERIFIED OPERATIONAL)\n")
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

	b.WriteString("5. LOCAL NETWORK / SYSTEM EVENTS (EXCLUDED FROM ISP METRICS)\n")
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

	b.WriteString("6. BRIEF PROBE FAILURES (NOT OUTAGES, NOT ISP EVIDENCE)\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	if profileDependent(profiles) {
		b.WriteString("Counts here depend on the monitoring profile: a profile that probes more often\n")
		b.WriteString("sees more brief failures than one that probes less often.\n\n")
	}
	if len(blipEvents) == 0 {
		b.WriteString("None recorded during this period.\n\n")
	} else {
		b.WriteString(fmt.Sprintf("%d short failures recovered on their own without meeting the outage rule\n", len(blipEvents)))
		b.WriteString("(two of TCP, DNS and HTTP failing together, or the router not answering).\n")
		b.WriteString("Failures that touched only ICMP, or the router itself, say nothing about the ISP.\n\n")
		b.WriteString(fmt.Sprintf("%-24s %-12s %-24s %-12s\n", "Start Time", "Failed for", "Failed checks", "Gateway OK"))
		b.WriteString(strings.Repeat("-", 80) + "\n")
		for _, e := range blipEvents {
			startStr := time.UnixMilli(e.StartMS).Local().Format("2006-01-02 15:04:05")
			durStr := "<1s"
			if e.DurationMS != nil && *e.DurationMS >= 1000 {
				durStr = fmt.Sprintf("%.1fs", float64(*e.DurationMS)/1000.0)
			}
			b.WriteString(fmt.Sprintf("%-24s %-12s %-24s %-12s\n",
				startStr, durStr, failedLayerNames(e.LayersDown), fmt.Sprintf("%.1f%%", e.GatewayOKPct)))
		}
		b.WriteString("\n")
	}

	b.WriteString("7. MEASUREMENT METHODOLOGY & SPECIFICATION\n")
	b.WriteString("--------------------------------------------------------------------------------\n")
	b.WriteString("The figures below describe the Standard profile. Section 3 lists the profiles used.\n\n")
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

// writeProfileUse lists the profiles in force during the period, with their
// share of the time and what each one costs to run.
func writeProfileUse(b *strings.Builder, usage []store.ProfileUse) {
	if len(usage) == 0 {
		b.WriteString("No profile was recorded for this period. Events from before profile history\n")
		b.WriteString("was added are read as Standard.\n\n")
		return
	}

	b.WriteString(fmt.Sprintf("%-22s %-8s %-10s %-10s %-22s\n", "Profile", "Share", "Probes/s", "Remote/s", "Min. detectable outage"))
	b.WriteString(strings.Repeat("-", 80) + "\n")
	for _, u := range usage {
		b.WriteString(fmt.Sprintf("%-22.22s %-8s %-10.1f %-10.1f %-22s\n",
			u.Name,
			fmt.Sprintf("%.1f%%", u.SharePct),
			u.Estimate.ProbesPerSec,
			u.Estimate.RemoteProbesPerSec,
			fmt.Sprintf("%.1fs", float64(u.Estimate.MinDetectableOutageMS)/1000)))
	}
	b.WriteString("\nThe two-of-three outage rule (TCP, DNS, HTTP; ICMP alone never counts) is the same under\n")
	b.WriteString("every profile. Profiles change how quickly evidence arrives, so an outage shorter than the\n")
	b.WriteString("minimum detectable outage may be missed or only partly seen.\n\n")
}

// profileDependent reports whether brief failures and latency counts depend on
// the profile: more than one was used, or the one used is not Standard.
func profileDependent(usage []store.ProfileUse) bool {
	return len(usage) > 1 || (len(usage) == 1 && usage[0].ID != config.ProfileStandard)
}

func failedLayerNames(mask int) string {
	var names []string
	for _, l := range []struct {
		bit  int
		name string
	}{
		{detector.LayerMaskGateway, "Gateway"},
		{detector.LayerMaskISPEdge, "ISP hop"},
		{detector.LayerMaskWANICMP, "ICMP"},
		{detector.LayerMaskWANTCP, "TCP"},
		{detector.LayerMaskDNS, "DNS"},
		{detector.LayerMaskHTTP, "HTTP"},
	} {
		if mask&l.bit != 0 {
			names = append(names, l.name)
		}
	}
	if len(names) == 0 {
		return "unknown"
	}
	return strings.Join(names, ", ")
}
