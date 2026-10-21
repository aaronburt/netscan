package export

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/aaronburt/netscan/internal/detector"
	"github.com/aaronburt/netscan/internal/store"
)

type ExportMeta struct {
	FromMS       int64  `json:"from_ms"`
	ToMS         int64  `json:"to_ms"`
	GeneratedAt  string `json:"generated_at"`
	AppVersion   string `json:"app_version"`
	NetworkLabel string `json:"network_label,omitempty"`
}

func ExportEventsCSV(w io.Writer, events []detector.Event) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{
		"id", "kind", "classification", "start_iso", "start_ts_ms",
		"end_iso", "end_ts_ms", "duration_ms", "start_uncert_ms",
		"end_uncert_ms", "gateway_ok_pct", "isp_hop_ok_pct", "layers_down", "flags",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, e := range events {
		startISO := time.UnixMilli(e.StartMS).Local().Format(time.RFC3339)
		endISO := ""
		endMSStr := ""
		endUncertStr := ""
		durStr := ""
		if e.EndMS != nil {
			endISO = time.UnixMilli(*e.EndMS).Local().Format(time.RFC3339)
			endMSStr = strconv.FormatInt(*e.EndMS, 10)
		}
		if e.EndUncertMS != nil {
			endUncertStr = strconv.FormatInt(*e.EndUncertMS, 10)
		}
		if e.DurationMS != nil {
			durStr = strconv.FormatInt(*e.DurationMS, 10)
		}

		row := []string{
			strconv.FormatInt(e.ID, 10),
			string(e.Kind),
			string(e.Classification),
			startISO,
			strconv.FormatInt(e.StartMS, 10),
			endISO,
			endMSStr,
			durStr,
			strconv.FormatInt(e.StartUncertMS, 10),
			endUncertStr,
			fmt.Sprintf("%.1f", e.GatewayOKPct),
			fmt.Sprintf("%.1f", e.ISPHopOKPct),
			strconv.Itoa(e.LayersDown),
			strconv.Itoa(e.Flags),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func ExportSamplesCSV(w io.Writer, samples []store.SampleRecord) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{
		"ts_ms", "local_time", "target_id", "target_label", "layer", "tier",
		"reached", "ok", "rtt_us", "err", "flags",
		"dns_us", "tcp_us", "tls_us", "ttfb_us", "status", "err_text",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, s := range samples {
		row := []string{
			strconv.FormatInt(s.TimestampMS, 10),
			s.LocalTime,
			strconv.Itoa(s.TargetID),
			s.TargetLabel,
			s.Layer,
			s.Tier,
			strconv.FormatBool(s.Reached),
			strconv.FormatBool(s.OK),
			strconv.FormatInt(s.RTTUS, 10),
			strconv.Itoa(s.ErrCode),
			strconv.Itoa(s.Flags),
			strconv.FormatInt(s.DNSUS, 10),
			strconv.FormatInt(s.TCPUS, 10),
			strconv.FormatInt(s.TLSUS, 10),
			strconv.FormatInt(s.TTFBUS, 10),
			strconv.Itoa(s.Status),
			s.ErrText,
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func ExportRollupsCSV(w io.Writer, rollups []store.RollupRecord) error {
	cw := csv.NewWriter(w)
	defer cw.Flush()

	header := []string{
		"bucket_ms", "local_time", "target_id", "target_label", "layer",
		"sent", "reached", "ok", "flagged", "loss_pct",
		"min_us", "p50_us", "p95_us", "max_us", "jitter_us",
	}
	if err := cw.Write(header); err != nil {
		return err
	}

	for _, r := range rollups {
		locTime := time.UnixMilli(r.BucketMS).Local().Format(time.RFC3339)
		row := []string{
			strconv.FormatInt(r.BucketMS, 10),
			locTime,
			strconv.Itoa(r.TargetID),
			r.TargetLabel,
			r.Layer,
			strconv.Itoa(r.Sent),
			strconv.Itoa(r.Reached),
			strconv.Itoa(r.OK),
			strconv.Itoa(r.Flagged),
			fmt.Sprintf("%.2f", r.LossPct),
			strconv.FormatInt(r.MinUS, 10),
			strconv.FormatInt(r.P50US, 10),
			strconv.FormatInt(r.P95US, 10),
			strconv.FormatInt(r.MaxUS, 10),
			strconv.FormatInt(r.JitterUS, 10),
		}
		if err := cw.Write(row); err != nil {
			return err
		}
	}

	return nil
}

func ExportJSON[T any](w io.Writer, meta ExportMeta, rows []T) error {
	payload := map[string]any{
		"meta": meta,
		"rows": rows,
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(payload)
}

func ExportJSONL[T any](w io.Writer, rows []T) error {
	enc := json.NewEncoder(w)
	for _, row := range rows {
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	return nil
}
