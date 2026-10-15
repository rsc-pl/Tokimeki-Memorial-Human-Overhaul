package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testN10RAMReport() n10RAMReport {
	h := func(n int) string { s := sha256.Sum256(make([]byte, n)); return fmt.Sprintf("%x", s[:]) }
	a := h(180)
	b := h(16)
	c := h(32)
	samples := make([]n10RAMSample, 6)
	for i := range samples {
		samples[i] = n10RAMSample{
			Number: i + 1, Timestamp: time.Date(2026, 10, 15, 1, 46, 57+i*5, 0, time.UTC).Format(time.RFC3339Nano), OverlayLBA: 38378,
		}
		samples[i].Assessment.RendererSiteMatches = true
		samples[i].Assessment.RendererFontMatches = true
		samples[i].Assessment.PoolIsZero = true
		samples[i].Assessment.BufferAIsZero = true
		samples[i].Assessment.BufferBIsZero = true
		samples[i].Assessment.TailSHA256 = a
		samples[i].Assessment.BufferASHA256 = b
		samples[i].Assessment.BufferBSHA256 = c
	}
	return n10RAMReport{Status: "PASSIVE_OBSERVATIONS_ONLY_NOT_RUNTIME_APPROVED", Samples: samples}
}

func TestN10G19ReportOneOverlayNoApproval(t *testing.T) {
	r := testN10RAMReport()
	s, e := reviewN10RAM(r)
	if e != nil {
		t.Fatal(e)
	}
	if s.SampleCount != 6 || s.DistinctOverlayCount != 1 || s.OverlayLBAs[0] != 38378 || s.DistinctTailHashes != 1 || s.Classification != "ONE_OVERLAY_REPEATED_OBSERVATION" || s.ElapsedSeconds != 25 || s.RuntimeSafe || s.CallerCoverageComplete {
		t.Fatalf("unexpected conclusion: %+v", s)
	}
}
func TestN10MixedOverlayStillNotApproved(t *testing.T) {
	r := testN10RAMReport()
	r.Samples[4].OverlayLBA = 37994
	r.Samples[5].Assessment.BufferBIsZero = false
	r.Samples[5].Assessment.TailSHA256 = strings.Repeat("c", 64)
	r.Samples[5].Assessment.PoolIsZero = false
	s, e := reviewN10RAM(r)
	if e != nil {
		t.Fatal(e)
	}
	if s.Classification != "POOL_OR_BUFFER_OCCUPIED" || s.DistinctOverlayCount != 2 || s.DistinctTailHashes != 2 || s.RuntimeSafe || s.CallerCoverageComplete {
		t.Fatalf("unexpected conclusion %+v", s)
	}
}
func TestN10BadEvidenceRejected(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*n10RAMReport)
	}{
		{"false-safe", func(r *n10RAMReport) { r.CandidateRAMSafe = true }},
		{"sample-safe", func(r *n10RAMReport) { r.Samples[0].Assessment.RuntimeSafe = true }},
		{"fake-caller", func(r *n10RAMReport) { r.CompleteCallerCoverage = true }},
		{"duplicate", func(r *n10RAMReport) { r.Samples[1].Number = 1 }},
		{"out-of-order-time", func(r *n10RAMReport) { r.Samples[1].Timestamp = r.Samples[0].Timestamp }},
		{"contradiction", func(r *n10RAMReport) { r.Samples[0].Assessment.NamePoolOccupied = true }},
		{"bad-hash", func(r *n10RAMReport) { r.Samples[0].Assessment.TailSHA256 = "bad" }},
		{"empty", func(r *n10RAMReport) { r.Samples = nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := testN10RAMReport()
			tc.mut(&r)
			if _, e := reviewN10RAM(r); e == nil {
				t.Fatal("accepted invalid evidence")
			}
		})
	}
}
func TestN10OfflineReportFromFile(t *testing.T) {
	r := testN10RAMReport()
	raw, e := json.Marshal(r)
	if e != nil {
		t.Fatal(e)
	}
	path := filepath.Join(t.TempDir(), "n10.json")
	if e = os.WriteFile(path, raw, 0600); e != nil {
		t.Fatal(e)
	}
	if e = cmdNameRAMReview("", []string{"--input", path, "--json"}); e != nil {
		t.Fatal(e)
	}
}
