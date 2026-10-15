package main

// G20: offline, read-only review of passive N10 RAM observations. This module
// never infers write permissions, allocation lifetime or patch authorization.
import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"sort"
	"time"
)

type n10RAMSummary struct {
	SampleCount            int      `json:"sample_count"`
	DistinctOverlayCount   int      `json:"distinct_overlay_count"`
	OverlayLBAs            []uint32 `json:"overlay_lbas"`
	DistinctTailHashes     int      `json:"distinct_tail_hashes"`
	ElapsedSeconds         float64  `json:"elapsed_seconds"`
	AllRendererSitesMatch  bool     `json:"all_renderer_sites_match"`
	AllFontsMatch          bool     `json:"all_fonts_match"`
	AllNamePoolsZero       bool     `json:"all_name_pools_zero"`
	AllCandidateABZero     bool     `json:"all_candidate_ab_zero"`
	Classification         string   `json:"classification"`
	RuntimeSafe            bool     `json:"runtime_safe"`
	CallerCoverageComplete bool     `json:"caller_coverage_complete"`
	Note                   string   `json:"note"`
}

// reviewN10RAM accepts only the passive G19/G20 schema and fails closed on
// malformed, reordered or falsely approved evidence. Multiple repeated reads
// within one overlay are NOT evidence of residency across other overlays.
func reviewN10RAM(r n10RAMReport) (n10RAMSummary, error) {
	var out n10RAMSummary
	if r.Status != "PASSIVE_OBSERVATIONS_ONLY_NOT_RUNTIME_APPROVED" || r.CandidateRAMSafe || r.CompleteCallerCoverage {
		return out, errors.New("invalid or falsely approved N10 passive evidence")
	}
	if len(r.Samples) < 1 || len(r.Samples) > 30 {
		return out, errors.New("invalid number of N10 samples")
	}
	overlays := map[uint32]bool{}
	tails := map[string]bool{}
	out.SampleCount = len(r.Samples)
	out.AllRendererSitesMatch = true
	out.AllFontsMatch = true
	out.AllNamePoolsZero = true
	out.AllCandidateABZero = true
	var first, previous time.Time
	for i, s := range r.Samples {
		if s.Number != i+1 || s.Assessment.RuntimeSafe || s.Assessment.TailSHA256 == "" || len(s.Assessment.TailSHA256) != 64 || len(s.Assessment.BufferASHA256) != 64 || len(s.Assessment.BufferBSHA256) != 64 {
			return n10RAMSummary{}, fmt.Errorf("invalid passive sample %d", i+1)
		}
		for _, hash := range []string{s.Assessment.TailSHA256, s.Assessment.BufferASHA256, s.Assessment.BufferBSHA256} {
			if _, e := hex.DecodeString(hash); e != nil {
				return n10RAMSummary{}, fmt.Errorf("invalid hash in sample %d", i+1)
			}
		}
		zeroHash := func(size int) string { h := sha256.Sum256(make([]byte, size)); return fmt.Sprintf("%x", h[:]) }
		if (s.Assessment.PoolIsZero && s.Assessment.TailSHA256 != zeroHash(180)) ||
			(s.Assessment.BufferAIsZero && s.Assessment.BufferASHA256 != zeroHash(16)) ||
			(s.Assessment.BufferBIsZero && s.Assessment.BufferBSHA256 != zeroHash(32)) {
			return n10RAMSummary{}, fmt.Errorf("zero-flag/hash mismatch in sample %d", i+1)
		}
		stamp, e := time.Parse(time.RFC3339Nano, s.Timestamp)
		if e != nil || (!previous.IsZero() && !stamp.After(previous)) {
			return n10RAMSummary{}, fmt.Errorf("invalid sample timestamp at %d", i+1)
		}
		if i == 0 {
			first = stamp
		}
		previous = stamp
		a := s.Assessment
		if a.PoolIsZero && a.NamePoolOccupied {
			return n10RAMSummary{}, fmt.Errorf("contradictory pool flags at sample %d", i+1)
		}
		overlays[s.OverlayLBA] = true
		tails[a.TailSHA256] = true
		out.AllRendererSitesMatch = out.AllRendererSitesMatch && a.RendererSiteMatches
		out.AllFontsMatch = out.AllFontsMatch && a.RendererFontMatches
		out.AllNamePoolsZero = out.AllNamePoolsZero && a.PoolIsZero
		out.AllCandidateABZero = out.AllCandidateABZero && a.BufferAIsZero && a.BufferBIsZero
	}
	for o := range overlays {
		out.OverlayLBAs = append(out.OverlayLBAs, o)
	}
	sort.Slice(out.OverlayLBAs, func(i, j int) bool { return out.OverlayLBAs[i] < out.OverlayLBAs[j] })
	out.DistinctOverlayCount = len(overlays)
	out.DistinctTailHashes = len(tails)
	out.ElapsedSeconds = previous.Sub(first).Seconds()
	switch {
	case !out.AllRendererSitesMatch || !out.AllFontsMatch:
		out.Classification = "RENDERER_MISMATCH"
	case !out.AllCandidateABZero || !out.AllNamePoolsZero:
		out.Classification = "POOL_OR_BUFFER_OCCUPIED"
	case len(overlays) == 1:
		out.Classification = "ONE_OVERLAY_REPEATED_OBSERVATION"
	default:
		out.Classification = "MULTI_OVERLAY_PASSIVE_OBSERVATION"
	}
	out.Note = "Read-only snapshots; no proof of RAM ownership, writable lifetime, indirect caller coverage, appended-text bounds or safe patch execution."
	return out, nil
}

func cmdNameRAMReview(_ string, args []string) error {
	fs := flag.NewFlagSet("name-ram-review", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	in := fs.String("input", "", "existing private N10 RAM report JSON (read-only)")
	asJSON := fs.Bool("json", false, "print machine-readable summary")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *in == "" || fs.NArg() != 0 {
		return errors.New("usage: name-ram-review --input FILE.json [--json]")
	}
	stat, e := os.Stat(*in)
	if e != nil {
		return e
	}
	if !stat.Mode().IsRegular() || stat.Size() > 1<<20 {
		return errors.New("expected a regular N10 JSON report <= 1 MiB")
	}
	f, e := os.Open(*in)
	if e != nil {
		return e
	}
	defer f.Close()
	var r n10RAMReport
	dec := json.NewDecoder(f)
	if e = dec.Decode(&r); e != nil {
		return e
	}
	// Strict single-document JSON: never silently ignore appended content.
	var extra any
	if e = dec.Decode(&extra); e == nil {
		return errors.New("unexpected additional JSON document")
	} else if !errors.Is(e, io.EOF) {
		return e
	}
	s, e := reviewN10RAM(r)
	if e != nil {
		return e
	}
	if *asJSON {
		raw, e := json.MarshalIndent(s, "", "  ")
		if e != nil {
			return e
		}
		fmt.Fprintln(commandOutput, string(raw))
		return nil
	}
	fmt.Fprintf(commandOutput, "N10 RAM: %d observations over %.1fs; overlays=%v (%d distinct), tail states=%d\n", s.SampleCount, s.ElapsedSeconds, s.OverlayLBAs, s.DistinctOverlayCount, s.DistinctTailHashes)
	fmt.Fprintf(commandOutput, "Renderer=%v font=%v pool-zero-all=%v A/B-zero-all=%v; %s\n", s.AllRendererSitesMatch, s.AllFontsMatch, s.AllNamePoolsZero, s.AllCandidateABZero, s.Classification)
	fmt.Fprintln(commandOutput, "Runtime-approved: NO. Stable observations do not prove safe storage or complete caller coverage.")
	return nil
}
