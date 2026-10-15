package main

// G19: passive, loopback-only N10 memory sampler. No R07-style breakpoints,
// force-event writes, patching, saves, or remote monitoring.
import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tokimemo/internal/duckstation"
	"tokimemo/internal/nametables"
)

type n10RAMSample struct {
	Number     int                              `json:"number"`
	Timestamp  string                           `json:"timestamp_utc"`
	OverlayLBA uint32                           `json:"overlay_lba"`
	Assessment nametables.RAMSnapshotAssessment `json:"assessment"`
}
type n10RAMReport struct {
	Summary                *n10RAMSummary `json:"summary,omitempty"`
	Status                 string         `json:"status"`
	Samples                []n10RAMSample `json:"samples"`
	CandidateRAMSafe       bool           `json:"candidate_ram_safe"`
	CompleteCallerCoverage bool           `json:"complete_caller_coverage"`
	Limitations            []string       `json:"limitations"`
}

// captureN10RAM uses one short connection per sample and always detaches.
// A transient error is not swallowed or reinterpreted as stable memory.
func captureN10RAM(port int, timeout time.Duration) (out n10RAMSample, retErr error) {
	c, err := duckstation.Dial(port, timeout)
	if err != nil {
		return out, err
	}
	defer func() {
		if e := c.Close(); e != nil {
			if retErr == nil {
				retErr = e
			} else {
				retErr = fmt.Errorf("%w; detach: %v", retErr, e)
			}
		}
	}()
	site, err := c.ReadMemory(nametables.RendererHookSite, 8)
	if err != nil {
		return out, err
	}
	font, err := c.ReadMemory(nametables.NarrowRAMAddress, nametables.NarrowRAMBytes)
	if err != nil {
		return out, err
	}
	overlay, err := c.ReadMemory(0x800b6d40, 4)
	if err != nil {
		return out, err
	}
	a, err := nametables.AssessRAMSnapshot(site, font)
	if err != nil {
		return out, err
	}
	out = n10RAMSample{Timestamp: time.Now().UTC().Format(time.RFC3339Nano), OverlayLBA: binary.LittleEndian.Uint32(overlay), Assessment: a}
	return out, nil
}
func cmdNameRAMWatch(root string, args []string) error {
	fs := flag.NewFlagSet("name-ram-watch", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	port := fs.Int("port", 2345, "DuckStation loopback GDB port")
	samples := fs.Int("samples", 1, "number of passive snapshots (1..30)")
	interval := fs.Duration("interval", 5*time.Second, "delay between snapshots (minimum 2s if multiple)")
	report := fs.String("report", "", "new JSON report in private .local/go_toolchain directory")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *samples < 1 || *samples > 30 || (*samples > 1 && (*interval < 2*time.Second || *interval > 60*time.Second)) {
		return errors.New("usage: name-ram-watch [--samples 1..30] [--interval 5s] [--port 2345] [--report .local/go_toolchain/reports/n10_ram.json]")
	}
	result := n10RAMReport{Status: "PASSIVE_OBSERVATIONS_ONLY_NOT_RUNTIME_APPROVED", Samples: []n10RAMSample{}, CandidateRAMSafe: false, CompleteCallerCoverage: false,
		Limitations: []string{"The original game's static English renderer must be installed to interpret candidate storage", "Unchanged memory across sampled instants cannot prove full-game ownership or writability", "No write-watch, indirect-pointer coverage, overlay lifetime, appended-string capacity, or name gameplay test performed"}}
	for i := 0; i < *samples; i++ {
		if i > 0 {
			time.Sleep(*interval)
		}
		sample, e := captureN10RAM(*port, 5*time.Second)
		if e != nil {
			return fmt.Errorf("snapshot %d failed (no false approval): %w", i+1, e)
		}
		sample.Number = i + 1
		result.Samples = append(result.Samples, sample)
		fmt.Fprintf(commandOutput, "N10 snapshot %d/%d: hook=%v font=%v pool_zero=%v A_zero=%v B_zero=%v overlay_LBA=%d; runtime approval=NO\n", i+1, *samples, sample.Assessment.RendererSiteMatches, sample.Assessment.RendererFontMatches, sample.Assessment.PoolIsZero, sample.Assessment.BufferAIsZero, sample.Assessment.BufferBIsZero, sample.OverlayLBA)
	}
	summary, e := reviewN10RAM(result)
	if e != nil {
		return e
	}
	result.Summary = &summary
	fmt.Fprintf(commandOutput, "N10 evidence: %d distinct overlay(s), %d distinct tail state(s); %s; runtime approval=NO\n", summary.DistinctOverlayCount, summary.DistinctTailHashes, summary.Classification)
	if *report == "" {
		fmt.Fprintln(commandOutput, "No raw bytes stored. Use --report in private .local/go_toolchain to save hashes and flags.")
		return nil
	}
	private := filepath.Join(root, ".local", "go_toolchain")
	base, e := filepath.EvalSymlinks(private)
	if e != nil {
		return e
	}
	p, e := filepath.Abs(*report)
	if e != nil {
		return e
	}
	parent, e := filepath.EvalSymlinks(filepath.Dir(p))
	if e != nil {
		return e
	}
	rel, e := filepath.Rel(base, parent)
	if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return errors.New("report must be inside existing private .local/go_toolchain")
	}
	raw, e := json.MarshalIndent(result, "", "  ")
	if e != nil {
		return e
	}
	f, e := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = f.Write(append(raw, '\n')); e != nil {
		f.Close()
		os.Remove(p)
		return e
	}
	if e = f.Close(); e != nil {
		os.Remove(p)
		return e
	}
	fmt.Fprintln(commandOutput, "Private report written; candidate still NOT approved for runtime.")
	return nil
}
