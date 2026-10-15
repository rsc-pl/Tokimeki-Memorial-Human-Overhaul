package main

// G40: one focused private original-disc EXE trace, read-only, SHA-bound.
import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"tokimemo/internal/nametables"
)

func cmdNameOverlayTrace(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-trace", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original retail CUE (auto-detected when empty)")
	report := fs.String("report", "", "NEW private focused JSON; no overwrite")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-trace [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_overlay_trace_G41.json]")
	}
	ref, err := privateN10ReportPath(root, filepath.Join(root, ".local", "go_toolchain", "reports", "G39_OWNER_G38_FOLLOWUP.json"), true)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(ref)
	if err != nil {
		return err
	}
	if len(raw) > 1<<20 || fmt.Sprintf("%x", sha256.Sum256(raw)) != ownerG38FollowupSHA {
		return errors.New("owner G38 retail report SHA mismatch")
	}
	var old nametables.N10LoaderFollowupReport
	if err = json.Unmarshal(raw, &old); err != nil {
		return err
	}
	cue, err := cueChoice(root, *game)
	if err != nil {
		return err
	}
	tracks, err := parseCue(cue)
	if err != nil {
		return err
	}
	f, iso, err := openDiscISO(tracks.Data, tracks.Sectors)
	if err != nil {
		return err
	}
	defer f.Close()
	exe, err := (isoSource{iso}).ReadFile(nametables.EXE)
	if err != nil {
		return err
	}
	traced, err := nametables.BuildN10DispatchTraceG41(exe, old, ownerG38FollowupSHA)
	if err != nil {
		return err
	}
	fmt.Fprintf(commandOutput, "Original EXE verified: %d bounded windows / %d bytes; %d lexical control-word candidates.\n", len(traced.Windows), traced.SourceWindowBytes, len(traced.LexicalControlSites))
	fmt.Fprintf(commandOutput, "G41 bounded static paths: %d seeds, %d nearby syntactic $t9 indirect controls.\n", len(traced.StaticFlow.Seeds), len(traced.StaticFlow.SyntacticT9IndirectWithin64Bytes))
	fmt.Fprintln(commandOutput, "Static bounded flow plus decoded words only. N10 HOLD / DO_NOT_BOOT: no loader RAM-write or BSS proof.")
	if *report == "" {
		fmt.Fprintln(commandOutput, "Pass --report to save the private detailed windows.")
		return nil
	}
	dst, err := privateN10ReportPath(root, *report, false)
	if err != nil {
		return err
	}
	buf, err := json.MarshalIndent(traced, "", "  ")
	if err != nil {
		return err
	}
	if len(buf) > 1<<20 {
		return errors.New("bounded G40 report exceeds 1MiB")
	}
	fOut, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = fOut.Write(append(buf, '\n')); err != nil {
		fOut.Close()
		os.Remove(dst)
		return err
	}
	if err = fOut.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	fmt.Fprintln(commandOutput, "Saved original EXE static trace under private .local/go_toolchain. Original disc unchanged.")
	return nil
}
