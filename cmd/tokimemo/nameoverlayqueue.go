package main

// G45: read-only bounded continuation of the G44 queue route. No ROM writes.
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

func cmdNameOverlayQueue(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-queue", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original PS1 CUE; auto-detected if omitted")
	report := fs.String("report", "", "NEW private G45 report JSON; existing files never overwritten")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-queue [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_overlay_queue_G45.json]")
	}
	load := func(name, sha string) ([]byte, error) {
		p, e := privateN10ReportPath(root, filepath.Join(root, ".local", "go_toolchain", "reports", name), true)
		if e != nil {
			return nil, e
		}
		b, e := os.ReadFile(p)
		if e != nil {
			return nil, e
		}
		if len(b) > 256<<10 || fmt.Sprintf("%x", sha256.Sum256(b)) != sha {
			return nil, fmt.Errorf("G45 owner %s SHA/size mismatch", name)
		}
		return b, nil
	}
	a, e := load("G45_OWNER_G44_ROUTE.json", nametables.N10OwnerG44RouteSHA)
	if e != nil {
		return e
	}
	b, e := load("G44_OWNER_G43_TRANSFER.json", nametables.N10OwnerG43TransferSHA)
	if e != nil {
		return e
	}
	review, e := nametables.ReviewN10QueueG45(a, b)
	if e != nil {
		return e
	}
	cue, e := cueChoice(root, *game)
	if e != nil {
		return e
	}
	tracks, e := parseCue(cue)
	if e != nil {
		return e
	}
	f, iso, e := openDiscISO(tracks.Data, tracks.Sectors)
	if e != nil {
		return e
	}
	defer f.Close()
	exe, e := (isoSource{iso}).ReadFile(nametables.EXE)
	if e != nil {
		return e
	}
	review, e = nametables.CaptureN10QueueG45(exe, review)
	if e != nil {
		return e
	}
	fmt.Fprintf(commandOutput, "G45 original retail queue: %d x %d bytes [%s,%s), %d bounded continuation windows; runtime DMA/ownership UNKNOWN. N10 HOLD.\n", review.Queue.Capacity, review.Queue.RecordStride, review.Queue.QueueBase, review.Queue.QueueEndExclusive, len(review.ExtraCodeWindows))
	if *report == "" {
		fmt.Fprintln(commandOutput, "Use --report to save original source windows.")
		return nil
	}
	dest, e := privateN10ReportPath(root, *report, false)
	if e != nil {
		return e
	}
	raw, e := json.MarshalIndent(review, "", "  ")
	if e != nil {
		return e
	}
	if len(raw) > 256<<10 {
		return errors.New("G45 report too large")
	}
	out, e := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if e != nil {
		return e
	}
	if _, e = out.Write(append(raw, '\n')); e != nil {
		out.Close()
		os.Remove(dest)
		return e
	}
	if e = out.Close(); e != nil {
		os.Remove(dest)
		return e
	}
	fmt.Fprintln(commandOutput, "Saved private G45 report; no game/translation changes.")
	return nil
}
