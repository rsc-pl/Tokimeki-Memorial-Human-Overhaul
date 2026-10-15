package main

// G39: offline reinterpretation of owner G38's authenticated raw-word windows.
// Does not open a game image or write patches; the full owner report is bundled.
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

const ownerG38FollowupSHA = "9ba733be9781712606e3a6d6bcfb23aa713c668160ee9c67073d6529d748c4da"

func cmdNameOverlayDispatch(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-dispatch", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	reportPath := fs.String("report", "", "optional NEW private offline classification JSON; refuses overwrite")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-dispatch [--report .local/go_toolchain/reports/n10_dispatch_G39.json]")
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
		return errors.New("original G38 report SHA-256 mismatch")
	}
	var owner nametables.N10LoaderFollowupReport
	if err = json.Unmarshal(raw, &owner); err != nil {
		return err
	}
	reviewed, err := nametables.ReviewN10OverlayDispatch(owner, ownerG38FollowupSHA)
	if err != nil {
		return err
	}
	fmt.Fprintf(commandOutput, "G38 source authenticated. Dispatch arms %d, common RAM pointer %s, join %s; %d isolated anchors.\n", len(reviewed.DispatchArms), reviewed.DispatchSlot, reviewed.DispatchJoinRAM, len(reviewed.SeparateAnchorOffsets))
	fmt.Fprintf(commandOutput, "Data-like JAL candidates %d (unproven); original O.BIN A/B/C=%d, C+64=%d.\n", len(reviewed.DataLikeJALOffsets), reviewed.OddBINDirectABC, reviewed.OddBINDirectCPlus64)
	fmt.Fprintln(commandOutput, "N10 HOLD: no loader/BSS lifetime, RAM-ownership, pointer-alias, append-bound or boot approval.")
	if *reportPath == "" {
		return nil
	}
	dst, err := privateN10ReportPath(root, *reportPath, false)
	if err != nil {
		return err
	}
	buf, err := json.MarshalIndent(reviewed, "", "  ")
	if err != nil {
		return err
	}
	fd, err := os.OpenFile(dst, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	if _, err = fd.Write(append(buf, '\n')); err != nil {
		fd.Close()
		os.Remove(dst)
		return err
	}
	if err = fd.Close(); err != nil {
		os.Remove(dst)
		return err
	}
	fmt.Fprintln(commandOutput, "Saved private offline dispatch review. Original game/translation unchanged.")
	return nil
}
