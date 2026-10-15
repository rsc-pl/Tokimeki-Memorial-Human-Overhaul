package main

// N10 loader investigation is header metadata + static main executable
// pointer/call catalog only. It cannot prove an overlay was loaded in RAM.
import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"tokimemo/internal/nametables"
	"tokimemo/internal/ps1"
)

const ownerG36GeometrySHA = "72452fe1df5ab2c9f0e5819946ae5402529a11272516a40f00541089878da024"

func cmdNameOverlayLoader(root string, args []string) error {
	fs := flag.NewFlagSet("name-overlay-loader", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "owner original PS1 CUE; auto-discovers if blank")
	report := fs.String("report", "", "NEW private JSON report path; no overwrite")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo name-overlay-loader [--game ORIGINAL.cue] [--report .local/go_toolchain/reports/n10_overlay_loader_G37.json]")
	}
	source, err := privateN10ReportPath(root, filepath.Join(root, ".local", "go_toolchain", "reports", "G37_OWNER_G36_GEOMETRY.json"), true)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		return err
	}
	if len(raw) > 2<<20 || fmt.Sprintf("%x", sha256.Sum256(raw)) != ownerG36GeometrySHA {
		return errors.New("owner G36 geometry SHA mismatch; original provenance required")
	}
	var geo nametables.GeometryReport
	if err := json.Unmarshal(raw, &geo); err != nil {
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
	analyzed, err := nametables.AnalyzeN10LoadHeader(exe, geo, ownerG36GeometrySHA)
	if err != nil {
		return err
	}
	const gapStart, gapEnd int64 = 38474, 38570
	analyzed.UnscannedEXNInventoryGapStartLBA = gapStart
	analyzed.UnscannedEXNInventoryGapEndExclusiveLBA = gapEnd
	for _, entry := range iso.Entries {
		if ps1.IsExternalTrackAudio(entry) || entry.Size < 0 || entry.LBA < 0 {
			continue
		}
		sectors := (entry.Size + 2047) / 2048
		if sectors == 0 || entry.LBA >= gapEnd || entry.LBA+sectors <= gapStart {
			continue
		}
		analyzed.ISOExtentsOverlappingGap = append(analyzed.ISOExtentsOverlappingGap, nametables.N10ISOGapOccupant{Path: entry.Path, LBA: entry.LBA, Size: entry.Size, Sectors: sectors, IsDirectory: entry.IsDir})
		if len(analyzed.ISOExtentsOverlappingGap) > 128 {
			return errors.New("too many ISO entries overlapping the EXN inventory gap")
		}
	}
	sort.Slice(analyzed.ISOExtentsOverlappingGap, func(i, j int) bool {
		a, b := analyzed.ISOExtentsOverlappingGap[i], analyzed.ISOExtentsOverlappingGap[j]
		if a.LBA != b.LBA {
			return a.LBA < b.LBA
		}
		return a.Path < b.Path
	})
	fmt.Fprintf(commandOutput, "Original PS-X EXE header: load %s, text bytes %d, BSS declared %s/%d.\n", analyzed.Header.TextAddress, analyzed.Header.TextSize, analyzed.Header.BSSAddress, analyzed.Header.BSSSize)
	fmt.Fprintf(commandOutput, "Legacy file-address mapping matches header: %v. Static main JAL toward overlay range: %d; adjacent overlay address pairs: %d.\n", analyzed.Header.LegacyMainBaseAgrees, analyzed.StaticDirectOverlayJALCount, analyzed.StaticOverlayAddressPairCount)
	fmt.Fprintln(commandOutput, "DECLARED METADATA / STATIC BYTES ONLY: loader, runtime BSS, scratch lifetime NOT verified; N10 DO_NOT_BOOT.")
	if *report == "" {
		fmt.Fprintln(commandOutput, "Use --report to save new private bounded JSON.")
		return nil
	}
	dest, err := privateN10ReportPath(root, *report, false)
	if err != nil {
		return err
	}
	out, err := json.MarshalIndent(analyzed, "", "  ")
	if err != nil {
		return err
	}
	if len(out) > 128<<10 {
		return errors.New("loader report exceeds 128KiB bound")
	}
	fd, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err = fd.Write(append(out, '\n')); err != nil {
		fd.Close()
		os.Remove(dest)
		return err
	}
	if err = fd.Close(); err != nil {
		os.Remove(dest)
		return err
	}
	fmt.Fprintln(commandOutput, "Private original-disc header/static report saved, game and translations unchanged.")
	return nil
}
