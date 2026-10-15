package main

// G46: export complete original executable sources once, instead of asking the
// owner for more and more sliced original-disc instruction windows.
// This intentionally never copies audio, FMV, translation, or the full game ISO.
import (
	"archive/zip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"tokimemo/internal/nametables"
	"tokimemo/internal/ps1"
)

type n10ExportEntry struct {
	Path   string `json:"path"`
	LBA    int64  `json:"lba"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}
type n10ExportManifest struct {
	Format            string           `json:"format"`
	OriginalEXESHA256 string           `json:"original_exe_sha256"`
	ExecutableSources int              `json:"executable_sources"`
	AdditionalOddBIN  bool             `json:"additional_odd_bin"`
	Files             []n10ExportEntry `json:"files"`
	Note              string           `json:"note"`
}

func selectN10SourceFiles(iso *ps1.ISO) ([]ps1.ISOEntry, error) {
	if iso == nil {
		return nil, errors.New("ISO inventory unavailable")
	}
	const odd = "CDROM/EXEDIR/O.BIN"
	exnCount, mainCount, oddCount := 0, 0, 0
	selected := []ps1.ISOEntry{}
	for _, ent := range iso.Entries {
		if ent.IsDir {
			continue
		}
		if ent.Path == nametables.EXE {
			mainCount++
		} else if strings.HasSuffix(ent.Path, ".EXN") {
			exnCount++
		} else if ent.Path == odd {
			oddCount++
		} else {
			continue
		}
		if ent.Size <= 0 || ent.Size > 16<<20 {
			return nil, fmt.Errorf("invalid size for %s: %d", ent.Path, ent.Size)
		}
		selected = append(selected, ent)
	}
	if mainCount != 1 || exnCount != 26 || oddCount != 1 || len(selected) != 28 {
		return nil, fmt.Errorf("unexpected original-disc source inventory: EXE=%d EXN=%d O.BIN=%d; export refused", mainCount, exnCount, oddCount)
	}
	sort.Slice(selected, func(i, j int) bool { return selected[i].Path < selected[j].Path })
	return selected, nil
}

// writeN10SourceZIP is deliberately independent from CUE parsing; tests use a
// synthetic reader, never a copy of the retail game.
func writeN10SourceZIP(w io.Writer, entries []ps1.ISOEntry, originalEXESHA string, reader func(ps1.ISOEntry, io.Writer) error) (n10ExportManifest, error) {
	result := n10ExportManifest{
		Format:            "TOKIMEMO_N10_G46_ORIGINAL_CODE_SOURCES",
		OriginalEXESHA256: originalEXESHA,
		ExecutableSources: 27,
		AdditionalOddBIN:  true,
		Files:             make([]n10ExportEntry, 0, len(entries)),
		Note:              "Private original-game source bytes; original-disc static evidence only. Does not prove N10 RAM ownership, runtime transfers, or patch safety.",
	}
	if len(entries) != 28 || reader == nil || len(originalEXESHA) != 64 {
		return result, errors.New("expected exactly 28 original source files")
	}
	zw := zip.NewWriter(w)
	for _, ent := range entries {
		if ent.IsDir || ent.Size <= 0 || ent.Size > 16<<20 || ent.Path == "" || filepath.IsAbs(ent.Path) || strings.Contains(ent.Path, "\\") || strings.Contains(ent.Path, "..") {
			return result, fmt.Errorf("unsafe source entry: %q", ent.Path)
		}
		header := &zip.FileHeader{Name: "sources/" + ent.Path, Method: zip.Deflate}
		header.SetMode(0600)
		header.Modified = time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC)
		zf, err := zw.CreateHeader(header)
		if err != nil {
			return result, err
		}
		h := sha256.New()
		n := &countingWriter{out: io.MultiWriter(zf, h)}
		if err = reader(ent, n); err != nil {
			return result, fmt.Errorf("read %s: %w", ent.Path, err)
		}
		if n.count != ent.Size {
			return result, fmt.Errorf("read %s: wanted %d, got %d bytes", ent.Path, ent.Size, n.count)
		}
		sum := hex.EncodeToString(h.Sum(nil))
		if ent.Path == nametables.EXE && sum != originalEXESHA {
			return result, errors.New("retail SLPM_86.053 SHA-256 mismatch; export refused")
		}
		result.Files = append(result.Files, n10ExportEntry{Path: ent.Path, LBA: ent.LBA, Size: ent.Size, SHA256: sum})
	}
	raw, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return result, err
	}
	zmanifest, err := zw.Create("SOURCE_MANIFEST.json")
	if err != nil {
		return result, err
	}
	if _, err = zmanifest.Write(append(raw, '\n')); err != nil {
		return result, err
	}
	if err = zw.Close(); err != nil {
		return result, err
	}
	return result, nil
}

type countingWriter struct {
	out   io.Writer
	count int64
}

func (w *countingWriter) Write(b []byte) (int, error) {
	n, e := w.out.Write(b)
	w.count += int64(n)
	return n, e
}

func cmdNameSourceExport(root string, args []string) error {
	fs := flag.NewFlagSet("name-source-export", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original PS1 CUE; auto-discovered if omitted")
	out := fs.String("out", "", "new private ZIP path outside the repository, e.g. ~/Downloads/Tokimemo-N10-sources.zip")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *out == "" {
		return errors.New("usage: tokimemo name-source-export --out /path/to/NEW-private-original-sources.zip [--game ORIGINAL.cue]")
	}
	absolute, err := filepath.Abs(*out)
	if err != nil {
		return err
	}
	if !strings.EqualFold(filepath.Ext(absolute), ".zip") {
		return errors.New("output must end in .zip")
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(absRoot, absolute)
	if err != nil {
		return err
	}
	if rel == "." || rel == ".." || (!strings.HasPrefix(rel, ".."+string(os.PathSeparator)) && !filepath.IsAbs(rel)) {
		return errors.New("private original-game export must be outside repository")
	}
	if st, err := os.Lstat(filepath.Dir(absolute)); err != nil || !st.IsDir() {
		return errors.New("export parent folder must already exist and be a directory")
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
	selected, err := selectN10SourceFiles(iso)
	if err != nil {
		return err
	}
	// File is opened exclusively: existing exports, including symlinks, never overwritten.
	output, err := os.OpenFile(absolute, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	ok := false
	defer func() {
		output.Close()
		if !ok {
			os.Remove(absolute)
		}
	}()
	manifest, err := writeN10SourceZIP(output, selected, nametables.N10OriginalEXESHA, func(ent ps1.ISOEntry, dst io.Writer) error {
		return ps1.ReadFileTo(f, tracks.Sectors, ent.LBA, ent.Size, dst)
	})
	if err != nil {
		return err
	}
	if err = output.Sync(); err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	ok = true
	var total int64
	for _, e := range manifest.Files {
		total += e.Size
	}
	fmt.Fprintf(commandOutput, "Exported %d complete original-disc sources (%d bytes) to %s. Only private source ZIP; no ROM writes. N10 HOLD.\n", len(manifest.Files), total, absolute)
	return nil
}
