package main

// Experimental native disc builder: copies the original multi-track CUE/BIN
// to a fresh private staging directory, writes only changed MODE2/Form1
// sectors, checks the resulting file hashes/EDC/ECC and atomically publishes
// the directory. Production `build` deliberately remains Python-backed.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"tokimemo/internal/config"
	"tokimemo/internal/patchplan"
	"tokimemo/internal/ps1"
)

func buildDigest(v []byte) string { s := sha256.Sum256(v); return hex.EncodeToString(s[:]) }

// writePlannedFiles verifies every original/patched file and every target
// sector before the first mutation of the staging copy. The original reader
// must remain open and read-only throughout this operation.
func writePlannedFiles(original *ps1.ISO, destination *os.File, plan patchplan.Result, modified map[string][]byte) (int, error) {
	type update struct {
		name          string
		entry         ps1.ISOEntry
		before, after []byte
	}
	updates := make([]update, 0, len(plan.Files))
	claimed := make(map[int64]string)
	for _, file := range plan.Files {
		entry, ok := original.Entries[file.Path]
		if !ok || entry.IsDir {
			return 0, fmt.Errorf("missing ISO file %q", file.Path)
		}
		if file.Size < 0 || int64(file.Size) != entry.Size {
			return 0, fmt.Errorf("invalid file extent %s", file.Path)
		}
		after, ok := modified[file.Path]
		if !ok || len(after) != file.Size {
			return 0, fmt.Errorf("missing planned bytes %s", file.Path)
		}
		if digest(after) != file.PatchedSHA256 {
			return 0, fmt.Errorf("planned bytes hash mismatch %s", file.Path)
		}
		var source bytes.Buffer
		if err := ps1.ReadFileTo(original.Reader, original.Sectors, entry.LBA, entry.Size, &source); err != nil {
			return 0, err
		}
		before := source.Bytes()
		if digest(before) != file.OriginalSHA256 {
			return 0, fmt.Errorf("source differs from plan: %s", file.Path)
		}
		changed, err := ps1.ChangedSectors(before, after)
		if err != nil {
			return 0, err
		}
		for _, offset := range changed {
			lba := entry.LBA + offset
			if lba < entry.LBA || lba >= original.Sectors {
				return 0, fmt.Errorf("LBA outside track for %s", file.Path)
			}
			if other, ok := claimed[lba]; ok {
				return 0, fmt.Errorf("overlapping modified LBA %d: %s and %s", lba, other, file.Path)
			}
			claimed[lba] = file.Path
			sector, err := ps1.ReadSectorAt(destination, lba)
			if err != nil {
				return 0, err
			}
			if !ps1.IsForm1(sector) {
				return 0, fmt.Errorf("LBA %d is not MODE2/Form1", lba)
			}
			start := int(offset) * ps1.DataSize
			end := start + ps1.DataSize
			if end > len(before) {
				end = len(before)
			}
			if !bytes.Equal(sector[ps1.DataOffset:ps1.DataOffset+end-start], before[start:end]) {
				return 0, fmt.Errorf("staged disc differs at LBA %d", lba)
			}
		}
		updates = append(updates, update{file.Path, entry, before, after})
	}
	total := 0
	for _, u := range updates {
		n, err := ps1.WriteFileDiff(destination, original.Sectors, u.entry.LBA, u.before, u.after)
		if err != nil {
			return 0, fmt.Errorf("writing %s: %w", u.name, err)
		}
		total += n
		var got bytes.Buffer
		if err = ps1.ReadFileTo(destination, original.Sectors, u.entry.LBA, u.entry.Size, &got); err != nil {
			return 0, err
		}
		if !bytes.Equal(got.Bytes(), u.after) {
			return 0, fmt.Errorf("post-write byte mismatch %s", u.name)
		}
	}
	if err := destination.Sync(); err != nil {
		return 0, err
	}
	return total, nil
}

func copyTrackFile(src, dest string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	out, err := os.OpenFile(dest, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	written, err := io.Copy(out, in)
	if err == nil {
		err = out.Sync()
	}
	if ce := out.Close(); err == nil {
		err = ce
	}
	if err != nil {
		return err
	}
	st, e := in.Stat()
	if e != nil {
		return e
	}
	if written != st.Size() {
		return fmt.Errorf("copy incomplete: %s", src)
	}
	// Verify every copied byte, including tracks not modified by the patch.
	a, e := shaFile(src)
	if e != nil {
		return e
	}
	b, e := shaFile(dest)
	if e != nil {
		return e
	}
	if a != b {
		return fmt.Errorf("copied track does not match source: %s", src)
	}
	return nil
}
func stageCue(cue string, info cueInfo, stage string) (string, error) {
	base := filepath.Dir(cue)
	sources := append([]string{cue}, info.Inputs...)
	seen := make(map[string]bool)
	for _, src := range sources {
		rel, err := filepath.Rel(base, src)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) || rel == "." {
			return "", fmt.Errorf("unsafe CUE track reference %s", src)
		}
		if seen[rel] {
			continue
		}
		seen[rel] = true
		if err = copyTrackFile(src, filepath.Join(stage, rel)); err != nil {
			return "", fmt.Errorf("copying %s: %w", rel, err)
		}
	}
	rel, err := filepath.Rel(base, info.Data)
	if err != nil {
		return "", err
	}
	return filepath.Join(stage, rel), nil
}
func shaFile(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err = io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func compareBuiltCues(native, python string) error {
	a, err := parseCue(native)
	if err != nil {
		return err
	}
	b, err := parseCue(python)
	if err != nil {
		return err
	}
	if len(a.Inputs) != len(b.Inputs) {
		return errors.New("Go/Python output track counts differ")
	}
	filesA := append([]string{native}, a.Inputs...)
	filesB := append([]string{python}, b.Inputs...)
	for i := range filesA {
		ha, err := shaFile(filesA[i])
		if err != nil {
			return err
		}
		hb, err := shaFile(filesB[i])
		if err != nil {
			return err
		}
		if ha != hb {
			return fmt.Errorf("Go/Python disc bytes differ for %s", filepath.Base(filesA[i]))
		}
	}
	return nil
}

func cmdNativeBuild(root string, argv []string) error {
	fs := flag.NewFlagSet("native-build", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	game := fs.String("game", "", "original CUE")
	output := fs.String("output", "", "new output directory (must not exist)")
	experimental := fs.Bool("experimental", false, "explicitly allow native experimental disc assembly")
	compare := fs.Bool("compare-python", false, "build a second temporary Python disc and compare every CUE/BIN hash")
	var translations strList
	fs.Var(&translations, "translation", "specific translation JSON; repeatable")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if !*experimental {
		return errors.New("native-build is an optional comparison command; pass --experimental (normal build uses the validated Go compositor)")
	}
	if fs.NArg() > 1 || (*game != "" && fs.NArg() != 0) {
		return errors.New("usage: tokimemo native-build --experimental [--game CUE] [--output NEW_DIR] [--compare-python]")
	}
	explicit := *game
	if fs.NArg() == 1 {
		explicit = fs.Arg(0)
	}
	cue, err := cueChoice(root, explicit)
	if err != nil {
		return err
	}
	info, err := parseCue(cue)
	if err != nil {
		return err
	}
	if _, err = auditCueForNative(cue); err != nil {
		return fmt.Errorf("native CUE safety audit: %w", err)
	}
	canonicalSourceDir, err := filepath.EvalSymlinks(filepath.Dir(cue))
	if err != nil {
		return err
	}
	out := *output
	if out == "" {
		out = filepath.Join(root, ".local", "build", "ps1-native-experimental")
	}
	out, err = filepath.Abs(out)
	if err != nil {
		return err
	}
	if err = config.SafeOutput(root, cue, out); err != nil {
		return err
	}
	if err = config.SafeOutput(root, filepath.Join(canonicalSourceDir, filepath.Base(cue)), out); err != nil {
		return fmt.Errorf("canonical source isolation: %w", err)
	}
	// Never create a native-build output inside the translation or public
	// checkout; only .local/build is an approved in-repo destination.
	if config.Within(root, out) && !config.Within(filepath.Join(root, ".local", "build"), out) {
		return errors.New("native build output inside repository must be under .local/build/")
	}
	if _, err = os.Lstat(out); err == nil {
		return fmt.Errorf("output exists; experimental builds require a NEW directory: %s", out)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	discInputs, err := freezeInputs(append([]string{cue}, info.Inputs...))
	if err != nil {
		return fmt.Errorf("snapshotting original CUE/tracks: %w", err)
	}
	paths := make([]string, 0, len(translations))
	for _, p := range translations {
		if !filepath.IsAbs(p) {
			p = filepath.Join(root, p)
		}
		paths = append(paths, p)
	}
	if len(paths) == 0 {
		paths, err = filepath.Glob(filepath.Join(root, "translation", "*.json"))
		if err != nil {
			return err
		}
		sort.Strings(paths)
	}
	translationInputs, err := freezeInputs(paths)
	if err != nil {
		return fmt.Errorf("snapshotting translation inputs: %w", err)
	}
	batch, err := patchplan.Load(root, paths)
	if err != nil {
		return err
	}
	if err = verifyFrozen(translationInputs); err != nil {
		return err
	}
	imageInputs, err := freezeInputs(graphicPaths(batch))
	if err != nil {
		return fmt.Errorf("snapshotting PNG inputs: %w", err)
	}
	src, iso, err := openDiscISO(info.Data, info.Sectors)
	if err != nil {
		return err
	}
	defer src.Close()
	cnf, ok := iso.Entries["SYSTEM.CNF"]
	if !ok || cnf.IsDir {
		return errors.New("missing SYSTEM.CNF")
	}
	var boot bytes.Buffer
	if err = ps1.ReadFileTo(src, info.Sectors, cnf.LBA, cnf.Size, &boot); err != nil {
		return err
	}
	if !bytes.Contains(boot.Bytes(), []byte("cdrom:SLPM_86.053")) {
		return errors.New("unsupported disc: SLPM-86053 marker missing")
	}
	fmt.Fprintln(commandOutput, "Step 1/4: planning changes against the original game (read-only)")
	plan, modified, err := patchplan.PlanBytes(isoSource{iso}, batch)
	if err != nil {
		return err
	}
	for _, snapshot := range [][]frozenInput{discInputs, translationInputs, imageInputs} {
		if err = verifyFrozen(snapshot); err != nil {
			return err
		}
	}
	parent := filepath.Dir(out)
	if err = os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(parent, ".tokimemo-native-stage-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage)
	fmt.Fprintln(commandOutput, "Step 2/4: copying CUE and all tracks into isolated staging")
	dataTrack, err := stageCue(cue, info, stage)
	if err != nil {
		return err
	}
	copied, err := os.OpenFile(dataTrack, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	fmt.Fprintln(commandOutput, "Step 3/4: applying changed sectors and checking EDC/ECC/file hashes")
	sectors, err := writePlannedFiles(iso, copied, plan, modified)
	ce := copied.Close()
	if err != nil {
		return err
	}
	if ce != nil {
		return ce
	}
	for _, snapshot := range [][]frozenInput{discInputs, translationInputs, imageInputs} {
		if err = verifyFrozen(snapshot); err != nil {
			return err
		}
	}
	if *compare {
		fmt.Fprintln(commandOutput, "Step 4/4: building separate Python reference and comparing every track byte")
		pyOut := filepath.Join(stage, "_python_reference") // excluded from publishing below
		python := os.Getenv("TOKIMEMO_PYTHON")
		if python == "" {
			python = "python3"
		}
		args := []string{"-m", "tokipatch", cue, "-o", pyOut}
		for _, p := range paths {
			args = append(args, "-t", p)
		}
		cmd := exec.Command(python, args...)
		cmd.Dir = root
		cmd.Env = pythonEnv(root)
		stdout, err := cmd.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Python reference failed: %w: %s", err, string(stdout))
		}
		parity, checkErr := DiscParity(filepath.Join(stage, filepath.Base(cue)), filepath.Join(pyOut, filepath.Base(cue)), cue)
		if checkErr != nil {
			return checkErr
		}
		if err = writeParityReport(filepath.Join(stage, ".parity-report.json"), parity); err != nil {
			return err
		}
		if err = os.RemoveAll(pyOut); err != nil {
			return err
		}
		fmt.Fprintln(commandOutput, "Go/Python entire disc bytes: PASS")
	} else {
		fmt.Fprintln(commandOutput, "Step 4/4: publishing verified experimental output (real-disc Python parity not checked)")
	}
	// Sources and translation data may have changed while the Python reference was running.
	// Fail closed rather than publish a result built from inconsistent inputs.
	for _, snapshot := range [][]frozenInput{discInputs, translationInputs, imageInputs} {
		if err = verifyFrozen(snapshot); err != nil {
			return err
		}
	}
	// No-existing-directory atomic rename publishes only a fully checked image.
	if _, err = os.Lstat(out); err == nil {
		return fmt.Errorf("output appeared during staging: %s", out)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = publishNativeDirectory(stage, out); err != nil {
		return err
	}
	fmt.Fprintf(commandOutput, "NATIVE EXPERIMENTAL BUILD: OK\nOutput CUE: %s\nFiles planned: %d; sectors rewritten: %d\nGo-written sectors: EDC/ECC verified; patched game files: verified\nDuckStation runtime: NOT TESTED\n", filepath.Join(out, filepath.Base(cue)), len(plan.Files), sectors)
	return nil
}
