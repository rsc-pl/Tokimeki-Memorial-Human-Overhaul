// Tokimemo Human Overhaul: Linux-first build and QA command line.
// Go owns orchestration and corpus checks. Legacy Python remains the tested
// sector/EDC/ECC/renderer writer until an independently tested Go port exists.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"tokimemo/internal/config"
	"tokimemo/internal/ps1"
	"tokimemo/internal/termui"
)

const (
	cyan  = "\033[36m"
	green = "\033[32m"
	red   = "\033[31m"
	amber = "\033[33m"
	bold  = "\033[1m"
	reset = "\033[0m"
)

var lineFile = regexp.MustCompile(`(?i)^\s*FILE\s+(?:"([^"]+)"|(\S+))\s+\S+`)
var lineTrack = regexp.MustCompile(`(?i)^\s*TRACK\s+\d+\s+(\S+)`)

var commandOutput io.Writer = os.Stdout

type counter struct{ Files, Strings, Images, Bytes, Blocks, Lines int }
type strList []string

func (s *strList) String() string     { return strings.Join(*s, ", ") }
func (s *strList) Set(v string) error { *s = append(*s, v); return nil }

func rootDir() (string, error) {
	if v := os.Getenv("TOKIMEMO_ROOT"); v != "" {
		return filepath.Abs(v)
	}
	wd, e := os.Getwd()
	if e != nil {
		return "", e
	}
	for p := wd; ; p = filepath.Dir(p) {
		if _, e := os.Stat(filepath.Join(p, "translation", "character_names.json")); e == nil {
			if _, e := os.Stat(filepath.Join(p, "legacy_scripts", "tokipatch", "patcher.py")); e == nil {
				return p, nil
			}
		}
		if parent := filepath.Dir(p); parent == p {
			break
		}
	}
	return "", errors.New("not inside the Human Overhaul repository (or set TOKIMEMO_ROOT)")
}
func say(head, val string)   { fmt.Fprintf(commandOutput, "%s%-14s%s %s\n", cyan, head, reset, val) }
func failure(err error)      { fmt.Fprintf(os.Stderr, "\n%s%sFAIL%s %v\n", bold, red, reset, err) }
func success(summary string) { fmt.Printf("\n%s%sOK%s %s\n", bold, green, reset, summary) }
func getInt(v any) (int64, error) {
	switch x := v.(type) {
	case string:
		return strconv.ParseInt(x, 0, 64)
	case float64:
		// encoding/json decodes unquoted JSON numbers as float64 here.
		// Outside the exactly representable integer range, two distinct
		// source offsets can silently become the same number (for example
		// 9007199254740993 rounds to 9007199254740992). Refuse that
		// ambiguity; quoted integer offsets remain parsed exactly above.
		const maxExactJSONInteger = float64(1<<53 - 1)
		if x < -maxExactJSONInteger || x > maxExactJSONInteger {
			return 0, errors.New("JSON integer exceeds exact numeric range; quote the offset")
		}
		if x != float64(int64(x)) {
			return 0, errors.New("not an integer")
		}
		return int64(x), nil
	default:
		return 0, fmt.Errorf("unsupported numeric value %T", v)
	}
}
func nonnegativeInput(v any) (int64, error) {
	n, err := getInt(v)
	if err != nil {
		return 0, err
	}
	if n < 0 {
		return 0, fmt.Errorf("negative offset: %d", n)
	}
	return n, nil
}

// validatedPNGSource checks the complete JSON-relative input path before a
// command reads a PNG. The production planner itself is source-reference-only
// in the cumulative installer, so every public CLI consumer uses this gate.
func validatedPNGSource(jsonFile, relative string) (string, error) {
	if relative == "" || filepath.IsAbs(relative) {
		return "", fmt.Errorf("invalid relative PNG path %q", relative)
	}
	base, err := filepath.Abs(filepath.Dir(jsonFile))
	if err != nil {
		return "", err
	}
	target := filepath.Clean(filepath.Join(base, relative))
	rel, err := filepath.Rel(base, target)
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("PNG leaves source directory: %q", relative)
	}
	st, err := os.Lstat(base)
	if err != nil {
		return "", err
	}
	if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("PNG source directory is not a real directory: %s", filepath.Base(base))
	}
	current := base
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		current = filepath.Join(current, part)
		st, err := os.Lstat(current)
		if err != nil {
			return "", fmt.Errorf("PNG input %s: %w", relative, err)
		}
		if st.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("PNG input crosses symlink: %s", relative)
		}
		if i == len(parts)-1 {
			if !st.Mode().IsRegular() {
				return "", fmt.Errorf("PNG input is not a regular file: %s", relative)
			}
		} else if !st.IsDir() {
			return "", fmt.Errorf("PNG parent is not a directory: %s", relative)
		}
	}
	return target, nil
}

// checkPNGSourceFiles is the common preflight for CLI readers that invoke the
// reference planner or graphics checker without the full corpus validation.
func checkPNGSourceFiles(paths []string) error {
	for _, source := range paths {
		data, err := os.ReadFile(source)
		if err != nil {
			return err
		}
		var doc struct {
			Images []struct {
				PNG string `json:"png"`
			} `json:"images"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			return fmt.Errorf("%s: %w", filepath.Base(source), err)
		}
		for _, image := range doc.Images {
			if _, err := validatedPNGSource(source, image.PNG); err != nil {
				return fmt.Errorf("%s: %w", filepath.Base(source), err)
			}
		}
	}
	return nil
}

func validate(root string) (counter, error) {
	paths, err := filepath.Glob(filepath.Join(root, "translation", "*.json"))
	if err != nil {
		return counter{}, err
	}
	return validateSourcePaths(root, paths, true)
}

// validateSourcePaths enforces the same source-value and PNG contract for
// explicit/native translation selections as ordinary status and build. A
// read-only planner must not silently round a JSON offset before planning.
func validateSourcePaths(root string, paths []string, includeStandaloneGraphics bool) (counter, error) {
	var n counter
	var issues []error
	paths = append([]string(nil), paths...)
	sort.Strings(paths)
	if len(paths) == 0 {
		return n, errors.New("no translation/*.json files found")
	}
	for _, p := range paths {
		raw, e := os.ReadFile(p)
		if e != nil {
			issues = append(issues, fmt.Errorf("%s: %w", filepath.Base(p), e))
			continue
		}
		var doc map[string]json.RawMessage
		if e = json.Unmarshal(raw, &doc); e != nil {
			issues = append(issues, fmt.Errorf("%s: %w", filepath.Base(p), e))
			continue
		}
		n.Files++
		for _, key := range []string{"strings", "dialogue", "images", "bytes"} {
			b, found := doc[key]
			if !found {
				continue
			}
			var items []map[string]any
			if e = json.Unmarshal(b, &items); e != nil {
				issues = append(issues, fmt.Errorf("%s/%s: %w", filepath.Base(p), key, e))
				continue
			}
			for i, item := range items {
				label := fmt.Sprintf("%s:%s[%d]", filepath.Base(p), key, i)
				file, ok := item["file"].(string)
				if !ok || file == "" {
					issues = append(issues, fmt.Errorf("%s: missing file", label))
					continue
				}
				if !strings.HasPrefix(file, "/") && !strings.Contains(file, "..") {
				} else {
					issues = append(issues, fmt.Errorf("%s: unsafe disc path", label))
					continue
				}
				switch key {
				case "strings":
					n.Strings++
					if _, e = nonnegativeInput(item["offset"]); e != nil {
						issues = append(issues, fmt.Errorf("%s: offset: %w", label, e))
						continue
					}
					for _, k := range []string{"original", "text"} {
						if _, ok := item[k].(string); !ok {
							issues = append(issues, fmt.Errorf("%s: %s not text", label, k))
							continue
						}
					}
					if slot, ok := item["slot"]; ok {
						v, e := getInt(slot)
						if e != nil || v < 2 {
							issues = append(issues, fmt.Errorf("%s: bad slot", label))
							continue
						}
					}
				case "dialogue":
					n.Blocks++
					if _, e = nonnegativeInput(item["base"]); e != nil {
						issues = append(issues, fmt.Errorf("%s: base: %w", label, e))
						continue
					}
					lines, ok := item["lines"].([]any)
					if !ok {
						issues = append(issues, fmt.Errorf("%s: missing lines", label))
						continue
					}
					for j, l := range lines {
						m, ok := l.(map[string]any)
						if !ok {
							issues = append(issues, fmt.Errorf("%s line %d: invalid", label, j))
							continue
						}
						if _, e = nonnegativeInput(m["offset"]); e != nil {
							issues = append(issues, fmt.Errorf("%s line %d: offset: %w", label, j, e))
							continue
						}
						for _, k := range []string{"original", "text"} {
							if _, ok := m[k].(string); !ok {
								issues = append(issues, fmt.Errorf("%s line %d: %s invalid", label, j, k))
								continue
							}
						}
						n.Lines++
					}
				case "images":
					n.Images++
					if pixels, exists := item["pixels"]; exists {
						if _, err := nonnegativeInput(pixels); err != nil {
							issues = append(issues, fmt.Errorf("%s: pixels: %w", label, err))
							continue
						}
					}
					relative, ok := item["png"].(string)
					if !ok || relative == "" {
						issues = append(issues, fmt.Errorf("%s: missing png", label))
						continue
					}
					if _, e = validatedPNGSource(p, relative); e != nil {
						issues = append(issues, fmt.Errorf("%s: %w", label, e))
						continue
					}
				case "bytes":
					n.Bytes++
					if _, e = nonnegativeInput(item["offset"]); e != nil {
						issues = append(issues, fmt.Errorf("%s: offset: %w", label, e))
						continue
					}
					for _, k := range []string{"original", "replacement"} {
						if _, ok := item[k].(string); !ok {
							issues = append(issues, fmt.Errorf("%s: missing %s", label, k))
							continue
						}
					}
				}
			}
		}
	}
	// The ordinary integrated English composer also consumes source-owned
	// translation/graphics/*.png assets, even when no JSON image record
	// explicitly mentions them. Apply the same guard to that input family.
	if !includeStandaloneGraphics {
		return n, errors.Join(issues...)
	}
	standalone, globErr := filepath.Glob(filepath.Join(root, "translation", "graphics", "*.png"))
	if globErr != nil {
		issues = append(issues, globErr)
	}
	for _, png := range standalone {
		if _, err := validatedPNGSource(filepath.Join(filepath.Dir(png), "_source.json"), filepath.Base(png)); err != nil {
			issues = append(issues, fmt.Errorf("graphic asset %s: %w", filepath.Base(png), err))
		}
	}
	return n, errors.Join(issues...)
}
func showCounts(n counter) {
	say("JSON files", strconv.Itoa(n.Files))
	say("Dialogues", fmt.Sprintf("%d records in %d blocks", n.Lines, n.Blocks))
	say("UI strings", strconv.Itoa(n.Strings))
	say("Images", strconv.Itoa(n.Images))
	say("Binary edits", strconv.Itoa(n.Bytes))
}

type cueInfo struct {
	Inputs  []string
	Data    string
	Tracks  int
	Sectors int64
}

func parseCue(path string) (cueInfo, error) {
	var c cueInfo
	// All read-only commands must enforce the same source-layout contract
	// as the ordinary builder. A permissive track parser by itself cannot
	// validate INDEX 01, unsupported pregaps, symlink tracks or file aliases.
	audit, e := auditCueForNative(path)
	if e != nil {
		return c, fmt.Errorf("CUE layout refused: %w", e)
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		return c, e
	}
	current := ""
	haveData := false
	for _, line := range strings.Split(string(raw), "\n") {
		if m := lineFile.FindStringSubmatch(line); m != nil {
			current = m[1]
			if current == "" {
				current = m[2]
			}
			if filepath.IsAbs(current) || strings.Contains(filepath.ToSlash(current), "../") {
				return c, fmt.Errorf("unsupported non-relative CUE FILE path %q", current)
			}
			c.Inputs = append(c.Inputs, filepath.Join(filepath.Dir(path), current))
		} else if m := lineTrack.FindStringSubmatch(line); m != nil {
			c.Tracks++
			if strings.EqualFold(m[1], "MODE2/2352") && !haveData {
				if current == "" {
					return c, errors.New("data track without FILE")
				}
				c.Data = filepath.Join(filepath.Dir(path), current)
				haveData = true
			}
		}
	}
	if c.Data == "" {
		return c, errors.New("CUE has no MODE2/2352 track")
	}
	if c.Tracks != audit.Tracks || len(c.Inputs) != audit.InputFiles {
		return c, errors.New("CUE track parser/audit disagreement")
	}
	for _, v := range c.Inputs {
		s, e := os.Stat(v)
		if e != nil {
			return c, fmt.Errorf("track %q: %w", v, e)
		}
		if s.IsDir() {
			return c, fmt.Errorf("track is a directory: %s", v)
		}
	}
	s, e := os.Stat(c.Data)
	if e != nil {
		return c, e
	}
	if s.Size()%2352 != 0 {
		return c, fmt.Errorf("data track size %d not divisible by 2352", s.Size())
	}
	c.Sectors = s.Size() / 2352
	if c.Sectors != audit.DataSectors {
		return c, errors.New("CUE track geometry changed after audit")
	}
	return c, nil
}
func inspect(path string) error {
	path, e := filepath.Abs(path)
	if e != nil {
		return e
	}
	if strings.EqualFold(filepath.Ext(path), ".cue") {
		info, e := parseCue(path)
		if e != nil {
			return e
		}
		say("CUE", path)
		say("Tracks", strconv.Itoa(info.Tracks))
		say("Sectors", strconv.FormatInt(info.Sectors, 10))
		say("Data", info.Data)
		if f, fs, checkErr := openDiscISO(info.Data, info.Sectors); checkErr == nil {
			say("ISO volume", fs.Volume)
			say("ISO entries", strconv.Itoa(len(fs.Entries)))
			_ = f.Close()
		} else {
			say("ISO9660", "read error: "+checkErr.Error())
		}
		say("Validation", "CUE / tracks checked; game identity and runtime not verified")
		return nil
	}
	s, e := os.Lstat(path)
	if e != nil {
		return e
	}
	if !s.Mode().IsRegular() || s.Size() == 0 || s.Size()%2352 != 0 {
		return errors.New("raw BIN must be a nonempty, regular, non-symlink 2352-byte-sector image")
	}
	say("Raw BIN", path)
	say("Sectors", strconv.FormatInt(s.Size()/2352, 10))
	return nil
}
func pythonEnv(root string) []string {
	env := os.Environ()
	p := filepath.Join(root, "legacy_scripts")
	if old := os.Getenv("PYTHONPATH"); old != "" {
		p += string(os.PathListSeparator) + old
	}
	return append(env, "PYTHONPATH="+p, "PYTHONDONTWRITEBYTECODE=1", "PYTHONUNBUFFERED=1")
}
func runProcess(root, bin string, args ...string) error {
	command := exec.Command(bin, args...)
	command.Dir = root
	command.Env = pythonEnv(root)
	command.Stdout = commandOutput
	command.Stderr = commandOutput
	command.Stdin = os.Stdin
	fmt.Fprintf(commandOutput, "%s▶ %s%s\n", cyan, strings.Join(append([]string{bin}, args...), " "), reset)
	if e := command.Run(); e != nil {
		return fmt.Errorf("%s: %w", bin, e)
	}
	return nil
}
func runPython(root string, args ...string) error {
	python := os.Getenv("TOKIMEMO_PYTHON")
	if python == "" {
		python = "python3"
	}
	return runProcess(root, python, args...)
}
func cueChoice(root, explicit string) (string, error) {
	p, from, e := config.Discover(root, explicit, func(p string) error {
		if !strings.EqualFold(filepath.Ext(p), ".cue") {
			return errors.New("expected CUE entry point")
		}
		_, e := parseCue(p)
		return e
	})
	if e == nil {
		say("Game CUE", p)
		say("Found via", from)
	}
	return p, e
}

// Check already-existing output track destinations; Python's shutil.copyfile follows
// symlinks and would otherwise overwrite arbitrary targets, including source tracks.
func guardOutputTracks(cue, target string) error {
	info, e := parseCue(cue)
	if e != nil {
		return e
	}
	for _, source := range append([]string{cue}, info.Inputs...) {
		dest := filepath.Join(target, filepath.Base(source))
		st, e := os.Lstat(dest)
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		if st.Mode()&os.ModeSymlink != 0 || !st.Mode().IsRegular() {
			return fmt.Errorf("unsafe existing build target: %s", dest)
		}
		original, e := os.Stat(source)
		if e != nil {
			return e
		}
		if os.SameFile(st, original) {
			return fmt.Errorf("build target is linked to original game: %s", dest)
		}
	}
	return nil
}

// Stage progress shows actual workflow phases, not a fabricated byte-level percentage.
// The Python backend remains responsible for verified disc patching.
type stageWriter struct {
	destination io.Writer
	mu          sync.Mutex
	tail        string
	stage       int
}

func (w *stageWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, e := w.destination.Write(p)
	combined := w.tail + string(p)
	for next := w.stage + 1; next <= 3; next++ {
		marker := fmt.Sprintf("Step %d/3:", next)
		if strings.Contains(combined, marker) {
			w.stage = next
			labels := []string{"", "Verifying and planning edits", "Copying original CUE/BIN tracks", "Writing verified sector changes"}
			bar := strings.Repeat("█", next*8) + strings.Repeat("░", (3-next)*8)
			fmt.Fprintf(w.destination, "\n%s  [%s]  STEP %d/3 — %s%s\n", cyan, bar, next, labels[next], reset)
		}
	}
	if len(combined) > 128 {
		combined = combined[len(combined)-128:]
	}
	w.tail = combined
	return n, e
}

// productionPlannerArgs retains the optional legacy planner comparison argument
// shape for isolated regression checks. The normal Go build path does not call it.
func productionPlannerArgs(input string, preflight bool) []string {
	module := "tokipatch"
	if preflight {
		module = "tokipatch.preflight"
	}
	return []string{"-m", module, input, "--all-errors"}
}

func cmdBuild(root string, argv []string, preflight bool) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	out := fs.String("output", "", "separate output directory (default: .local/build/ps1-english)")
	game := fs.String("game", "", "original game CUE (also accepted as positional argument)")
	force := fs.Bool("force", false, "replace output files in selected safe output directory")
	verbose := fs.Bool("verbose", false, "list every patched string")
	var translations strList
	fs.Var(&translations, "translation", "specific translation JSON (repeatable)")
	if e := fs.Parse(argv); e != nil {
		return e
	}
	if fs.NArg() > 1 || (*game != "" && fs.NArg() != 0) {
		return errors.New("usage: tokimemo build|preflight [--game CUE] [--output DIR] [GAME.cue]")
	}
	explicit := *game
	if fs.NArg() == 1 {
		explicit = fs.Arg(0)
	}
	input, e := cueChoice(root, explicit)
	if e != nil {
		return e
	}
	n, e := validate(root)
	if e != nil {
		return e
	}
	fmt.Fprintf(commandOutput, "Corpus check passed: %d files / %d dialogue lines\n", n.Files, n.Lines)
	// No Python packing: the complete original N10/N20 composer validates
	// source-owned names, both GEKO policies, overlay MIPS and every EN byte
	// before the existing Go sector writer is entered.
	if *verbose {
		fmt.Fprintln(commandOutput, "Verbose N10/N20 build selected (verified input files)")
	}
	if len(translations) != 0 {
		return errors.New("full English N10/N20 build requires the complete source-owned translation corpus; partial --translation builds are not authorized")
	}
	return cmdIntegratedEnglishBuild(root, input, *out, *force, preflight)

}

// Select an exact ISO9660 file through the existing native reader. The CLI
// performs this selection without changing the separate disc reader.
func normalizeExtractionEntry(name string) (string, error) {
	if name == "" || len(name) > 255 || strings.HasPrefix(name, "/") || strings.HasSuffix(name, "/") || strings.Contains(name, "\\") {
		return "", fmt.Errorf("invalid ISO selection %q", name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("unsafe ISO selection %q", name)
		}
		for _, r := range part {
			if !(r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '_' || r == '-' || r == '.') {
				return "", fmt.Errorf("unsupported ISO selection %q", name)
			}
		}
	}
	return strings.ToUpper(name), nil
}

// A selected file is exported to a newly staged directory and published
// atomically. Source BIN sectors are read-only; no other ISO files are copied.
func nativeExtractSelected(dataTrack string, sectors int64, target, selected string) (int, error) {
	if selected == "" {
		return nativeExtract(dataTrack, sectors, target)
	}
	name, err := normalizeExtractionEntry(selected)
	if err != nil {
		return 0, err
	}
	if _, err := os.Lstat(target); err == nil {
		return 0, fmt.Errorf("extraction target exists: %s", target)
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	f, iso, err := openDiscISO(dataTrack, sectors)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	entry, exists := iso.Entries[name]
	if !exists || entry.IsDir || ps1.IsExternalTrackAudio(entry) || strings.HasSuffix(entry.Path, ".STR") {
		return 0, fmt.Errorf("ISO selection is not a supported data-track file: %s", name)
	}
	parent := filepath.Dir(target)
	if err = os.MkdirAll(parent, 0700); err != nil {
		return 0, err
	}
	stage, err := os.MkdirTemp(parent, ".tokimemo-extract-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(stage)
	dst := filepath.Join(stage, filepath.FromSlash(entry.Path))
	if err = os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
		return 0, err
	}
	out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return 0, err
	}
	if err = ps1.ReadFileTo(f, sectors, entry.LBA, entry.Size, out); err != nil {
		out.Close()
		return 0, err
	}
	if err = out.Close(); err != nil {
		return 0, err
	}
	inventory := fmt.Sprintf("%d\t%d\t%s\n", entry.LBA, entry.Size, entry.Path)
	if err = os.WriteFile(filepath.Join(stage, "files.tsv"), []byte(inventory), 0600); err != nil {
		return 0, err
	}
	if err = os.Rename(stage, target); err != nil {
		return 0, err
	}
	return 1, nil
}

// Extraction may write into dedicated working directories but never into
// translation sources, executable source, metadata or private tool state.
// Unknown private directories remain protected by default.
func guardExtractDestination(root, target string) error {
	protected := [...]string{"translation", ".git", "legacy_scripts", "cmd", "internal"}
	for _, rel := range protected {
		if config.Within(filepath.Join(root, rel), target) {
			return fmt.Errorf("extraction output is inside protected project tree %s", rel)
		}
	}
	privateRoot := filepath.Join(root, ".local")
	if config.Within(privateRoot, target) {
		for _, rel := range [...]string{"qa_inputs", "build"} {
			if config.Within(filepath.Join(privateRoot, rel), target) {
				return nil
			}
		}
		return errors.New("extraction output is inside a protected private project directory")
	}
	return nil
}

func cmdExtract(root string, args []string) error {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	out := fs.String("output", "", "directory for extracted game files (ignored by Git)")
	game := fs.String("game", "", "original game CUE")
	pythonFallback := fs.Bool("python", false, "use legacy Python extraction instead of native Go")
	only := fs.String("only", "", "extract only one exact ISO file (native Go)")
	if e := fs.Parse(args); e != nil {
		return e
	}
	// A supplied --only with an empty value is not the same as omitting
	// the flag: treating it as absent would unexpectedly extract the entire
	// disc. Refuse this request before CUE discovery or any output writes.
	selectionProvided := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "only" {
			selectionProvided = true
		}
	})
	if selectionProvided && *only == "" {
		return errors.New("--only requires a nonempty ISO file path; omit --only to extract all files")
	}
	if fs.NArg() > 1 || (*game != "" && fs.NArg() != 0) {
		return errors.New("usage: tokimemo extract [--python] [--only CDROM/PATH/FILE.BIN] [--game GAME.cue] [--output DIR] [GAME.cue]")
	}
	if *only != "" {
		if *pythonFallback {
			return errors.New("--only requires native Go extraction; --python is not supported")
		}
		if _, e := normalizeExtractionEntry(*only); e != nil {
			return e
		}
	}
	explicit := *game
	if fs.NArg() == 1 {
		explicit = fs.Arg(0)
	}
	cue, e := cueChoice(root, explicit)
	if e != nil {
		return e
	}
	target := *out
	if target == "" {
		target = filepath.Join(root, "extracted")
	}
	target, e = filepath.Abs(target)
	if e != nil {
		return e
	}
	if e = config.SafeOutput(root, cue, target); e != nil {
		return e
	}
	if e = guardExtractDestination(root, target); e != nil {
		return e
	}
	if _, e = os.Stat(target); e == nil {
		return errors.New("output directory exists; choose a new directory")
	}
	if *pythonFallback {
		return runPython(root, "legacy_scripts/tools/extract.py", cue, target)
	}
	info, e := parseCue(cue)
	if e != nil {
		return e
	}
	extracted, e := nativeExtractSelected(info.Data, info.Sectors, target, *only)
	if e != nil {
		return e
	}
	say("Extracted", fmt.Sprintf("%d files to %s (native Go)", extracted, target))
	return nil
}
func cmdLegacy(root string, args []string) error {
	if len(args) < 1 {
		return errors.New("usage: tokimemo legacy RELATIVE_SCRIPT.py [args...]")
	}
	name := filepath.Clean(args[0])
	if filepath.IsAbs(name) || strings.HasPrefix(name, "..") || filepath.Ext(name) != ".py" {
		return errors.New("legacy only runs .py scripts under legacy_scripts/tools/")
	}
	// Check every path component, not only the leaf: Lstat on the final
	// .py file follows symlinks in parent directories. The legacy command
	// must not execute a script through an alias outside the tools tree.
	p := root
	parts := append([]string{"legacy_scripts", "tools"}, strings.Split(name, string(filepath.Separator))...)
	for i, part := range parts {
		p = filepath.Join(p, part)
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("legacy script path crosses symlink: %s", p)
		}
		if i == len(parts)-1 {
			if !info.Mode().IsRegular() {
				return fmt.Errorf("legacy script is not a regular file: %s", p)
			}
		} else if !info.IsDir() {
			return fmt.Errorf("legacy script path component is not a directory: %s", p)
		}
	}
	return runPython(root, append([]string{p}, args[1:]...)...)
}

// cmdBuildProof reads the existing completed image and verifies that the
// CUE, untouched audio and data-track geometry still match the authenticated
// source. No build, emulator, project file or marker is modified.
func cmdBuildProof(root string, args []string) error {
	if len(args) != 0 {
		return errors.New("usage: tokimemo build-proof")
	}
	cue, target, err := buildPaths(root)
	if err != nil {
		return err
	}
	if _, err := auditCompletedBuild(cue, target); err != nil {
		return fmt.Errorf("built image verification refused: %w", err)
	}
	info, err := parseCue(cue)
	if err != nil {
		return err
	}
	built := filepath.Join(target, filepath.Base(info.Data))
	got, err := diskSHA(built)
	if err != nil {
		return fmt.Errorf("hashing verified built Track 1: %w", err)
	}
	fmt.Fprintf(commandOutput, "Verified built Track 1 SHA-256: %s\n", got)
	fmt.Fprintf(commandOutput, "Built Track 1: %s\n", built)
	fmt.Fprintln(commandOutput, "DuckStation loaded-image identity and gameplay are NOT verified by this command.")
	return nil
}

// launchBuiltEmulator uses the previously verified English build, never the
// original game CUE. Refuse incomplete, changed or unrecognized output before
// starting DuckStation; the existing emulator command still opens the source.
func launchBuiltEmulator(root string, args []string) error {
	if len(args) != 0 {
		return errors.New("usage: tokimemo emulator-built")
	}
	cue, target, err := buildPaths(root)
	if err != nil {
		return err
	}
	if _, err = auditCompletedBuild(cue, target); err != nil {
		return fmt.Errorf("built image verification refused: %w", err)
	}
	info, err := parseCue(cue)
	if err != nil {
		return err
	}
	builtCue := filepath.Join(target, filepath.Base(cue))
	builtData := filepath.Join(target, filepath.Base(info.Data))
	sha, err := diskSHA(builtData)
	if err != nil {
		return err
	}
	fmt.Fprintf(commandOutput, "Verified built Track 1 SHA-256: %s\n", sha)
	fmt.Fprintf(commandOutput, "Launching built English CUE: %s\n", builtCue)
	return runProcess(root, "duckstation", builtCue)
}

func cmdDoctor(root string) {
	say("Project", root)
	for _, x := range []string{"go", "python3", "duckstation", "zstd"} {
		if p, e := exec.LookPath(x); e == nil {
			say(x, green+p+reset)
		} else {
			say(x, amber+"not found"+reset)
		}
	}
	fmt.Fprintln(commandOutput, "Legacy PS1 patcher requires Python standard library only; Go CLI requires Go 1.23+ to compile.")
}
func usage() {
	fmt.Print(bold + "Tokimeki Memorial — Human Overhaul\n" + reset)
	fmt.Println("  tokimemo                     Interactive terminal dashboard")
	fmt.Println("  tokimemo doctor              Check dependencies and configuration")
	fmt.Println("  tokimemo status|validate     Validate translation input (read-only)")
	fmt.Println("  tokimemo inspect [CUE]       Inspect CUE/BIN structure")
	fmt.Println("  tokimemo build [CUE]         Create English game image using the production backend")
	fmt.Println("  tokimemo build-proof         Verify existing output and print its Track 1 SHA-256")
	fmt.Println("  tokimemo preflight [CUE]     Check patch sites without writing")
	fmt.Println("  tokimemo config              Configure game and output locations")
	fmt.Println("  tokimemo files [CUE]         List disc files")
	fmt.Println("  tokimemo extract [CUE]       Extract all assets or --only one ISO file")
	fmt.Println("  tokimemo sectors [CUE]       Inspect disc sectors")
	fmt.Println("  tokimemo codec-check         Validate codec parity")
	fmt.Println("  tokimemo planner-check       Validate patch planning")
	fmt.Println("  tokimemo graphics-check      Validate graphics processing")
	fmt.Println("  tokimemo renderer-check      Validate font/renderer behavior")
	fmt.Println("  tokimemo native-plan         Inspect proposed native build changes (read-only)")
	fmt.Println("  tokimemo native-plan-parity  Compare native and production plan")
	fmt.Println("  tokimemo dialogue-budget     Verify dialogue space limits")
	fmt.Println("  tokimemo native-build        Experimental native build to a separate output")
	fmt.Println("  tokimemo native-verify       Verify a native build")
	fmt.Println("  tokimemo cue-audit           Validate disc track geometry")
	fmt.Println("  tokimemo emulator [CUE]      Launch DuckStation")
	fmt.Println("  tokimemo emulator-built      Launch verified English build in DuckStation")
	fmt.Println("  tokimemo legacy SCRIPT.py    Run inherited tooling")
	fmt.Println("  tokimemo help                Show this help")
}

func launchEmulator(root string, args []string) error {
	if len(args) > 1 {
		return errors.New("usage: tokimemo emulator [CUE]")
	}
	explicit := ""
	if len(args) == 1 {
		explicit = args[0]
	}
	cue, e := cueChoice(root, explicit)
	if e != nil {
		return e
	}
	return runProcess(root, "duckstation", cue)
}
func cmdConfig(root string, args []string) error {
	if len(args) == 0 {
		s, e := config.Load(root)
		if e != nil {
			return e
		}
		cue, kind, ce := config.Discover(root, "", func(p string) error { _, e := parseCue(p); return e })
		say("Saved game", s.GameCue)
		say("Saved output", s.OutputDir)
		if ce == nil {
			say("Resolved CUE", cue)
			say("Discovery", kind)
		} else {
			say("Game", ce.Error())
		}
		return nil
	}
	if len(args) != 2 {
		return errors.New("usage: tokimemo config game CUE | config output DIR")
	}
	switch args[0] {
	case "game":
		return config.SetGame(root, args[1], func(p string) error {
			if filepath.Ext(strings.ToLower(p)) != ".cue" {
				return errors.New("CUE required")
			}
			_, e := parseCue(p)
			return e
		})
	case "output":
		return config.SetOutput(root, args[1])
	default:
		return errors.New("config subcommand must be game or output")
	}
}
func entry(root, cmd string, args []string) error {
	switch cmd {
	case "help", "-h", "--help":
		usage()
		return nil
	case "doctor":
		cmdDoctor(root)
		_ = cmdConfig(root, nil)
		return nil
	case "status", "validate":
		n, e := validate(root)
		if e != nil {
			return e
		}
		showCounts(n)
		return nil
	case "codec-check":
		return cmdCodecCheck(root, args)
	case "planner-check":
		return cmdPlannerCheck(root, args)
	case "graphics-check":
		if _, err := validate(root); err != nil {
			return err
		}
		return cmdGraphicsCheck(root, args)
	case "renderer-check":
		return cmdRendererCheck(root, args)
	case "native-plan":
		return cmdNativePlan(root, args)
	case "dialogue-budget":
		return cmdDialogueBudget(root, args)
	case "native-plan-parity":
		return cmdNativePlan(root, append([]string{"--compare-python", "--summary"}, args...))
	case "cue-audit":
		return cmdCueAudit(root, args)
	case "native-build":
		return cmdNativeBuild(root, args)
	case "native-verify":
		return cmdNativeVerify(root, args)
	case "inspect":
		if len(args) > 1 {
			return errors.New("usage: tokimemo inspect [GAME.cue]")
		}
		explicit := ""
		if len(args) == 1 {
			explicit = args[0]
		}
		p, e := cueChoice(root, explicit)
		if e != nil {
			return e
		}
		return inspect(p)
	case "config":
		return cmdConfig(root, args)
	case "build":
		return cmdBuild(root, args, false)
	case "build-proof":
		return cmdBuildProof(root, args)
	case "preflight":
		return cmdBuild(root, args, true)
	case "extract":
		return cmdExtract(root, args)
	case "files":
		return cmdFiles(root, args)
	case "sectors":
		return cmdSectorCheck(root, args)
	case "legacy":
		return cmdLegacy(root, args)
	case "emulator":
		return launchEmulator(root, args)
	case "emulator-built":
		return launchBuiltEmulator(root, args)
	case "emulator-probe":
		return cmdEmulatorProbe(args)
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}
func menu(root string) error {
	return termui.Run(root, func(action string, emit io.Writer) error {
		old := commandOutput
		commandOutput = emit
		defer func() { commandOutput = old }()
		switch action {
		case "settings_game":
			return termui.ChooseFile(root, filepath.Join(root, ".local", "rom"), ".cue", func(p string) error {
				return config.SetGame(root, p, func(p string) error { _, e := parseCue(p); return e })
			})
		case "settings_output":
			return termui.ChooseDirectory(root, func(p string) error { return config.SetOutput(root, p) })
		case "view_settings":
			return cmdConfig(root, nil)
		case "emulator_probe_state":
			return cmdEmulatorProbe([]string{"--state"})
		default:
			return entry(root, action, nil)
		}
	}, &termui.BuildHooks{
		Inspect: func() (termui.BuildTarget, error) { return inspectTUIBuild(root) },
		Execute: func(b termui.BuildTarget, w io.Writer) error { return buildTUI(root, b, w) },
	})
}
func main() {
	root, e := rootDir()
	if e != nil {
		failure(e)
		os.Exit(1)
	}
	if len(os.Args) == 1 {
		e = menu(root)
	} else {
		start := time.Now()
		e = entry(root, os.Args[1], os.Args[2:])
		jsonResult := false
		for _, arg := range os.Args[2:] {
			if arg == "--json" || strings.HasPrefix(arg, "--json=") {
				jsonResult = true
			}
		}
		if e == nil && !jsonResult && os.Args[1] != "help" && os.Args[1] != "--help" && os.Args[1] != "-h" {
			success(fmt.Sprintf("%s completed in %.1fs", os.Args[1], time.Since(start).Seconds()))
		}
	}
	if e != nil {
		failure(e)
		os.Exit(1)
	}
}
