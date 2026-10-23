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
		if x != float64(int64(x)) {
			return 0, errors.New("not an integer")
		}
		return int64(x), nil
	default:
		return 0, fmt.Errorf("unsupported numeric value %T", v)
	}
}
func validate(root string) (counter, error) {
	var n counter
	var issues []error
	paths, e := filepath.Glob(filepath.Join(root, "translation", "*.json"))
	if e != nil {
		return n, e
	}
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
					if _, e = getInt(item["offset"]); e != nil {
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
					if _, e = getInt(item["base"]); e != nil {
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
						if _, e = getInt(m["offset"]); e != nil {
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
					relative, ok := item["png"].(string)
					if !ok || relative == "" {
						issues = append(issues, fmt.Errorf("%s: missing png", label))
						continue
					}
					png := filepath.Clean(filepath.Join(filepath.Dir(p), relative))
					parent := filepath.Join(root, "translation") + string(os.PathSeparator)
					if !strings.HasPrefix(png, parent) {
						issues = append(issues, fmt.Errorf("%s: unsafe png path", label))
						continue
					}
					if _, e = os.Stat(png); e != nil {
						issues = append(issues, fmt.Errorf("%s: PNG %s: %w", label, relative, e))
						continue
					}
				case "bytes":
					n.Bytes++
					if _, e = getInt(item["offset"]); e != nil {
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
	s, e := os.Stat(path)
	if e != nil {
		return e
	}
	if s.IsDir() || s.Size()%2352 != 0 {
		return errors.New("raw BIN must be a regular 2352-byte-sector image")
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

// productionPlannerArgs keeps public Go CLI/TUI builds on the authoritative
// Python planner while requesting all independent errors in one pass.
// The writer is never entered if validation fails.
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
	a := productionPlannerArgs(input, preflight)
	if !preflight {
		target := *out
		if target == "" {
			target, e = config.Output(root)
			if e != nil {
				return e
			}
		}
		target, e = filepath.Abs(target)
		if e != nil {
			return e
		}
		if e = config.SafeOutput(root, input, target); e != nil {
			return e
		}
		if e = guardOutputTracks(input, target); e != nil {
			return e
		}
		a = append(a, "-o", target)
		if *force {
			a = append(a, "--force")
		}
		if *verbose {
			a = append(a, "--verbose")
		}
	}
	for _, t := range translations {
		a = append(a, "-t", t)
	}
	// Record only the bounded Python log tail for automatic, read-only
	// failure explanation. The normal unmodified Python output is still shown.
	previous := commandOutput
	tail := &buildErrorTail{}
	targetOutput := io.MultiWriter(previous, tail)
	if !preflight {
		commandOutput = &stageWriter{destination: targetOutput}
	} else {
		commandOutput = targetOutput
	}
	defer func() { commandOutput = previous }()
	if e = runPython(root, a...); e != nil {
		explainPythonPackingError(root, input, string(tail.data), previous)
		return e
	}
	if !preflight {
		fmt.Fprintf(commandOutput, "Verification: Python preflight and patch application passed; emulator runtime NOT verified by this command.\n")
	}
	return nil
}
func cmdExtract(root string, args []string) error {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	out := fs.String("output", "", "directory for extracted game files (ignored by Git)")
	game := fs.String("game", "", "original game CUE")
	pythonFallback := fs.Bool("python", false, "use legacy Python extraction instead of native Go")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() > 1 || (*game != "" && fs.NArg() != 0) {
		return errors.New("usage: tokimemo extract [--python] [--game GAME.cue] [--output DIR] [GAME.cue]")
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
	extracted, e := nativeExtract(info.Data, info.Sectors, target)
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
	p := filepath.Join(root, "legacy_scripts", "tools", name)
	info, e := os.Lstat(p)
	if e != nil {
		return e
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return errors.New("legacy script must not be a symlink")
	}
	return runPython(root, append([]string{p}, args[1:]...)...)
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
	fmt.Println("  tokimemo preflight [CUE]     Check patch sites without writing")
	fmt.Println("  tokimemo config              Configure game and output locations")
	fmt.Println("  tokimemo files [CUE]         List disc files")
	fmt.Println("  tokimemo extract [CUE]       Extract game assets to a new directory")
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
