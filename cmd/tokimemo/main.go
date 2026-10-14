// Tokimemo Human Overhaul: Linux-first build and QA command line.
// Go owns orchestration and corpus checks. Legacy Python remains the tested
// sector/EDC/ECC/renderer writer until an independently tested Go port exists.
package main

import (
	"bufio"
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
	"time"
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
func say(head, val string)   { fmt.Printf("%s%-14s%s %s\n", cyan, head, reset, val) }
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
			return n, e
		}
		var doc map[string]json.RawMessage
		if e = json.Unmarshal(raw, &doc); e != nil {
			return n, fmt.Errorf("%s: %w", filepath.Base(p), e)
		}
		n.Files++
		for _, key := range []string{"strings", "dialogue", "images", "bytes"} {
			b, found := doc[key]
			if !found {
				continue
			}
			var items []map[string]any
			if e = json.Unmarshal(b, &items); e != nil {
				return n, fmt.Errorf("%s/%s: %w", filepath.Base(p), key, e)
			}
			for i, item := range items {
				label := fmt.Sprintf("%s:%s[%d]", filepath.Base(p), key, i)
				file, ok := item["file"].(string)
				if !ok || file == "" {
					return n, fmt.Errorf("%s: missing file", label)
				}
				if !strings.HasPrefix(file, "/") && !strings.Contains(file, "..") {
				} else {
					return n, fmt.Errorf("%s: unsafe disc path", label)
				}
				switch key {
				case "strings":
					n.Strings++
					if _, e = getInt(item["offset"]); e != nil {
						return n, fmt.Errorf("%s: offset: %w", label, e)
					}
					for _, k := range []string{"original", "text"} {
						if _, ok := item[k].(string); !ok {
							return n, fmt.Errorf("%s: %s not text", label, k)
						}
					}
					if slot, ok := item["slot"]; ok {
						v, e := getInt(slot)
						if e != nil || v < 2 {
							return n, fmt.Errorf("%s: bad slot", label)
						}
					}
				case "dialogue":
					n.Blocks++
					if _, e = getInt(item["base"]); e != nil {
						return n, fmt.Errorf("%s: base: %w", label, e)
					}
					lines, ok := item["lines"].([]any)
					if !ok {
						return n, fmt.Errorf("%s: missing lines", label)
					}
					for j, l := range lines {
						m, ok := l.(map[string]any)
						if !ok {
							return n, fmt.Errorf("%s line %d: invalid", label, j)
						}
						if _, e = getInt(m["offset"]); e != nil {
							return n, fmt.Errorf("%s line %d: offset: %w", label, j, e)
						}
						for _, k := range []string{"original", "text"} {
							if _, ok := m[k].(string); !ok {
								return n, fmt.Errorf("%s line %d: %s invalid", label, j, k)
							}
						}
						n.Lines++
					}
				case "images":
					n.Images++
					relative, ok := item["png"].(string)
					if !ok || relative == "" {
						return n, fmt.Errorf("%s: missing png", label)
					}
					png := filepath.Clean(filepath.Join(filepath.Dir(p), relative))
					parent := filepath.Join(root, "translation") + string(os.PathSeparator)
					if !strings.HasPrefix(png, parent) {
						return n, fmt.Errorf("%s: unsafe png path", label)
					}
					if _, e = os.Stat(png); e != nil {
						return n, fmt.Errorf("%s: PNG %s: %w", label, relative, e)
					}
				case "bytes":
					n.Bytes++
					if _, e = getInt(item["offset"]); e != nil {
						return n, fmt.Errorf("%s: offset: %w", label, e)
					}
					for _, k := range []string{"original", "replacement"} {
						if _, ok := item[k].(string); !ok {
							return n, fmt.Errorf("%s: missing %s", label, k)
						}
					}
				}
			}
		}
	}
	return n, nil
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
		say("Validation", "CUE and track files checked; game identity not yet verified")
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
	return append(env, "PYTHONPATH="+p, "PYTHONDONTWRITEBYTECODE=1")
}
func runProcess(root, bin string, args ...string) error {
	command := exec.Command(bin, args...)
	command.Dir = root
	command.Env = pythonEnv(root)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = os.Stdin
	fmt.Printf("%s▶ %s%s\n", cyan, strings.Join(append([]string{bin}, args...), " "), reset)
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
func cmdBuild(root string, argv []string, preflight bool) error {
	fs := flag.NewFlagSet("build", flag.ContinueOnError)
	out := fs.String("output", "", "output directory (defaults to source directory + [English])")
	force := fs.Bool("force", false, "replace existing output")
	verbose := fs.Bool("verbose", false, "list every patched string")
	var translations strList
	fs.Var(&translations, "translation", "specific translation JSON (repeatable)")
	if e := fs.Parse(argv); e != nil {
		return e
	}
	if fs.NArg() != 1 {
		return errors.New("usage: tokimemo build|preflight [options] GAME.cue")
	}
	input, e := filepath.Abs(fs.Arg(0))
	if e != nil {
		return e
	}
	if e = inspect(input); e != nil {
		return e
	}
	n, e := validate(root)
	if e != nil {
		return e
	}
	fmt.Printf("%sCorpus check passed%s: %d files / %d dialogue lines\n", green, reset, n.Files, n.Lines)
	a := []string{"-m", "tokipatch"}
	if preflight {
		a = []string{"-m", "tokipatch.preflight"}
	}
	a = append(a, input)
	if *out != "" && !preflight {
		a = append(a, "-o", *out)
	}
	if *force && !preflight {
		a = append(a, "--force")
	}
	if *verbose && !preflight {
		a = append(a, "--verbose")
	}
	for _, t := range translations {
		a = append(a, "-t", t)
	}
	return runPython(root, a...)
}
func cmdTests(root string) error {
	if e := runProcess(root, "go", "test", "./..."); e != nil {
		return e
	}
	return runPython(root, "-m", "unittest", "discover", "-s", "tests", "-q")
}
func cmdExtract(root string, args []string) error {
	fs := flag.NewFlagSet("extract", flag.ContinueOnError)
	out := fs.String("output", "", "directory for extracted game files (ignored by Git)")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 1 {
		return errors.New("usage: tokimemo extract [--output DIR] GAME.cue")
	}
	cue, e := filepath.Abs(fs.Arg(0))
	if e != nil {
		return e
	}
	if _, e = parseCue(cue); e != nil {
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
	if _, e = os.Stat(target); e == nil {
		return errors.New("output directory already exists; choose an empty new directory")
	}
	if e = runPython(root, "legacy_scripts/tools/extract.py", cue, target); e != nil {
		return e
	}
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
	fmt.Println("Legacy PS1 patcher requires Python standard library only; Go CLI requires Go 1.23+ to compile.")
}
func usage() {
	fmt.Print(bold + "Tokimeki Memorial — Human Overhaul\n" + reset)
	fmt.Println("  tokimemo                    Interactive terminal menu")
	fmt.Println("  tokimemo doctor             Check available dependencies")
	fmt.Println("  tokimemo status             Count and validate translation corpus")
	fmt.Println("  tokimemo validate           Validate translation resources (no disc)")
	fmt.Println("  tokimemo inspect GAME.cue   Inspect CUE/BIN structure")
	fmt.Println("  tokimemo preflight GAME.cue Validate patch against original disc, no writes")
	fmt.Println("  tokimemo build GAME.cue     Build patched PS1 BIN/CUE via verified Python backend")
	fmt.Println("    --output DIR  --force  --verbose  --translation FILE.json")
	fmt.Println("  tokimemo extract GAME.cue   Extract files, default ./extracted")
	fmt.Println("  tokimemo test               Run Go tests and inherited Python tests")
	fmt.Println("  tokimemo legacy FILE.py     Run a legacy Python utility (not PowerShell)")
	fmt.Println("  tokimemo emulator CUE       Launch DuckStation with a game CUE")
	fmt.Println("  tokimemo help")
}
func launchEmulator(root string, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: tokimemo emulator GAME.cue")
	}
	cue, e := filepath.Abs(args[0])
	if e != nil {
		return e
	}
	if _, e = parseCue(cue); e != nil {
		return e
	}
	return runProcess(root, "duckstation", cue)
}
func entry(root, cmd string, args []string) error {
	switch cmd {
	case "help", "-h", "--help":
		usage()
		return nil
	case "doctor":
		cmdDoctor(root)
		return nil
	case "status", "validate":
		n, e := validate(root)
		if e != nil {
			return e
		}
		showCounts(n)
		return nil
	case "inspect":
		if len(args) != 1 {
			return errors.New("usage: tokimemo inspect GAME.cue")
		}
		return inspect(args[0])
	case "build":
		return cmdBuild(root, args, false)
	case "preflight":
		return cmdBuild(root, args, true)
	case "extract":
		return cmdExtract(root, args)
	case "test":
		return cmdTests(root)
	case "legacy":
		return cmdLegacy(root, args)
	case "emulator":
		return launchEmulator(root, args)
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}
func menu(root string) error {
	// Works over SSH and ordinary terminals without external UI dependencies.
	opts := []struct{ label, desc, cmd string }{
		{"Project status", "Count translated resources and check source", "status"},
		{"Build PS1 patch", "Safe 3-stage disc validation and writing", "build"},
		{"Preflight disc", "Verify ALL edits without changing a byte", "preflight"},
		{"Inspect CUE", "Check tracks, data file and sector alignment", "inspect"},
		{"Run regression tests", "Go plus legacy Python unit tests", "test"},
		{"Extract game files", "Store copyrighted resources outside Git", "extract"},
		{"System doctor", "Go, Python, DuckStation availability", "doctor"},
		{"Exit", "Leave the project unchanged", "exit"},
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("\033[2J\033[H" + bold + cyan + "╭────────────────────────────────────────────────────────────────────╮\n" +
			"│       TOKIMEKI MEMORIAL  ·  HUMAN OVERHAUL                        │\n" +
			"│       PS1 BUILD & QA                               GO EDITION      │\n" +
			"╰────────────────────────────────────────────────────────────────────╯" + reset + "\n")
		for i, o := range opts {
			fmt.Printf("  %s%2d%s  %-22s  %s\n", cyan, i+1, reset, o.label, o.desc)
		}
		fmt.Printf("\n%sSelect [1-%d]: %s", bold, len(opts), reset)
		input, e := reader.ReadString('\n')
		if e != nil && e != io.EOF {
			return e
		}
		i, e := strconv.Atoi(strings.TrimSpace(input))
		if e != nil || i < 1 || i > len(opts) {
			if e == io.EOF {
				return nil
			}
			continue
		}
		picked := opts[i-1]
		if picked.cmd == "exit" {
			return nil
		}
		var argv []string
		if picked.cmd == "build" || picked.cmd == "preflight" || picked.cmd == "inspect" || picked.cmd == "extract" {
			fmt.Print("Path to original game .cue: ")
			p, err := reader.ReadString('\n')
			if err != nil {
				return err
			}
			p = strings.Trim(strings.TrimSpace(p), "\"'")
			if p == "" {
				continue
			}
			argv = []string{p}
		}
		fmt.Println()
		start := time.Now()
		err := entry(root, picked.cmd, argv)
		if err != nil {
			failure(err)
		} else {
			success(fmt.Sprintf("%s completed (%.1fs)", picked.cmd, time.Since(start).Seconds()))
		}
		fmt.Print("\nPress Enter to return to the menu...")
		_, _ = reader.ReadString('\n')
	}
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
		if e == nil && os.Args[1] != "help" && os.Args[1] != "--help" && os.Args[1] != "-h" {
			success(fmt.Sprintf("%s completed in %.1fs", os.Args[1], time.Since(start).Seconds()))
		}
	}
	if e != nil {
		failure(e)
		os.Exit(1)
	}
}
