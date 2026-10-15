// Package termui implements a bounded, resize-safe terminal UI without network dependencies.
package termui

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	reset    = "\x1b[0m"
	accent   = "\x1b[38;5;81m"
	ink      = "\x1b[1;37m"
	hint     = "\x1b[38;5;246m"
	selected = "\x1b[48;5;24m\x1b[1;97m"
	magenta  = "\x1b[38;5;177m"
)

type action struct{ title, subtitle, cmd string }

var mainActions = []action{
	{"Build English patch", "Validate, copy tracks and apply edits", "build"},
	{"Inspect game image", "Check CUE, tracks and native ISO9660", "inspect"},
	{"Audit source CUE", "Check safe native two-track sector layout", "cue-audit"},
	{"Browse ISO9660 files", "Read-only Go filesystem inventory", "files"},
	{"Run disc preflight", "Check original bytes; never modify source", "preflight"},
	{"Native Go file plan", "Read-only complete file planning and checksums", "native-plan"},
	{"Validate resources", "Read-only corpus structure checks", "validate"},
	{"Run regression tests", "Go modules and inherited Python tests", "test"},
	{"Verify game graphics", "Native indexed PNG / 4bpp / 8bpp checks", "graphics-check"},
	{"Launch DuckStation", "Open original CUE in emulator", "emulator"},
	{"Inspect running scene", "Read-only DuckStation GDB state / scene", "emulator_probe_state"},
	{"Configure paths", "Select source CUE and output folder", "settings"},
	{"Build and test logs", "Scroll through recent command output", "logs"},
	{"System doctor", "Inspect dependencies and saved paths", "doctor"},
	{"Exit", "Return to your shell", "exit"},
}
var settingsActions = []action{
	{"Select source game CUE", "Browse directories; game image not modified", "settings_game"},
	{"Select output directory", "Saved privately under .local/go_toolchain/", "settings_output"},
	{"Show current settings", "Default .local/rom/ takes priority", "view_settings"},
	{"Back", "Return to dashboard", "back"},
}

type state struct {
	page                          string
	index, scroll                 int
	logs                          []string
	status, root                  string
	stage, activeCommand, logPath string
	started                       time.Time
	running, follow               bool
	confirmIndex                  int
	buildTarget                   BuildTarget
	events                        chan string
	completed                     chan error
}

func cleanLine(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "\r", ""), "\n", "") }
func enterScreen()              { fmt.Fprint(os.Stdout, "\x1b[?1049h\x1b[?25l\x1b[?7l\x1b[H") }
func leaveScreen()              { fmt.Fprint(os.Stdout, "\x1b[0m\x1b[?7h\x1b[?25h\x1b[?1049l") }
func (s *state) draw()          { w, h := termSize(); fmt.Fprint(os.Stdout, s.frame(w, h)) }

func key() string {
	var buf [1]byte
	if _, e := os.Stdin.Read(buf[:]); e != nil {
		return "quit"
	}
	switch c := buf[0]; c {
	case 3:
		return "quit"
	case 13, 10:
		return "enter"
	case 27:
		if !inputReady() {
			return "esc"
		}
		if _, e := os.Stdin.Read(buf[:]); e != nil {
			return "esc"
		}
		if buf[0] != '[' && buf[0] != 'O' {
			return "esc"
		}
		seq := ""
		for len(seq) < 8 && inputReady() {
			if _, e := os.Stdin.Read(buf[:]); e != nil {
				break
			}
			ch := buf[0]
			seq += string(ch)
			if ch >= 'A' && ch <= 'Z' || ch == '~' {
				break
			}
		}
		switch seq {
		case "A":
			return "up"
		case "B":
			return "down"
		case "C":
			return "right"
		case "D":
			return "left"
		case "H", "1~", "7~":
			return "home"
		case "F", "4~", "8~":
			return "end"
		case "5~":
			return "pgup"
		case "6~":
			return "pgdown"
		}
		return "esc"
	case 127, 8:
		return "back"
	case 'j':
		return "down"
	case 'k':
		return "up"
	case 'q':
		return "quit"
	case 'l':
		return "logs"
	}
	return string(buf[0])
}

// Polling the input and resize on the same goroutine keeps cursor output and
// selection/scroll state serialized. The G11 signal-drawing goroutine raced
// with the menu and could corrupt the file chooser during resize.
func Run(root string, callback func(string, io.Writer) error, build *BuildHooks) error {
	raw, e := rawOn()
	if e != nil {
		return e
	}
	defer func() { _ = rawOff(raw); leaveScreen(); fmt.Println() }()
	enterScreen()
	s := &state{root: root, page: "main", status: "Source game and translation are read-only"}
	s.draw()
	lastW, lastH := termSize()
	lastClock := time.Now().Unix()
	for {
		dirty := s.pump()
		if !waitInput(75 * time.Millisecond) {
			w, h := termSize()
			now := time.Now().Unix()
			if dirty || w != lastW || h != lastH || s.page == "running" && now != lastClock {
				s.draw()
				lastW, lastH = w, h
				lastClock = now
			}
			continue
		}
		k := key()
		if s.page == "confirm" {
			switch k {
			case "left", "up", "home":
				s.confirmIndex = 0
			case "right", "down", "end":
				s.confirmIndex = 1
			case "esc", "back", "quit":
				s.page = "main"
				s.status = "Build cancelled; previous output untouched"
			case "enter":
				if s.confirmIndex == 0 {
					s.page = "main"
					s.status = "Build cancelled; previous output untouched"
				} else {
					target := s.buildTarget
					s.startJob("build", func(w io.Writer) error { return build.Execute(target, w) })
				}
			}
		} else if s.page == "running" {
			switch k {
			case "up":
				s.follow = false
				s.scroll--
			case "down":
				s.follow = false
				s.scroll++
			case "pgup":
				s.follow = false
				_, h := termSize()
				s.scroll -= max(1, h-9)
			case "pgdown":
				s.follow = false
				_, h := termSize()
				s.scroll += max(1, h-9)
			case "home":
				s.follow = false
				s.scroll = 0
			case "end", "f":
				s.follow = true
			case "esc", "back", "enter", "quit":
				if !s.running {
					s.page = "main"
					s.index = 0
					s.scroll = 0
				}
			}
			if s.running && (k == "quit" || k == "esc") {
				s.status = "Build active; exit available after completion"
			}
		} else {
			switch k {
			case "quit":
				return nil
			case "back", "esc", "left":
				s.page = "main"
				s.index = 0
				s.scroll = 0
			case "logs":
				s.page = "logs"
				_, h := termSize()
				s.scroll = max(0, len(s.logs)-max(0, h-9))
			case "up", "down", "home", "end", "pgup", "pgdown":
				if s.page == "logs" {
					_, h := termSize()
					step := max(1, h-9)
					switch k {
					case "up":
						s.scroll--
					case "down":
						s.scroll++
					case "home":
						s.scroll = 0
					case "end":
						s.scroll = len(s.logs)
					case "pgup":
						s.scroll -= step
					case "pgdown":
						s.scroll += step
					}
					s.scroll = max(0, s.scroll)
				} else {
					opts := chosenActions(s.page)
					switch k {
					case "up":
						s.index = (s.index + len(opts) - 1) % len(opts)
					case "down":
						s.index = (s.index + 1) % len(opts)
					case "home":
						s.index = 0
					case "end":
						s.index = len(opts) - 1
					case "pgup":
						s.index = max(0, s.index-6)
					case "pgdown":
						s.index = min(len(opts)-1, s.index+6)
					}
				}
			case "enter", "right":
				if s.page == "logs" {
					break
				}
				opts := chosenActions(s.page)
				if s.index < 0 || s.index >= len(opts) {
					break
				}
				cmd := opts[s.index].cmd
				switch cmd {
				case "exit":
					return nil
				case "back":
					s.page = "main"
					s.index = 0
					s.scroll = 0
				case "settings":
					s.page = "settings"
					s.index = 0
					s.scroll = 0
				case "logs":
					s.page = "logs"
					s.scroll = 0
				case "build":
					if build == nil {
						s.status = "Build handler unavailable"
						break
					}
					target, err := build.Inspect()
					if err != nil {
						s.status = "Cannot start build: " + err.Error()
						break
					}
					s.buildTarget = target
					if target.Exists {
						s.page = "confirm"
						s.confirmIndex = 0
					} else {
						s.startJob("build", func(w io.Writer) error { return build.Execute(target, w) })
					}
				case "settings_game", "settings_output":
					// The existing nested native picker still controls its own raw terminal.
					_ = rawOff(raw)
					leaveScreen()
					var result error
					result = callback(cmd, io.Discard)
					raw, e = rawOn()
					if e != nil {
						return e
					}
					enterScreen()
					if result != nil {
						s.status = "Settings: " + result.Error()
					} else {
						s.status = "Settings updated"
					}
				default:
					s.startJob(cmd, func(w io.Writer) error { return callback(cmd, w) })
				}
			}
		}
		s.draw()
		lastW, lastH = termSize()
		lastClock = time.Now().Unix()
	}
}
func choose(start, suffix string, dirsOnly bool, apply func(string) error) error {
	dir, _ := filepath.Abs(start)
	for {
		if st, e := os.Stat(dir); e == nil && st.IsDir() {
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return fmt.Errorf("no accessible directory at %s", start)
		}
		dir = parent
	}
	raw, e := rawOn()
	if e != nil {
		return e
	}
	defer func() { _ = rawOff(raw); leaveScreen() }()
	enterScreen()
	index, offset := 0, 0
	message := "Enter opens/selects; Backspace parent; p enter path"
	dirty := true
	var names []string
	draw := func() {
		width, height := termSize()
		avail := max(0, height-8)
		if height < 10 {
			avail = max(0, height-4)
		}
		if index < offset {
			offset = index
		}
		if avail > 0 && index >= offset+avail {
			offset = index - avail + 1
		}
		offset = clamp(offset, 0, max(0, len(names)-avail))
		fmt.Fprint(os.Stdout, pickerFrame(width, height, dir, message, names, index, offset, dirsOnly))
	}
	lastW, lastH := 0, 0
	for {
		if dirty {
			entries, err := os.ReadDir(dir)
			if err != nil {
				return err
			}
			names = []string{".."}
			for _, x := range entries {
				if x.IsDir() || (!dirsOnly && strings.EqualFold(filepath.Ext(x.Name()), suffix)) {
					names = append(names, x.Name())
				}
			}
			sort.Slice(names[1:], func(i, j int) bool { return strings.ToLower(names[i+1]) < strings.ToLower(names[j+1]) })
			index = clamp(index, 0, len(names)-1)
			dirty = false
			draw()
			lastW, lastH = termSize()
		}
		if !waitInput(90 * time.Millisecond) {
			w, h := termSize()
			if w != lastW || h != lastH {
				draw()
				lastW, lastH = w, h
			}
			continue
		}
		k := key()
		switch k {
		case "quit", "esc":
			return fmt.Errorf("selection cancelled")
		case "up":
			index = (index + len(names) - 1) % len(names)
		case "down":
			index = (index + 1) % len(names)
		case "home":
			index = 0
		case "end":
			index = len(names) - 1
		case "pgup":
			_, h := termSize()
			index = max(0, index-max(1, h-8))
		case "pgdown":
			_, h := termSize()
			index = min(len(names)-1, index+max(1, h-8))
		case "back", "left":
			dir = filepath.Dir(dir)
			index = 0
			offset = 0
			dirty = true
		case "s":
			if dirsOnly {
				if err := apply(dir); err == nil {
					return nil
				} else {
					message = err.Error()
				}
			}
		case "enter", "right":
			candidate := filepath.Join(dir, names[index])
			if isDirectory(candidate) {
				dir = candidate
				index = 0
				offset = 0
				dirty = true
			} else if !dirsOnly {
				if err := apply(candidate); err == nil {
					return nil
				} else {
					message = err.Error()
				}
			}
		case "p":
			_ = rawOff(raw)
			leaveScreen()
			fmt.Print("Enter full path: ")
			val, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			val = strings.Trim(strings.TrimSpace(val), "\"'")
			raw, e = rawOn()
			if e != nil {
				return e
			}
			enterScreen()
			if val != "" {
				if err := apply(val); err == nil {
					return nil
				} else {
					message = err.Error()
				}
			}
		}
		if !dirty {
			draw()
			lastW, lastH = termSize()
		}
	}
}
func isDirectory(p string) bool { x, e := os.Stat(p); return e == nil && x.IsDir() }
func ChooseFile(root, start, suffix string, apply func(string) error) error {
	return choose(start, suffix, false, apply)
}
func ChooseDirectory(root string, apply func(string) error) error {
	return choose(filepath.Join(root, ".local", "build"), "", true, apply)
}
func ShortStatus(code int, elapsed time.Duration) string {
	return "exit=" + strconv.Itoa(code) + " elapsed=" + elapsed.Round(time.Millisecond).String()
}
