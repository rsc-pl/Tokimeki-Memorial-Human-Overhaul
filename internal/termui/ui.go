// Package termui provides a small dependency-free raw-terminal UI for offline Arch installs.
// No network download or cached third-party TUI dependencies are required.
package termui

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"
)

const (
	clear    = "\x1b[2J\x1b[H"
	reset    = "\x1b[0m"
	dim      = "\x1b[2m"
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
	{"Browse ISO9660 files", "Read-only Go filesystem inventory", "files"},
	{"Run disc preflight", "Check original bytes; never modify source", "preflight"},
	{"Native Go file plan", "Read-only complete file planning and checksums", "native-plan"},
	{"Validate resources", "Read-only corpus structure checks", "validate"},
	{"Run regression tests", "Go modules and 38 inherited Python tests", "test"},
	{"Verify game graphics", "Native indexed PNG / 4bpp / 8bpp checks", "graphics-check"},
	{"Launch DuckStation", "Open original CUE in emulator", "emulator"},
	{"Configure paths", "Select source CUE and output folder", "settings"},
	{"Build and test logs", "Scroll through recent command output", "logs"},
	{"System doctor", "Inspect dependencies and saved paths", "doctor"},
	{"Exit", "Return to your shell", "exit"},
}
var settingsActions = []action{
	{"Select source game CUE", "Browse directories; no game image modification", "settings_game"},
	{"Select output directory", "Stored privately under .local/go_toolchain/", "settings_output"},
	{"Show current settings", "Default .local/rom/ takes priority", "view_settings"},
	{"Back", "Return to dashboard", "back"},
}

type state struct {
	mutex  sync.Mutex
	page   string
	index  int
	scroll int
	logs   []string
	status string
	root   string
}

func trimRunes(s string, n int) string {
	if n <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	if n < 2 {
		return "…"
	}
	return string([]rune(s)[:n-1]) + "…"
}
func cleanLine(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	return strings.TrimSuffix(s, "\n")
}
func (s *state) draw() { s.mutex.Lock(); defer s.mutex.Unlock(); s.drawLocked() }
func (s *state) drawLocked() {
	width, height := termSize()
	if width < 48 {
		width = 48
	}
	if height < 16 {
		height = 16
	}
	titleWidth := width - 4
	bar := strings.Repeat("─", max(1, width-2))
	var b strings.Builder
	b.WriteString(clear + "\x1b[?25l")
	b.WriteString(accent + "╭" + bar + "╮\n")
	b.WriteString("│" + reset + ink + "  TOKIMEKI MEMORIAL  " + magenta + "◆ " + ink + "HUMAN OVERHAUL" + reset + strings.Repeat(" ", max(0, width-43)) + accent + "│\n")
	b.WriteString("│" + reset + hint + fmt.Sprintf("  PS1 Toolchain  •  G05  /  Offline Go terminal UI") + reset + strings.Repeat(" ", max(0, width-53)) + accent + "│\n")
	b.WriteString("╰" + bar + "╯" + reset + "\n")
	if s.page == "logs" {
		b.WriteString("  " + ink + "BUILD / TEST LOGS" + reset + hint + "      ↑↓ scroll   Esc return" + reset + "\n\n")
		avail := max(2, height-10)
		if s.scroll > max(0, len(s.logs)-avail) {
			s.scroll = max(0, len(s.logs)-avail)
		}
		end := min(len(s.logs), s.scroll+avail)
		if len(s.logs) == 0 {
			b.WriteString(dim + "    No commands have run during this session.\n" + reset)
		}
		for _, line := range s.logs[s.scroll:end] {
			b.WriteString("  " + trimRunes(line, width-4) + "\n")
		}
		b.WriteString("\n" + hint + fmt.Sprintf("  Showing %d–%d of %d log lines", min(s.scroll+1, len(s.logs)), end, len(s.logs)) + reset)
	} else {
		opts := mainActions
		if s.page == "settings" {
			opts = settingsActions
		}
		if s.page == "settings" {
			b.WriteString("  " + ink + "PRIVATE SETTINGS" + reset + hint + "      Esc return" + reset + "\n\n")
		} else {
			b.WriteString("  " + ink + "CONTROL CENTER" + reset + hint + "      Run / Configure / Verify" + reset + "\n\n")
		}
		avail := max(3, height-13)
		if s.index < s.scroll {
			s.scroll = s.index
		}
		if s.index >= s.scroll+avail {
			s.scroll = s.index - avail + 1
		}
		for i := s.scroll; i < len(opts) && i < s.scroll+avail; i++ {
			it := opts[i]
			label := fmt.Sprintf("  %02d  %-24s  %s", i+1, it.title, it.subtitle)
			if i == s.index {
				b.WriteString(selected + trimRunes(label, titleWidth) + strings.Repeat(" ", max(0, titleWidth-utf8.RuneCountInString(trimRunes(label, titleWidth)))) + reset + "\n")
			} else {
				b.WriteString("  " + accent + "▹ " + reset + trimRunes(fmt.Sprintf("%-24s  %s", it.title, it.subtitle), width-9) + "\n")
			}
		}
		b.WriteString("\n" + hint + "  ↑↓ navigate   Enter select   l logs   Esc back   q quit" + reset + "\n")
	}
	b.WriteString("\n" + accent + "  ─" + strings.Repeat("─", max(1, width-6)) + reset + "\n")
	b.WriteString("  " + hint + trimRunes(s.status, width-4) + reset + "\n")
	fmt.Print(b.String())
}
func key() string {
	var buf [1]byte
	if _, e := os.Stdin.Read(buf[:]); e != nil {
		return "quit"
	}
	c := buf[0]
	switch c {
	case 3:
		return "quit"
	case 13, 10:
		return "enter"
	case 27:
		// Read escape sequence only when immediately available: arrows send ESC [ A/B.
		// In raw VMIN=1 this may block for standalone Esc; caller uses q/backspace to return.
		if !inputReady() {
			return "esc"
		}
		if _, e := os.Stdin.Read(buf[:]); e != nil {
			return "esc"
		}
		if buf[0] != '[' {
			return "esc"
		}
		if _, e := os.Stdin.Read(buf[:]); e != nil {
			return "esc"
		}
		switch buf[0] {
		case 'A':
			return "up"
		case 'B':
			return "down"
		case 'C':
			return "right"
		case 'D':
			return "left"
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
	return string(c)
}
func (s *state) execute(cmd string, run func(string, io.Writer) error) {
	// Restore the cooked terminal while the existing patcher writes live progress.
	fmt.Print("\x1b[?25h" + clear + accent + "TOKIMEKI TOOLCHAIN" + reset + "  /  " + cmd + "\n" + strings.Repeat("─", 62) + "\n")
	var out bytes.Buffer
	logDir := filepath.Join(s.root, ".local", "go_toolchain", "logs")
	_ = os.MkdirAll(logDir, 0700)
	file, _ := os.OpenFile(filepath.Join(logDir, "latest.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	var dest io.Writer = io.MultiWriter(os.Stdout, &out)
	if file != nil {
		dest = io.MultiWriter(os.Stdout, &out, file)
	}
	fmt.Fprintf(dest, "Action: %s (%s)\n", cmd, time.Now().Format(time.RFC3339))
	started := time.Now()
	err := run(cmd, dest)
	if err != nil {
		fmt.Fprintf(dest, "\nFAIL: %v\n", err)
		s.status = "Failed: " + err.Error()
	} else {
		fmt.Fprintf(dest, "\nOK: %s completed in %.1fs (runtime QA separate)\n", cmd, time.Since(started).Seconds())
		s.status = "Completed: " + cmd
	}
	if file != nil {
		_ = file.Sync()
		_ = file.Close()
	}
	s.logs = strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(s.logs) > 10000 {
		s.logs = s.logs[len(s.logs)-10000:]
	}
	fmt.Print("\n" + hint + "Press Enter to return to the TUI..." + reset)
	_, _ = bufio.NewReader(os.Stdin).ReadString('\n')
}
func Run(root string, callback func(string, io.Writer) error) error {
	st, e := rawOn()
	if e != nil {
		return e
	}
	defer func() { _ = rawOff(st); fmt.Print("\x1b[?25h\n") }()
	s := &state{root: root, page: "main", status: "Source files are read-only • Go UI + Python production patcher"}
	resize := make(chan os.Signal, 2)
	signal.Notify(resize, syscall.SIGWINCH)
	defer func() { signal.Stop(resize); close(resize) }()
	running := true
	var signalMu sync.Mutex
	go func() {
		for range resize {
			signalMu.Lock()
			if running {
				s.draw()
			}
			signalMu.Unlock()
		}
	}()
	defer func() { signalMu.Lock(); running = false; signalMu.Unlock() }()
	s.draw()
	for {
		k := key()
		switch k {
		case "quit":
			if s.page != "main" {
				s.page = "main"
				s.index = 0
				s.scroll = 0
			} else {
				return nil
			}
		case "back", "esc", "left":
			s.page = "main"
			s.index = 0
			s.scroll = 0
		case "logs":
			s.page = "logs"
			s.scroll = max(0, len(s.logs)-max(3, termHeight()-10))
		case "up", "down":
			if s.page == "logs" {
				if k == "up" {
					s.scroll = max(0, s.scroll-1)
				} else {
					s.scroll = min(max(0, len(s.logs)-1), s.scroll+1)
				}
			} else {
				opts := mainActions
				if s.page == "settings" {
					opts = settingsActions
				}
				if k == "up" {
					s.index = (s.index + len(opts) - 1) % len(opts)
				} else {
					s.index = (s.index + 1) % len(opts)
				}
			}
		case "enter", "right":
			if s.page == "logs" {
				break
			}
			opts := mainActions
			if s.page == "settings" {
				opts = settingsActions
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
			default:
				signalMu.Lock()
				running = false
				signalMu.Unlock()
				_ = rawOff(st)
				s.execute(cmd, callback)
				st, e = rawOn()
				signalMu.Lock()
				running = true
				signalMu.Unlock()
				if e != nil {
					return e
				}
				s.scroll = 0
			}
		}
		s.draw()
	}
}
func termHeight() int { _, h := termSize(); return h }
func choose(start, suffix string, dirsOnly bool, apply func(string) error) error {
	dir, _ := filepath.Abs(start)
	for {
		if st, e := os.Stat(dir); e != nil || !st.IsDir() {
			dir = filepath.Dir(dir)
		} else {
			break
		}
	}
	st, e := rawOn()
	if e != nil {
		return e
	}
	defer func() { _ = rawOff(st); fmt.Print("\x1b[?25h\n") }()
	index := 0
	offset := 0
	message := "Enter opens folders / selects CUE. Backspace = parent. p = type a path."
	for {
		entries, e := os.ReadDir(dir)
		if e != nil {
			return e
		}
		names := []string{".."}
		for _, x := range entries {
			if x.IsDir() || (!dirsOnly && strings.EqualFold(filepath.Ext(x.Name()), suffix)) {
				names = append(names, x.Name())
			}
		}
		sort.Slice(names[1:], func(i, j int) bool { return strings.ToLower(names[i+1]) < strings.ToLower(names[j+1]) })
		if index >= len(names) {
			index = len(names) - 1
		}
		width, height := termSize()
		avail := max(4, height-10)
		if index < offset {
			offset = index
		}
		if index >= offset+avail {
			offset = index - avail + 1
		}
		fmt.Print(clear + accent + "TOKIMEKI  /  FILE NAVIGATOR" + reset + "\n" + ink + trimRunes(dir, width-2) + reset + "\n" + hint + trimRunes(message, width-2) + reset + "\n\n")
		if dirsOnly {
			fmt.Print(magenta + "  s = use this directory" + reset + "\n")
		}
		for i := offset; i < len(names) && i < offset+avail; i++ {
			label := "  " + names[i]
			if names[i] == ".." || isDirectory(filepath.Join(dir, names[i])) {
				label += "/"
			}
			if i == index {
				fmt.Print(selected + trimRunes(label, width-3) + reset + "\n")
			} else {
				fmt.Print("  " + trimRunes(label, width-5) + "\n")
			}
		}
		k := key()
		switch k {
		case "quit", "esc":
			return fmt.Errorf("selection cancelled")
		case "up":
			index = (index + len(names) - 1) % len(names)
		case "down":
			index = (index + 1) % len(names)
		case "back", "left":
			dir = filepath.Dir(dir)
			index = 0
			offset = 0
		case "s":
			if dirsOnly {
				if e = apply(dir); e == nil {
					return nil
				}
				message = e.Error()
			}
		case "enter", "right":
			candidate := filepath.Join(dir, names[index])
			if isDirectory(candidate) {
				dir = candidate
				index = 0
				offset = 0
			} else if !dirsOnly {
				if e = apply(candidate); e == nil {
					return nil
				}
				message = e.Error()
			}
		case "p":
			_ = rawOff(st)
			fmt.Print("\x1b[?25h\nEnter full path: ")
			val, _ := bufio.NewReader(os.Stdin).ReadString('\n')
			val = strings.Trim(strings.TrimSpace(val), "\"'")
			st, e = rawOn()
			if e != nil {
				return e
			}
			if val != "" {
				if e = apply(val); e == nil {
					return nil
				}
				message = e.Error()
			}
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

// Useful without the raw terminal in unit tests.
func ShortStatus(code int, elapsed time.Duration) string {
	return "exit=" + strconv.Itoa(code) + " elapsed=" + elapsed.Round(time.Millisecond).String()
}
