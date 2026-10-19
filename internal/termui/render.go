package termui

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Every screen is assembled in terminal *cells*, not runes or bytes. Frames
// always fit the physical terminal; even a 10x4 terminal must not wrap.
func cellWidth(r rune) int {
	if r == 0 || unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || r == '\u200d' || (r >= 0xfe00 && r <= 0xfe0f) {
		return 0
	}
	if r < 32 || r == 127 {
		return 0
	}
	if r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a || r >= 0x2e80 && r <= 0xa4cf && r != 0x303f || r >= 0xac00 && r <= 0xd7a3 || r >= 0xf900 && r <= 0xfaff || r >= 0xfe10 && r <= 0xfe19 || r >= 0xfe30 && r <= 0xfe6f || r >= 0xff00 && r <= 0xff60 || r >= 0xffe0 && r <= 0xffe6 || r >= 0x1f300 && r <= 0x1faff || r >= 0x20000 && r <= 0x3fffd) {
		return 2
	}
	return 1
}

// fitStyled keeps ANSI SGR color sequences intact, removes other controls,
// and never emits more than width terminal cells. It adds blank padding.
func fitStyled(s string, width int) string {
	if width <= 0 {
		return ""
	}
	var b strings.Builder
	cells := 0
	for i := 0; i < len(s); {
		if s[i] == '\x1b' {
			// Allow only CSI SGR; never allow cursor-positioning sequences in content.
			if i+2 < len(s) && s[i+1] == '[' {
				j := i + 2
				for j < len(s) && ((s[j] >= '0' && s[j] <= '9') || s[j] == ';') {
					j++
				}
				if j < len(s) && s[j] == 'm' {
					b.WriteString(s[i : j+1])
					i = j + 1
					continue
				}
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		if r == '\n' || r == '\r' || r == '\t' {
			r = ' '
		}
		cw := cellWidth(r)
		if cells+cw > width {
			break
		}
		b.WriteRune(r)
		cells += cw
	}
	b.WriteString(reset)
	b.WriteString(strings.Repeat(" ", width-cells))
	return b.String()
}
func plainWidth(s string) int {
	n := 0
	for _, r := range s {
		n += cellWidth(r)
	}
	return n
}
func truncateCells(s string, width int) string {
	if width <= 0 {
		return ""
	}
	if plainWidth(s) <= width {
		return s
	}
	if width == 1 {
		return "…"
	}
	var b strings.Builder
	used := 0
	for _, r := range s {
		cw := cellWidth(r)
		if used+cw > width-1 {
			break
		}
		b.WriteRune(r)
		used += cw
	}
	b.WriteRune('…')
	return b.String()
}
func wordsLines(s string, w int) []string {
	if w <= 0 {
		return nil
	}
	var out []string
	line := ""
	for _, word := range strings.Fields(s) {
		if plainWidth(word) > w {
			word = truncateCells(word, w)
		}
		if line != "" && plainWidth(line)+1+plainWidth(word) > w {
			out = append(out, line)
			line = ""
		}
		if line != "" {
			line += " "
		}
		line += word
	}
	if line != "" {
		out = append(out, line)
	}
	return out
}

// canvas enforces width/height at one choke point. An explicit CRLF is used
// because the legacy terminal raw mode previously disabled OPOST/ONLCR.
type canvas struct {
	width, height int
	lines         []string
}

func newCanvas(w, h int) *canvas {
	if w < 1 {
		w = 1
	}
	if h < 1 {
		h = 1
	}
	c := &canvas{width: w, height: h, lines: make([]string, h)}
	for i := range c.lines {
		c.lines[i] = strings.Repeat(" ", w)
	}
	return c
}
func (c *canvas) put(y int, s string) {
	if y >= 0 && y < c.height {
		c.lines[y] = fitStyled(s, c.width)
	}
}
func (c *canvas) box(y int, s string) {
	if c.width < 2 {
		c.put(y, s)
		return
	}
	c.put(y, accent+"│"+reset+fitStyled(s, c.width-2)+accent+"│"+reset)
}
func (c *canvas) border(y int, top bool) {
	if c.width < 2 {
		c.put(y, "")
		return
	}
	if top {
		c.put(y, accent+"╭"+strings.Repeat("─", c.width-2)+"╮")
	}
	if !top {
		c.put(y, accent+"╰"+strings.Repeat("─", c.width-2)+"╯")
	}
}
func (c *canvas) rule(y int) {
	if c.width < 2 {
		return
	}
	c.put(y, accent+"├"+strings.Repeat("─", c.width-2)+"┤")
}
func (c *canvas) output() string { return "\x1b[H" + strings.Join(c.lines, "\r\n") }
func chosenActions(page string) []action {
	if page == "settings" {
		return settingsActions
	}
	return mainActions
}
func clamp(v, minV, maxV int) int {
	if v < minV {
		return minV
	}
	if v > maxV {
		return maxV
	}
	return v
}

func (s *state) frame(width, height int) string {
	if s.page == "running" {
		return s.runFrame(width, height)
	}
	if s.page == "confirm" {
		return s.confirmFrame(width, height)
	}
	c := newCanvas(width, height)
	c.border(0, true)
	if height < 5 || width < 12 {
		c.box(1, ink+" TOKIMEMO  /  GO TOOLCHAIN")
		if height > 2 {
			c.box(2, hint+" Resize for more | q exit")
		}
		if height > 3 {
			c.border(height-1, false)
		}
		return c.output()
	}
	if height < 11 {
		c.box(1, ink+"  TOKIMEMO  /  GO TOOLCHAIN")
		available := max(0, height-4)
		if s.page == "logs" {
			s.scroll = clamp(s.scroll, 0, max(0, len(s.logs)-available))
			for y := 2; y < height-2; y++ {
				i := s.scroll + y - 2
				if i < len(s.logs) {
					c.box(y, "  "+cleanLine(s.logs[i]))
				}
			}
		} else {
			opts := chosenActions(s.page)
			s.index = clamp(s.index, 0, len(opts)-1)
			s.scroll = clamp(s.scroll, 0, max(0, len(opts)-available))
			if available > 0 {
				if s.index < s.scroll {
					s.scroll = s.index
				}
				if s.index >= s.scroll+available {
					s.scroll = s.index - available + 1
				}
			}
			for y := 2; y < height-2; y++ {
				i := s.scroll + y - 2
				if i < len(opts) {
					label := fmt.Sprintf("  %02d %s", i+1, opts[i].title)
					if i == s.index {
						c.box(y, selected+label+reset)
					} else {
						c.box(y, accent+" ▹ "+reset+label)
					}
				}
			}
		}
		c.box(height-2, hint+"  ↑↓ / Enter / c Copy error / Esc / q")
		c.border(height-1, false)
		return c.output()
	}

	c.box(1, ink+"  TOKIMEKI MEMORIAL"+reset+accent+"  /  "+magenta+"HUMAN OVERHAUL")
	c.box(2, hint+"  PS1 • Go toolchain                         Original game and translation: read-only")
	c.rule(3)
	label := "CONTROL CENTER"
	switch s.page {
	case "settings":
		label = "PRIVATE SETTINGS"
	case "logs":
		label = "SESSION LOGS"
	}
	c.box(4, ink+"  "+label+reset+hint+"   /   "+fmt.Sprintf("%d × %d", width, height))
	headerEnd := 5
	footerRule := height - 4
	if footerRule <= headerEnd {
		footerRule = height - 3
	}
	contentEnd := footerRule // exclusive
	if s.page == "logs" {
		available := max(0, contentEnd-headerEnd)
		maxScroll := max(0, len(s.logs)-available)
		s.scroll = clamp(s.scroll, 0, maxScroll)
		if len(s.logs) == 0 && available > 0 {
			c.box(headerEnd, hint+"  No commands have run in this session.")
		}
		for i := 0; i < available && s.scroll+i < len(s.logs); i++ {
			c.box(headerEnd+i, "  "+truncateCells(cleanLine(s.logs[s.scroll+i]), width-6))
		}
	} else {
		opts := chosenActions(s.page)
		s.index = clamp(s.index, 0, len(opts)-1)
		available := max(0, contentEnd-headerEnd)
		s.scroll = clamp(s.scroll, 0, max(0, len(opts)-available))
		if available > 0 {
			if s.index < s.scroll {
				s.scroll = s.index
			}
			if s.index >= s.scroll+available {
				s.scroll = s.index - available + 1
			}
		}
		twoColumn := width >= 84 && available >= 6
		if twoColumn {
			leftW := clamp(width/2, 35, 49)
			rightW := width - 3 - leftW
			entryWidth := max(0, leftW-3)
			for y := headerEnd; y < contentEnd; y++ {
				i := s.scroll + y - headerEnd
				left := ""
				if i < len(opts) {
					a := opts[i]
					marker := "  "
					if i == s.index {
						marker = "› "
					}
					left = marker + fmt.Sprintf("%02d  ", i+1) + truncateCells(a.title, entryWidth-5)
					if i == s.index {
						left = selected + left + reset
					} else {
						left = accent + "▹ " + reset + left
					}
				}
				right := ""
				sel := opts[s.index]
				var detail []string
				detail = append(detail, "", accent+"   SELECTED ACTION"+reset, ink+"   "+sel.title+reset, "")
				for _, ln := range wordsLines(sel.subtitle, rightW-5) {
					detail = append(detail, "   "+ln)
				}
				detail = append(detail, "", hint+"   Enter   run/select", hint+"   ↑↓     navigate", hint+"   l      logs", hint+"   c      copy last error", hint+"   Esc    back", hint+"   q      quit")
				if y-headerEnd < len(detail) {
					right = detail[y-headerEnd]
				}
				c.put(y, accent+"│"+reset+fitStyled(left, leftW)+accent+"│"+reset+fitStyled(right, rightW)+accent+"│")
			}
		} else {
			for y := headerEnd; y < contentEnd; y++ {
				i := s.scroll + y - headerEnd
				if i >= len(opts) {
					c.box(y, "")
					continue
				}
				a := opts[i]
				entry := "  " + fmt.Sprintf("%02d ", i+1) + a.title
				if width >= 65 {
					entry += "  " + a.subtitle
				}
				if i == s.index {
					c.box(y, selected+" "+truncateCells(entry, width-6)+reset)
				} else {
					c.box(y, accent+" ▹ "+reset+truncateCells(entry, width-6))
				}
			}
		}
	}
	if footerRule > 4 {
		c.rule(footerRule)
	}
	footer := hint + "  ↑↓ Navigate  Enter Select  l Logs  c Copy error  Esc Back  q Exit" + reset
	if s.page == "logs" {
		footer = hint + "  ↑↓ Scroll  PgUp/PgDn  c Copy error  Esc Back  q Exit" + reset
	}
	if height >= 3 {
		c.box(height-3, footer)
	}
	if height >= 2 {
		c.box(height-2, accent+"  ● "+reset+hint+truncateCells(s.status, max(0, width-7)))
	}
	c.border(height-1, false)
	return c.output()
}

func pickerFrame(w, h int, dir, message string, names []string, index, offset int, dirsOnly bool) string {
	c := newCanvas(w, h)
	c.border(0, true)
	if h < 5 || w < 12 {
		c.box(1, ink+" SELECT FILE / DIRECTORY")
		if h > 2 {
			c.box(2, hint+" Resize for more | q back")
		}
		if h > 3 {
			c.border(h-1, false)
		}
		return c.output()
	}
	if h < 10 {
		c.box(1, ink+"  FILE NAVIGATOR")
		for y := 2; y < h-2; y++ {
			i := offset + y - 2
			if i < len(names) {
				item := names[i]
				if i == 0 {
					item += "/"
				}
				label := fmt.Sprintf("  %02d %s", i+1, item)
				if i == index {
					c.box(y, selected+label+reset)
				} else {
					c.box(y, label)
				}
			}
		}
		c.box(h-2, hint+"  Enter / ← / p / q")
		c.border(h-1, false)
		return c.output()
	}

	c.box(1, ink+"  FILE NAVIGATOR"+reset+hint+"   /   Go toolchain")
	c.box(2, accent+"  "+truncateCells(dir, w-6))
	c.rule(3)
	avail := max(0, h-8)
	for y := 4; y < 4+avail; y++ {
		i := offset + y - 4
		if i >= len(names) {
			c.box(y, "")
			continue
		}
		label := names[i]
		if i == 0 || isDirectory(filepath.Join(dir, label)) {
			label += "/"
		}
		label = truncateCells(label, w-10)
		entry := "  " + fmt.Sprintf("%02d ", i+1) + label
		if i == index {
			c.box(y, selected+" › "+entry+reset)
		} else {
			c.box(y, accent+" ▹ "+reset+entry)
		}
	}
	if h >= 4 {
		c.rule(h - 4)
	}
	info := "  Enter Open/Select  Backspace Parent  p Path  q Cancel"
	if dirsOnly {
		info = "  Enter Open  s Use this directory  p Path  q Cancel"
	}
	c.box(h-3, hint+info)
	c.box(h-2, hint+"  "+truncateCells(message, w-6))
	c.border(h-1, false)
	return c.output()
}

// runFrame owns the entire alternate screen throughout the command. No terminal
// output from a child process is ever written directly to the TTY.
func (s *state) runFrame(w, h int) string {
	c := newCanvas(w, h)
	c.border(0, true)
	if h > 1 {
		c.box(1, ink+"  TOKIMEMO / "+s.activeCommand+reset)
	}
	if h > 2 {
		c.box(2, accent+"  "+s.stage+reset)
	}
	if h > 3 {
		c.box(3, hint+fmt.Sprintf("  Elapsed %ds  •  %s", int(time.Since(s.started).Seconds()), map[bool]string{true: "RUNNING", false: "DONE"}[s.running]))
	}
	if h > 4 {
		if s.activeCommand == "build" {
			c.box(4, accent+"  Output: "+truncateCells(s.buildTarget.Path, w-16))
		} else {
			c.box(4, hint+"  "+truncateCells(s.status, w-7))
		}
	}
	if h > 5 {
		c.box(5, hint+"  Log: "+truncateCells(s.logPath, w-13))
	}
	start := 6
	footer := h - 3
	if h < 9 {
		start = 3
		footer = h - 2
	}
	available := max(0, footer-start)
	s.scroll = clamp(s.scroll, 0, max(0, len(s.logs)-available))
	if s.follow {
		s.scroll = max(0, len(s.logs)-available)
	}
	for y := start; y < footer; y++ {
		idx := s.scroll + y - start
		if idx < len(s.logs) {
			c.box(y, "  "+truncateCells(cleanLine(s.logs[idx]), max(0, w-6)))
		}
	}
	if h > 3 && h >= 10 {
		c.box(h-3, hint+"  "+truncateCells(s.status, max(0, w-7)))
	}
	if h > 2 {
		c.box(h-2, hint+"  ↑↓ Scroll • PgUp/PgDn • f Follow • c Copy last error"+reset+map[bool]string{true: " • building...", false: " • Enter Back"}[s.running])
	}
	if h > 1 {
		c.border(h-1, false)
	}
	return c.output()
}
func (s *state) confirmFrame(w, h int) string {
	c := newCanvas(w, h)
	c.border(0, true)
	if h > 1 {
		c.box(1, ink+"  EXISTING OUTPUT / REPLACE?"+reset)
	}
	if h > 2 {
		c.box(2, "  The previous image will be retained if the new build fails.")
	}
	target := s.buildTarget.Path
	lines := []string{}
	width := max(1, w-7)
	for len(target) > 0 {
		pos := 0
		cells := 0
		for i, r := range target {
			cw := cellWidth(r)
			if cells+cw > width {
				break
			}
			pos = i + len(string(r))
			cells += cw
		}
		if pos == 0 {
			pos = 1
		}
		lines = append(lines, target[:pos])
		target = target[pos:]
	}
	for i, line := range lines {
		if 4+i >= h-4 {
			break
		}
		c.box(4+i, hint+"  "+line)
	}
	if h > 3 {
		cancel, replace := "  [ CANCEL ]  ", "  [ OVERWRITE ]  "
		if s.confirmIndex == 0 {
			cancel = selected + cancel + reset
		} else {
			replace = selected + replace + reset
		}
		c.box(h-3, "  "+cancel+"  "+replace)
		c.box(h-2, hint+"  ←→ Choose • Enter Confirm • Esc Cancel")
	}
	if h > 1 {
		c.border(h-1, false)
	}
	return c.output()
}
