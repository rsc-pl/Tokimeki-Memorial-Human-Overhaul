package termui

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
)

var ansiSGR = regexp.MustCompile(`\x1b\[[0-9;]*m`)

func assertFits(t *testing.T, frame string, w, h int) {
	t.Helper()
	if !strings.HasPrefix(frame, "\x1b[H") {
		t.Fatalf("no home cursor command")
	}
	frame = strings.TrimPrefix(frame, "\x1b[H")
	rows := strings.Split(frame, "\r\n")
	if len(rows) != h {
		t.Fatalf("%dx%d: got %d rows not %d", w, h, len(rows), h)
	}
	for i, row := range rows {
		plain := ansiSGR.ReplaceAllString(row, "")
		if strings.ContainsRune(plain, '\x1b') || strings.ContainsAny(plain, "\r\n\t") {
			t.Fatalf("invalid escape/control in row %d: %q", i, plain)
		}
		if cells := plainWidth(plain); cells != w {
			t.Fatalf("%dx%d: row %d is %d cells: %q", w, h, i, cells, plain)
		}
	}
}
func TestResponsiveFramesFitExactly(t *testing.T) {
	widths := []int{1, 2, 8, 12, 20, 21, 22, 23, 24, 39, 47, 48, 63, 83, 84, 100, 144, 230}
	heights := []int{1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 16, 24, 44}
	for _, w := range widths {
		for _, h := range heights {
			for _, page := range []string{"main", "settings", "logs"} {
				s := &state{page: page, index: 14, status: "A very long status: łódź 你好 😀 ↔ " + strings.Repeat("very-long-", 42), logs: []string{"abc", "hello\nworld\x1b[2J", strings.Repeat("═", 256)}}
				if page == "settings" {
					s.index = 3
				}
				t.Run(fmt.Sprintf("%s-%dx%d", page, w, h), func(t *testing.T) { assertFits(t, s.frame(w, h), w, h) })
			}
		}
	}
}
func TestFilePickerFramesFitExactly(t *testing.T) {
	names := []string{"..", "translations", "my really long directory name + unicode 日本語 🗾", "some.file.cue"}
	for _, w := range []int{1, 12, 21, 22, 32, 60, 90, 150} {
		for _, h := range []int{1, 4, 5, 7, 8, 12, 24, 44} {
			for _, dirsOnly := range []bool{true, false} {
				t.Run(fmt.Sprintf("%dx%d-%v", w, h, dirsOnly), func(t *testing.T) {
					assertFits(t, pickerFrame(w, h, "/tmp/日本語/"+strings.Repeat("n", 80), "resize ok", names, 2, 0, dirsOnly), w, h)
				})
			}
		}
	}
}
func TestStyledClippingAndUnicode(t *testing.T) {
	for _, w := range []int{1, 2, 3, 4, 5, 12, 100} {
		got := fitStyled("\x1b[31mła☺ \x1b[?25l 你好😀\r\n\x1b[0m", w)
		plain := ansiSGR.ReplaceAllString(got, "")
		if plainWidth(plain) != w {
			t.Fatalf("got %d cells at width %d: %q", plainWidth(plain), w, plain)
		}
		if strings.Contains(plain, "\x1b") || strings.ContainsAny(plain, "\r\n") {
			t.Fatalf("control leak %q", plain)
		}
	}
}
func TestScrollKeepsSelectedVisible(t *testing.T) {
	for _, wh := range [][2]int{{50, 12}, {80, 16}, {120, 30}} {
		s := &state{page: "main", index: len(mainActions) - 1, status: "safe"}
		out := s.frame(wh[0], wh[1])
		assertFits(t, out, wh[0], wh[1])
		if !strings.Contains(out, "Exit") {
			t.Fatalf("last item not visible at %v", wh)
		}
		s.index = 0
		s.frame(wh[0], wh[1])
		if s.scroll != 0 {
			t.Fatalf("first item not in view")
		}
	}
}
