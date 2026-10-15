package termui

import (
	"strings"
	"testing"
	"time"
)

func TestBuildFramesBounded(t *testing.T) {
	for _, sz := range [][2]int{{12, 4}, {24, 8}, {60, 15}, {140, 40}} {
		s := &state{page: "confirm", buildTarget: BuildTarget{Path: "/some/very/long/directory/containing/Tokimeki Memorial/(Track 1)/output with spaces"}, confirmIndex: 0}
		assertFits(t, s.frame(sz[0], sz[1]), sz[0], sz[1])
		s.confirmIndex = 1
		assertFits(t, s.frame(sz[0], sz[1]), sz[0], sz[1])
		s.page = "running"
		s.started = time.Now()
		s.stage = "Copying"
		s.activeCommand = "build"
		s.logPath = "/tmp/latest.log"
		s.follow = true
		for i := 0; i < 250; i++ {
			s.logs = append(s.logs, "Step 2/3: copying "+strings.Repeat("A", 300))
		}
		assertFits(t, s.frame(sz[0], sz[1]), sz[0], sz[1])
	}
}
func TestChunkedLogEventsAndProgress(t *testing.T) {
	c := make(chan string, 50)
	w := &lineEventWriter{events: c}
	for _, chunk := range []string{"Step 1/", "3: plan\nStep ", "2/3: copy\nStep 3/3: write\n", "finish"} {
		if _, e := w.Write([]byte(chunk)); e != nil {
			t.Fatal(e)
		}
	}
	w.flush()
	close(c)
	var got []string
	for line := range c {
		got = append(got, line)
	}
	if len(got) != 4 || !strings.Contains(strings.Join(got, "|"), "Step 2/3: copy") {
		t.Fatalf("log chunks not reconstructed: %q", got)
	}
}
