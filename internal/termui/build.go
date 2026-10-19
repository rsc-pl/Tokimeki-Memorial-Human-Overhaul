package termui

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// BuildTarget is a verified, read-only snapshot of a tool-produced image.
// Snapshot is opaque to the UI; the producer rechecks it before publication.
type BuildTarget struct {
	Path     string
	Exists   bool
	Snapshot string
}
type BuildHooks struct {
	Inspect func() (BuildTarget, error)
	Execute func(BuildTarget, io.Writer) error
}

type lineEventWriter struct {
	mu     sync.Mutex
	tail   string
	events chan<- string
}

func (w *lineEventWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	text := w.tail + string(b)
	for {
		p := strings.IndexAny(text, "\n\r")
		if p < 0 {
			break
		}
		if p > 0 {
			w.events <- text[:p]
		} else if len(text) == 1 {
			w.events <- ""
		}
		text = text[p+1:]
	}
	// Oversized binary lines cannot exhaust the UI or event queue.
	for len(text) > 8192 {
		w.events <- text[:8192]
		text = text[8192:]
	}
	w.tail = text
	return len(b), nil
}
func (w *lineEventWriter) flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.tail != "" {
		w.events <- w.tail
		w.tail = ""
	}
}

func (s *state) startJob(cmd string, run func(io.Writer) error) {
	s.page = "running"
	s.logs = nil
	s.scroll = 0
	s.follow = true
	s.running = true
	s.stage = "Preparing"
	s.started = time.Now()
	s.activeCommand = cmd
	s.logPath = filepath.Join(s.root, ".local", "go_toolchain", "logs", "latest.log")
	s.events = make(chan string, 512)
	s.completed = make(chan error, 1)
	go func() {
		_ = os.MkdirAll(filepath.Dir(s.logPath), 0700)
		f, err := os.OpenFile(s.logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
		if err != nil {
			s.events <- fmt.Sprintf("Unable to open log: %v", err)
		}
		output := &lineEventWriter{events: s.events}
		var writer io.Writer = output
		if f != nil {
			writer = io.MultiWriter(f, output)
		}
		fmt.Fprintf(writer, "Action: %s (%s)\n", cmd, s.started.Format(time.RFC3339))
		if err == nil {
			err = run(writer)
		}
		if err != nil {
			fmt.Fprintf(writer, "FAIL: %v\n", err)
		} else {
			fmt.Fprintf(writer, "OK: %s completed; game runtime not verified\n", cmd)
		}
		output.flush()
		if f != nil {
			_ = f.Sync()
			_ = f.Close()
		}
		// Preserve the entire FAILED command log before latest.log can be
		// replaced by the next command, even after the TUI is restarted.
		if err != nil && f != nil {
			if saveErr := saveLastError(s.logPath, s.errorLogPath()); saveErr != nil {
				s.events <- "Could not save last-error.log: " + saveErr.Error()
			}
		}
		s.completed <- err
	}()
}
func (s *state) pump() bool {
	dirty := false
	if s.clipboardDone != nil {
		select {
		case msg := <-s.clipboardDone:
			s.clipboardDone = nil
			s.status = msg
			dirty = true
		default:
		}
	}
	if s.page != "running" {
		return dirty
	}
	for i := 0; i < 300; i++ {
		select {
		case line := <-s.events:
			s.logs = append(s.logs, cleanLine(line))
			if len(s.logs) > 4000 {
				s.logs = s.logs[len(s.logs)-4000:]
				if s.scroll > 0 {
					s.scroll--
				}
			}
			if strings.Contains(line, "Step 1/3") || strings.Contains(line, "STEP 1/3") {
				s.stage = "1/3 • Validating original disc and resources"
			}
			if strings.Contains(line, "Step 2/3") || strings.Contains(line, "STEP 2/3") {
				s.stage = "2/3 • Copying original tracks"
			}
			if strings.Contains(line, "Step 3/3") || strings.Contains(line, "STEP 3/3") {
				s.stage = "3/3 • Writing verified changes"
			}
			dirty = true
		default:
			i = 300
		}
	}
	select {
	case err := <-s.completed:
		s.running = false
		if err != nil {
			s.status = "Build failed: " + err.Error()
			s.stage = "FAILED"
		} else {
			s.status = "Completed: " + s.activeCommand
			s.stage = "FINISHED"
		}
		dirty = true
	default:
	}
	if s.follow {
		s.scroll = 1000000000
	}
	return dirty
}
