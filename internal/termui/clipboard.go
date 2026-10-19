package termui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// Preserve the complete failed-command log before the next command overwrites
// latest.log. A successful command must never remove the previous failure.
func (s *state) errorLogPath() string {
	return filepath.Join(s.root, ".local", "go_toolchain", "logs", "last-error.log")
}

func saveLastError(source, destination string) error {
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
		return err
	}
	out, err := os.CreateTemp(filepath.Dir(destination), ".last-error-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(out.Name())
	if err := out.Chmod(0600); err != nil {
		out.Close()
		return err
	}
	if _, err = io.Copy(out, in); err != nil {
		out.Close()
		return err
	}
	if err = out.Sync(); err != nil {
		out.Close()
		return err
	}
	if err = out.Close(); err != nil {
		return err
	}
	return os.Rename(out.Name(), destination)
}

var csiControl = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)
var oscControl = regexp.MustCompile(`\x1b\][^\x07]*(?:\x07|\x1b\\)`)

func plainLog(data []byte) string {
	v := oscControl.ReplaceAll(data, nil)
	v = csiControl.ReplaceAll(v, nil)
	var b strings.Builder
	for _, r := range string(v) {
		if r == '\r' {
			b.WriteByte('\n')
			continue
		}
		if r == '\n' || r == '\t' || (r >= 32 && r != 127) {
			b.WriteRune(r)
		}
	}
	return strings.TrimRight(b.String(), "\n") + "\n"
}

const clipboardTimeout = 1500 * time.Millisecond
const maxClipboardBytes = 32 << 20 // Full report remains on disk for unusual huge logs.

// writeClipboard always runs outside the TUI input/render goroutine. Never
// inherit a terminal descriptor or create stderr pipes: forking clipboard tools
// may leave those pipes open and make exec.Cmd.Wait hang indefinitely.
// Use regular-file stdin (no input-copy goroutine) and Cmd.WaitDelay. Crucially,
// OSC 52 is NOT used automatically: some terminals stall on large sequences.
func writeClipboard(ctx context.Context, contents string) (string, error) {
	if strings.TrimSpace(contents) == "" {
		return "", errors.New("empty error report")
	}
	type provider struct {
		name    string
		args    []string
		enabled bool
	}
	providers := []provider{
		{"wl-copy", nil, os.Getenv("WAYLAND_DISPLAY") != ""},
		{"xclip", []string{"-selection", "clipboard"}, os.Getenv("DISPLAY") != ""},
		{"xsel", []string{"--clipboard", "--input"}, os.Getenv("DISPLAY") != ""},
	}
	// A regular file stdin avoids os/exec's input-copy goroutine and pipes;
	// forked clipboard daemons can otherwise keep the pipe open after their
	// parent exits and make Cmd.Wait return ErrWaitDelay or hang.
	f, err := os.CreateTemp("", "tokimemo-clipboard-*.tmp")
	if err != nil {
		return "", fmt.Errorf("clipboard input: %w", err)
	}
	defer func() { f.Close(); os.Remove(f.Name()) }()
	if err := f.Chmod(0600); err != nil {
		return "", err
	}
	if _, err := io.WriteString(f, contents); err != nil {
		return "", err
	}
	found := false
	var lastErr error
	for _, p := range providers {
		if !p.enabled {
			continue
		}
		if _, err := exec.LookPath(p.name); err != nil {
			continue
		}
		found = true
		// One bounded operation per provider, including the stdin writer.
		runCtx, cancel := context.WithTimeout(ctx, clipboardTimeout)
		cmd := exec.CommandContext(runCtx, p.name, p.args...)
		cmd.WaitDelay = 200 * time.Millisecond
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			cancel()
			return "", err
		}
		cmd.Stdin = f
		cmd.Stdout = nil // os/exec uses /dev/null directly; no Go copy goroutine
		cmd.Stderr = nil // forked clipboard child cannot keep a Go pipe open
		err := cmd.Run()
		ctxErr := runCtx.Err()
		cancel()
		if err == nil && ctxErr == nil {
			return p.name, nil
		}
		if ctxErr != nil {
			lastErr = fmt.Errorf("%s timed out: %w", p.name, ctxErr)
		} else {
			lastErr = fmt.Errorf("%s failed: %w", p.name, err)
		}
		if ctx.Err() != nil {
			return "", ctx.Err()
		}
	}
	if !found {
		return "", errors.New("no clipboard provider; on Wayland install wl-clipboard, on X11 xclip or xsel")
	}
	return "", lastErr
}

// This is deliberately asynchronous. No filesystem read, clipboard process,
// or terminal clipboard sequence is allowed to block the TUI event loop.
func (s *state) copyLastError() {
	if s.clipboardDone != nil {
		s.status = "Clipboard request already running; TUI remains responsive"
		return
	}
	s.clipboardDone = make(chan string, 1)
	channel := s.clipboardDone
	path := s.errorLogPath()
	s.status = "Copying last error... (navigation still available)"
	go func() {
		data, err := os.ReadFile(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				channel <- "No failed command log yet; run a command that fails first"
			} else {
				channel <- "Cannot read last error: " + err.Error()
			}
			return
		}
		if len(data) > maxClipboardBytes {
			channel <- fmt.Sprintf("Error log too large for clipboard (%d bytes); saved at %s", len(data), path)
			return
		}
		payload := plainLog(data)
		if strings.TrimSpace(payload) == "" {
			channel <- "Last error log is empty"
			return
		}
		method, err := writeClipboard(context.Background(), payload)
		if err != nil {
			channel <- "Clipboard unavailable: " + err.Error() + "; saved at " + path
			return
		}
		channel <- fmt.Sprintf("Copied %d bytes of last error with %s", len(payload), method)
	}()
}
