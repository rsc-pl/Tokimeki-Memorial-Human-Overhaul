package termui

import (
	"fmt"
	"io"
	"os"
	"testing"
	"time"
)

func TestPTYBuildFixture(t *testing.T) {
	if os.Getenv("TOKIMEMO_TUI_FIXTURE") != "1" {
		t.Skip("PTY fixture only")
	}
	count := 0
	target := BuildTarget{Path: "/tmp/tokimemo/PS1 English Output/Previous build", Exists: true, Snapshot: "test"}
	err := Run(t.TempDir(), func(cmd string, out io.Writer) error { fmt.Fprintf(out, "Action %s\n", cmd); return nil }, &BuildHooks{
		Inspect: func() (BuildTarget, error) { return target, nil },
		Execute: func(chosen BuildTarget, out io.Writer) error {
			count++
			for i := 1; i <= 3; i++ {
				fmt.Fprintf(out, "Step %d/3: phase %d\n", i, i)
				time.Sleep(420 * time.Millisecond)
			}
			if count == 1 {
				return fmt.Errorf("synthetic build error, previous output preserved")
			}
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
}
