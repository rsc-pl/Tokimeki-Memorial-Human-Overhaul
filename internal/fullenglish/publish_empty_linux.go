//go:build linux

package fullenglish

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// PublishIntoEmptyBuildDirectory publishes a verified staged CUE/BIN image
// as one directory entry, even if the caller owns an existing empty staging
// directory. It never copies data tracks separately into a visible folder.
func PublishIntoEmptyBuildDirectory(stage, output string) error {
	original, err := os.Lstat(output)
	if err != nil {
		return err
	}
	if !original.IsDir() || original.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("empty build destination is not an ordinary directory: %s", output)
	}
	files, err := os.ReadDir(output)
	if err != nil {
		return err
	}
	if len(files) != 0 {
		return fmt.Errorf("build destination no longer empty: %s", output)
	}
	if err = swapBuildDirectoryEntries(stage, output); err != nil {
		return err
	}
	rollback := func(reason error) error {
		if e := swapBuildDirectoryEntries(stage, output); e != nil {
			return fmt.Errorf("%v; CRITICAL rollback failed: %w; old output retained at %s", reason, e, stage)
		}
		return reason
	}
	old, err := os.Lstat(stage)
	if err != nil || !os.SameFile(original, old) {
		return rollback(fmt.Errorf("empty output identity changed during atomic publication"))
	}
	files, err = os.ReadDir(stage)
	if err != nil || len(files) != 0 {
		return rollback(fmt.Errorf("empty output changed during atomic publication: %v", err))
	}
	if err = os.Remove(stage); err != nil {
		return fmt.Errorf("new build published, old empty directory cleanup failed at %s: %w", stage, err)
	}
	dir, err := os.Open(filepath.Dir(output))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// Same syscall contract as the already validated CLI atomic overwrite, used
// only for the existing-empty-directory case. No new public CLI mode.
func swapBuildDirectoryEntries(from, to string) error {
	var nr uintptr
	switch runtime.GOARCH {
	case "amd64":
		nr = 316
	case "arm64":
		nr = 276
	default:
		return fmt.Errorf("atomic build swap unsupported on linux/%s", runtime.GOARCH)
	}
	a, err := syscall.BytePtrFromString(from)
	if err != nil {
		return err
	}
	b, err := syscall.BytePtrFromString(to)
	if err != nil {
		return err
	}
	const cwd = ^uintptr(99)
	_, _, errno := syscall.RawSyscall6(nr, cwd, uintptr(unsafe.Pointer(a)), cwd, uintptr(unsafe.Pointer(b)), 2, 0)
	runtime.KeepAlive(a)
	runtime.KeepAlive(b)
	if errno != 0 {
		return fmt.Errorf("atomic empty build swap refused: %w", errno)
	}
	return nil
}
