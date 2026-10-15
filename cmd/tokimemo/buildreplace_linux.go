//go:build linux

package main

import (
	"fmt"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

func swapDirectories(a, b string) error {
	var nr uintptr
	switch runtime.GOARCH {
	case "amd64":
		nr = 316
	case "arm64":
		nr = 276
	default:
		return fmt.Errorf("rename exchange unsupported on %s", runtime.GOARCH)
	}
	from, e := syscall.BytePtrFromString(a)
	if e != nil {
		return e
	}
	to, e := syscall.BytePtrFromString(b)
	if e != nil {
		return e
	}
	const cwd = ^uintptr(99)
	_, _, errno := syscall.RawSyscall6(nr, cwd, uintptr(unsafe.Pointer(from)), cwd, uintptr(unsafe.Pointer(to)), 2, 0)
	runtime.KeepAlive(from)
	runtime.KeepAlive(to)
	if errno != 0 {
		return fmt.Errorf("atomic exchange refused: %w", errno)
	}
	return nil
}
func replaceBuildDirectory(stage, target, snapshot, cue string) error {
	// This exchanges BOTH directory entries atomically. If the old output was
	// replaced after our scan, the copy now in 'stage' is checked BEFORE deletion.
	old, e := os.Lstat(target)
	if e != nil {
		return e
	}
	if e = swapDirectories(stage, target); e != nil {
		return e
	}
	rollback := func(reason error) error {
		if e := swapDirectories(stage, target); e != nil {
			return fmt.Errorf("%v; CRITICAL: rollback failed: %w; previous output retained at %s", reason, e, stage)
		}
		return reason
	}
	moved, e := os.Lstat(stage)
	if e != nil || !os.SameFile(old, moved) {
		return rollback(fmt.Errorf("output identity changed during replacement"))
	}
	got, e := auditCompletedBuild(cue, stage)
	if e != nil || got != snapshot {
		return rollback(fmt.Errorf("old output changed during replacement; restoring it: %v", e))
	}
	// The new output is in target; the prior verified image is now at stage.
	// Failure to remove the backup is safe: do not risk the new output.
	if e = os.RemoveAll(stage); e != nil {
		return fmt.Errorf("new image published, but old backup cleanup failed at %s: %w", stage, e)
	}
	return nil
}
