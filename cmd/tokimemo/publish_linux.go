//go:build linux

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"
)

// publishNativeDirectory is an atomic, NO-REPLACE rename. os.Rename is not
// sufficient on Linux: it may replace an existing *empty* output directory
// if another process creates one after our preflight check.
func publishNativeDirectory(stage, output string) error {
	var nr uintptr
	switch runtime.GOARCH {
	case "amd64":
		nr = 316
	case "arm64":
		nr = 276
	default:
		return fmt.Errorf("atomic no-replace publish is unsupported on linux/%s", runtime.GOARCH)
	}
	src, err := syscall.BytePtrFromString(stage)
	if err != nil {
		return err
	}
	dst, err := syscall.BytePtrFromString(output)
	if err != nil {
		return err
	}
	const atFDCWD = ^uintptr(99) // -100 (AT_FDCWD)
	const renameNoReplace = uintptr(1)
	_, _, errno := syscall.RawSyscall6(nr, atFDCWD, uintptr(unsafe.Pointer(src)), atFDCWD, uintptr(unsafe.Pointer(dst)), renameNoReplace, 0)
	runtime.KeepAlive(src)
	runtime.KeepAlive(dst)
	if errno != 0 {
		return fmt.Errorf("atomic publish refused: %w", errno)
	}
	// fsync parent to preserve publication across power loss where supported.
	parent, err := os.Open(filepath.Dir(output))
	if err != nil {
		return err
	}
	defer parent.Close()
	return parent.Sync()
}
