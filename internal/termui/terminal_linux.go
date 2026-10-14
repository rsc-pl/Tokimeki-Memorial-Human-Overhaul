//go:build linux

package termui

import (
	"os"
	"syscall"
	"unsafe"
)

type terminalState struct{ term syscall.Termios }

func rawOn() (terminalState, error) {
	var old syscall.Termios
	fd := os.Stdin.Fd()
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCGETS), uintptr(unsafe.Pointer(&old)))
	if errno != 0 {
		return terminalState{}, errno
	}
	t := old
	t.Iflag &^= syscall.IXON | syscall.ICRNL | syscall.BRKINT | syscall.INPCK | syscall.ISTRIP
	t.Oflag &^= syscall.OPOST
	t.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	t.Cflag |= syscall.CS8
	t.Cc[syscall.VMIN] = 1
	t.Cc[syscall.VTIME] = 0
	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&t)))
	if errno != 0 {
		return terminalState{}, errno
	}
	return terminalState{term: old}, nil
}
func rawOff(t terminalState) error {
	_, _, e := syscall.Syscall(syscall.SYS_IOCTL, os.Stdin.Fd(), uintptr(syscall.TCSETS), uintptr(unsafe.Pointer(&t.term)))
	if e != 0 {
		return e
	}
	return nil
}
func termSize() (int, int) {
	var w struct{ Rows, Cols, XPixels, YPixels uint16 }
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, os.Stdout.Fd(), uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&w)))
	if errno != 0 || w.Cols == 0 {
		return 92, 28
	}
	return int(w.Cols), int(w.Rows)
}
func inputReady() bool {
	fd := int(os.Stdin.Fd())
	if fd >= 1024 {
		return false
	}
	var set syscall.FdSet
	set.Bits[fd/64] |= 1 << uint(fd%64)
	timeout := syscall.Timeval{Sec: 0, Usec: 80000}
	n, err := syscall.Select(fd+1, &set, nil, nil, &timeout)
	return err == nil && n > 0
}
