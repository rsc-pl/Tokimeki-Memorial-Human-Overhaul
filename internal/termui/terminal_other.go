//go:build !linux

package termui

import "errors"

type terminalState struct{}

func rawOn() (terminalState, error) {
	return terminalState{}, errors.New("interactive raw-terminal UI currently requires Linux; CLI commands work on other platforms")
}
func rawOff(terminalState) error { return nil }
func termSize() (int, int)       { return 92, 28 }
func inputReady() bool           { return false }
