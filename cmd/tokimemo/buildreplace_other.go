//go:build !linux

package main

import "errors"

func replaceBuildDirectory(stage, target, snapshot, cue string) error {
	return errors.New("atomic build replacement currently requires Linux")
}
