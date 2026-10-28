//go:build !linux

package fullenglish

import "errors"

// Fail closed rather than expose partially published CUE/BIN tracks.
func PublishIntoEmptyBuildDirectory(stage, output string) error {
	return errors.New("atomic empty-output publishing requires Linux")
}
