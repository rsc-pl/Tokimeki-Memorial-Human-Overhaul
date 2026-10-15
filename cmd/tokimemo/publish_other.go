//go:build !linux

package main

import "errors"

// Never use os.Rename as a no-clobber primitive for whole directory builds.
// Other platforms will receive a native no-replace implementation separately.
func publishNativeDirectory(stage, output string) error {
	return errors.New("native-build atomic no-replace publishing is currently supported only on Linux")
}
