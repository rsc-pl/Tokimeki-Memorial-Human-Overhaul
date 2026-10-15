package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"tokimemo/internal/patchplan"
)

type frozenInput struct {
	path, sha string
	info      os.FileInfo
}

// freezeInputs records content and file identity for a private build's
// immutable sources. The second pass rejects both content changes and a
// replacement inode, even when the replacement has identical bytes.
func freezeInputs(paths []string) ([]frozenInput, error) {
	seen := map[string]bool{}
	var ordered []string
	for _, p := range paths {
		abs, err := filepath.Abs(p)
		if err != nil {
			return nil, err
		}
		if !seen[abs] {
			seen[abs] = true
			ordered = append(ordered, abs)
		}
	}
	sort.Strings(ordered)
	out := make([]frozenInput, 0, len(ordered))
	for _, p := range ordered {
		st, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("input %s: %w", filepath.Base(p), err)
		}
		if !st.Mode().IsRegular() {
			return nil, fmt.Errorf("input is not a regular file: %s", filepath.Base(p))
		}
		hash, err := shaFile(p)
		if err != nil {
			return nil, err
		}
		out = append(out, frozenInput{p, hash, st})
	}
	return out, nil
}
func verifyFrozen(inputs []frozenInput) error {
	for _, input := range inputs {
		st, err := os.Stat(input.path)
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("build input disappeared: %s", filepath.Base(input.path))
		}
		if err != nil {
			return err
		}
		if !st.Mode().IsRegular() || !os.SameFile(input.info, st) || st.Size() != input.info.Size() {
			return fmt.Errorf("build input replaced: %s", filepath.Base(input.path))
		}
		current, err := shaFile(input.path)
		if err != nil {
			return err
		}
		if current != input.sha {
			return fmt.Errorf("build input changed during operation: %s", filepath.Base(input.path))
		}
	}
	return nil
}
func graphicPaths(batch patchplan.Batch) []string {
	paths := make([]string, 0, len(batch.Images))
	for _, im := range batch.Images {
		paths = append(paths, im.PNG)
	}
	return paths
}
