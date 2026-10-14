package patchplan

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"

	"github.com/rsc-pl/Tokimeki-Memorial-Human-Overhaul/internal/graphics"
	"github.com/rsc-pl/Tokimeki-Memorial-Human-Overhaul/internal/ps1"
	"github.com/rsc-pl/Tokimeki-Memorial-Human-Overhaul/internal/script"
)

// Reader provides unmodified file bytes and never exposes writable storage.
type Reader interface {
	ReadFile(path string) ([]byte, error)
}
type FileResult struct {
	Path            string `json:"path"`
	Size            int    `json:"size"`
	OriginalSHA256  string `json:"original_sha256"`
	PatchedSHA256   string `json:"patched_sha256"`
	ChangedBytes    int    `json:"changed_bytes"`
	ChecksumUpdated bool   `json:"checksum_updated"`
}
type Result struct {
	Files             []FileResult `json:"files"`
	RendererInstalled bool         `json:"renderer_installed"`
	Strings           int          `json:"strings"`
	Images            int          `json:"images"`
	Bytes             int          `json:"bytes"`
	Blocks            int          `json:"blocks"`
}

func sha(b []byte) string { return fmt.Sprintf("%x", sha256.Sum256(b)) }

type edit struct{ pristine, data []byte }

// Plan applies the full sequence in memory and returns only metadata. No file,
// translation resource, disc or private configuration is ever written.
// On error the caller receives no partial plan.
func Plan(source Reader, batch Batch) (Result, error) {
	var result Result
	if source == nil {
		return result, fmt.Errorf("missing source")
	}
	edits := map[string]*edit{}
	order := []string{}
	get := func(path string) (*edit, error) {
		if e, ok := edits[path]; ok {
			return e, nil
		}
		data, err := source.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		e := &edit{pristine: append([]byte(nil), data...), data: append([]byte(nil), data...)}
		edits[path] = e
		order = append(order, path)
		return e, nil
	}
	pairs := &script.PairEncoder{}
	for _, p := range batch.Strings {
		e, err := get(p.File)
		if err != nil {
			return result, err
		}
		if err = script.ApplyInPlaceString(e.data, p, pairs); err != nil {
			return result, err
		}
	}
	for _, p := range batch.Images {
		e, err := get(p.File)
		if err != nil {
			return result, err
		}
		im, err := graphics.ReadIndexedFile(p.PNG)
		if err != nil {
			return result, fmt.Errorf("%s: %w", p.Source, err)
		}
		updated, err := graphics.ApplyPatch(e.data, im, p.Patch)
		if err != nil {
			return result, fmt.Errorf("%s: %w", p.Source, err)
		}
		e.data = updated
	}
	for _, p := range batch.Bytes {
		e, err := get(p.File)
		if err != nil {
			return result, err
		}
		if err = script.ApplyBytesPatch(e.data, p); err != nil {
			return result, err
		}
	}
	for _, p := range batch.Dialogue {
		e, err := get(p.File)
		if err != nil {
			return result, err
		}
		if _, err = script.ApplyDialogue(e.pristine, e.data, p, pairs); err != nil {
			return result, err
		}
	}
	if pairs.Used {
		e, err := get("SLPM_86.053")
		if err != nil {
			return result, err
		}
		updated, err := graphics.InstallRenderer(e.data)
		if err != nil {
			return result, err
		}
		e.data = updated
		result.RendererInstalled = true
	}
	for _, path := range order {
		e := edits[path]
		checksum := ps1.TailChecksumValid(e.pristine)
		if checksum {
			if !bytes.Equal(e.pristine[len(e.pristine)-4:], e.data[len(e.data)-4:]) {
				return Result{}, fmt.Errorf("%s: edit modified checksum trailer", path)
			}
			if err := ps1.FixTailChecksum(e.data); err != nil {
				return Result{}, err
			}
		}
		changed := 0
		for i := range e.data {
			if e.data[i] != e.pristine[i] {
				changed++
			}
		}
		result.Files = append(result.Files, FileResult{Path: path, Size: len(e.data), OriginalSHA256: sha(e.pristine), PatchedSHA256: sha(e.data), ChangedBytes: changed, ChecksumUpdated: checksum})
	}
	// Python returns edits in first-access order. Preserve that order for exact
	// cross-language comparison, while allowing consumers to sort for display.
	result.Strings = len(batch.Strings)
	result.Images = len(batch.Images)
	result.Bytes = len(batch.Bytes)
	result.Blocks = len(batch.Dialogue)
	return result, nil
}
func SortedFiles(r Result) []FileResult {
	files := append([]FileResult(nil), r.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	return files
}
