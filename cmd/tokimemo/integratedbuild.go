package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"tokimemo/internal/config"
	"tokimemo/internal/fullenglish"
	"tokimemo/internal/patchplan"
	"tokimemo/internal/ps1"
)

// cmdIntegratedEnglishBuild is the regular CLI and TUI build path.
// It composes authenticated English and name rendering edits and writes
// validated Mode2/Form1 sectors through the native Go writer.
// It never writes source game files, translation, Git, saves or existing output
// until every in-memory input and staged image has passed validation.
func cmdIntegratedEnglishBuild(root, cue, requested string, force, preflight bool) error {
	info, err := parseCue(cue)
	if err != nil {
		return err
	}
	if _, err = auditCueForNative(cue); err != nil {
		return fmt.Errorf("game CUE authentication: %w", err)
	}
	paths, err := filepath.Glob(filepath.Join(root, "translation", "*.json"))
	if err != nil {
		return err
	}
	sort.Strings(paths)
	discInputs, err := freezeInputs(append([]string{cue}, info.Inputs...))
	if err != nil {
		return err
	}
	translationInputs, err := freezeInputs(paths)
	if err != nil {
		return err
	}
	batch, err := patchplan.Load(root, paths)
	if err != nil {
		return err
	}
	imageInputs, err := freezeInputs(graphicPaths(batch))
	if err != nil {
		return fmt.Errorf("snapshotting translation images: %w", err)
	}
	fmt.Fprintln(commandOutput, "Step 1/3: authenticating full English, name-source relocation and N10/N20 composition")
	physical, err := fullenglish.ComposeEnglish(root, cue)
	if err != nil {
		return fmt.Errorf("full source-owned composition refused: %w", err)
	}
	if err = verifyFrozen(discInputs); err != nil {
		return err
	}
	if err = verifyFrozen(translationInputs); err != nil {
		return err
	}
	if err = verifyFrozen(imageInputs); err != nil {
		return err
	}
	if preflight {
		fmt.Fprintf(commandOutput, "Integrated English/N10/N20 preflight PASS: %d candidate game files; gameplay RAM/DMA/IRQ safety still unverified\n", len(physical))
		return nil
	}
	dest := requested
	if dest == "" {
		dest, err = config.Output(root)
		if err != nil {
			return err
		}
	}
	dest, err = filepath.Abs(dest)
	if err != nil {
		return err
	}
	if err = config.SafeOutput(root, cue, dest); err != nil {
		return err
	}
	if err = guardOutputTracks(cue, dest); err != nil {
		return err
	}
	source, iso, err := openDiscISO(info.Data, info.Sectors)
	if err != nil {
		return err
	}
	defer source.Close()
	plan := patchplan.Result{Files: make([]patchplan.FileResult, 0, len(physical))}
	for path, data := range physical {
		entry, ok := iso.Entries[path]
		if !ok || entry.IsDir || entry.Size != int64(len(data)) {
			return fmt.Errorf("invalid ISO file extent or length: %s", path)
		}
		var original bytes.Buffer
		if err = ps1.ReadFileTo(source, info.Sectors, entry.LBA, entry.Size, &original); err != nil {
			return err
		}
		plan.Files = append(plan.Files, patchplan.FileResult{Path: path, Size: len(data), OriginalSHA256: digest(original.Bytes()), PatchedSHA256: digest(data)})
	}
	sort.Slice(plan.Files, func(i, j int) bool { return plan.Files[i].Path < plan.Files[j].Path })
	// A TUI-created empty staging directory is allowed; an existing completed
	// image is replaced only on explicit --force and a verified prior snapshot.
	exists, err := os.Lstat(dest)
	var previous string
	emptyTarget := false
	if err == nil {
		if !exists.IsDir() || exists.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe output destination %s", dest)
		}
		contents, e := os.ReadDir(dest)
		if e != nil {
			return e
		}
		if len(contents) == 0 {
			emptyTarget = true
		} else {
			if !force {
				return fmt.Errorf("output already contains files, --force required after verification: %s", dest)
			}
			previous, e = auditCompletedBuild(cue, dest)
			if e != nil {
				return fmt.Errorf("existing build not verified; refusing replacement: %w", e)
			}
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(filepath.Dir(dest), ".tokimemo-integrated-stage-*")
	if err != nil {
		return err
	}
	stageIdentity, err := os.Lstat(stage)
	if err != nil {
		return err
	}
	defer cleanupOwnedBuildStage(stage, stageIdentity)
	fmt.Fprintln(commandOutput, "Step 2/3: copying original CUE/BIN tracks to temporary staging")
	dataTrack, err := stageCue(cue, info, stage)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(dataTrack, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	fmt.Fprintln(commandOutput, "Step 3/3: writing and verifying Form1 sectors, hashes, and prior output")
	sectors, e := writePlannedFiles(iso, f, plan, physical)
	closeErr := f.Close()
	if e != nil {
		return e
	}
	if closeErr != nil {
		return closeErr
	}
	if err = verifyFrozen(discInputs); err != nil {
		return err
	}
	if err = verifyFrozen(translationInputs); err != nil {
		return err
	}
	if err = verifyFrozen(imageInputs); err != nil {
		return err
	}
	if _, err = auditCompletedBuild(cue, stage); err != nil {
		return fmt.Errorf("staged image readback: %w", err)
	}
	if previous != "" {
		current, e := auditCompletedBuild(cue, dest)
		if e != nil || current != previous {
			return errors.New("prior output changed during staging; refusing replacement")
		}
		if err = replaceBuildDirectory(stage, dest, previous, cue); err != nil {
			return err
		}
	} else if emptyTarget {
		// TUI builds inside an existing empty temporary output directory.
		// Publish the complete verified disc atomically, never file by file.
		if err = fullenglish.PublishIntoEmptyBuildDirectory(stage, dest); err != nil {
			return err
		}
	} else {
		if err = publishNativeDirectory(stage, dest); err != nil {
			return err
		}
	}
	fmt.Fprintf(commandOutput, "Full English + N10/N20 Go build: %d verified files; %d rewritten sectors. No original, translation or saved-game changes. Runtime safety is NOT certified.\n", len(plan.Files), sectors)
	return nil
}

// A failed replacement rollback may move the user's previous image into the
// stage path. Never recursively remove a directory unless it remains the
// temporary directory created by this build.
func cleanupOwnedBuildStage(stage string, created os.FileInfo) {
	current, err := os.Lstat(stage)
	if err != nil || !os.SameFile(created, current) {
		return
	}
	_ = os.RemoveAll(stage)
}
