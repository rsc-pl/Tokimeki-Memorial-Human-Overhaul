package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tokimemo/internal/ps1"
)

func openDiscISO(dataTrack string, sectors int64) (*os.File, *ps1.ISO, error) {
	f, err := os.Open(dataTrack)
	if err != nil {
		return nil, nil, err
	}
	iso, err := ps1.OpenISO(f, sectors)
	if err != nil {
		_ = f.Close()
		return nil, nil, err
	}
	return f, iso, nil
}

// Native read-only directory inventory. No game content is included in technical handoffs.
func cmdFiles(root string, args []string) error {
	fs := flag.NewFlagSet("files", flag.ContinueOnError)
	game := fs.String("game", "", "original CUE (automatic discovery if omitted)")
	prefix := fs.String("prefix", "", "only list normalized paths with this prefix")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 || (*game != "" && fs.NArg() != 0) {
		return errors.New("usage: tokimemo files [--game CUE] [--prefix CDROM/] [CUE]")
	}
	explicit := *game
	if fs.NArg() == 1 {
		explicit = fs.Arg(0)
	}
	cue, err := cueChoice(root, explicit)
	if err != nil {
		return err
	}
	info, err := parseCue(cue)
	if err != nil {
		return err
	}
	f, iso, err := openDiscISO(info.Data, info.Sectors)
	if err != nil {
		return err
	}
	defer f.Close()
	say("ISO volume", iso.Volume)
	say("ISO entries", fmt.Sprint(len(iso.Entries)))
	n := 0
	for _, entry := range iso.Sorted() {
		if !strings.HasPrefix(entry.Path, strings.ToUpper(*prefix)) {
			continue
		}
		trailing := ""
		if entry.IsDir {
			trailing = "/"
		}
		fmt.Fprintf(commandOutput, "%9d\t%10d\t%s%s\n", entry.LBA, entry.Size, entry.Path, trailing)
		n++
	}
	if *prefix != "" {
		say("Matches", fmt.Sprint(n))
	}
	return nil
}

// Native extraction stages output in a new temporary sibling and publishes it
// only on success. It cannot write into the game image or an existing directory.
func nativeExtract(dataTrack string, sectors int64, target string) (int, error) {
	if _, err := os.Lstat(target); err == nil {
		return 0, fmt.Errorf("extraction target exists: %s", target)
	} else if !os.IsNotExist(err) {
		return 0, err
	}
	f, iso, err := openDiscISO(dataTrack, sectors)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	parent := filepath.Dir(target)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return 0, err
	}
	stage, err := os.MkdirTemp(parent, ".tokimemo-extract-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(stage)
	list, err := os.Create(filepath.Join(stage, "files.tsv"))
	if err != nil {
		return 0, err
	}
	extracted := 0
	for _, e := range iso.Sorted() {
		suffix := ""
		if e.IsDir {
			suffix = "/"
		}
		if _, err = fmt.Fprintf(list, "%d\t%d\t%s%s\n", e.LBA, e.Size, e.Path, suffix); err != nil {
			break
		}
		if e.IsDir || ps1.IsExternalTrackAudio(e) || strings.HasSuffix(e.Path, ".STR") {
			continue
		}
		dest := filepath.Join(stage, filepath.FromSlash(e.Path))
		if err = os.MkdirAll(filepath.Dir(dest), 0700); err != nil {
			break
		}
		var out *os.File
		out, err = os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			break
		}
		err = ps1.ReadFileTo(f, sectors, e.LBA, e.Size, out)
		if closeErr := out.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			break
		}
		extracted++
	}
	if closeErr := list.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return 0, err
	}
	if err = os.Rename(stage, target); err != nil {
		return 0, err
	}
	return extracted, nil
}

func cmdSectorCheck(root string, args []string) error {
	fs := flag.NewFlagSet("sectors", flag.ContinueOnError)
	game := fs.String("game", "", "original game CUE")
	start := fs.Int64("start", 16, "start logical sector (LBA)")
	count := fs.Int64("count", 16, "number of sectors to check (0: rest of data track)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() > 1 || (*game != "" && fs.NArg() != 0) {
		return errors.New("usage: tokimemo sectors [--game CUE] [--start N] [--count N] [CUE]")
	}
	explicit := *game
	if fs.NArg() == 1 {
		explicit = fs.Arg(0)
	}
	cue, err := cueChoice(root, explicit)
	if err != nil {
		return err
	}
	info, err := parseCue(cue)
	if err != nil {
		return err
	}
	if *start < 0 || *count < 0 || *start >= info.Sectors {
		return errors.New("sector range outside image")
	}
	end := info.Sectors
	if *count > 0 && *count < end-*start {
		end = *start + *count
	}
	f, err := os.Open(info.Data)
	if err != nil {
		return err
	}
	defer f.Close()
	checked, nonform1, special, bad := 0, 0, 0, 0
	cdromLBA := int64(-1)
	if fs, fsErr := ps1.OpenISO(f, info.Sectors); fsErr == nil {
		if entry, found := fs.Entries["CDROM"]; found && entry.IsDir {
			cdromLBA = entry.LBA
		}
	}
	for lba := *start; lba < end; lba++ {
		s, e := ps1.ReadSectorAt(f, lba)
		if e != nil {
			return e
		}
		if !ps1.IsForm1(s) {
			nonform1++
			continue
		}
		if lba == cdromLBA && !bytes.Equal(s[0x10:0x14], s[0x14:0x18]) {
			special++ // documented malformed /CDROM directory sector; do not label as an EDC failure
			continue
		}
		checked++
		if err = ps1.VerifyForm1(s); err != nil {
			if bad < 12 {
				fmt.Fprintf(commandOutput, "Mismatch LBA %d: %v\n", lba, err)
			}
			bad++
		}
	}
	say("Form1 checked", fmt.Sprint(checked))
	say("Non-Form1", fmt.Sprint(nonform1))
	say("Special /CDROM", fmt.Sprint(special))
	say("EDC/ECC failures", fmt.Sprint(bad))
	if bad > 0 {
		return fmt.Errorf("%d sectors failed EDC/ECC verification; source was NOT modified", bad)
	}
	return nil
}
