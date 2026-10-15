package ps1

import (
	"bytes"
	"errors"
	"fmt"
	"io"
)

// ChangedSectors identifies exactly the data sectors modified by the legacy
// Track.write_file algorithm. A file's byte length must never change.
func ChangedSectors(old, replacement []byte) ([]int64, error) {
	if len(old) != len(replacement) {
		return nil, errors.New("replacement changed ISO9660 file size")
	}
	var touched []int64
	for off := 0; off < len(old); off += DataSize {
		end := off + DataSize
		if end > len(old) {
			end = len(old)
		}
		if !bytes.Equal(old[off:end], replacement[off:end]) {
			touched = append(touched, int64(off/DataSize))
		}
	}
	return touched, nil
}

// WriteFileDiff changes only the necessary sectors in an isolated writable
// track copy. All affected sectors are checked before writing any of them.
// The caller is responsible for atomic publication of the entire disc.
func WriteFileDiff(track interface {
	io.ReaderAt
	io.WriterAt
}, sectors, lba int64, old, replacement []byte) (int, error) {
	touched, err := ChangedSectors(old, replacement)
	if err != nil {
		return 0, err
	}
	if lba < 0 || sectors < 0 || lba > sectors {
		return 0, errors.New("invalid file extent")
	}
	for _, sectorOffset := range touched {
		sectorLBA := lba + sectorOffset
		if sectorLBA < lba || sectorLBA >= sectors {
			return 0, fmt.Errorf("changed file sector outside track: LBA %d", sectorLBA)
		}
		s, e := ReadSectorAt(track, sectorLBA)
		if e != nil {
			return 0, e
		}
		if !IsForm1(s) {
			return 0, fmt.Errorf("LBA %d not MODE2/Form1", sectorLBA)
		}
		// A changed data sector must match the entire pristine image; never overwrite
		// external edits or an unexpected sector layout.
		start := sectorOffset * DataSize
		stop := start + DataSize
		if stop > int64(len(old)) {
			stop = int64(len(old))
		}
		if !bytes.Equal(s[DataOffset:DataOffset+stop-start], old[start:stop]) {
			return 0, fmt.Errorf("LBA %d pristine sector differs from plan", sectorLBA)
		}
	}
	for _, sectorOffset := range touched {
		start := sectorOffset * DataSize
		stop := start + DataSize
		if stop > int64(len(replacement)) {
			stop = int64(len(replacement))
		}
		if _, e := WriteFileBytes(track, sectors, lba, start, replacement[start:stop]); e != nil {
			return 0, e
		}
		newSector, e := ReadSectorAt(track, lba+sectorOffset)
		if e != nil {
			return 0, e
		}
		if e = VerifyForm1(newSector); e != nil {
			return 0, fmt.Errorf("LBA %d after patch: %w", lba+sectorOffset, e)
		}
	}
	return len(touched), nil
}
