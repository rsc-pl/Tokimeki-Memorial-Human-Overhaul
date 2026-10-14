package ps1

import (
	"errors"
	"fmt"
	"io"
)

// WriteFileBytes replaces file bytes in a writable copy of a MODE2/2352 track.
// It deliberately matches Track.write_file_bytes in the legacy Python backend.
// A validation pass checks all targeted sectors before the first write.
// Production patching remains Python-owned until the full planner is migrated.
func WriteFileBytes(track interface {
	io.ReaderAt
	io.WriterAt
}, sectors, fileLBA, offset int64, bytes []byte) (int, error) {
	if track == nil || sectors < 0 || fileLBA < 0 || offset < 0 {
		return 0, errors.New("invalid writable track or offset")
	}
	if len(bytes) == 0 {
		return 0, nil
	}
	if offset > int64(^uint64(0)>>1)-int64(len(bytes)) {
		return 0, errors.New("sector offset overflow")
	}
	if fileLBA > sectors || offset/DataSize > sectors-fileLBA {
		return 0, errors.New("write offset outside track")
	}
	first := fileLBA + offset/DataSize
	last := fileLBA + (offset+int64(len(bytes))-1)/DataSize
	if first < fileLBA || last >= sectors || last < first {
		return 0, errors.New("write exceeds data track")
	}
	count := int(last - first + 1)
	// Preflight avoids corrupting an earlier sector when a later sector has a
	// mismatched mode; I/O failures during writing can still cause partial writes.
	existing := make([][]byte, count)
	for k := range existing {
		s, err := ReadSectorAt(track, first+int64(k))
		if err != nil {
			return 0, err
		}
		if !IsForm1(s) {
			return 0, fmt.Errorf("LBA %d not MODE2/Form1", first+int64(k))
		}
		existing[k] = s
	}
	for k, s := range existing {
		sectorPosition := (first + int64(k) - fileLBA) * DataSize
		begin := max64(offset, sectorPosition)
		end := min64(offset+int64(len(bytes)), sectorPosition+DataSize)
		copy(s[DataOffset+begin-sectorPosition:DataOffset+end-sectorPosition], bytes[begin-offset:end-offset])
		if err := RegenerateForm1(s); err != nil {
			return k, err
		}
	}
	for k, s := range existing {
		n, err := track.WriteAt(s, (first+int64(k))*SectorSize)
		if err != nil {
			return k, err
		}
		if n != len(s) {
			return k, io.ErrShortWrite
		}
	}
	return count, nil
}
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func min64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}
