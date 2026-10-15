package ps1

// Read-only ISO9660 directory support for the game's MODE2/2352 data track.
// Normalization follows legacy_scripts/tokipatch/iso9660.py: uppercase paths,
// discarding ;version, and retaining directories in the returned mapping.
// The /CDROM mangled-subheader exception is intentionally handled by Data().

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
)

const isoSectorSize = 2048
const maxDirectoryBytes = 32 << 20
const maxEntries = 100000
const maxDepth = 64

// IsExternalTrackAudio reports the ISO9660 audio-track directory descriptors.
// The game lists Track 2 audio under CDROM/DADIR, but its sectors live in a
// separate CUE BIN, not in the MODE2 data track. Such records are metadata, not
// readable files in the data track. Never use their LBAs with ReadFileTo.
func IsExternalTrackAudio(e ISOEntry) bool {
	if e.IsDir || !strings.HasPrefix(e.Path, "CDROM/DADIR/TR") || !strings.HasSuffix(e.Path, ".DA") {
		return false
	}
	name := strings.TrimSuffix(strings.TrimPrefix(e.Path, "CDROM/DADIR/TR"), ".DA")
	if len(name) != 2 || name[0] < '0' || name[0] > '9' || name[1] < '0' || name[1] > '9' {
		return false
	}
	return name != "00" && name != "01" // Track 1 is the MODE2 data track
}

type ISOEntry struct {
	Path  string
	LBA   int64
	Size  int64
	IsDir bool
}

type ISO struct {
	Reader  io.ReaderAt
	Sectors int64
	Volume  string
	Entries map[string]ISOEntry
	order   []ISOEntry
}

// ReadFileTo writes exactly size user-data bytes using the disc-specific sector layout.
// It never reads outside the data track. Unlike the legacy reader, this streams
// large assets instead of allocating an entire FMV in memory.
func ReadFileTo(r io.ReaderAt, sectors, lba, size int64, out io.Writer) error {
	if r == nil || sectors < 0 || lba < 0 || size < 0 {
		return errors.New("invalid track, file extent or size")
	}
	n := size / DataSize
	if size%DataSize != 0 {
		n++
	}
	if lba > sectors || n > sectors-lba {
		return fmt.Errorf("file extent LBA %d size %d is outside %d-sector data track", lba, size, sectors)
	}
	for i := int64(0); i < n; i++ {
		sector, err := ReadSectorAt(r, lba+i)
		if err != nil {
			return fmt.Errorf("read LBA %d: %w", lba+i, err)
		}
		data, err := Data(sector)
		if err != nil {
			return err
		}
		remain := size - i*DataSize
		if remain < DataSize {
			data = data[:remain]
		}
		if written, writeErr := out.Write(data); writeErr != nil {
			return writeErr
		} else if written != len(data) {
			return io.ErrShortWrite
		}
	}
	return nil
}

func readSmall(r io.ReaderAt, sectors, lba, size int64) ([]byte, error) {
	if size < 0 || size > maxDirectoryBytes {
		return nil, fmt.Errorf("directory size %d exceeds limit", size)
	}
	out := &smallWriter{b: make([]byte, 0, int(size))}
	if err := ReadFileTo(r, sectors, lba, size, out); err != nil {
		return nil, err
	}
	return out.b, nil
}

type smallWriter struct{ b []byte }

func (w *smallWriter) Write(p []byte) (int, error) { w.b = append(w.b, p...); return len(p), nil }

func safeISOName(raw []byte) (string, error) {
	for _, b := range raw {
		if b < 32 || b > 126 {
			return "", fmt.Errorf("unsupported directory identifier %q", raw)
		}
	}
	name := strings.ToUpper(strings.SplitN(string(raw), ";", 2)[0])
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\\:`) || path.Base(name) != name {
		return "", fmt.Errorf("unsafe ISO9660 directory identifier %q", raw)
	}
	return name, nil
}

// OpenISO lists the ISO9660 filesystem without modifying the disc image.
func OpenISO(r io.ReaderAt, sectors int64) (*ISO, error) {
	if r == nil || sectors <= 16 {
		return nil, errors.New("data track too short for ISO9660")
	}
	sector, err := ReadSectorAt(r, 16)
	if err != nil {
		return nil, err
	}
	pvd, err := Data(sector)
	if err != nil {
		return nil, err
	}
	if pvd[0] != 1 || string(pvd[1:6]) != "CD001" || pvd[6] != 1 {
		return nil, errors.New("no valid ISO9660 primary volume descriptor at LBA 16")
	}
	root := pvd[156:]
	if len(root) < 34 || root[0] < 34 || len(root) < int(root[0]) || root[25]&2 == 0 {
		return nil, errors.New("invalid ISO9660 root directory")
	}
	result := &ISO{
		Reader: r, Sectors: sectors, Volume: strings.Trim(string(pvd[40:72]), " \x00"),
		Entries: make(map[string]ISOEntry),
	}
	seen := make(map[[2]int64]bool)
	var walk func(lba, size int64, prefix string, depth int) error
	walk = func(lba, size int64, prefix string, depth int) error {
		if depth > maxDepth {
			return errors.New("ISO9660 directory recursion exceeds limit")
		}
		key := [2]int64{lba, size}
		if seen[key] {
			return fmt.Errorf("repeated ISO9660 directory extent at LBA %d", lba)
		}
		seen[key] = true
		buf, err := readSmall(r, sectors, lba, size)
		if err != nil {
			return fmt.Errorf("directory %q: %w", prefix, err)
		}
		for i := 0; i < len(buf); {
			length := int(buf[i])
			if length == 0 {
				i = (i/isoSectorSize + 1) * isoSectorSize
				continue
			}
			if length > isoSectorSize-i%isoSectorSize || i+length > len(buf) || length < 34 {
				return fmt.Errorf("malformed directory record at %q+%d", prefix, i)
			}
			rec := buf[i : i+length]
			i += length
			idLen := int(rec[32])
			if 33+idLen > len(rec) {
				return fmt.Errorf("invalid ISO9660 filename length in %q", prefix)
			}
			raw := rec[33 : 33+idLen]
			if len(raw) == 1 && (raw[0] == 0 || raw[0] == 1) {
				continue
			}
			name, err := safeISOName(raw)
			if err != nil {
				return err
			}
			e := ISOEntry{
				Path:  prefix + name,
				LBA:   int64(binary.LittleEndian.Uint32(rec[2:6])),
				Size:  int64(binary.LittleEndian.Uint32(rec[10:14])),
				IsDir: rec[25]&2 != 0,
			}
			if _, exists := result.Entries[e.Path]; exists {
				return fmt.Errorf("duplicate ISO9660 path %q", e.Path)
			}
			if len(result.Entries) >= maxEntries {
				return errors.New("ISO9660 entry limit exceeded")
			}
			n := (e.Size + DataSize - 1) / DataSize
			if e.LBA > sectors || n > sectors-e.LBA {
				// The game describes audio tracks in DADIR using disc-wide
				// LBAs. Keep the directory listing intact for Python parity,
				// but never read an external track through this data reader.
				if !IsExternalTrackAudio(e) {
					return fmt.Errorf("ISO9660 entry %s points outside data track", e.Path)
				}
			}
			result.Entries[e.Path] = e
			result.order = append(result.order, e)
			if e.IsDir {
				if err := walk(e.LBA, e.Size, e.Path+"/", depth+1); err != nil {
					return err
				}
			}
		}
		return nil
	}
	if err = walk(int64(binary.LittleEndian.Uint32(root[2:6])), int64(binary.LittleEndian.Uint32(root[10:14])), "", 0); err != nil {
		return nil, err
	}
	return result, nil
}

func (i *ISO) Sorted() []ISOEntry {
	result := append([]ISOEntry(nil), i.order...)
	sort.SliceStable(result, func(a, b int) bool { return result[a].LBA < result[b].LBA })
	return result
}
