package script

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

type Pointer struct {
	WordOffset   int
	TargetOffset uint32
}
type wordAt struct {
	Value uint32
	Index int
}

// FindPointers finds aligned little-endian addresses equal to base+offset.
func FindPointers(data []byte, base, offset uint32) []int {
	addr := base + offset
	needle := make([]byte, 4)
	binary.LittleEndian.PutUint32(needle, addr)
	hits := []int{}
	for pos := bytes.Index(data, needle); pos >= 0; {
		if pos%4 == 0 {
			hits = append(hits, pos)
		}
		next := bytes.Index(data[pos+1:], needle)
		if next < 0 {
			break
		}
		pos += 1 + next
	}
	return hits
}

// WordIndex indexes aligned addresses and MIPS LUI instructions in a file.
// Work performed once per file; it is independent of the disc and translation.
type WordIndex struct {
	words  []uint32
	sorted []wordAt
	lui    map[uint16][]int
}

func NewWordIndex(data []byte) *WordIndex {
	n := len(data) / 4
	idx := &WordIndex{words: make([]uint32, n), sorted: make([]wordAt, n), lui: make(map[uint16][]int)}
	for i := range idx.words {
		w := binary.LittleEndian.Uint32(data[i*4:])
		idx.words[i] = w
		idx.sorted[i] = wordAt{Value: w, Index: i}
		if w>>26 == 0x0f {
			hi := uint16(w)
			idx.lui[hi] = append(idx.lui[hi], i)
		}
	}
	sort.Slice(idx.sorted, func(i, j int) bool {
		if idx.sorted[i].Value == idx.sorted[j].Value {
			return idx.sorted[i].Index < idx.sorted[j].Index
		}
		return idx.sorted[i].Value < idx.sorted[j].Value
	})
	return idx
}
func (idx *WordIndex) PointersInto(base, start, end uint32) []Pointer {
	results := []Pointer{}
	if start >= end || uint64(base)+uint64(end) > 0xffffffff {
		return results
	}
	lo := sort.Search(len(idx.sorted), func(i int) bool { return idx.sorted[i].Value >= base+start })
	for ; lo < len(idx.sorted) && idx.sorted[lo].Value < base+end; lo++ {
		x := idx.sorted[lo]
		results = append(results, Pointer{WordOffset: x.Index * 4, TargetOffset: x.Value - base})
	}
	sort.Slice(results, func(i, j int) bool { return results[i].WordOffset < results[j].WordOffset })
	return results
}

// CodeReferences finds LUI+ADDIU/ORI/load sequences building the address.
// These direct code references mean the target cannot safely be relocated by
// changing only pointer tables. Matching intentionally mirrors script.py.
func (idx *WordIndex) CodeReferences(base, target uint32, window int) []int {
	if window < 0 {
		window = 0
	}
	addr := base + target
	lo := uint16(addr)
	hiAddiu := uint16((uint64(addr) + 0x8000) >> 16)
	hiOri := uint16(addr >> 16)
	candidates := map[int]bool{}
	for _, hi := range []uint16{hiAddiu, hiOri} {
		for _, i := range idx.lui[hi] {
			candidates[i] = true
		}
	}
	hits := []int{}
	for i := range candidates {
		w := idx.words[i]
		rt := (w >> 16) & 31
		imm := uint16(w)
		upper := i + window + 1
		if upper > len(idx.words) {
			upper = len(idx.words)
		}
		for j := i + 1; j < upper; j++ {
			w2 := idx.words[j]
			op := w2 >> 26
			rs := (w2 >> 21) & 31
			if rs != rt || uint16(w2) != lo {
				continue
			}
			if ((op == 0x09 || op == 0x20 || op == 0x21 || op == 0x23 || op == 0x24 || op == 0x25) && imm == hiAddiu) || (op == 0x0d && imm == hiOri) {
				hits = append(hits, i*4)
				break
			}
		}
	}
	sort.Ints(hits)
	return hits
}

func ReadString(data []byte, offset int) ([]byte, error) {
	if offset < 0 || offset >= len(data) {
		return nil, fmt.Errorf("offset %d outside file", offset)
	}
	end := bytes.IndexByte(data[offset:], 0)
	if end < 0 {
		return nil, fmt.Errorf("string starting at %d has no NUL terminator", offset)
	}
	return append([]byte(nil), data[offset:offset+end]...), nil
}

const checksumMarker uint16 = 0x1210

// HasChecksum and FixChecksum match the game's big-endian u16 additive
// trailer + 0x12 0x10. Only call FixChecksum on checked file formats.
func HasChecksum(data []byte) bool {
	if len(data) < 4 || binary.BigEndian.Uint16(data[len(data)-2:]) != checksumMarker {
		return false
	}
	var sum uint32
	for _, b := range data[:len(data)-4] {
		sum += uint32(b)
	}
	return uint16(sum) == binary.BigEndian.Uint16(data[len(data)-4:])
}
func FixChecksum(data []byte) error {
	if len(data) < 4 || binary.BigEndian.Uint16(data[len(data)-2:]) != checksumMarker {
		return fmt.Errorf("file lacks 0x1210 checksum trailer")
	}
	var sum uint32
	for _, b := range data[:len(data)-4] {
		sum += uint32(b)
	}
	binary.BigEndian.PutUint16(data[len(data)-4:], uint16(sum))
	return nil
}
