package playername

// packed transliteration table reproduces the N20 Muse/DeepSeek 1,424-byte derived CP932 romanizer
// table in production Go. It is data-only: no executing MIPS packed decoder
// exists yet, and this does not authorise a playable patch.
import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

const packedTablePackedTableSHA = "02062b0c4558d8a672c82324cc336393962c5ffaa1560112acde7e83068e85c5"

// BuildPS1PackedRomanizationTable constructs and roundtrip-checks all 327
// canonical transliteration records. It returns an independent byte slice.
// Layout: BE16 base + 143*(u8 delta, LE24) + BE16 base + 184*(u8 delta,
// LE24) + sixteen BE16 second codes + 32 ASCII letter codes + 6*8 suffixes.
func BuildPS1PackedRomanizationTable() ([]byte, error) {
	simple, dig := buildPS1KanaTable(), buildPS1DigraphTable()
	if len(simple) != 143 || len(dig) != 184 {
		return nil, fmt.Errorf("N20 unexpected map sizes %d/%d", len(simple), len(dig))
	}
	lettersSet := make(map[byte]bool)
	for _, e := range simple {
		for i := range e.latin {
			lettersSet[e.latin[i]] = true
		}
	}
	for _, e := range dig {
		for i := range e.latin {
			lettersSet[e.latin[i]] = true
		}
	}
	letters := make([]byte, 0, len(lettersSet))
	for c := range lettersSet {
		letters = append(letters, c)
	}
	sort.Slice(letters, func(i, j int) bool { return letters[i] < letters[j] })
	if len(letters) > 32 {
		return nil, fmt.Errorf("N20 alphabet too large")
	}
	alphaIndex := make(map[byte]uint32)
	for i, c := range letters {
		alphaIndex[c] = uint32(i)
	}
	secondsSet := make(map[uint16]bool)
	for _, e := range dig {
		secondsSet[e.second] = true
	}
	seconds := make([]uint16, 0, len(secondsSet))
	for c := range secondsSet {
		seconds = append(seconds, c)
	}
	sort.Slice(seconds, func(i, j int) bool { return seconds[i] < seconds[j] })
	if len(seconds) > 16 {
		return nil, fmt.Errorf("N20 too many digraph second codes")
	}
	secondIndex := make(map[uint16]uint32)
	for i, c := range seconds {
		secondIndex[c] = uint32(i)
	}
	out := make([]byte, 0, 1424)
	be16 := func(v uint16) { out = append(out, byte(v>>8), byte(v)) }
	pack := func(delta uint16, value uint32) error {
		if delta > 255 || value > 0xffffff {
			return fmt.Errorf("N20 bad packed word")
		}
		out = append(out, byte(delta), byte(value), byte(value>>8), byte(value>>16))
		return nil
	}
	be16(simple[0].code)
	prev := simple[0].code
	for _, e := range simple {
		if e.code < prev || len(e.latin) < 1 || len(e.latin) > 3 {
			return nil, fmt.Errorf("N20 simple record invalid")
		}
		p := uint32(len(e.latin)) << 15
		for i := range e.latin {
			p |= alphaIndex[e.latin[i]] << uint(5*i)
		}
		if err := pack(e.code-prev, p); err != nil {
			return nil, err
		}
		prev = e.code
	}
	be16(dig[0].first)
	prev = dig[0].first
	for _, e := range dig {
		if e.first < prev || len(e.latin) < 1 || len(e.latin) > 3 {
			return nil, fmt.Errorf("N20 digraph record invalid")
		}
		p := secondIndex[e.second] | uint32(len(e.latin))<<19
		for i := range e.latin {
			p |= alphaIndex[e.latin[i]] << uint(4+5*i)
		}
		if err := pack(e.first-prev, p); err != nil {
			return nil, err
		}
		prev = e.first
	}
	for _, c := range seconds {
		be16(c)
	}
	for range 16 - len(seconds) {
		be16(0)
	}
	out = append(out, letters...)
	for range 32 - len(letters) {
		out = append(out, 0)
	}
	for _, suffix := range []string{"", "-kun", "-san", "-chan", "-sama", "-senpai"} {
		if len(suffix) > 7 {
			return nil, fmt.Errorf("N20 suffix longer than record")
		}
		out = append(out, byte(len(suffix)))
		out = append(out, []byte(suffix)...)
		for range 7 - len(suffix) {
			out = append(out, 0)
		}
	}
	if len(out) != 1424 {
		return nil, fmt.Errorf("N20 packed size %d !=1424", len(out))
	}
	if fmt.Sprintf("%x", sha256.Sum256(out)) != packedTablePackedTableSHA {
		return nil, fmt.Errorf("N20 packed data mismatches independent Muse SHA")
	}
	if err := packedTableCheckPackedTable(out, simple, dig); err != nil {
		return nil, err
	}
	return out, nil
}

func packedTableCheckPackedTable(data []byte, simple []kanaTableEntry, dig []kanaDigraphEntry) error {
	sBase := binary.BigEndian.Uint16(data[:2])
	dBase := binary.BigEndian.Uint16(data[574:576])
	seconds := data[1312:1344]
	alphabet := data[1344:1376]
	cur := sBase
	for i, e := range simple {
		o := 2 + i*4
		cur += uint16(data[o])
		p := uint32(data[o+1]) | uint32(data[o+2])<<8 | uint32(data[o+3])<<16
		n := int((p >> 15) & 3)
		var lat []byte
		for j := 0; j < n; j++ {
			lat = append(lat, alphabet[(p>>uint(5*j))&31])
		}
		if cur != e.code || string(lat) != e.latin {
			return fmt.Errorf("N20 simple mismatch %d", i)
		}
	}
	cur = dBase
	for i, e := range dig {
		o := 576 + i*4
		cur += uint16(data[o])
		p := uint32(data[o+1]) | uint32(data[o+2])<<8 | uint32(data[o+3])<<16
		second := binary.BigEndian.Uint16(seconds[2*(p&15):])
		n := int((p >> 19) & 3)
		var lat []byte
		for j := 0; j < n; j++ {
			lat = append(lat, alphabet[(p>>uint(4+5*j))&31])
		}
		if cur != e.first || second != e.second || string(lat) != e.latin {
			return fmt.Errorf("N20 digraph mismatch %d", i)
		}
	}
	return nil
}
