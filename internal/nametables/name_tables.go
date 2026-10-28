// Source-preserving extraction of name-table composition primitives.
package nametables

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/script"
)

const (
	NameFullPoolStart    = 0x72c80
	NameFullPoolSplit    = 0x72d38
	NameFullTableEnd     = 0x72d78
	NameFullFragment2End = 0x72da4
	NamePhase2AOffset    = 0x72da4

	NamePhase2G2Offset = 0x72dd4
	NamePhase2SpareEnd = 0x72df4
	NamePhase2A        = 0x800b35a4
	NamePhase2B        = 0x800b35b4
	NamePhase2G2       = 0x800b35d4
)

var nameFullFirst = [...]int{0, 2, 3, 4, 5, 6, 9, 10, 11, 13, 14, 1}
var nameFullSecond = [...]int{7, 8, 12, 15}

type FullSplitResult struct {
	FirstBytes      int  `json:"first_bytes"`
	SecondBytes     int  `json:"second_bytes"`
	PointerWords    int  `json:"pointer_words"`
	RuntimeVerified bool `json:"runtime_verified"`
	SafeToPatch     bool `json:"safe_to_patch"`
}

func StageFullNameSplit(stagedEXE []byte, expectedSHA [32]byte, names []string) ([]byte, FullSplitResult, error) {
	fail := func(format string, args ...any) ([]byte, FullSplitResult, error) {
		return nil, FullSplitResult{}, fmt.Errorf("Name full split: "+format, args...)
	}
	if sha256.Sum256(stagedEXE) != expectedSHA || len(stagedEXE) < PointerTable+64 || len(names) != Entries {
		return fail("input SHA, length, or entry count mismatch")
	}

	for i := 0; i < Entries; i++ {
		p := binary.LittleEndian.Uint32(stagedEXE[PointerTable+4*i:])
		if p < 0x8004ba78 || p > 0x8004bafb {
			return fail("short pointer %d not in staged renderer tail: %#x", i, p)
		}
	}
	seen := map[uint32]bool{}
	for i := 0; i < Entries; i++ {
		p := binary.LittleEndian.Uint32(stagedEXE[NameFullPoolSplit+4*i:])
		if p < Base+NameFullPoolStart || p >= Base+NameFullPoolSplit || seen[p] {
			return fail("original full-name pointer %d unrecognized: %#x", i, p)
		}
		seen[p] = true
		at := int(p - Base)
		if end := bytes.IndexByte(stagedEXE[at:NameFullPoolSplit], 0); end <= 0 {
			return fail("original full name %d lacks terminated content", i)
		}
	}
	out := bytes.Clone(stagedEXE)

	clear(out[NameFullPoolStart:NameFullPoolSplit])
	clear(out[NameFullTableEnd:NameFullFragment2End])
	pointers := [Entries]uint32{}
	encoder := &script.PairEncoder{}
	pack := func(start, end int, order []int) (int, error) {
		at := start
		for _, i := range order {
			n := names[i]
			if n == "" || bytes.IndexByte([]byte(n), 0) >= 0 {
				return 0, fmt.Errorf("empty/NUL full name %d", i)
			}
			raw, err := encoder.Encode(n)
			if err != nil {
				return 0, fmt.Errorf("name %d: %w", i, err)
			}
			if len(raw) == 0 || at+len(raw)+1 > end {
				return 0, fmt.Errorf("full name %d overflows fragment", i)
			}
			copy(out[at:], raw)
			out[at+len(raw)] = 0
			pointers[i] = Base + uint32(at)
			at += len(raw) + 1
		}

		return at - start, nil
	}
	one, err := pack(NameFullPoolStart, NameFullPoolSplit, nameFullFirst[:])
	if err != nil {
		return fail("first fragment: %v", err)
	}
	two, err := pack(NameFullTableEnd, NameFullFragment2End, nameFullSecond[:])
	if err != nil {
		return fail("second fragment: %v", err)
	}

	clear(out[NameFullFragment2End:NamePhase2SpareEnd])
	for i, p := range pointers {
		binary.LittleEndian.PutUint32(out[NameFullPoolSplit+4*i:], p)
	}
	for i, p := range pointers {
		at := int(p - Base)
		if at < NameFullPoolStart || at >= NameFullFragment2End ||
			(at >= NameFullPoolSplit && at < NameFullTableEnd) ||
			bytes.IndexByte(out[at:NameFullFragment2End], 0) <= 0 {
			return fail("relocated full pointer %d invalid", i)
		}
	}
	return out, FullSplitResult{FirstBytes: one, SecondBytes: two, PointerWords: Entries}, nil
}

var namePhase2ASites = map[string][][2]uint32{
	EXE: {
		{0x8007fb78, 0x8007fb80}, {0x8007fb90, 0x8007fb98},
		{0x8007fc50, 0x8007fc58}, {0x8007fe44, 0x8007fe4c},
		{0x8007fe54, 0x8007fe5c}, {0x80080094, 0x8008009c},
		{0x800800ac, 0x800800b4}, {0x8008016c, 0x80080174},
		{0x80081030, 0x80081034}, {0x80081044, 0x8008104c},
		{0x80084820, 0x80084828},
	},
	"GEKO.EXN": {
		{0x801396f4, 0x80139704}, {0x8013cbac, 0x8013cbc0},
		{0x8013cbec, 0x8013cbfc}, {0x80141168, 0x80141178},
		{0x80141464, 0x80141474},
	},
}
var namePhase2BSites = map[string][][2]uint32{
	EXE: {
		{0x800816c8, 0x800816d0}, {0x800816d8, 0x800816dc},
		{0x8008172c, 0x80081734}, {0x80081744, 0x80081750},
		{0x80082000, 0x80082008}, {0x80082028, 0x8008202c},
		{0x80082068, 0x80082070}, {0x80082080, 0x8008208c},
		{0x8008482c, 0x80084838},
	},
	"GEKO.EXN":     {{0x80141478, 0x80141488}},
	"SHUGAKU.EXN":  {{0x801397f0, 0x801397f8}},
	"SHOUGATU.EXN": {{0x8013df98, 0x8013dfa8}},
}
var namePhase2ImageSHA = map[string]string{
	EXE:            "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae",
	"GEKO.EXN":     "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad",
	"SHUGAKU.EXN":  "06f885c6038811fbbf2f4081d81a18b74cfec08c244e12004e4fa91a8e54cc14",
	"SHOUGATU.EXN": "84842bc3e8540ef9853d38ca04bb453eddb60a5a9b14786896ac618b3b84bb13",
}
var namePhase2Base = map[string]uint32{EXE: Base, "GEKO.EXN": 0x80132000, "SHUGAKU.EXN": 0x80132000, "SHOUGATU.EXN": 0x80132000}

type Phase2ABResult struct {
	RewrittenA      int    `json:"rewritten_a"`
	RewrittenB      int    `json:"rewritten_b"`
	ImageCount      int    `json:"image_count"`
	NewA            uint32 `json:"new_a"`
	NewB            uint32 `json:"new_b"`
	UnsafeToBoot    bool   `json:"unsafe_to_boot"`
	RuntimeVerified bool   `json:"runtime_verified"`
}

func StagePhase2AB(originals, staged map[string][]byte) (map[string][]byte, Phase2ABResult, error) {
	fail := func(format string, args ...any) (map[string][]byte, Phase2ABResult, error) {
		return nil, Phase2ABResult{}, fmt.Errorf("Name Phase-2 A/B: "+format, args...)
	}
	if len(originals) != 4 || len(staged) != 4 {
		return fail("four exact images required")
	}
	if len(staged[EXE]) <= NamePhase2SpareEnd ||
		!bytes.Equal(staged[EXE][NamePhase2AOffset:NamePhase2SpareEnd], make([]byte, NamePhase2SpareEnd-NamePhase2AOffset)) {
		return fail("split full pool/A/B/G2 prerequisite missing or region occupied")
	}
	output := make(map[string][]byte, 4)
	aCount, bCount := 0, 0
	for name, digest := range namePhase2ImageSHA {
		before, ok := originals[name]
		if !ok || fmt.Sprintf("%x", sha256.Sum256(before)) != digest {
			return fail("%s original identity mismatch", name)
		}
		now, ok := staged[name]
		if !ok || len(now) != len(before) {
			return fail("%s staged file geometry mismatch", name)
		}
		refs := make([]AddressPair, 0, len(namePhase2ASites[name])+len(namePhase2BSites[name]))
		for _, kind := range []struct {
			sites    [][2]uint32
			old, new uint32
		}{
			{namePhase2ASites[name], BufferA, NamePhase2A},
			{namePhase2BSites[name], BufferB, NamePhase2B},
		} {
			for _, at := range kind.sites {
				base := namePhase2Base[name]
				if at[0] < base || at[1] < base {
					return fail("%s invalid PC", name)
				}
				upper, lower := int(at[0]-base), int(at[1]-base)
				if lower+4 > len(now) || upper+4 > len(now) {
					return fail("%s PC outside file", name)
				}
				hi := binary.LittleEndian.Uint32(before[upper:])
				lo := binary.LittleEndian.Uint32(before[lower:])
				if hi>>26 != 15 || lo>>26 != 9 || ((hi>>16)&31) == 0 || ((hi>>16)&31) != ((lo>>16)&31) || ((hi>>16)&31) != ((lo>>21)&31) {
					return fail("%s site %#x unexpected instruction registers %#x/%#x", name, at[0], hi, lo)
				}

				if binary.LittleEndian.Uint32(now[upper:]) != hi || binary.LittleEndian.Uint32(now[lower:]) != lo {
					return fail("%s changed address pair at %#x", name, at[0])
				}
				refs = append(refs, AddressPair{UpperOffset: upper, LowerOffset: lower, UpperWord: hi, LowerWord: lo, OldAddress: kind.old, NewAddress: kind.new})
			}
		}
		next, r, err := RewriteGuardedAddressPairs(now, refs)
		if err != nil {
			return fail("%s: %v", name, err)
		}
		if r.Sites != len(refs) {
			return fail("%s incomplete rewrite", name)
		}
		output[name] = next
		aCount += len(namePhase2ASites[name])
		bCount += len(namePhase2BSites[name])
	}
	if aCount != 16 || bCount != 12 {
		return fail("expected 16 A + 12 B, got %d/%d", aCount, bCount)
	}

	return output, Phase2ABResult{RewrittenA: aCount, RewrittenB: bCount, ImageCount: 4, NewA: NamePhase2A, NewB: NamePhase2B, UnsafeToBoot: true}, nil
}

const (
	NameGEKOBare = "bare"
	NameGEKOSan  = "san"
)

type GEKOG2Result struct {
	Policy              string `json:"policy"`
	Destination         uint32 `json:"destination"`
	EncodedBytesWithNUL int    `json:"encoded_bytes_with_nul"`
	UnsafeToBoot        bool   `json:"unsafe_to_boot"`
}

func StageGEKOG2(exe, geko, originalGEKO []byte, policy string, nameForIndex11 string) ([]byte, []byte, GEKOG2Result, error) {
	fail := func(format string, args ...any) ([]byte, []byte, GEKOG2Result, error) {
		return nil, nil, GEKOG2Result{}, fmt.Errorf("Name GEKO G2: "+format, args...)
	}
	if fmt.Sprintf("%x", sha256.Sum256(originalGEKO)) != namePhase2ImageSHA["GEKO.EXN"] || len(geko) != len(originalGEKO) || len(exe) < NamePhase2SpareEnd {
		return fail("source revision or length mismatch")
	}
	if !bytes.Equal(geko[0x12b1c:0x12b30], originalGEKO[0x12b1c:0x12b30]) {
		return fail("original GEKO literals already overwritten")
	}
	if !bytes.Equal(exe[NamePhase2G2Offset:NamePhase2SpareEnd], make([]byte, NamePhase2SpareEnd-NamePhase2G2Offset)) {
		return fail("G2 destination or spare already occupied")
	}

	name := nameForIndex11
	shortPtr := binary.LittleEndian.Uint32(exe[PointerTable+11*4:])
	if shortPtr < Base || shortPtr >= Base+uint32(len(exe)) || name == "" {
		return fail("invalid staged short name entry 11")
	}
	shortAt := int(shortPtr - Base)
	shortRaw, encErr := (&script.PairEncoder{}).Encode(name)
	if encErr != nil || shortAt+len(shortRaw)+1 > len(exe) ||
		!bytes.Equal(exe[shortAt:shortAt+len(shortRaw)], shortRaw) || exe[shortAt+len(shortRaw)] != 0 {
		return fail("staged short entry 11 differs from source-provided name")
	}
	dst := shortPtr
	if policy == NameGEKOSan {
		name += "-san"
		dst = NamePhase2G2
	} else if policy != NameGEKOBare {
		return fail("translation policy must be explicit: bare or san")
	}
	raw, e := (&script.PairEncoder{}).Encode(name)
	if e != nil {
		return fail("encode: %v", e)
	}
	want := len(raw) + 1
	if want > 17 || want < 2 {
		return fail("G2 value requires %d bytes, destination 17", want)
	}
	nextEXE := bytes.Clone(exe)
	if policy == NameGEKOSan {
		copy(nextEXE[NamePhase2G2Offset:], raw)
		nextEXE[NamePhase2G2Offset+len(raw)] = 0
	}

	const hiOff, loOff = 0xf47c, 0xf480
	hi := binary.LittleEndian.Uint32(originalGEKO[hiOff:])
	lo := binary.LittleEndian.Uint32(originalGEKO[loOff:])
	if hi != 0x3c058014 || lo != 0x24a54b24 || binary.LittleEndian.Uint32(geko[hiOff:]) != hi || binary.LittleEndian.Uint32(geko[loOff:]) != lo || binary.LittleEndian.Uint32(geko[0xf484:]) != 0x0c02b83c {
		return fail("G2 source/callsite was changed or wrong")
	}
	nextGEKO, _, e := RewriteGuardedAddressPairs(geko, []AddressPair{{UpperOffset: hiOff, LowerOffset: loOff, UpperWord: hi, LowerWord: lo, OldAddress: 0x80144b24, NewAddress: dst}})
	if e != nil {
		return fail("G2 source rewrite: %v", e)
	}
	if !bytes.Equal(nextGEKO[0x12b1c:0x12b30], originalGEKO[0x12b1c:0x12b30]) {
		return fail("GEKO originals changed")
	}
	return nextEXE, nextGEKO, GEKOG2Result{Policy: policy, Destination: dst, EncodedBytesWithNUL: want, UnsafeToBoot: true}, nil
}
