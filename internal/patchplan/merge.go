package patchplan

// Three-way source/content/code merger moved from the existing English image
// composer. Fail closed when translated bytes and executable code both claim
// the same byte. No disc-writing or runtime-status decisions are made here.
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"
	"strings"
	"tokimemo/internal/graphics"
	"tokimemo/internal/nametables"
	"tokimemo/internal/ps1"
	"tokimemo/internal/script"
)

type MergeConflict struct {
	File    string `json:"file"`
	Offset  int    `json:"offset"`
	Retail  string `json:"retail"`
	English string `json:"english"`
	Code    string `json:"code"`
}

const (
	rendererGuardStart  = int(0x8004ba78 - 0x80040800)
	rendererGuardBytes  = 180
	exclusiveNameStart  = int(0x80044530 - 0x80040800)
	exclusiveNameEnd    = exclusiveNameStart + 132 + 308
	nameFullStart       = 0x72c80
	nameFullPointers    = 0x72d38
	nameShortStart      = 0x72d78
	nameShortPointers   = 0x72df4
	nameShortPointerEnd = nameShortPointers + 16*4
)

type nameSlot struct {
	start, end int
	value      string
}

func MergeFile(path string, retail, english, n20 []byte) ([]byte, int, []MergeConflict, error) {
	if len(retail) != len(english) || len(retail) != len(n20) {
		return nil, 0, nil, fmt.Errorf("ISO file length changed %s", path)
	}
	result := bytes.Clone(retail)
	clashes := 0
	samples := []MergeConflict{}
	checksum := strings.HasSuffix(path, ".EXN") && ps1.TailChecksumValid(retail)
	for i := range retail {
		ed := english[i] != retail[i]
		nd := n20[i] != retail[i]
		if checksum && i >= len(retail)-4 && i < len(retail)-2 {
			continue
		}
		if ed && nd {
			clashes++
			if len(samples) < 30 {
				samples = append(samples, MergeConflict{path, i, fmt.Sprintf("%02x", retail[i]), fmt.Sprintf("%02x", english[i]), fmt.Sprintf("%02x", n20[i])})
			}
			continue
		}
		if nd {
			result[i] = n20[i]
		} else if ed {
			result[i] = english[i]
		}
	}
	if clashes > 0 {
		return nil, clashes, samples, nil
	}
	if checksum {
		if err := ps1.FixTailChecksum(result); err != nil {
			return nil, 0, nil, err
		}
	}
	return result, 0, nil, nil
}

func releaseRendererGuard(retail, translated, n20EXE []byte) ([]byte, error) {
	if len(retail) != len(translated) || len(retail) != len(n20EXE) {
		return nil, errors.New("executable EXE lengths differ")
	}
	start := int(0x8004ba78 - 0x80040800)
	end := start + rendererGuardBytes
	if end > len(retail) {
		return nil, errors.New("executable renderer reservation outside EXE")
	}
	for i := start; i < end; i++ {
		if translated[i] != 0 {
			return nil, fmt.Errorf("executable English tail nonzero at %x", i)
		}
	}
	if bytes.Equal(retail[start:end], n20EXE[start:end]) {
		return nil, errors.New("executable EXE guard tail missing")
	}
	// Release only this precisely pre-authorized renderer reservation back to
	// retail for the conflict detector. code layer owns the complete 180-byte result;
	// dialogue/text and all other renderer glyphs retain the normal rules.
	corrected := bytes.Clone(translated)
	copy(corrected[start:end], retail[start:end])
	return corrected, nil
}

func mergeExecutableRendererOwned(retail, english, code, authorized []byte, ownerStart, ownerEnd int) ([]byte, int, []MergeConflict, error) {
	renderer, err := graphics.InstallRenderer(retail)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("executable retail renderer auth: %w", err)
	}
	adjusted, err := releaseRendererGuard(retail, english, code)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("executable renderer tail: %w", err)
	}
	if len(retail) != len(code) || len(renderer) != len(code) {
		return nil, 0, nil, errors.New("executable EXE size drift")
	}
	lo := int(0x8004ba78 - 0x80040800)
	hi := lo + rendererGuardBytes
	const expectedNameStart = int(0x80044530 - 0x80040800)
	const expectedNameEnd = expectedNameStart + 132 + 308
	if authorized != nil && (len(authorized) != len(retail) || ownerStart != expectedNameStart || ownerEnd != expectedNameEnd || ownerEnd > len(retail) || (ownerStart < hi && ownerEnd > lo)) {
		return nil, 0, nil, errors.New("executable invalid name layout ownership reservation")
	}
	for i := range retail {
		owned := authorized != nil && i >= ownerStart && i < ownerEnd
		if owned {
			// Both the retail image and installed renderer are pinned by the
			// authenticated planner. Its exclusive reserved bytes must be zero
			// in the current English renderer. Never waive EN changes here.
			if renderer[i] != 0 || english[i] != renderer[i] || code[i] != authorized[i] {
				return nil, 0, nil, fmt.Errorf("executable name layout exclusive renderer reservation drift EXE+%#x", i)
			}
			// English renderer's zero-filled allocation is relinquished only
			// inside this exact region, so name layout is treated as its sole writer.
			adjusted[i] = retail[i]
		} else if (i < lo || i >= hi) && renderer[i] != retail[i] && code[i] != renderer[i] {
			return nil, 0, nil, fmt.Errorf("executable modified required English renderer EXE+%#x", i)
		}
		if adjusted[i] != retail[i] && code[i] != retail[i] &&
			renderer[i] != retail[i] && adjusted[i] == renderer[i] && code[i] == renderer[i] {
			adjusted[i] = retail[i]
		}
	}
	return MergeFile("SLPM_86.053", retail, adjusted, code)
}

func decodePairName(raw []byte) (string, error) {
	if len(raw) == 0 || len(raw)%2 != 0 {
		return "", errors.New("not a nonempty pair glyph string")
	}
	var s strings.Builder
	for i := 0; i < len(raw); i += 2 {
		if raw[i] == 0x81 && raw[i+1] == 0x40 {
			s.WriteString("  ")
			continue
		}
		a, b := raw[i], raw[i+1]
		if a&0x80 == 0 || b&0x80 == 0 {
			return "", fmt.Errorf("non-English glyph at pair %d", i/2)
		}
		a &= 0x7f
		b &= 0x7f
		for _, c := range []byte{a, b} {
			if c < 0x20 || c > 0x7e || strings.ContainsRune("{}~`\\|@#$^*_=[:\\]", rune(c)) {
				return "", fmt.Errorf("unsupported English glyph at pair %d", i/2)
			}
		}
		s.WriteByte(a)
		s.WriteByte(b)
	}
	result := strings.TrimRight(s.String(), " ")
	// Confirm the exact encoded source, including odd-length space padding.
	encoded, e := (&script.PairEncoder{}).Encode(result)
	if e != nil || !bytes.Equal(encoded, raw) {
		return "", errors.New("noncanonical English name glyph encoding")
	}
	return result, nil
}

func readNameSlots(image []byte, original []byte, table, start, end int) ([]nameSlot, error) {
	if len(image) != len(original) || end > len(image) || table+16*4 > len(image) {
		return nil, errors.New("name table out of file")
	}
	// The production English patch can independently repack these shortened
	// strings. It may therefore legitimately change the pointer table. The
	// complete table is decoded and validated, rather than compared to retail.
	slots := make([]nameSlot, 16)
	seen := map[int]bool{}
	for i := 0; i < 16; i++ {
		addr := binary.LittleEndian.Uint32(image[table+4*i:])
		off := int64(addr) - int64(nametables.Base)
		if off < int64(start) || off >= int64(end) || seen[int(off)] {
			return nil, fmt.Errorf("name pointer index %d outside unique source pool", i)
		}
		seen[int(off)] = true
		slots[i].start = int(off)
	}
	for i := 0; i < 16; i++ {
		at := slots[i].start
		limit := end
		for j := 0; j < 16; j++ {
			if slots[j].start > at && slots[j].start < limit {
				limit = slots[j].start
			}
		}
		nul := bytes.IndexByte(image[at:limit], 0)
		if nul < 1 || nul%2 != 0 {
			return nil, fmt.Errorf("name index %d is not pair-encoded and NUL terminated", i)
		}
		name, e := decodePairName(image[at : at+nul])
		if e != nil {
			return nil, fmt.Errorf("name index %d: %w", i, e)
		}
		slots[i].end = limit
		slots[i].value = name
	}
	return slots, nil
}

func expandedAbbreviation(source, target string) bool {
	// Current official-era EN fits fixed source name slots by abbreviating,
	// e.g. `Fujisaki S.`. name layout's complete value `Fujisaki Shiori` can be
	// accepted only as an explicit extension of the exact same prefix.
	if source == target {
		return true
	}
	s := strings.TrimSuffix(source, ".")
	return len(s) >= 3 && strings.HasPrefix(target, s)
}

func confirmNameOwnership(retail, english []byte, shortCurrent, fullTarget []string) error {
	if len(shortCurrent) != 16 || len(fullTarget) != 16 {
		return errors.New("executable requires 16 name-source and name-target strings")
	}
	full, e := readNameSlots(english, retail, nameFullPointers, nameFullStart, nameFullPointers)
	if e != nil {
		return fmt.Errorf("full names: %w", e)
	}
	short, e := readNameSlots(english, retail, nameShortPointers, nameShortStart, nameShortPointers)
	if e != nil {
		return fmt.Errorf("short names: %w", e)
	}
	for i := 0; i < 16; i++ {
		if short[i].value != shortCurrent[i] {
			return fmt.Errorf("executable live EN short name %d differs from provisional name layout source: EN=%q name layout=%q; no overwrite", i, short[i].value, shortCurrent[i])
		}
		if !expandedAbbreviation(full[i].value, fullTarget[i]) {
			return fmt.Errorf("executable live EN full name %d not compatible with provisional name layout expansion: EN=%q name layout=%q; no overwrite", i, full[i].value, fullTarget[i])
		}
	}
	// Every changed English byte in the old repurposed zone must actually
	// belong to a validated name slot. Unrelated bytes cannot be waived.
	mask := make([]bool, nameShortPointerEnd)
	for _, slot := range append(full, short...) {
		for i := slot.start; i < slot.end; i++ {
			mask[i] = true
		}
	}
	for i := nameFullPointers; i < nameShortStart; i++ {
		mask[i] = true
	} // full pointers
	for i := nameShortPointers; i < nameShortPointerEnd; i++ {
		mask[i] = true
	} // short pointers
	for i := nameFullStart; i < nameShortPointerEnd; i++ {
		if english[i] != retail[i] && !mask[i] {
			return fmt.Errorf("executable unowned English EXE name-area mutation +%#x", i)
		}
	}
	return nil
}

func mergeNameOwnedExecutable(retail, english, physical, authorized []byte, spareStart, spareEnd int, currentShort, targetFull []string) ([]byte, int, []MergeConflict, error) {
	if len(retail) != len(english) || len(retail) != len(physical) || len(english) < nameShortPointerEnd {
		return nil, 0, nil, errors.New("executable unequal/short EXE")
	}
	if e := confirmNameOwnership(retail, english, currentShort, targetFull); e != nil {
		return nil, 0, nil, e
	}
	// The live English patch's short/full name pool is intentionally
	// replaced by the name layout relocation, *only after* its semantic check.
	adjusted := bytes.Clone(english)
	copy(adjusted[nameFullStart:nameShortPointerEnd], retail[nameFullStart:nameShortPointerEnd])
	return mergeExecutableRendererOwned(retail, adjusted, physical, authorized, spareStart, spareEnd)
}

// MergeNameExecutable preserves all independent translation edits and applies
// only the authenticated name relocation/renderer code. The caller MUST give
// both complete 16-name lists from the current translation source. No runtime
// substitutions or test names are accepted.
func MergeNameExecutable(retail, english, code, authorized []byte, sourceShort, targetFull []string) ([]byte, int, []MergeConflict, error) {
	return mergeNameOwnedExecutable(retail, english, code, authorized, exclusiveNameStart, exclusiveNameEnd, sourceShort, targetFull)
}

// MergeLayeredFiles composes all edited English files with executable patches
// against unchanged retail bytes. It does not access composition engines or write
// a CUE/ROM. The caller owns the final verified sector writer.
func MergeLayeredFiles(readRetail func(string) ([]byte, error), english, code map[string][]byte, currentShort, targetFull []string, authorizedEXE []byte) (map[string][]byte, error) {
	names := make(map[string]bool, len(english)+len(code))
	for p := range english {
		names[p] = true
	}
	for p := range code {
		names[p] = true
	}
	out := make(map[string][]byte, len(names))
	paths := make([]string, 0, len(names))
	for path := range names {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		retail, e := readRetail(path)
		if e != nil {
			return nil, e
		}
		translated, ok := english[path]
		if !ok {
			translated = retail
		}
		executable, ok := code[path]
		if !ok {
			executable = retail
		}
		var got []byte
		var count int
		var collisions []MergeConflict
		if path == "SLPM_86.053" && ok {
			got, count, collisions, e = MergeNameExecutable(retail, translated, executable, authorizedEXE, currentShort, targetFull)
		} else {
			got, count, collisions, e = MergeFile(path, retail, translated, executable)
		}
		if e != nil {
			return nil, fmt.Errorf("merge %s: %w", path, e)
		}
		if count != 0 {
			return nil, fmt.Errorf("merge %s: %d conflicting bytes (first at %#x)", path, count, collisions[0].Offset)
		}
		if !bytes.Equal(got, retail) {
			out[path] = got
		}
	}
	return out, nil
}
