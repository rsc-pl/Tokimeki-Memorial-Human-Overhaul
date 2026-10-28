package fullenglish

// The original short- and full-name pools overlap locations subsequently
// reused by name relocation. This is an intentional, source-verified shared
// edit, not an arbitrary byte conflict. All 32 translated values must match
// the authenticated source/target mapping. Validation of byte ownership does
// not certify translation choices or runtime memory safety.
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	nametables "tokimemo/internal/namepatch"
	"tokimemo/internal/script"
)

// These bounds are fixed by the authenticated N10 table layout, not derived
// from edits. The 16 full-name pointers occupy 0x72d38..0x72d78 and the 16
// short-name pointers occupy 0x72df4..0x72e34.
const (
	namePoolLayoutFullPoolStart   = 0x72c80
	namePoolLayoutFullPointer     = 0x72d38
	namePoolLayoutShortPoolStart  = 0x72d78
	namePoolLayoutShortPointer    = 0x72df4
	namePoolLayoutShortPointerEnd = namePoolLayoutShortPointer + 16*4
)

type namePoolLayoutNameSlot struct {
	start, end int
	value      string
}

// Decode only the installed English *pair font*, not Shift-JIS. A Japanese
// source or unrecognised token is an error; no best-effort transliteration.
func namePoolLayoutPairName(raw []byte) (string, error) {
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

func namePoolLayoutReadNameSlots(image []byte, original []byte, table, start, end int) ([]namePoolLayoutNameSlot, error) {
	if len(image) != len(original) || end > len(image) || table+16*4 > len(image) {
		return nil, errors.New("name table out of file")
	}
	// The production English patch can independently repack these shortened
	// strings. It may therefore legitimately change the pointer table. The
	// complete table is decoded and validated, rather than compared to retail.
	slots := make([]namePoolLayoutNameSlot, 16)
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
		name, e := namePoolLayoutPairName(image[at : at+nul])
		if e != nil {
			return nil, fmt.Errorf("name index %d: %w", i, e)
		}
		slots[i].end = limit
		slots[i].value = name
	}
	return slots, nil
}

func namePoolLayoutExpandedAbbreviation(source, target string) bool {
	// Current official-era EN fits fixed source name slots by abbreviating,
	// e.g. `Fujisaki S.`. N10's complete value `Fujisaki Shiori` can be
	// accepted only as an explicit extension of the exact same prefix.
	if source == target {
		return true
	}
	s := strings.TrimSuffix(source, ".")
	return len(s) >= 3 && strings.HasPrefix(target, s)
}

func namePoolLayoutConfirmNameOwnership(retail, english []byte, shortCurrent, fullTarget []string) error {
	if len(shortCurrent) != 16 || len(fullTarget) != 16 {
		return errors.New("source names requires 16 name-source and name-target strings")
	}
	full, e := namePoolLayoutReadNameSlots(english, retail, namePoolLayoutFullPointer, namePoolLayoutFullPoolStart, namePoolLayoutFullPointer)
	if e != nil {
		return fmt.Errorf("full names: %w", e)
	}
	short, e := namePoolLayoutReadNameSlots(english, retail, namePoolLayoutShortPointer, namePoolLayoutShortPoolStart, namePoolLayoutShortPointer)
	if e != nil {
		return fmt.Errorf("short names: %w", e)
	}
	for i := 0; i < 16; i++ {
		if short[i].value != shortCurrent[i] {
			return fmt.Errorf("source names live EN short name %d differs from provisional N10 source: EN=%q N10=%q; no overwrite", i, short[i].value, shortCurrent[i])
		}
		if !namePoolLayoutExpandedAbbreviation(full[i].value, fullTarget[i]) {
			return fmt.Errorf("source names live EN full name %d not compatible with provisional N10 expansion: EN=%q N10=%q; no overwrite", i, full[i].value, fullTarget[i])
		}
	}
	// Every changed English byte in the old repurposed zone must actually
	// belong to a validated name slot. Unrelated bytes cannot be waived.
	mask := make([]bool, namePoolLayoutShortPointerEnd)
	for _, slot := range append(full, short...) {
		for i := slot.start; i < slot.end; i++ {
			mask[i] = true
		}
	}
	for i := namePoolLayoutFullPointer; i < namePoolLayoutShortPoolStart; i++ {
		mask[i] = true
	} // full pointers
	for i := namePoolLayoutShortPointer; i < namePoolLayoutShortPointerEnd; i++ {
		mask[i] = true
	} // short pointers
	for i := namePoolLayoutFullPoolStart; i < namePoolLayoutShortPointerEnd; i++ {
		if english[i] != retail[i] && !mask[i] {
			return fmt.Errorf("source names unowned English EXE name-area mutation +%#x", i)
		}
	}
	return nil
}

// Release exactly the semantically authenticated old N10 name storage to the
// candidate's ownership. pool ownership keeps exclusive protection for its separate
// 440-byte reserved renderer region. No other shared changes are bypassed.
func fullMergeN10Names(retail, english, physical, authorized []byte, spareStart, spareEnd int, currentShort, targetFull []string) ([]byte, int, []fullConflict, error) {
	if len(retail) != len(english) || len(retail) != len(physical) || len(english) < namePoolLayoutShortPointerEnd {
		return nil, 0, nil, errors.New("source names unequal/short EXE")
	}
	if e := namePoolLayoutConfirmNameOwnership(retail, english, currentShort, targetFull); e != nil {
		return nil, 0, nil, e
	}
	// The live English patch's short/full name pool is intentionally
	// replaced by the N10 relocation, *only after* its semantic check.
	adjusted := bytes.Clone(english)
	copy(adjusted[namePoolLayoutFullPoolStart:namePoolLayoutShortPointerEnd], retail[namePoolLayoutFullPoolStart:namePoolLayoutShortPointerEnd])
	return fullMergeEXEOwned(retail, adjusted, physical, authorized, spareStart, spareEnd)
}
