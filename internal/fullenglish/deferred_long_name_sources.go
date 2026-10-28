package fullenglish

// Defers only verified name records that cannot fit the original fixed slots.
// The translated values remain authoritative and are installed by the
// name-table relocation stage. Unrecognized oversized records still fail.
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"

	nametables "tokimemo/internal/namepatch"
	"tokimemo/internal/patchplan"
	"tokimemo/internal/script"
)

type longNameDeferredName struct {
	entry       script.InPlaceString
	kind        string // short, full, fujisaki, geko11, geko11san
	index       int
	placeholder string
}

func longNameOriginalNameIndex(exe []byte, table, indexOffset, end, at int) (int, bool) {
	if at < indexOffset || at >= end || len(exe) < table+64 {
		return 0, false
	}
	for i := 0; i < 16; i++ {
		ptr := binary.LittleEndian.Uint32(exe[table+i*4:])
		if ptr == nametables.Base+uint32(at) {
			return i, true
		}
	}
	return 0, false
}

func longNameClassifyName(exe []byte, p script.InPlaceString) (string, int, bool) {
	if p.Source != "character_names.json" {
		return "", 0, false
	}
	if p.File == "SLPM_86.053" {
		switch p.Offset {
		case 0x71980, 0x71988, 0x7199c, 0x719a4:
			return "fujisaki", 0, true
		}
		if i, ok := longNameOriginalNameIndex(exe, namePoolLayoutShortPointer, namePoolLayoutShortPoolStart, namePoolLayoutShortPointer, p.Offset); ok {
			return "short", i, true
		}
		if i, ok := longNameOriginalNameIndex(exe, namePoolLayoutFullPointer, namePoolLayoutFullPoolStart, namePoolLayoutFullPointer, p.Offset); ok {
			return "full", i, true
		}
	}
	if p.File == "CDROM/EXEDIR/GEKO.EXN" {
		switch p.Offset {
		case 0x12b1c:
			return "geko11", 11, true
		case 0x12b24:
			return "geko11san", 11, true
		}
	}
	return "", 0, false
}

// A placeholder is ONLY an intermediate English-pair label fitting an old
// slot so that the unchanged authenticated source names pool reader can validate the
// staged build. Never output it as the final translated value.
func longNamePlaceholder(text string, available int) (string, error) {
	if text == "" || strings.TrimSpace(text) != text || strings.ContainsAny(text, "{}\n\r\t") {
		return "", errors.New("invalid source-authored NPC name")
	}
	if _, e := (&script.PairEncoder{}).Encode(text); e != nil {
		return "", e
	}
	for n := len(text); n >= 2; n-- {
		candidate := text[:n]
		if strings.HasSuffix(candidate, " ") {
			continue
		}
		raw, e := (&script.PairEncoder{}).Encode(candidate)
		if e == nil && len(raw)+1 <= available {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("name %q cannot be represented even as private short-stage prefix in %d bytes", text, available)
}

// separateLongNameSources validates preimages using the existing production
// exact-slot parser, but never changes its behavior. Only N10-authenticated
// name records may be deferred. Any unknown overlong record still fails in
// patchplan.PlanBytes (or here if malformed), with no image produced.
func longNameSeparateLongNames(exe, geko []byte, batch patchplan.Batch) (patchplan.Batch, []longNameDeferredName, error) {
	cleaned := batch
	cleaned.Strings = make([]script.InPlaceString, 0, len(batch.Strings))
	deferred := []longNameDeferredName{}
	seen := map[string]string{}
	for _, p := range batch.Strings {
		kind, ix, known := longNameClassifyName(exe, p)
		if !known {
			cleaned.Strings = append(cleaned.Strings, p)
			continue
		}
		var original []byte
		if p.File == "SLPM_86.053" {
			original = exe
		} else {
			original = geko
		}
		probe := bytes.Clone(original)
		err := script.ApplyInPlaceString(probe, p, &script.PairEncoder{})
		if err == nil {
			cleaned.Strings = append(cleaned.Strings, p)
			continue
		}
		if !strings.Contains(err.Error(), "English requires") {
			return cleaned, nil, fmt.Errorf("long-name source source-name preflight: %w", err)
		}
		jp, e := script.EncodeOriginal(p.Original)
		if e != nil {
			return cleaned, nil, e
		}
		cap := len(jp) + 1
		if p.Slot != nil {
			cap = *p.Slot
		} else {
			for (p.Offset+cap)%4 != 0 && p.Offset+cap < len(original) && original[p.Offset+cap] == 0 {
				cap++
			}
		}
		if p.Offset < 0 || p.Offset+cap > len(original) || !bytes.Equal(original[p.Offset:p.Offset+len(jp)], jp) || original[p.Offset+len(jp)] != 0 {
			return cleaned, nil, fmt.Errorf("long-name source source-name preimage mismatched %s +%#x", p.File, p.Offset)
		}
		// The G2 translation is verified against the source-authored short
		// name plus -san below. Both diagnostic branches stay undecided.
		placeholder, e := longNamePlaceholder(p.Text, cap)
		if e != nil {
			return cleaned, nil, e
		}
		key := fmt.Sprintf("%s:%d", kind, ix)
		if prev, ok := seen[key]; ok && prev != p.Text {
			return cleaned, nil, fmt.Errorf("long-name source conflicting source labels at %s: %q and %q", key, prev, p.Text)
		}
		seen[key] = p.Text
		deferred = append(deferred, longNameDeferredName{entry: p, kind: kind, index: ix, placeholder: placeholder})
	}
	return cleaned, deferred, nil
}

// Stages only pool locations using the short English placeholder. Fixed
// Fujisaki/GEKO literal regions stay byte-identical to Japanese source and
// MUST be handled by the separately authenticated N10 direct-alias rewrite.
func longNameApplyNameStage(english []byte, deferred []longNameDeferredName) error {
	for _, d := range deferred {
		if d.kind != "short" && d.kind != "full" {
			continue
		}
		p := d.entry
		enc, e := (&script.PairEncoder{}).Encode(d.placeholder)
		if e != nil {
			return e
		}
		raw, e := script.EncodeOriginal(p.Original)
		if e != nil {
			return e
		}
		cap := len(raw) + 1
		if p.Slot != nil {
			cap = *p.Slot
		} else {
			for (p.Offset+cap)%4 != 0 && p.Offset+cap < len(english) && english[p.Offset+cap] == 0 {
				cap++
			}
		}
		if p.Offset < 0 || p.Offset+cap > len(english) || len(enc)+1 > cap || !bytes.Equal(english[p.Offset:p.Offset+len(raw)], raw) || english[p.Offset+len(raw)] != 0 {
			return fmt.Errorf("long-name source private name stage invalid original area %s %#x", p.File, p.Offset)
		}
		clear(english[p.Offset : p.Offset+cap])
		copy(english[p.Offset:], enc)
	}
	return nil
}

func longNameSourceNames(retail, english []byte, deferred []longNameDeferredName) (stageShort, fullStage, desiredShort, desiredFull []string, err error) {
	stageShort, fullStage, err = ownerEnglishSourceNames(retail, english)
	if err != nil {
		return
	}
	desiredShort = append([]string(nil), stageShort...)
	desiredFull = append([]string(nil), fullStage...)
	seen := map[string]string{}
	explicitShort := map[int]string{}
	for _, d := range deferred {
		if d.kind == "short" || d.kind == "fujisaki" || d.kind == "geko11" {
			if old, ok := explicitShort[d.index]; ok && old != d.entry.Text {
				err = fmt.Errorf("long-name source conflicting source-authoritative names for NPC index %d: %q / %q", d.index, old, d.entry.Text)
				return
			}
			explicitShort[d.index] = d.entry.Text
		}
	}
	var g2Source string
	for _, d := range deferred {
		key := fmt.Sprintf("%s:%d", d.kind, d.index)
		if old, ok := seen[key]; ok && old != d.entry.Text {
			err = fmt.Errorf("long-name source conflicting %s", key)
			return
		}
		seen[key] = d.entry.Text
		switch d.kind {
		case "short", "fujisaki", "geko11":
			if d.kind != "short" && desiredShort[d.index] != stageShort[d.index] && desiredShort[d.index] != d.entry.Text {
				err = fmt.Errorf("long-name source alias conflicts with translated name index %d", d.index)
				return
			}
			desiredShort[d.index] = d.entry.Text
		case "full":
			desiredFull[d.index] = d.entry.Text
		case "geko11san":
			// Verify after applying all other source edits, independent of JSON order.
			g2Source = d.entry.Text
		}
	}
	// No GEKO bare/san owner decision is inferred from a source suffix.
	// This validates only the san diagnostic branch's exact spelling.
	if g2Source != "" && g2Source != desiredShort[11]+"-san" {
		err = fmt.Errorf("long-name source GEKO G2 source %q disagrees with source-owned index 11 + -san %q", g2Source, desiredShort[11]+"-san")
		return
	}
	// An old copyable prefix in the source names legacy-slot region is proof of byte
	// ownership, NOT authorization to replace different editorial names.
	for i := 0; i < 16; i++ {
		if desiredShort[i] == "" || desiredFull[i] == "" {
			err = fmt.Errorf("long-name source empty translated name %d", i)
			return
		}
		if !namePoolLayoutExpandedAbbreviation(fullStage[i], desiredFull[i]) {
			err = fmt.Errorf("long-name source full-name stage %d not prefix of source translation", i)
			return
		}
	}
	return
}
