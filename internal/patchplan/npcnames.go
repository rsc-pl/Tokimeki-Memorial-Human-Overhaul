package patchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"strings"

	"tokimemo/internal/script"
)

// NPCNameEdit identifies a translated, source-owned name that must be emitted
// through the pointer-relocating name writer rather than the original fixed
// capacity string/dialogue packer. Its text is never abbreviated or inferred.
// No caller may publish a batch with these edits simply removed.
type NPCNameEdit struct {
	File     string
	Offset   int
	Original string
	Text     string
	Kind     string
	Index    int
}

// NPCSourcePlan is an incomplete intermediate representation until its NameEdits
// are installed. The caller owns applying them and proving that final names are
// byte-for-byte the source translation; The unexported stage is not a buildable translation and cannot be used by an external build caller.
type NPCSourcePlan struct {
	stage     Batch
	NameEdits []NPCNameEdit
}

const (
	npcExeBase    uint32 = 0x80040800
	npcFullStart         = 0x72c80
	npcFullPtrs          = 0x72d38
	npcShortStart        = 0x72d78
	npcShortPtrs         = 0x72df4
)

func sourceNPCRecord(retail []byte, file string, off int) (string, int, bool) {
	if file == "SLPM_86.053" {
		switch off {
		case 0x71980, 0x71988, 0x7199c, 0x719a4:
			return "direct-label", 0, true
		}
		for _, group := range [...]struct {
			start, table int
			kind         string
		}{
			{npcShortStart, npcShortPtrs, "short"},
			{npcFullStart, npcFullPtrs, "full"},
		} {
			if off < group.start || off >= group.table || len(retail) < group.table+64 {
				continue
			}
			for i := 0; i < 16; i++ {
				if binary.LittleEndian.Uint32(retail[group.table+4*i:]) == npcExeBase+uint32(off) {
					return group.kind, i, true
				}
			}
		}
	}
	if file == "CDROM/EXEDIR/GEKO.EXN" {
		switch off {
		case 0x12b1c:
			return "alias", 11, true
		case 0x12b24:
			return "honorific-alias", 11, true
		}
	}
	return "", 0, false
}

func sourceOriginalIsAuthentic(file []byte, offset int, japanese string) error {
	raw, err := script.EncodeOriginal(japanese)
	if err != nil {
		return err
	}
	if offset < 0 || offset+len(raw) >= len(file) || !bytes.Equal(file[offset:offset+len(raw)], raw) || file[offset+len(raw)] != 0 {
		return fmt.Errorf("source original and NUL mismatch at %#x", offset)
	}
	return nil
}

func namedEdit(file string, offset int, original, text, kind string, index int) (NPCNameEdit, error) {
	if text == "" || strings.TrimSpace(text) != text || strings.ContainsAny(text, "{}\n\r\t") {
		return NPCNameEdit{}, fmt.Errorf("invalid translated name at %#x", offset)
	}
	if _, err := (&script.PairEncoder{}).Encode(text); err != nil {
		return NPCNameEdit{}, err
	}
	return NPCNameEdit{File: file, Offset: offset, Original: original, Text: text, Kind: kind, Index: index}, nil
}

// PrepareNPCSource edits only authenticated name records from character_names.json.
// The unmodified planner remains responsible for every other record. This
// function is transactional and returns source values, never test substitutions
// or truncated temporary names. It does not write an EXE or disc.
func PrepareNPCSource(exe, geko []byte, batch Batch) (NPCSourcePlan, error) {
	if len(exe) != 667648 || len(geko) != 196608 {
		return NPCSourcePlan{}, fmt.Errorf("wrong original NPC source file dimensions")
	}
	if fmt.Sprintf("%x", sha256.Sum256(exe)) != "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae" ||
		fmt.Sprintf("%x", sha256.Sum256(geko)) != "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad" {
		return NPCSourcePlan{}, fmt.Errorf("unrecognized original NPC source images")
	}
	plan := NPCSourcePlan{stage: batch}
	plan.stage.Strings = make([]script.InPlaceString, 0, len(batch.Strings))
	plan.stage.Dialogue = make([]script.DialogueBlock, 0, len(batch.Dialogue))
	seen := make(map[string]string)
	add := func(v NPCNameEdit) error {
		key := fmt.Sprintf("%s:%d", v.Kind, v.Index)
		if previous, ok := seen[key]; ok && previous != v.Text {
			return fmt.Errorf("conflicting translated names for %s", key)
		}
		seen[key] = v.Text
		plan.NameEdits = append(plan.NameEdits, v)
		return nil
	}
	for _, s := range batch.Strings {
		kind, index, known := sourceNPCRecord(exe, s.File, s.Offset)
		if !known || s.Source != "character_names.json" {
			plan.stage.Strings = append(plan.stage.Strings, s)
			continue
		}
		original := exe
		if s.File == "CDROM/EXEDIR/GEKO.EXN" {
			original = geko
		}
		// Keep all records that fit exactly in the original slot on the
		// standard Go/Python planner path. Only true overflows are deferred.
		err := script.ApplyInPlaceString(bytes.Clone(original), s, &script.PairEncoder{})
		if err == nil {
			plan.stage.Strings = append(plan.stage.Strings, s)
			continue
		}
		if !strings.Contains(err.Error(), "English requires") {
			return NPCSourcePlan{}, fmt.Errorf("name-source preflight: %w", err)
		}
		if err := sourceOriginalIsAuthentic(original, s.Offset, s.Original); err != nil {
			return NPCSourcePlan{}, err
		}
		v, err := namedEdit(s.File, s.Offset, s.Original, s.Text, kind, index)
		if err != nil {
			return NPCSourcePlan{}, err
		}
		if err = add(v); err != nil {
			return NPCSourcePlan{}, err
		}
	}
	for _, b := range batch.Dialogue {
		if b.Source != "character_names.json" || b.File != "SLPM_86.053" || b.Base != npcExeBase || len(b.Lines) == 0 {
			plan.stage.Dialogue = append(plan.stage.Dialogue, b)
			continue
		}
		var blockNames []NPCNameEdit
		blockKind := ""
		indexes := map[int]bool{}
		eligible := true
		for _, line := range b.Lines {
			kind, index, ok := sourceNPCRecord(exe, b.File, line.Offset)
			if !ok || (kind != "short" && kind != "full") || line.Text == "" || (blockKind != "" && blockKind != kind) {
				eligible = false
				break
			}
			if indexes[index] {
				return NPCSourcePlan{}, fmt.Errorf("duplicate name index %d in a source block", index)
			}
			indexes[index] = true
			if err := sourceOriginalIsAuthentic(exe, line.Offset, line.Original); err != nil {
				return NPCSourcePlan{}, err
			}
			v, err := namedEdit(b.File, line.Offset, line.Original, line.Text, kind, index)
			if err != nil {
				return NPCSourcePlan{}, err
			}
			blockNames = append(blockNames, v)
			blockKind = kind
		}
		if !eligible {
			plan.stage.Dialogue = append(plan.stage.Dialogue, b)
			continue
		}
		for _, v := range blockNames {
			if err := add(v); err != nil {
				return NPCSourcePlan{}, err
			}
		}
	}
	return plan, nil
}
