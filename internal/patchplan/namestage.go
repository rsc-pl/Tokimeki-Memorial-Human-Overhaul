package patchplan

// Source-authored names that exceed original fixed slots are staged in the
// original English name pools, then consumed by the existing pointer-relocating
// composer. This is the pre-packing stage, not a new name relocation algorithm.
// The temporary prefixes must never be published to a disc.
import (
	"bytes"
	"fmt"
	"strings"
	"tokimemo/internal/script"
)

// NameSource is read from the current translation, not from engineering test
// fixtures or a runtime name substitution table.
type NameSource struct {
	StageShort  []string
	StageFull   []string
	TargetShort []string
	TargetFull  []string
}

func namePrefix(text string, capacity int) (string, error) {
	if text == "" || strings.TrimSpace(text) != text || strings.ContainsAny(text, "{}\n\r\t") {
		return "", fmt.Errorf("invalid translated name %q", text)
	}
	if _, err := (&script.PairEncoder{}).Encode(text); err != nil {
		return "", err
	}
	for n := len(text); n >= 2; n-- {
		prefix := text[:n]
		if strings.HasSuffix(prefix, " ") {
			continue
		}
		raw, err := (&script.PairEncoder{}).Encode(prefix)
		if err == nil && len(raw)+1 <= capacity {
			return prefix, nil
		}
	}
	return "", fmt.Errorf("cannot fit temporary source-name prefix into %d bytes", capacity)
}

func (p NPCSourcePlan) applyDeferredNamePrefixes(english []byte) error {
	for _, edit := range p.NameEdits {
		if edit.Kind != "short" && edit.Kind != "full" {
			continue
		}
		raw, err := script.EncodeOriginal(edit.Original)
		if err != nil {
			return err
		}
		cap := len(raw) + 1
		for (edit.Offset+cap)%4 != 0 && edit.Offset+cap < len(english) && english[edit.Offset+cap] == 0 {
			cap++
		}
		if edit.Offset < 0 || edit.Offset+cap > len(english) || !bytes.Equal(english[edit.Offset:edit.Offset+len(raw)], raw) || english[edit.Offset+len(raw)] != 0 {
			return fmt.Errorf("name-source stage preimage changed at %#x", edit.Offset)
		}
		prefix, err := namePrefix(edit.Text, cap)
		if err != nil {
			return err
		}
		encoded, err := (&script.PairEncoder{}).Encode(prefix)
		if err != nil {
			return err
		}
		clear(english[edit.Offset : edit.Offset+cap])
		copy(english[edit.Offset:], encoded)
	}
	return nil
}

func readLiveStageNames(retail, english []byte) (NameSource, error) {
	sh, err := readNameSlots(english, retail, nameShortPointers, nameShortStart, nameShortPointers)
	if err != nil {
		return NameSource{}, err
	}
	fu, err := readNameSlots(english, retail, nameFullPointers, nameFullStart, nameFullPointers)
	if err != nil {
		return NameSource{}, err
	}
	v := NameSource{StageShort: make([]string, 16), StageFull: make([]string, 16), TargetShort: make([]string, 16), TargetFull: make([]string, 16)}
	for i := 0; i < 16; i++ {
		v.StageShort[i] = sh[i].value
		v.StageFull[i] = fu[i].value
		v.TargetShort[i] = sh[i].value
		v.TargetFull[i] = fu[i].value
	}
	if err := confirmNameOwnership(retail, english, v.StageShort, v.StageFull); err != nil {
		return NameSource{}, err
	}
	return v, nil
}

// PrepareEnglishWithNames preserves the complete ordinary translation plan and
// stages exactly the authenticated too-long source fields before relocation.
// The result MUST be passed into the physical name-composition stage and must
// not be sent directly to a sector writer. No file or source is modified.
func (p NPCSourcePlan) PrepareEnglishWithNames(source Reader) (Result, map[string][]byte, NameSource, error) {
	var zero Result
	if source == nil {
		return zero, nil, NameSource{}, fmt.Errorf("missing retail source")
	}
	retail, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return zero, nil, NameSource{}, err
	}
	result, english, err := PlanBytes(source, p.stage)
	if err != nil {
		return zero, nil, NameSource{}, err
	}
	exe, ok := english["SLPM_86.053"]
	if !ok {
		return zero, nil, NameSource{}, fmt.Errorf("translation stage lacks executable")
	}
	if err = p.applyDeferredNamePrefixes(exe); err != nil {
		return zero, nil, NameSource{}, err
	}
	names, err := readLiveStageNames(retail, exe)
	if err != nil {
		return zero, nil, NameSource{}, err
	}
	explicit := map[int]string{}
	var nameSan string
	for _, item := range p.NameEdits {
		i := item.Index
		if i < 0 || i >= 16 {
			return zero, nil, NameSource{}, fmt.Errorf("invalid name index")
		}
		if item.Kind == "short" || item.Kind == "direct-label" || item.Kind == "alias" {
			if old, ok := explicit[i]; ok && old != item.Text {
				return zero, nil, NameSource{}, fmt.Errorf("conflicting translated names for index %d", i)
			}
			explicit[i] = item.Text
		}
	}
	for _, item := range p.NameEdits {
		switch item.Kind {
		case "short", "direct-label", "alias":
			if item.Kind != "short" && names.TargetShort[item.Index] != names.StageShort[item.Index] && names.TargetShort[item.Index] != item.Text {
				return zero, nil, NameSource{}, fmt.Errorf("name alias conflicts with source %d", item.Index)
			}
			names.TargetShort[item.Index] = item.Text
		case "full":
			names.TargetFull[item.Index] = item.Text
		case "honorific-alias":
			nameSan = item.Text
		default:
			return zero, nil, NameSource{}, fmt.Errorf("unknown deferred name kind")
		}
	}
	if nameSan != "" && nameSan != names.TargetShort[11]+"-san" {
		return zero, nil, NameSource{}, fmt.Errorf("honorific alias conflicts with source name")
	}
	for i := 0; i < 16; i++ {
		if names.TargetShort[i] == "" || names.TargetFull[i] == "" || !expandedAbbreviation(names.StageFull[i], names.TargetFull[i]) {
			return zero, nil, NameSource{}, fmt.Errorf("invalid source-name extension %d", i)
		}
	}
	for i := range result.Files {
		if result.Files[i].Path == "SLPM_86.053" {
			result.Files[i].PatchedSHA256 = sha(exe)
			count := 0
			for j := range exe {
				if exe[j] != retail[j] {
					count++
				}
			}
			result.Files[i].ChangedBytes = count
		}
	}
	return result, english, names, nil
}
