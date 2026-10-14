package script

import (
	"bytes"
	"fmt"
)

// InPlaceString implements the original PS1 patcher's fixed-slot and aligned
// strings behavior. Unlike dialogue blocks these locations cannot relocate.
type InPlaceString struct {
	File     string `json:"file"`
	Source   string `json:"source"`
	Offset   int    `json:"offset"`
	Original string `json:"original"`
	Text     string `json:"text"`
	Encoding string `json:"encoding"`
	Slot     *int   `json:"slot,omitempty"`
}
type BytesPatch struct {
	File        string `json:"file"`
	Source      string `json:"source"`
	Offset      int    `json:"offset"`
	Original    []byte `json:"original"`
	Replacement []byte `json:"replacement"`
}

func ApplyInPlaceString(data []byte, p InPlaceString, pairs *PairEncoder) error {
	where := fmt.Sprintf("%s: %s @ %#x", p.Source, p.File, p.Offset)
	raw, e := EncodeOriginal(p.Original)
	if e != nil {
		return fmt.Errorf("%s: %w", where, e)
	}
	end := p.Offset + len(raw)
	if p.Offset < 0 || end < 0 || end >= len(data) {
		return fmt.Errorf("%s: original string outside file", where)
	}
	if !bytes.Equal(data[p.Offset:end], raw) || data[end] != 0 {
		return fmt.Errorf("%s: expected original bytes and NUL terminator", where)
	}
	cap := len(raw) + 1
	if p.Slot != nil {
		if *p.Slot < 2 || cap > *p.Slot || p.Offset+*p.Slot > len(data) {
			return fmt.Errorf("%s: invalid fixed slot", where)
		}
		for _, b := range data[end : p.Offset+*p.Slot] {
			if b != 0 {
				return fmt.Errorf("%s: nonzero bytes in fixed slot", where)
			}
		}
		cap = *p.Slot
	} else {
		for (p.Offset+cap)%4 != 0 && p.Offset+cap < len(data) && data[p.Offset+cap] == 0 {
			cap++
		}
	}
	var encoded []byte
	switch p.Encoding {
	case "", "pairs":
		encoded, _, e = EncodeEnglish(p.Text, pairs)
	case "fullwidth":
		encoded, e = EncodeFullwidth(p.Text)
	default:
		return fmt.Errorf("%s: unknown encoding %q", where, p.Encoding)
	}
	if e != nil {
		return fmt.Errorf("%s: English: %w", where, e)
	}
	if len(encoded)+1 > cap {
		return fmt.Errorf("%s: English requires %d bytes but slot is %d bytes", where, len(encoded)+1, cap)
	}
	clear(data[p.Offset : p.Offset+cap])
	copy(data[p.Offset:], encoded)
	return nil
}

func ApplyBytesPatch(data []byte, p BytesPatch) error {
	where := fmt.Sprintf("%s: %s @ %#x", p.Source, p.File, p.Offset)
	if len(p.Original) != len(p.Replacement) {
		return fmt.Errorf("%s: byte patch changes length", where)
	}
	if p.Offset < 0 || p.Offset > len(data) || len(p.Original) > len(data)-p.Offset {
		return fmt.Errorf("%s: byte patch outside file", where)
	}
	if !bytes.Equal(data[p.Offset:p.Offset+len(p.Original)], p.Original) {
		return fmt.Errorf("%s: expected original bytes differ", where)
	}
	copy(data[p.Offset:], p.Replacement)
	return nil
}

// ApplyTextEdits is an atomic partial in-memory planner. The production plan
// also applies PNGs and renderer hooks, so no disc writer may assume this is
// the complete build. The input order matches patcher.py: strings, then bytes,
// then dialogue (the caller must apply image patches in between when needed).
func ApplyTextEdits(pristine, working []byte, strings []InPlaceString, bytesPatches []BytesPatch, blocks []DialogueBlock) ([]PlanStats, error) {
	if len(pristine) != len(working) {
		return nil, fmt.Errorf("mismatched pristine/working lengths")
	}
	scratch := append([]byte(nil), working...)
	pairs := &PairEncoder{}
	for _, s := range strings {
		if e := ApplyInPlaceString(scratch, s, pairs); e != nil {
			return nil, e
		}
	}
	for _, p := range bytesPatches {
		if e := ApplyBytesPatch(scratch, p); e != nil {
			return nil, e
		}
	}
	var stats []PlanStats
	for _, b := range blocks {
		result, e := ApplyDialogue(pristine, scratch, b, pairs)
		if e != nil {
			return nil, e
		}
		stats = append(stats, result)
	}
	copy(working, scratch)
	return stats, nil
}
