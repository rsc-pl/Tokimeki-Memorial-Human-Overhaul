package fullenglish

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"tokimemo/internal/graphics"
	n "tokimemo/internal/n20arch"
	nametables "tokimemo/internal/namepatch"
	"tokimemo/internal/script"
)

func namePoolLayoutEnglishFixture(t *testing.T, original []byte) []byte {
	t.Helper()
	en, err := graphics.InstallRenderer(original)
	if err != nil {
		t.Fatal(err)
	}
	encoder := &script.PairEncoder{}
	fill := func(start, end, ptr int, names []string) {
		t.Helper()
		clear(en[start:end])
		pos := start
		for i, name := range names {
			raw, e := encoder.Encode(name)
			if e != nil {
				t.Fatal(e)
			}
			if pos+len(raw)+1 > end {
				t.Fatalf("source name pool overflow %d: %q", i, name)
			}
			copy(en[pos:], raw)
			en[pos+len(raw)] = 0
			binary.LittleEndian.PutUint32(en[ptr+4*i:], nametables.Base+uint32(pos))
			pos += len(raw) + 1
		}
	}
	abbreviated := make([]string, 16)
	for i, target := range imageCompositionFull {
		a := strings.Split(target, " ")
		if len(a) == 2 {
			abbreviated[i] = a[0] + " " + a[1][:1] + "."
		} else {
			abbreviated[i] = target
		}
	}
	fill(namePoolLayoutFullPoolStart, namePoolLayoutFullPointer, namePoolLayoutFullPointer, abbreviated)
	fill(namePoolLayoutShortPoolStart, namePoolLayoutShortPointer, namePoolLayoutShortPointer, imageCompositionCurrent)
	return en
}

func TestLiveEnglishNamePoolAuthAndMerge(t *testing.T) {
	orig, overlays := imageCompositionTestFiles(t)
	english := namePoolLayoutEnglishFixture(t, orig)
	if e := namePoolLayoutConfirmNameOwnership(orig, english, imageCompositionCurrent, imageCompositionFull); e != nil {
		t.Fatal(e)
	}
	for _, policy := range []string{nametables.N10GEKOBare, nametables.N10GEKOSan} {
		t.Run(policy, func(t *testing.T) {
			tx, e := imageCompositionInput(orig, overlays, policy)
			if e != nil {
				t.Fatal(e)
			}
			manualCopyStage, e := n.PlanAllManualLoopsOffline(orig, overlays, tx)
			if e != nil {
				t.Fatal(e)
			}
			start := int(n.ShortHookSpareRAM - n.Base)
			end := start + n.ShortHookSpareBytes + 308
			_, oldClashes, _, oldErr := fullMergeEXEOwned(orig, english, manualCopyStage.EnglishRendererEXE, manualCopyStage.EnglishRendererEXE, start, end)
			if oldErr != nil || oldClashes == 0 {
				t.Fatalf("expected pool ownership intentional name conflict oldErr=%v count=%d", oldErr, oldClashes)
			}
			combined, clashes, examples, e := fullMergeN10Names(orig, english, manualCopyStage.EnglishRendererEXE, manualCopyStage.EnglishRendererEXE, start, end, imageCompositionCurrent, imageCompositionFull)
			if e != nil || clashes != 0 || len(examples) != 0 {
				t.Fatalf("source names merge error=%v conflicts=%d first=%v", e, clashes, examples)
			}
			if !bytes.Equal(combined, manualCopyStage.EnglishRendererEXE) {
				t.Fatal("N10 physical EXE altered by English merge")
			}
			// Even byte-identical unrelated code ownership remains exclusive;
			// source names is not a generic "same result means no conflict" policy.
			sameOther := bytes.Clone(english)
			found := false
			for at := 0; at < len(orig); at++ {
				if at >= namePoolLayoutFullPoolStart && at < namePoolLayoutShortPointerEnd {
					continue
				}
				if at >= start && at < end {
					continue
				}
				if manualCopyStage.EnglishRendererEXE[at] != orig[at] && english[at] == orig[at] {
					sameOther[at] = manualCopyStage.EnglishRendererEXE[at]
					found = true
					break
				}
			}
			if !found {
				t.Fatal("expected unrelated N20 code edit")
			}
			_, nconf, _, errSame := fullMergeN10Names(orig, sameOther, manualCopyStage.EnglishRendererEXE, manualCopyStage.EnglishRendererEXE, start, end, imageCompositionCurrent, imageCompositionFull)
			if errSame == nil && nconf == 0 {
				t.Fatal("source names improperly waived unrelated shared code byte")
			}
			// Unrelated translated code is never released from pool ownership's strict
			// ownership checks; equal common edits outside names still fail.
			broken := bytes.Clone(english)
			broken[0x72f50] = 0x64
			if broken[0x72f50] == orig[0x72f50] {
				broken[0x72f50] ^= 0x01
			}
			_, nc, _, e := fullMergeN10Names(orig, broken, manualCopyStage.EnglishRendererEXE, manualCopyStage.EnglishRendererEXE, start, end, imageCompositionCurrent, imageCompositionFull)
			if e != nil || nc != 0 { // independently translated byte is preserved
				t.Fatalf("unrelated EN edit blocked: %v %d", e, nc)
			}
		})
	}
	mutated := bytes.Clone(english)
	mutated[namePoolLayoutFullPoolStart] = 'A' | 0x80
	if e := namePoolLayoutConfirmNameOwnership(orig, mutated, imageCompositionCurrent, imageCompositionFull); e == nil {
		t.Fatal("N10 silently overwrites nonmatching live full name")
	}
	badShort := append([]string(nil), imageCompositionCurrent...)
	badShort[8] = "Yuuko"
	if e := namePoolLayoutConfirmNameOwnership(orig, english, badShort, imageCompositionFull); e == nil {
		t.Fatal("N10 silently overwrites current short name variation")
	}
}
