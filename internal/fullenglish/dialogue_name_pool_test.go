package fullenglish

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	n "tokimemo/internal/n20arch"
	nametables "tokimemo/internal/namepatch"
	"tokimemo/internal/patchplan"
	"tokimemo/internal/script"
)

// These are original authenticated retail strings, in retail pointer order.
// The surname targets reproduce exactly the owner's 132-needed/124-available
// geometry, without requiring or inventing any locally provided translation corpus.
func npcDialogueNamesRetailShortNames() []string {
	return []string{"藤崎", "如月", "紐緒", "片桐", "虹野", "古式", "清川", "鏡", "朝日奈", "美樹原", "早乙女", "館林", "伊集院", "好雄", "外井", "優美"}
}

func TestActualShortPoolOverflow132Over124AndRelocation(t *testing.T) {
	original, overlays := imageCompositionTestFiles(t)
	edited := patchplan.Batch{Dialogue: []script.DialogueBlock{{
		Source: "character_names.json", File: "SLPM_86.053", Base: nametables.Base,
	}}}
	for ix, jp := range npcDialogueNamesRetailShortNames() {
		ptr := binary.LittleEndian.Uint32(original[namePoolLayoutShortPointer+ix*4:])
		at := int(ptr - nametables.Base)
		edited.Dialogue[0].Lines = append(edited.Dialogue[0].Lines, script.DialogueLine{
			Offset: at, Original: jp, Text: imageCompositionShort[ix],
		})
	}
	if len(edited.Dialogue[0].Lines) != 16 {
		t.Fatal("incomplete source pool")
	}
	// This reproduces the exact observable production failure on the true
	// 124-byte Japanese short pool, not a synthetic 124-byte array.
	_, err := script.ApplyDialogue(original, bytes.Clone(original), edited.Dialogue[0], &script.PairEncoder{})
	if err == nil || !strings.Contains(err.Error(), "132 needed, 124 available") {
		t.Fatalf("expected original 132/124 failure, got %v", err)
	}
	clean, deferred, err := npcDialogueNamesSeparateNPCNameDialogue(original, edited)
	if err != nil || len(clean.Dialogue) != 0 || len(deferred) != 16 {
		t.Fatalf("source pool bridge: %v, blocks=%d deferred=%d", err, len(clean.Dialogue), len(deferred))
	}
	// A full-English baseline's full-name pool is provided as actual data;
	// short names remain retail JP until the dialogue name pool stage fills safe old slots.
	staged := bytes.Clone(original)
	baseline := namePoolLayoutEnglishFixture(t, original)
	copy(staged[namePoolLayoutFullPoolStart:namePoolLayoutShortPoolStart], baseline[namePoolLayoutFullPoolStart:namePoolLayoutShortPoolStart])
	if err := longNameApplyNameStage(staged, deferred); err != nil {
		t.Fatal(err)
	}
	stageShort, _, targetShort, targetFull, err := longNameSourceNames(original, staged, deferred)
	if err != nil {
		t.Fatal(err)
	}
	for i, s := range imageCompositionShort {
		if targetShort[i] != s {
			t.Fatalf("target %d: %q != %q", i, targetShort[i], s)
		}
	}
	for _, policy := range []string{nametables.N10GEKOBare, nametables.N10GEKOSan} {
		input, e := longNameInput(original, overlays, policy, stageShort, targetShort, targetFull)
		if e != nil {
			t.Fatal(e)
		}
		out, e := n.PlanAllManualLoopsOffline(original, overlays, input)
		if e != nil {
			t.Fatalf("%s: %v", policy, e)
		}
		if out.SafeToPatch || out.RuntimePass || out.ImageBuilt {
			t.Fatal("offline proof incorrectly promoted to release")
		}
		for ix, expected := range targetShort {
			ptr := binary.LittleEndian.Uint32(out.EnglishRendererEXE[nametables.PointerTable+ix*4:])
			offset := int(ptr - nametables.Base)
			encoded, e := (&script.PairEncoder{}).Encode(expected)
			if e != nil || !bytes.Equal(out.EnglishRendererEXE[offset:offset+len(encoded)], encoded) || out.EnglishRendererEXE[offset+len(encoded)] != 0 {
				t.Fatalf("%s name %d not verbatim", policy, ix)
			}
		}
	}
}

func TestUnknownDialogueNeverBypassesProductionPlanner(t *testing.T) {
	original, _ := imageCompositionTestFiles(t)
	cases := []script.DialogueBlock{
		{Source: "unrelated.json", File: "SLPM_86.053", Base: nametables.Base, Lines: []script.DialogueLine{{Offset: 0x72d78, Original: "藤崎", Text: "Fujisaki"}}},
		{Source: "character_names.json", File: "SLPM_86.053", Base: nametables.Base, Lines: []script.DialogueLine{{Offset: 0x72d78, Original: "藤崎", Text: "Fujisaki"}, {Offset: 0x71980, Original: "藤崎", Text: "Fujisaki"}}},
		{Source: "character_names.json", File: "SLPM_86.053", Base: 0, Lines: []script.DialogueLine{{Offset: 0x72d78, Original: "藤崎", Text: "Fujisaki"}}},
	}
	for _, b := range cases {
		clean, def, err := npcDialogueNamesSeparateNPCNameDialogue(original, patchplan.Batch{Dialogue: []script.DialogueBlock{b}})
		if err != nil || len(def) != 0 || len(clean.Dialogue) != 1 {
			t.Fatalf("unauthorized exemption %s/%x: %v", b.Source, b.Base, err)
		}
	}
	bad := patchplan.Batch{Dialogue: []script.DialogueBlock{{Source: "character_names.json", File: "SLPM_86.053", Base: nametables.Base, Lines: []script.DialogueLine{{Offset: 0x72d78, Original: "WRONG", Text: "Fujisaki"}}}}}
	if _, _, err := npcDialogueNamesSeparateNPCNameDialogue(original, bad); err == nil {
		t.Fatal("untrusted retail preimage accepted")
	}
}
