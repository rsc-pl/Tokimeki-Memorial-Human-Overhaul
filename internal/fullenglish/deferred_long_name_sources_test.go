package fullenglish

import (
	"bytes"
	"encoding/binary"
	"testing"
	n "tokimemo/internal/n20arch"
	nametables "tokimemo/internal/namepatch"
	"tokimemo/internal/patchplan"
	"tokimemo/internal/script"
)

func TestAuthenticatedOverlengthNameSourceDeferrals(t *testing.T) {
	orig, ov := imageCompositionTestFiles(t)
	batch := patchplan.Batch{Strings: []script.InPlaceString{
		{File: "SLPM_86.053", Source: "character_names.json", Offset: 0x71980, Original: "藤崎", Text: "Fujisaki"},
		{File: "SLPM_86.053", Source: "character_names.json", Offset: 0x72da0, Original: "古式", Text: "Koshiki"},
		{File: "SLPM_86.053", Source: "character_names.json", Offset: 0x72c80, Original: "藤崎詩織", Text: "Fujisaki Shiori"},
		{File: "SLPM_86.053", Source: "character_names.json", Offset: 0x71988, Original: "藤崎", Text: "Fujisaki"},
	}}
	cleaned, deferred, err := longNameSeparateLongNames(orig, ov["GEKO.EXN"], batch)
	if err != nil {
		t.Fatal(err)
	}
	if len(cleaned.Strings) != 0 || len(deferred) != 4 {
		t.Fatalf("expected four deferred source names, got %d original %d", len(deferred), len(cleaned.Strings))
	}
	if deferred[0].kind != "fujisaki" || deferred[1].kind != "short" || deferred[1].index != 5 || deferred[2].kind != "full" || deferred[2].index != 0 {
		t.Fatalf("wrong owner mappings: %+v", deferred)
	}
	staged := bytes.Clone(orig)
	if err := longNameApplyNameStage(staged, deferred); err != nil {
		t.Fatal(err)
	}
	// The special literal was not truncated or modified. It is handled by its
	// separately authenticated N10 address-rewrite, never a dropped overflow.
	if !bytes.Equal(staged[0x71980:0x71988], orig[0x71980:0x71988]) {
		t.Fatal("fixed Fujisaki bytes were overwritten")
	}
	for _, d := range deferred {
		if d.kind == "short" || d.kind == "full" {
			raw, e := (&script.PairEncoder{}).Encode(d.placeholder)
			if e != nil || !bytes.Equal(staged[d.entry.Offset:d.entry.Offset+len(raw)], raw) {
				t.Fatalf("invalid staged %s", d.kind)
			}
		}
	}
	// All input translation edits must remain untouched and source-authoritative.
	if batch.Strings[0].Text != "Fujisaki" || batch.Strings[2].Text != "Fujisaki Shiori" {
		t.Fatal("translation was rewritten")
	}
}

func TestRejectsUnknownAndConflictingNameSource(t *testing.T) {
	ex, ov := imageCompositionTestFiles(t)
	invalid := patchplan.Batch{Strings: []script.InPlaceString{{File: "SLPM_86.053", Source: "character_names.json", Offset: 0x71980, Original: "藤崎", Text: "Fujisaki"}, {File: "SLPM_86.053", Source: "character_names.json", Offset: 0x71988, Original: "藤崎", Text: "Kisaragi"}}}
	_, def, e := longNameSeparateLongNames(ex, ov["GEKO.EXN"], invalid)
	if e == nil {
		t.Fatal("conflicting Fujisaki source labels approved")
	}
	if len(def) != 0 {
		t.Fatal("partial deferred edits escaped")
	}
	invalid.Strings = invalid.Strings[:1]
	invalid.Strings[0].Original = "wrong Japanese source"
	_, _, e = longNameSeparateLongNames(ex, ov["GEKO.EXN"], invalid)
	if e == nil {
		t.Fatal("wrong Japanese original source accepted")
	}
	invalid.Strings = []script.InPlaceString{{File: "SLPM_86.053", Source: "character_names.json", Offset: 0x71984, Original: "", Text: "Fujisaki"}}
	clean, def, e := longNameSeparateLongNames(ex, ov["GEKO.EXN"], invalid)
	if e != nil || len(def) != 0 || len(clean.Strings) != 1 {
		t.Fatalf("unknown offset must remain under normal strict planner: %v", e)
	}
}

func TestN10LongSourceNamesRemainVerbatimInBothPolicies(t *testing.T) {
	ex, ov := imageCompositionTestFiles(t)
	english := namePoolLayoutEnglishFixture(t, ex)
	stageShort, stageFull, e := ownerEnglishSourceNames(ex, english)
	if e != nil {
		t.Fatal(e)
	}
	desired := append([]string(nil), stageShort...)
	desired[0] = "Fujisaki"
	desired[1] = "Kisaragi"
	desired[5] = "Koshiki"
	desired[11] = "Tatebayashi"
	for _, policy := range []string{nametables.N10GEKOBare, nametables.N10GEKOSan} {
		tx, e := longNameInput(ex, ov, policy, stageShort, desired, stageFull)
		if e != nil {
			t.Fatal(e)
		}
		got, e := n.PlanAllManualLoopsOffline(ex, ov, tx)
		if e != nil {
			t.Fatalf("%s: %v", policy, e)
		}
		for _, ix := range []int{0, 1, 5, 11} {
			p := binary.LittleEndian.Uint32(got.EnglishRendererEXE[nametables.PointerTable+4*ix:])
			at := int(p - nametables.Base)
			b, e := (&script.PairEncoder{}).Encode(desired[ix])
			if e != nil || !bytes.Equal(got.EnglishRendererEXE[at:at+len(b)], b) || got.EnglishRendererEXE[at+len(b)] != 0 {
				t.Fatalf("policy %s name %d not present verbatim", policy, ix)
			}
		}
		start := int(n.ShortHookSpareRAM - n.Base)
		_, clashes, _, e := fullMergeN10Names(ex, english, got.EnglishRendererEXE, got.EnglishRendererEXE, start, start+132+308, stageShort, stageFull)
		if e != nil || clashes != 0 {
			t.Fatalf("policy %s conflicts %d: %v", policy, clashes, e)
		}
	}
}
