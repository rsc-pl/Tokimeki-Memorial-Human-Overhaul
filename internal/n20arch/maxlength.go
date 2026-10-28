package n20arch

// N20 maximum romaji output length and consumer-redirection audit (offline).
//
// This file answers three questions from the authenticated bytes, not from a
// host estimate:
//
//  1. What is the longest ASCII romanization the rebuilt N20 packed core can
//     emit for a NAME_ENT name of at most three kana? The answer is derived
//     from the actual rebuilt table (72 simple records, 67 digraph records)
//     and the actual packing rules (single, digraph, sokuon, long mark, wave
//     dash, suffix none for a3=3).
//  2. What wire form does that output take (high-bit ASCII, one odd-length
//     high-bit pad, NUL), and how many bytes would an exact / padded / aligned
//     working slot need?
//  3. Which authenticated instructions consume the two shared working fields,
//     and can any of them be redirected to independently owned storage without
//     touching 0x800CA17C/0x800CA188/0x800CA190?
//
// The consumer trace is a static decode of the original EXE and all 26
// original overlays. It is not a runtime trace and does not promote any row.
// safe_to_patch remains false; nothing here writes an image, RAM or save.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"

	pn "tokimemo/internal/playername"
)

const (
	// N20MaxRomanBytes is the proven maximum ASCII length for a three-kana
	// NAME_ENT name under the rebuilt table. It is reached by three 3-byte
	// simple records (shi, chi, tsu).
	N20MaxRomanBytes = 9
	// N20MaxExactSlotBytes includes the NUL but not the odd-length pad.
	N20MaxExactSlotBytes = N20MaxRomanBytes + 1
	// N20MaxPaddedSlotBytes includes the high-bit pad and the NUL.
	N20MaxPaddedSlotBytes = N20MaxRomanBytes + 1 + 1
	// N20MaxAlignedSlotBytes is the padded slot rounded up to 4 bytes.
	N20MaxAlignedSlotBytes = (N20MaxPaddedSlotBytes + 3) &^ 3
	// The shim accepts v0 < 8, i.e. at most six roman bytes (even) or five
	// roman bytes (odd plus pad) before the NUL; seven wire bytes including NUL.
	N20MaxAcceptedRomanBytes = 6
	N20MaxAcceptedWireBytes  = 7
)

// N20MaxComposition is one kana-token composition and its analytic upper bound.
type N20MaxComposition struct {
	Shape    string `json:"shape"`
	Kana     int    `json:"kana_consumed"`
	MaxBytes int    `json:"max_roman_bytes"`
	Note     string `json:"note"`
}

// N20MaxWitness is one constructive boundary name.
type N20MaxWitness struct {
	Kind       string `json:"kind"`
	Kana       string `json:"kana"`
	Roman      string `json:"roman"`
	RomanBytes int    `json:"roman_bytes"`
	WireBytes  int    `json:"wire_bytes_before_nul"`
	V0         int    `json:"v0_including_nul"`
	SlotBytes  int    `json:"slot_bytes_including_nul"`
	FitsSlot   bool   `json:"fits_current_8_byte_slot"`
	GridKana   bool   `json:"every_kana_is_name_ent_selectable"`
	Katakana   bool   `json:"katakana_variant_via_normalisation"`
}

// N20FieldRef is one authenticated instruction that materialises, reads,
// writes or passes one of the two shared working fields.
type N20FieldRef struct {
	PC        uint32 `json:"pc"`
	Word      uint32 `json:"word"`
	Field     string `json:"field"`
	Kind      string `json:"kind"` // address, read, write, call, use
	Op        string `json:"op"`
	Semantics string `json:"semantics"`
	Buffer    string `json:"buffer,omitempty"`
	Capacity  int    `json:"capacity_bytes,omitempty"`
	Owner     string `json:"owner"` // EXE or overlay name
	FileOff   int    `json:"file_off,omitempty"`
}

// N20OverlayRefScan is the base-resolved overlay reference summary. Raw
// immediate matches include harmless constants whose LUI base is 0x8014/0x8015/
// 0x8019 and therefore resolve to overlay-local data, not the EXE fields.
type N20OverlayRefScan struct {
	Overlays               int `json:"overlays"`
	RawFamilyImmediates    int `json:"raw_family_immediates"`
	RawGivenImmediates     int `json:"raw_given_immediates"`
	FamilyRefs             int `json:"resolved_family_refs"`
	GivenRefs              int `json:"resolved_given_refs"`
	FalsePositives         int `json:"resolved_local_false_positives"`
	Unresolved             int `json:"unresolved_immediates"`
	PointerLiteralsFamily  int `json:"pointer_literals_family"`
	PointerLiteralsGiven   int `json:"pointer_literals_given"`
	PointerLiteralsBlocked int `json:"pointer_literals_blocked"`
	RendererJALs           int `json:"overlay_jals_to_renderer"`
	FormatterEntryJALs     int `json:"overlay_jals_to_formatter_entry"`
	FieldPrepJALs          int `json:"overlay_jals_to_fieldprep"`
}

// N20BufferLifetime is one downstream buffer and its byte budget.
type N20BufferLifetime struct {
	Consumer              string `json:"consumer"`
	Site                  string `json:"site"`
	Buffer                string `json:"buffer"`
	Capacity              int    `json:"capacity_bytes"`
	Required              int    `json:"required_bytes_for_9b_pair"`
	Fits                  bool   `json:"fits"`
	Lifetime              string `json:"lifetime"`
	WritableFromFieldPrep bool   `json:"writable_from_fieldprep"`
	Note                  string `json:"note"`
}

// N20RedirectCandidate is one candidate redirection target.
type N20RedirectCandidate struct {
	Candidate       string `json:"candidate"`
	OwnedLifetime   bool   `json:"owned_lifetime"`
	OverlayConsumer bool   `json:"consumed_by_overlay_owned_callsite"`
	LifecycleSafe   bool   `json:"lifecycle_safe_across_gap"`
	AdjacentSafe    bool   `json:"adjacent_fields_preserved"`
	Viable          bool   `json:"viable"`
	Reason          string `json:"reason"`
}

// N20MaxLengthAudit is the complete maximum-length and redirection verdict.
type N20MaxLengthAudit struct {
	Schema      int  `json:"schema"`
	SafeToPatch bool `json:"safe_to_patch"`
	RuntimePass bool `json:"runtime_pass"`

	SimpleEntries      int                 `json:"simple_entries"`
	DigraphEntries     int                 `json:"digraph_entries"`
	SecondsEntries     int                 `json:"seconds_entries"`
	AlphabetEntries    int                 `json:"alphabet_entries"`
	TableBytes         int                 `json:"table_bytes"`
	TableSHA           string              `json:"table_sha256"`
	SimpleMaxBytes     int                 `json:"simple_max_roman_bytes"`
	SimpleMaxKana      []string            `json:"simple_max_kana"`
	DigraphMaxBytes    int                 `json:"digraph_max_roman_bytes"`
	DigraphMaxCount    int                 `json:"digraph_max_records"`
	Compositions       []N20MaxComposition `json:"compositions"`
	MaxRomanBytes      int                 `json:"max_roman_bytes"`
	MaxComposition     string              `json:"max_composition"`
	ExactSlotBytes     int                 `json:"exact_slot_bytes_including_nul"`
	PaddedSlotBytes    int                 `json:"padded_slot_bytes_including_nul"`
	AlignedSlotBytes   int                 `json:"aligned_slot_bytes"`
	AcceptedRomanBytes int                 `json:"max_accepted_roman_bytes"`
	AcceptedWireBytes  int                 `json:"max_accepted_wire_bytes_including_nul"`
	MaxV0              int                 `json:"max_v0_including_nul"`
	CurrentSlotBytes   int                 `json:"current_slot_bytes_including_nul"`
	Witnesses          []N20MaxWitness     `json:"witnesses"`

	FieldRefs         []N20FieldRef       `json:"field_refs"`
	FamilyAddressRefs int                 `json:"exe_family_address_refs"`
	GivenAddressRefs  int                 `json:"exe_given_address_refs"`
	Overlay           N20OverlayRefScan   `json:"overlay_refs"`
	Buffers           []N20BufferLifetime `json:"buffers"`

	FamilyEnd11        uint32 `json:"family_end_if_11_bytes"`
	GivenStart         uint32 `json:"given_start"`
	GivenEnd11         uint32 `json:"given_end_if_11_bytes"`
	BlockedStart       uint32 `json:"blocked_family_start"`
	FamilyOverlapBytes int    `json:"family_11b_overlap_into_given"`
	GivenOverlapBytes  int    `json:"given_11b_overlap_into_blocked"`
	FamilyOverlap12    int    `json:"family_12b_overlap_into_given"`
	GivenOverlap12     int    `json:"given_12b_overlap_into_blocked"`

	Candidates  []N20RedirectCandidate `json:"candidates"`
	Verdict     string                 `json:"verdict"`
	Requirement string                 `json:"requirement"`
	Reason      string                 `json:"reason"`
}

func n20KanaOfCode(c uint16, tag string) (string, error) {
	s, err := pn.DecodeCP932Kana([]byte{byte(c >> 8), byte(c)})
	if err != nil {
		return "", fmt.Errorf("%s code %04x: %w", tag, c, err)
	}
	return s, nil
}

func n20KataString(s string) string {
	out := make([]rune, 0, len([]rune(s)))
	for _, r := range s {
		out = append(out, n20Kata(r))
	}
	return string(out)
}

func n20FindSimpleLatin(tab N20PackedTable, latin string) (string, bool) {
	for _, e := range tab.Simple {
		if e.latin == latin {
			s, err := n20KanaOfCode(e.code, "simple")
			if err != nil {
				return "", false
			}
			return s, true
		}
	}
	return "", false
}

func n20FindDigraphLatin(tab N20PackedTable, latin string) (string, bool) {
	for _, e := range tab.Digraph {
		if e.latin == latin {
			a, err1 := n20KanaOfCode(e.first, "digraph first")
			b, err2 := n20KanaOfCode(e.second, "digraph second")
			if err1 != nil || err2 != nil {
				return "", false
			}
			return a + b, true
		}
	}
	return "", false
}

func n20GridSet(nameEnt []byte) (map[string]bool, error) {
	if len(nameEnt) != 196608 || sha(nameEnt) != OverlaySHA["NAME_ENT.EXN"] {
		return nil, fmt.Errorf("NAME_ENT.EXN is not the authenticated original")
	}
	rows, err := pn.ParseNameEntryKeyboardRows(nameEnt)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, r := range rows {
		for _, c := range r.Cells {
			seen[c.Kana] = true
		}
	}
	return seen, nil
}

// n20TableRomanBytes models the rebuilt parser only to sum table record
// lengths. It is not used as the max proof: the max proof scans the table and
// composes token upper bounds. The MIPS test is the executable check.
func n20TableRomanBytes(name string, tab N20PackedTable) (int, bool) {
	rr := []rune(name)
	for i, r := range rr {
		rr[i] = n20Hira(r)
	}
	simple := map[uint16]int{}
	for _, e := range tab.Simple {
		simple[e.code] = len(e.latin)
	}
	digraph := map[[2]uint16]int{}
	for _, e := range tab.Digraph {
		digraph[[2]uint16{e.first, e.second}] = len(e.latin)
	}
	code := func(r rune) (uint16, bool) {
		b, err := pn.EncodeCP932Kana(string(r))
		if err != nil || len(b) != 2 {
			return 0, false
		}
		return binary.BigEndian.Uint16(b), true
	}
	unit := func(i int) (int, int, bool) {
		if i >= len(rr) {
			return 0, 0, false
		}
		if i+1 < len(rr) && n20SmallKana[rr[i+1]] {
			a, ok1 := code(rr[i])
			b, ok2 := code(rr[i+1])
			if ok1 && ok2 {
				if n, ok := digraph[[2]uint16{a, b}]; ok {
					return n, 2, true
				}
			}
		}
		a, ok := code(rr[i])
		if !ok {
			return 0, 0, false
		}
		n, ok := simple[a]
		return n, 1, ok
	}
	total := 0
	letters := 0
	for i := 0; i < len(rr); i++ {
		r := rr[i]
		if r == 'っ' {
			if i+1 >= len(rr) {
				return 0, false
			}
			n, used, ok := unit(i + 1)
			if !ok || n == 0 {
				return 0, false
			}
			_ = used
			total++ // one geminate byte
			continue
		}
		if r == 'ー' {
			if letters == 0 {
				return 0, false
			}
			total++
			continue
		}
		if r == '～' {
			total++
			letters++
			continue
		}
		if r == ' ' || r == '　' || r == '・' || (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') {
			total++
			letters++
			continue
		}
		n, used, ok := unit(i)
		if !ok {
			return 0, false
		}
		total += n
		letters += n
		i += used - 1
	}
	if total == 0 {
		return 0, false
	}
	return total, true
}

// AnalyzeN20MaxRoman derives the maximum from the actual rebuilt table and
// constructs boundary witnesses. It does not execute MIPS.
func AnalyzeN20MaxRoman() (N20MaxLengthAudit, error) {
	var a N20MaxLengthAudit
	a.Schema = 1
	a.SafeToPatch = false
	a.RuntimePass = false
	tab, err := N20BuildLocalTable()
	if err != nil {
		return a, err
	}
	a.SimpleEntries = len(tab.Simple)
	a.DigraphEntries = len(tab.Digraph)
	a.SecondsEntries = len(tab.Seconds)
	a.AlphabetEntries = len(tab.Letters)
	a.TableBytes = len(tab.Bytes)
	a.TableSHA = N20PackedTableSHA
	for _, e := range tab.Simple {
		if len(e.latin) > a.SimpleMaxBytes {
			a.SimpleMaxBytes = len(e.latin)
		}
	}
	for _, e := range tab.Simple {
		if len(e.latin) != a.SimpleMaxBytes {
			continue
		}
		k, err := n20KanaOfCode(e.code, "simple max")
		if err != nil {
			return a, err
		}
		a.SimpleMaxKana = append(a.SimpleMaxKana, k)
	}
	for _, e := range tab.Digraph {
		if len(e.latin) > a.DigraphMaxBytes {
			a.DigraphMaxBytes = len(e.latin)
		}
	}
	for _, e := range tab.Digraph {
		if len(e.latin) == a.DigraphMaxBytes {
			a.DigraphMaxCount++
		}
	}
	if a.SimpleMaxBytes != 3 || a.DigraphMaxBytes != 3 {
		return a, fmt.Errorf("table maxima drifted simple=%d digraph=%d", a.SimpleMaxBytes, a.DigraphMaxBytes)
	}
	if len(a.SimpleMaxKana) != 3 {
		return a, fmt.Errorf("expected exactly three 3-byte simple records, got %v", a.SimpleMaxKana)
	}

	// Token compositions for exactly three kana. The maxima come from the
	// table, so these are upper bounds of the actual rebuilt parser, not of
	// the host RomanizeKana primitive.
	s, d := a.SimpleMaxBytes, a.DigraphMaxBytes
	a.Compositions = []N20MaxComposition{
		{"S+S+S", 3, 3 * s, "three simple records"},
		{"D+S", 3, d + s, "one two-kana digraph plus one simple"},
		{"S+D", 3, s + d, "one simple plus one two-kana digraph"},
		{"sokuon+S+S", 3, 1 + 2*s, "geminate prefix plus two simples"},
		{"S+sokuon+S", 3, 2*s + 1, "simple, geminate prefix, simple"},
		{"sokuon+D", 3, 1 + d, "geminate prefix plus digraph"},
		{"S+S+long", 3, 2*s + 1, "long mark copies one vowel byte"},
		{"S+long+S", 3, 2*s + 1, "long mark between simples"},
		{"S+S+wave", 3, 2*s + 1, "wave dash is one ASCII byte"},
		{"wave+S+S", 3, 1 + 2*s, "wave dash plus two simples"},
		{"S+long+long", 3, s + 2, "two one-byte long marks"},
		{"long/wave only", 3, 3, "each mark is one byte"},
	}
	a.MaxRomanBytes = 0
	for _, c := range a.Compositions {
		if c.MaxBytes > a.MaxRomanBytes {
			a.MaxRomanBytes = c.MaxBytes
			a.MaxComposition = c.Shape
		}
	}
	if a.MaxRomanBytes != N20MaxRomanBytes || a.MaxComposition != "S+S+S" {
		return a, fmt.Errorf("composition maximum drifted %d/%s", a.MaxRomanBytes, a.MaxComposition)
	}
	a.ExactSlotBytes = N20MaxExactSlotBytes
	a.PaddedSlotBytes = N20MaxPaddedSlotBytes
	a.AlignedSlotBytes = N20MaxAlignedSlotBytes
	a.AcceptedRomanBytes = N20MaxAcceptedRomanBytes
	a.AcceptedWireBytes = N20MaxAcceptedWireBytes
	a.MaxV0 = a.PaddedSlotBytes
	a.CurrentSlotBytes = OLFieldPrepSlotBytes

	// Constructive witnesses from the actual table. Sokuon/long/wave literals
	// are NAME_ENT cells; the tests assert that against the authenticated grid.
	shi, ok := n20FindSimpleLatin(tab, "shi")
	if !ok {
		return a, fmt.Errorf("shi record missing")
	}
	chi, ok := n20FindSimpleLatin(tab, "chi")
	if !ok {
		return a, fmt.Errorf("chi record missing")
	}
	tsu, ok := n20FindSimpleLatin(tab, "tsu")
	if !ok {
		return a, fmt.Errorf("tsu record missing")
	}
	ka, ok := n20FindSimpleLatin(tab, "ka")
	if !ok {
		return a, fmt.Errorf("ka record missing")
	}
	aKana, ok := n20FindSimpleLatin(tab, "a")
	if !ok {
		return a, fmt.Errorf("a record missing")
	}
	kya, ok := n20FindDigraphLatin(tab, "kya")
	if !ok {
		return a, fmt.Errorf("kya digraph missing")
	}
	cha, ok := n20FindDigraphLatin(tab, "cha")
	if !ok {
		return a, fmt.Errorf("cha digraph missing")
	}
	mk := func(kind, kana string, katakana bool) N20MaxWitness {
		n, _ := n20TableRomanBytes(kana, tab)
		w := N20MaxWitness{Kind: kind, Kana: kana, RomanBytes: n,
			WireBytes: FieldPrepWireBytes(n), SlotBytes: FieldPrepWireBytes(n) + 1,
			Katakana: katakana}
		w.FitsSlot = FieldPrepAcceptedRomanLen(n)
		w.V0 = w.SlotBytes
		return w
	}
	a.Witnesses = []N20MaxWitness{
		mk("max-9 hiragana", shi+shi+shi, false),
		mk("max-9 hiragana", chi+chi+chi, false),
		mk("max-9 hiragana", tsu+tsu+tsu, false),
		mk("max-9 mixed simple", shi+chi+tsu, false),
		mk("max-9 katakana", n20KataString(shi+shi+shi), true),
		mk("max-9 mixed kata/hira", shi+n20KataString(chi)+tsu, true),
		mk("simple 3-byte", shi, false),
		mk("simple 3-byte", chi, false),
		mk("simple 3-byte", tsu, false),
		mk("digraph+simple", kya+shi, false),
		mk("simple+digraph", shi+kya, false),
		mk("sokuon+two simples", "っ"+shi+shi, false),
		mk("8-byte boundary", ka+shi+shi, false),
		mk("7-byte boundary", shi+shi+aKana, false),
		mk("7-byte boundary", tsu+ka+ka, false),
		mk("6-byte accepted", shi+shi, false),
		mk("5-byte accepted", shi+ka, false),
		mk("digraph max", kya, false),
		mk("simple 2-byte", ka, false),
		mk("simple 1-byte", aKana, false),
		mk("wave dash", "～", false),
		mk("sokuon+digraph", "っ"+kya, false),
		mk("sokuon+ch-digraph", "っ"+cha, false),
		mk("long mark", shi+"ー", false),
		mk("long mark context", shi+"ー"+shi, false),
		mk("wave context", "～"+shi+shi, false),
	}
	for i := range a.Witnesses {
		want, ok := n20TableRomanBytes(a.Witnesses[i].Kana, tab)
		if !ok || want != a.Witnesses[i].RomanBytes {
			return a, fmt.Errorf("witness %q model %d/%v", a.Witnesses[i].Kana, want, ok)
		}
		// The string is illustrative only; the byte count above came from the
		// table. The MIPS test re-executes every witness and compares bytes.
		if roman, err := RomanizeKanaN20Local(a.Witnesses[i].Kana); err == nil && len(roman) == want {
			a.Witnesses[i].Roman = roman
		}
	}
	return a, nil
}

// n20ExeFieldRefs is the exhaustive EXE-side instruction table for the two
// working fields. Every word is re-checked against the authenticated EXE.
func n20ExeFieldRefs() []N20FieldRef {
	return []N20FieldRef{
		// formatter_a..d: strlen(family) and sprintf(sp+0x68,"%s ",family)
		{0x8007F788, 0x2484A16C, "family", "address", "addiu a0,a0,0xA16C", "formatter_a strlen(family)", "formatter frame sp+0x290; buffer sp+0x68", 532, "EXE", 0},
		{0x8007F798, 0x24C6A16C, "family", "address", "addiu a2,a2,0xA16C", "formatter_a sprintf arg3=family", "sp+0x68", 532, "EXE", 0},
		{0x8007F84C, 0x2484A16C, "family", "address", "addiu a0,a0,0xA16C", "formatter_b strlen(family)", "sp+0x68", 532, "EXE", 0},
		{0x8007F85C, 0x24C6A16C, "family", "address", "addiu a2,a2,0xA16C", "formatter_b sprintf arg3=family", "sp+0x68", 532, "EXE", 0},
		{0x8007F910, 0x2484A16C, "family", "address", "addiu a0,a0,0xA16C", "formatter_c strlen(family)", "sp+0x68", 532, "EXE", 0},
		{0x8007F920, 0x24C6A16C, "family", "address", "addiu a2,a2,0xA16C", "formatter_c sprintf arg3=family", "sp+0x68", 532, "EXE", 0},
		{0x80080BE4, 0x2484A16C, "family", "address", "addiu a0,a0,0xA16C", "formatter_d strlen(family)", "sp+0x68", 532, "EXE", 0},
		{0x80080BF4, 0x24C6A16C, "family", "address", "addiu a2,a2,0xA16C", "formatter_d sprintf arg3=family", "sp+0x68", 532, "EXE", 0},
		// renderer p: s6 = family; three strlen calls and the byte copy loop.
		{0x80081408, 0x26D6A16C, "family", "address", "addiu s6,s6,0xA16C", "renderer p sets s6=family", "renderer frame sp+0x2F8", 760, "EXE", 0},
		{0x80081784, 0x02C02025, "family", "use", "or a0,s6,zero", "renderer p strlen(family) entry", "line buffer sp+0x2A4", 64, "EXE", 0},
		{0x80081794, 0x930E0000, "family", "read", "lbu t6,0(t8)", "renderer p copy loop reads family byte", "line buffer sp+0x2A4", 64, "EXE", 0},
		{0x800817E0, 0x02C02025, "family", "use", "or a0,s6,zero", "renderer p strlen(family) for width", "line buffer sp+0x2A4", 64, "EXE", 0},
		{0x800817F8, 0x02C02025, "family", "use", "or a0,s6,zero", "renderer p strlen(family) after copy", "line buffer sp+0x2A4", 64, "EXE", 0},
		// renderer F: sprintf(temp,"%s%s",family,given)
		{0x800818F0, 0x02C03025, "family", "use", "or a2,s6,zero", "renderer F sprintf family arg", "F temp sp+0x28C", 24, "EXE", 0},
		{0x800818F4, 0x0C02B84C, "family+given", "call", "jal 0x800AE130", "renderer F sprintf(\"%s%s\",family,given)", "F temp sp+0x28C", 24, "EXE", 0},
		// given
		{0x800818E8, 0x24E7A174, "given", "address", "addiu a3,a3,0xA174", "renderer F sprintf arg4=given", "F temp sp+0x28C", 24, "EXE", 0},
		{0x800819A8, 0x24A5A174, "given", "address", "addiu a1,a1,0xA174", "renderer m strcpy src=given", "F temp sp+0x28C", 24, "EXE", 0},
		{0x800819AC, 0x0C02B83C, "given", "call", "jal 0x800AE0F0", "renderer m strcpy(temp,given)", "F temp sp+0x28C", 24, "EXE", 0},
		{0x80082224, 0x24E7A174, "given", "address", "addiu a3,a3,0xA174", "renderer second F sprintf arg4=given", "F temp sp+0x28C", 24, "EXE", 0},
		{0x80082230, 0x0C02B84C, "given", "call", "jal 0x800AE130", "renderer second F sprintf(\"%s%s\")", "F temp sp+0x28C", 24, "EXE", 0},
		{0x800822E4, 0x24A5A174, "given", "address", "addiu a1,a1,0xA174", "renderer second m strcpy src=given", "F temp sp+0x28C", 24, "EXE", 0},
		{0x800822E8, 0x0C02B83C, "given", "call", "jal 0x800AE0F0", "renderer second m strcpy(temp,given)", "F temp sp+0x28C", 24, "EXE", 0},
		// writers
		{0x800847D0, 0x0C02B83C, "family", "call", "jal 0x800AE0F0", "fieldprep strcpy(0x800CA16C,0x800E6354)", "shared working field", 8, "EXE", 0},
		{0x800847D4, 0x2484A16C, "family", "write", "addiu a0,a0,0xA16C", "fieldprep destination 0x800CA16C", "shared working field", 8, "EXE", 0},
		{0x800847E4, 0x0C02B83C, "given", "call", "jal 0x800AE0F0", "fieldprep strcpy(0x800CA174,0x800E635C)", "shared working field", 8, "EXE", 0},
		{0x800847E8, 0x2484A174, "given", "write", "addiu a0,a0,0xA174", "fieldprep destination 0x800CA174", "shared working field", 8, "EXE", 0},
	}
}

type n20OverlayRawRef struct {
	overlay  string
	off      int
	pc       uint32
	word     uint32
	imm      uint16
	field    string
	ea       uint32
	resolved bool
}

// n20ResolveBase finds the nearest preceding LUI that writes the base register
// used by an immediate reference. It returns ok=false when the producer is not
// a LUI within the bounded window.
func n20ResolveBase(d []byte, off int, baseReg uint32) (uint32, bool) {
	for back := 1; back <= 24; back++ {
		p := off - 4*back
		if p < 0 {
			return 0, false
		}
		w := binary.LittleEndian.Uint32(d[p:])
		op := w >> 26
		rt := (w >> 16) & 31
		if op == 0x0F && rt == baseReg {
			return w & 0xFFFF, true
		}
		// Any other instruction that writes the base register before the LUI
		// invalidates the search.
		writes := false
		switch op {
		case 0x0F:
			writes = rt == baseReg
		case 0x09, 0x0D, 0x0A, 0x0B, 0x0C, 0x23, 0x24, 0x25, 0x21, 0x28, 0x29, 0x2B:
			writes = rt == baseReg
		case 0x00:
			rd := (w >> 11) & 31
			if w&63 != 0x08 && w&63 != 0x09 {
				writes = rd == baseReg
			}
		}
		if writes {
			return 0, false
		}
	}
	return 0, false
}

func n20Sext16(v uint16) int32 { return int32(int16(v)) }

// ScanOverlayWorkingFieldRefs resolves every immediate reference in all 26
// authenticated overlays. Constants based on 0x8014/0x8015/0x8019 resolve to
// overlay-local data and are counted as false positives, not as field refs.
func ScanOverlayWorkingFieldRefs(overlays map[string][]byte) ([]N20FieldRef, N20OverlayRefScan, error) {
	var out []N20FieldRef
	var scan N20OverlayRefScan
	if len(overlays) != len(OverlaySHA) {
		return nil, scan, fmt.Errorf("need all 26 authenticated overlays, got %d", len(overlays))
	}
	scan.Overlays = len(overlays)
	names := make([]string, 0, len(overlays))
	for n := range overlays {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		d := overlays[name]
		if len(d) != 196608 || sha(d) != OverlaySHA[name] {
			return nil, scan, fmt.Errorf("overlay %s is not the authenticated original", name)
		}
		if d[0x2FFFE] != 0x12 || d[0x2FFFF] != 0x10 {
			return nil, scan, fmt.Errorf("overlay %s trailer mismatch", name)
		}
		if packedTableChecksum(d) != binary.BigEndian.Uint16(d[0x2FFFC:]) {
			return nil, scan, fmt.Errorf("overlay %s checksum mismatch", name)
		}
		for _, pat := range []struct {
			b []byte
			n *int
		}{
			{[]byte{0x6C, 0xA1, 0x0C, 0x80}, &scan.PointerLiteralsFamily},
			{[]byte{0x74, 0xA1, 0x0C, 0x80}, &scan.PointerLiteralsGiven},
			{[]byte{0x7C, 0xA1, 0x0C, 0x80}, &scan.PointerLiteralsBlocked},
		} {
			*pat.n += bytes.Count(d, pat.b)
		}
		codeEnd := overlayCodeEnd(d)
		for off := 0; off+4 <= codeEnd; off += 4 {
			w := binary.LittleEndian.Uint32(d[off:])
			op := w >> 26
			imm := uint16(w & 0xFFFF)
			if imm != 0xA16C && imm != 0xA174 {
				continue
			}
			if imm == 0xA16C {
				scan.RawFamilyImmediates++
			} else {
				scan.RawGivenImmediates++
			}
			var baseReg uint32
			var ea uint32
			switch op {
			case 0x09: // addiu rt,rs,imm
				baseReg = (w >> 21) & 31
				hi, ok := n20ResolveBase(d, off, baseReg)
				if !ok {
					scan.Unresolved++
					continue
				}
				ea = uint32(hi)<<16 + uint32(n20Sext16(imm))
			case 0x0D: // ori rt,rs,imm
				baseReg = (w >> 21) & 31
				hi, ok := n20ResolveBase(d, off, baseReg)
				if !ok {
					scan.Unresolved++
					continue
				}
				ea = uint32(hi)<<16 | uint32(imm)
			case 0x23, 0x2B, 0x24, 0x28, 0x21, 0x25, 0x29: // loads/stores
				baseReg = (w >> 21) & 31
				hi, ok := n20ResolveBase(d, off, baseReg)
				if !ok {
					scan.Unresolved++
					continue
				}
				ea = uint32(hi)<<16 + uint32(n20Sext16(imm))
			default:
				scan.Unresolved++
				continue
			}
			field := "family"
			if imm == 0xA174 {
				field = "given"
			}
			if ea != 0x800CA16C && ea != 0x800CA174 {
				scan.FalsePositives++
				continue
			}
			var kind, semantics string
			switch op {
			case 0x09, 0x0D:
				kind, semantics = "address", "materialises "+field+" pointer"
			case 0x23:
				kind, semantics = "read", "loads "+field+" pointer"
			case 0x2B:
				kind, semantics = "write", "stores to "+field+" field"
			case 0x24:
				kind, semantics = "read", "loads a "+field+" byte"
			case 0x28:
				kind, semantics = "write", "stores a "+field+" byte"
			case 0x21, 0x25, 0x29:
				kind, semantics = "read", "loads a "+field+" halfword"
			}
			if field == "family" {
				scan.FamilyRefs++
			} else {
				scan.GivenRefs++
			}
			switch OverlaySlotBase + uint32(off) {
			case 0x80141164, 0x80141294, 0x80141460, 0x8013DC30:
				kind = "write"
				semantics = "duplicate writer: strcpy(0x800CA16C,0x800E6354)"
			case 0x80133B88:
				kind = "read"
				semantics = "strlen(0x800CA16C) for the SHOUGATU NAME_ENT confirmation queue"
			case 0x80133BA0:
				kind = "use"
				semantics = "a3=0x800CA16C passed to the overlay-owned queue call 0x8004E788"
			}
			out = append(out, N20FieldRef{
				PC: OverlaySlotBase + uint32(off), Word: w, Field: field,
				Kind: kind, Op: fmt.Sprintf("op%02x", op), Semantics: semantics,
				Owner: name, FileOff: off,
			})
		}
		// Overlay calls to the renderer, formatter entry and fieldprep are
		// lifecycle-relevant; they do not change the EXE-fixed field constants.
		for off := 0; off+8 <= codeEnd; off += 4 {
			w := binary.LittleEndian.Uint32(d[off:])
			if w>>26 != 0x03 {
				continue
			}
			tgt := ((w & 0x03FFFFFF) << 2) | 0x80000000
			switch tgt {
			case N20RendererEntry:
				scan.RendererJALs++
			case N20FormatterEntry:
				scan.FormatterEntryJALs++
			case OLFieldPrepOriginal:
				scan.FieldPrepJALs++
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Owner == out[j].Owner {
			return out[i].FileOff < out[j].FileOff
		}
		return out[i].Owner < out[j].Owner
	})
	return out, scan, nil
}

// AuditN20MaxLength re-decodes the table, the EXE consumer instructions and
// all 26 overlays, then returns the blocked/implemented verdict.
func AuditN20MaxLength(exe []byte, overlays map[string][]byte) (N20MaxLengthAudit, error) {
	a, err := AnalyzeN20MaxRoman()
	if err != nil {
		return a, err
	}
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return a, fmt.Errorf("unrecognised original EXE")
	}
	nameEnt, ok := overlays["NAME_ENT.EXN"]
	if !ok {
		return a, fmt.Errorf("NAME_ENT.EXN missing")
	}
	grid, err := n20GridSet(nameEnt)
	if err != nil {
		return a, err
	}
	for i := range a.Witnesses {
		all := true
		for _, r := range a.Witnesses[i].Kana {
			if !grid[string(r)] {
				all = false
				break
			}
		}
		a.Witnesses[i].GridKana = all
	}
	refs := n20ExeFieldRefs()
	for _, r := range refs {
		if got := wordAt(exe, r.PC); got != r.Word {
			return a, fmt.Errorf("field ref %08x drifted: %08x want %08x", r.PC, got, r.Word)
		}
		switch r.Field {
		case "family":
			if r.Kind == "address" || r.Kind == "write" {
				a.FamilyAddressRefs++
			}
		case "given":
			if r.Kind == "address" || r.Kind == "write" {
				a.GivenAddressRefs++
			}
		}
	}
	a.FieldRefs = refs
	ovRefs, ovScan, err := ScanOverlayWorkingFieldRefs(overlays)
	if err != nil {
		return a, err
	}
	a.Overlay = ovScan
	a.FieldRefs = append(a.FieldRefs, ovRefs...)

	// Buffer lifetimes.
	a.Buffers = []N20BufferLifetime{
		{"formatter_b/d", "0x8007F868 / 0x80080C00", "sprintf dest sp+0x68", 532, 12, true,
			"formatter frame 0x290, freed on return", false,
			"next recorded local at sp+0x27C; only name+space+NUL is written"},
		{"renderer p", "0x80081780", "line buffer sp+0x2A4", 64, 11, true,
			"renderer frame 0x2F8", false, "64-byte line clamp"},
		{"renderer m", "0x800819A4", "F temp sp+0x28C", 24, 11, true,
			"renderer frame 0x2F8", false, "strcpy of one field into 24-byte temp"},
		{"renderer F", "0x800818DC", "F temp sp+0x28C", 24, 21, true,
			"renderer frame 0x2F8", false, "sprintf(\"%s%s\") join; 21 bytes incl NUL"},
		{"renderer line", "0x80081D7C", "line buffer sp+0x2A4", 64, 21, true,
			"renderer frame 0x2F8", false, "queue text argument; 64-byte clamp"},
		{"generic queue", "0x8004E788", "entry table 0x800B3DC0", 52 * 8, 8, true,
			"global render queue, 52 entries", false, "8-byte metadata entry; length/width byte at +5"},
	}

	// Byte overlap: 9 roman -> 10 wire -> 11 incl NUL; aligned 12.
	a.FamilyEnd11 = OLFieldPrepWorkFam + N20MaxPaddedSlotBytes - 1
	a.GivenStart = OLFieldPrepWorkGiv
	a.GivenEnd11 = OLFieldPrepWorkGiv + N20MaxPaddedSlotBytes - 1
	a.BlockedStart = OLFieldPrepBlockedFam
	if a.FamilyEnd11 >= a.GivenStart {
		a.FamilyOverlapBytes = int(a.FamilyEnd11 - a.GivenStart + 1)
	}
	if a.GivenEnd11 >= a.BlockedStart {
		a.GivenOverlapBytes = int(a.GivenEnd11 - a.BlockedStart + 1)
	}
	a.FamilyOverlap12 = int(OLFieldPrepWorkFam + N20MaxAlignedSlotBytes - 1 - OLFieldPrepWorkGiv + 1)
	a.GivenOverlap12 = int(OLFieldPrepWorkGiv + N20MaxAlignedSlotBytes - 1 - OLFieldPrepBlockedFam + 1)
	if a.FamilyOverlap12 < 0 {
		a.FamilyOverlap12 = 0
	}
	if a.GivenOverlap12 < 0 {
		a.GivenOverlap12 = 0
	}

	// Redirection candidates.
	shougat := "SHOUGATU.EXN 0x80133B88 strlen(family) / 0x80133BA0 queue a3=family"
	a.Candidates = []N20RedirectCandidate{
		{"overlay slot payload spare (N6-FP 1,272 B / N6 728 B)", true, false, false, true, false,
			"loader-owned lifetime, but no EXE consumer reads it; only the module itself could read it"},
		{"N6-FP shim frame 0x40", false, false, false, true, false,
			"callee-owned stack, released on return; no consumer can address it after the shim returns"},
		{"renderer F temp sp+0x28C (24 B)", false, false, false, true, false,
			"renderer frame is callee-owned; fieldprep has no pointer and the address depends on that call chain"},
		{"formatter sp+0x68 (532 B)", false, false, false, true, false,
			"formatter frame is callee-owned; same lifetime problem"},
		{"SHOUGATU overlay-owned direct family consumer: " + shougat, false, true, false, true, false,
			"only the family pointer is overlay-owned; there is no given consumer, no fieldprep call in 0x80133B44..0x80133CD8 (the function is reached indirectly), and the EXE formatter/renderer still read the fixed fields. Not a complete or lifecycle-proven path."},
		{"generic renderer queue 0x80081DC8", false, false, false, true, false,
			"explicitly forbidden; it is the EXE renderer's queue site reached by every line"},
	}

	a.Verdict = "blocked_shared_working_field_8_bytes_no_lifecycle_safe_overlay_consumer"
	a.Requirement = fmt.Sprintf(
		"relocate/expand both working fields to at least 12 aligned bytes each (10 exact, 11 padded, 12 aligned including NUL) and update every EXE consumer constant: 10 family address refs, 5 given address refs, plus 0x800CA17C/0x800CA188/0x800CA190; or add an EXE hook that redirects every consumer (forbidden here). Overlay-local redirection is insufficient: only %s is overlay-owned and it covers family only.", shougat)
	a.Reason = fmt.Sprintf(
		"the rebuilt table's longest simple and digraph records are 3 bytes, so three 3-byte simples produce %d ASCII bytes; odd-length padding makes %d wire bytes plus NUL = %d bytes, aligned %d. The two working fields are %d bytes including NUL and the next field starts at 0x%08x; an 11-byte family write overlaps given by %d bytes and an 11-byte given write overlaps 0x%08x by %d bytes. Downstream buffers fit the 21-byte family+given join (formatter 532, line 64, F temp 24, queue metadata); the shared fields are the only binding limit. All %d EXE consumer constants are fixed. Overlays contain %d resolved family refs and %d given refs after LUI-base resolution (6 real family refs: 4 duplicate writers + 2 SHOUGATU consumer instructions); no overlay-owned given consumer exists, and the SHOUGATU function has no direct fieldprep call and is reached indirectly. No complete lifecycle-safe redirected path exists without an EXE change.",
		a.MaxRomanBytes, a.PaddedSlotBytes-1, a.PaddedSlotBytes, a.AlignedSlotBytes,
		a.CurrentSlotBytes, a.BlockedStart, a.FamilyOverlapBytes, a.BlockedStart, a.GivenOverlapBytes,
		a.FamilyAddressRefs+a.GivenAddressRefs, a.Overlay.FamilyRefs, a.Overlay.GivenRefs)
	return a, nil
}

// N20MaxLengthReportFor exposes the audit to the evidence generator.
func N20MaxLengthReportFor(a N20MaxLengthAudit) map[string]any {
	return map[string]any{
		"safe_to_patch": a.SafeToPatch, "runtime_pass": a.RuntimePass,
		"simple_entries": a.SimpleEntries, "digraph_entries": a.DigraphEntries,
		"simple_max_bytes": a.SimpleMaxBytes, "simple_max_kana": a.SimpleMaxKana,
		"digraph_max_bytes": a.DigraphMaxBytes, "digraph_max_records": a.DigraphMaxCount,
		"max_roman_bytes": a.MaxRomanBytes, "max_composition": a.MaxComposition,
		"exact_slot_bytes": a.ExactSlotBytes, "padded_slot_bytes": a.PaddedSlotBytes,
		"aligned_slot_bytes": a.AlignedSlotBytes, "max_v0": a.MaxV0,
		"verdict": a.Verdict, "requirement": a.Requirement,
		"overlay_refs": a.Overlay,
	}
}
