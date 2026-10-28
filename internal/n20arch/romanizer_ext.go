package n20arch

// N20-local, private packed romanizer (the "N20 romanizer rebuild").
//
// This file deliberately does NOT edit or import-edit the production
// internal/playername builder. It copies the packed romanizer packed-table and packed-MIPS
// algorithm into this isolated package, then makes two source-grounded
// changes on top of the authenticated packed romanizer behaviour:
//
//  1. the fullwidth wave dash '～' (CP932 0x8160) is accepted and emitted as
//     the host's established compact ASCII "~";
//  2. the 19 NAME_ENT-selectable Hepburn digraphs listed in coverage_ext.go
//     are accepted (ウ/ウィ/... variants are handled by CP932 normalisation,
//     not by storing four redundant records per pair).
//
// Mapping basis
// -------------
// Every supplemental digraph below is standard/modified Hepburn and is a
// selectable NAME_ENT keyboard cell pair (pinned by coverage_ext_test.go):
//
//	うぃ=wi  うぇ=we  うぉ=wo  いぇ=ye
//	くぁ=kwa くぃ=kwi くぇ=kwe くぉ=kwo
//	ぐぁ=gwa ぐぃ=gwi ぐぇ=gwe ぐぉ=gwo
//	つぁ=tsa つぃ=tsi つぇ=tse つぉ=tso
//	ぢゃ=ja  ぢゅ=ju  ぢょ=jo
//
// Rejected speculative foreign extensions (てゃ/てゅ/てょ, でゃ/でゅ/でょ,
// ふゃ/ふゅ/ふょ, すぃ/ずぃ) remain OUT. Standalone small kana, っ and ー stay
// invalid because the shared parser still rejects them.
//
// Table representation
// --------------------
// The authenticated packed romanizer table is 1,424 B: 143 simple records + 184 digraph
// records (four hira/kata spellings for each of 46 host digraphs) + 16 second
// codes + 32 alphabet bytes + 48 suffix bytes. Storing four variants for each
// of the 19 additions would need 304 B, which does not fit the N6 body's
// remaining capacity without dropping safety. Instead the guest normalises a
// CP932 katakana lead/trail byte to its hiragana code before lookup, so the
// table only needs the canonical hiragana spelling. This preserves every
// mapping (the mixed/kata spellings still reach the same record) while
// shrinking the table:
//
//	simple:   71 hiragana + ヴ                       72 records (was 143)
//	digraph:  44 canonical host + 4 ヴ + 19 new      67 records (was 184)
//	seconds:  8 hiragana small kana                  16 B (was 16 codes/32 B)
//	alphabet: 23 letters                             32 B (unchanged)
//	suffix:   6 records                              48 B (unchanged)
//	total:    672 B (was 1,424 B)
//
// The normalisation is exact for the NAME_ENT grid:
//   0x8340..0x837E -> subtract 0xA1 (ァ..ミ)
//   0x8380..0x8393 -> subtract 0xA2 (ム..ン)
// 0x837F and 0x8394..0x8396 are left alone; ヴ (0x8394) keeps its existing
// simple record and its four ヴぁ/ヴぃ/ヴぇ/ヴぉ digraph records. The guest still rejects every unsupported glyph exactly as
// before.
//
// safe_to_patch remains false. Nothing here installs code or claims RAM.

import (
	"encoding/binary"
	"fmt"
	"sort"

	pn "tokimemo/internal/playername"
)

const (
	// Rebuilt core geometry (pinned by romanizer_ext_test.go).
	N20PackedCodeBytes      = 1840
	N20PackedTableBytes     = 672
	N20PackedProgramBytes   = 2512
	N20PackedSimpleEntries  = 72
	N20PackedDigraphEntries = 67
	N20PackedSecondsEntries = 8
	N20PackedAlphabetCount  = 23
	N20PackedTableSHA       = "61def8c7ba0fe4d05240989ca3dee914357bf7803be879d6a40d38c4afdaf1b2"

	// Authenticated packed romanizer packed-table geometry used only for decoding.
	n20TableBytes    = 1424
	n20SimpleBase    = 0
	n20SimpleCount   = 143
	n20DigraphBase   = 574
	n20DigraphCount  = 184
	n20SecondsOffset = 1312
	n20AlphabetOff   = 1344
)

// N20PackedTable is the local, canonical table used by the rebuilt core.
type N20PackedTable struct {
	Simple        []n20PackedSimple
	Digraph       []n20PackedDigraph
	Letters       []byte
	Seconds       []uint16
	Bytes         []byte
	SimpleOffset  int
	DigraphOffset int
	SecondsOffset int
	AlphabetOff   int
	SuffixOffset  int
}

type n20PackedSimple struct {
	code  uint16
	latin string
}

type n20PackedDigraph struct {
	first, second uint16
	latin         string
}

// N20PackedCore is the rebuilt guest converter.
type N20PackedCore struct {
	Entry           uint32
	CodeBytes       int
	TableBytes      int
	ProgramBytes    int
	SimpleEntries   int
	DigraphEntries  int
	SecondsEntries  int
	AlphabetEntries int
	WaveDashInCode  bool
	KatakanaNormal  bool
	Binary          []byte
	Words           []uint32
	TableSHA        string
}

func n20BE16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }

// n20Decode reads the authenticated packed romanizer table through the production
// data builder, then decodes its simple/digraph records. It is read-only.
func n20Decode() ([]n20PackedSimple, []n20PackedDigraph, error) {
	data, err := pn.BuildPS1PackedRomanizationTable()
	if err != nil {
		return nil, nil, err
	}
	if len(data) != n20TableBytes {
		return nil, nil, fmt.Errorf("packed romanizer table length %d", len(data))
	}
	alphabet := data[n20AlphabetOff : n20AlphabetOff+32]
	seconds := data[n20SecondsOffset : n20SecondsOffset+32]

	var simple []n20PackedSimple
	cur := int(n20BE16(data[n20SimpleBase:]))
	for i := 0; i < n20SimpleCount; i++ {
		o := n20SimpleBase + 2 + i*4
		cur += int(data[o])
		p := uint32(data[o+1]) | uint32(data[o+2])<<8 | uint32(data[o+3])<<16
		n := int((p >> 15) & 3)
		if n < 1 || n > 3 {
			return nil, nil, fmt.Errorf("packed romanizer simple record %d length %d", i, n)
		}
		var latin []byte
		for j := 0; j < n; j++ {
			latin = append(latin, alphabet[(p>>uint(5*j))&31])
		}
		simple = append(simple, n20PackedSimple{code: uint16(cur), latin: string(latin)})
	}
	var dig []n20PackedDigraph
	cur = int(n20BE16(data[n20DigraphBase:]))
	for i := 0; i < n20DigraphCount; i++ {
		o := n20DigraphBase + 2 + i*4
		cur += int(data[o])
		p := uint32(data[o+1]) | uint32(data[o+2])<<8 | uint32(data[o+3])<<16
		second := n20BE16(seconds[2*(p&15):])
		n := int((p >> 19) & 3)
		if n < 1 || n > 3 {
			return nil, nil, fmt.Errorf("packed romanizer digraph record %d length %d", i, n)
		}
		var latin []byte
		for j := 0; j < n; j++ {
			latin = append(latin, alphabet[(p>>uint(4+5*j))&31])
		}
		dig = append(dig, n20PackedDigraph{first: uint16(cur), second: second, latin: string(latin)})
	}
	return simple, dig, nil
}

func n20IsHiraganaCode(c uint16) bool { return c >= 0x829F && c <= 0x82F1 }

// N20BuildLocalTable builds the compact canonical table. The wave dash is a
// generated code branch, not a table record, because 0x8160 sorts before the
// simple base and its 0x140 delta to あ does not fit the one-byte delta field.
func N20BuildLocalTable() (N20PackedTable, error) {
	var t N20PackedTable
	romanizerCaseSimple, romanizerCaseDig, err := n20Decode()
	if err != nil {
		return t, err
	}
	for _, s := range romanizerCaseSimple {
		if n20IsHiraganaCode(s.code) || s.code == 0x8394 { // ヴ has no hiragana code
			t.Simple = append(t.Simple, s)
		}
	}
	for _, d := range romanizerCaseDig {
		// ヴ (0x8394) has no hiragana CP932 code; retain its four compounds
		// (ヴぁ/ヴぃ/ヴぇ/ヴぉ with hiragana second) so the existing ヴァ etc.
		// mappings are not lost. All other records become canonical hiragana.
		if (n20IsHiraganaCode(d.first) || d.first == 0x8394) && n20IsHiraganaCode(d.second) {
			t.Digraph = append(t.Digraph, d)
		}
	}
	// Add the 19 source-supported digraphs in canonical hiragana spelling.
	have := map[[2]uint16]bool{}
	for _, d := range t.Digraph {
		have[[2]uint16{d.first, d.second}] = true
	}
	for _, e := range N20CoverageExtensions {
		codeb, err := pn.EncodeCP932Kana(e.Kana)
		if err != nil || len(codeb) != 4 {
			return t, fmt.Errorf("extension %q is not encodable as two CP932 kana", e.Kana)
		}
		first := n20BE16(codeb[:2])
		second := n20BE16(codeb[2:])
		if have[[2]uint16{first, second}] {
			return t, fmt.Errorf("extension %q is already in the canonical table", e.Kana)
		}
		have[[2]uint16{first, second}] = true
		t.Digraph = append(t.Digraph, n20PackedDigraph{first: first, second: second, latin: e.Roman})
	}
	sort.Slice(t.Simple, func(i, j int) bool { return t.Simple[i].code < t.Simple[j].code })
	sort.Slice(t.Digraph, func(i, j int) bool {
		if t.Digraph[i].first == t.Digraph[j].first {
			return t.Digraph[i].second < t.Digraph[j].second
		}
		return t.Digraph[i].first < t.Digraph[j].first
	})
	if len(t.Simple) == 0 || len(t.Simple) > 255 || len(t.Digraph) == 0 || len(t.Digraph) > 255 {
		return t, fmt.Errorf("local table sizes %d/%d", len(t.Simple), len(t.Digraph))
	}
	letterSet := map[byte]bool{}
	for _, e := range t.Simple {
		for i := range e.latin {
			letterSet[e.latin[i]] = true
		}
	}
	for _, e := range t.Digraph {
		for i := range e.latin {
			letterSet[e.latin[i]] = true
		}
	}
	for c := range letterSet {
		t.Letters = append(t.Letters, c)
	}
	sort.Slice(t.Letters, func(i, j int) bool { return t.Letters[i] < t.Letters[j] })
	if len(t.Letters) > 32 {
		return t, fmt.Errorf("local alphabet %d exceeds 32", len(t.Letters))
	}
	secondsSet := map[uint16]bool{}
	for _, d := range t.Digraph {
		secondsSet[d.second] = true
	}
	for c := range secondsSet {
		t.Seconds = append(t.Seconds, c)
	}
	sort.Slice(t.Seconds, func(i, j int) bool { return t.Seconds[i] < t.Seconds[j] })
	if len(t.Seconds) > 16 {
		return t, fmt.Errorf("local second codes %d exceed 16", len(t.Seconds))
	}
	alphaIndex := map[byte]uint32{}
	for i, c := range t.Letters {
		alphaIndex[c] = uint32(i)
	}
	secondIndex := map[uint16]uint32{}
	for i, c := range t.Seconds {
		secondIndex[c] = uint32(i)
	}
	out := make([]byte, 0, 1024)
	be16 := func(v uint16) { out = append(out, byte(v>>8), byte(v)) }
	pack := func(delta uint16, value uint32) error {
		if delta > 255 || value > 0xffffff {
			return fmt.Errorf("local packed word delta=%d value=%x", delta, value)
		}
		out = append(out, byte(delta), byte(value), byte(value>>8), byte(value>>16))
		return nil
	}
	t.SimpleOffset = len(out)
	be16(t.Simple[0].code)
	prev := t.Simple[0].code
	for _, e := range t.Simple {
		if e.code < prev || len(e.latin) < 1 || len(e.latin) > 3 {
			return t, fmt.Errorf("local simple record invalid")
		}
		p := uint32(len(e.latin)) << 15
		for i := range e.latin {
			p |= alphaIndex[e.latin[i]] << uint(5*i)
		}
		if err := pack(e.code-prev, p); err != nil {
			return t, err
		}
		prev = e.code
	}
	t.DigraphOffset = len(out)
	be16(t.Digraph[0].first)
	prev = t.Digraph[0].first
	for _, e := range t.Digraph {
		if e.first < prev || len(e.latin) < 1 || len(e.latin) > 3 {
			return t, fmt.Errorf("local digraph record invalid")
		}
		p := secondIndex[e.second] | uint32(len(e.latin))<<19
		for i := range e.latin {
			p |= alphaIndex[e.latin[i]] << uint(4+5*i)
		}
		if err := pack(e.first-prev, p); err != nil {
			return t, err
		}
		prev = e.first
	}
	t.SecondsOffset = len(out)
	for _, c := range t.Seconds {
		be16(c)
	}
	for range 16 - len(t.Seconds) {
		be16(0)
	}
	t.AlphabetOff = len(out)
	out = append(out, t.Letters...)
	for range 32 - len(t.Letters) {
		out = append(out, 0)
	}
	t.SuffixOffset = len(out)
	for _, suffix := range []string{"", "-kun", "-san", "-chan", "-sama", "-senpai"} {
		if len(suffix) > 7 {
			return t, fmt.Errorf("suffix longer than record")
		}
		out = append(out, byte(len(suffix)))
		out = append(out, []byte(suffix)...)
		for range 7 - len(suffix) {
			out = append(out, 0)
		}
	}
	t.Bytes = out
	return t, nil
}

// --- local MIPS assembler -------------------------------------------------

type n20PackedBranch struct {
	at    int
	label string
}

type n20PackedMips struct {
	words    []uint32
	labels   map[string]int
	branches []n20PackedBranch
}

func (b *n20PackedMips) emit(w uint32)  { b.words = append(b.words, w) }
func (b *n20PackedMips) label(s string) { b.labels[s] = len(b.words) }
func (b *n20PackedMips) branch(op, rs, rt uint32, label string) {
	b.branches = append(b.branches, n20PackedBranch{len(b.words), label})
	b.emit((op << 26) | (rs << 21) | (rt << 16))
}
func (b *n20PackedMips) resolve() error {
	for _, v := range b.branches {
		to, ok := b.labels[v.label]
		if !ok {
			return fmt.Errorf("undefined N20 MIPS label %s", v.label)
		}
		disp := to - v.at - 1
		if disp < -32768 || disp > 32767 {
			return fmt.Errorf("N20 MIPS branch range %s", v.label)
		}
		b.words[v.at] |= uint32(uint16(int16(disp)))
	}
	return nil
}

func n20IType(op, rs, rt uint32, imm int16) uint32 {
	return (op << 26) | (rs << 21) | (rt << 16) | uint32(uint16(imm))
}

// n20ITypeU is the unsigned-immediate form; sltiu compares in unsigned space,
// so 0x8340 must not be sign-extended at compile time.
func n20ITypeU(op, rs, rt uint32, imm uint16) uint32 {
	return (op << 26) | (rs << 21) | (rt << 16) | uint32(imm)
}
func n20RType(rs, rt, rd, shamt, funct uint32) uint32 {
	return rs<<21 | rt<<16 | rd<<11 | shamt<<6 | funct
}

// BuildN20PackedRomanizer assembles the rebuilt packed converter at origin.
// ABI is unchanged from packed romanizer: a0=CP932 NUL string, a1=output, a2=capacity
// including NUL, a3=(selector<<8)|maxKana. v0=bytes including NUL on success,
// 0 on failure with the destination untouched.
func BuildN20PackedRomanizer(origin uint32) (N20PackedCore, error) {
	var r N20PackedCore
	table, err := N20BuildLocalTable()
	if err != nil {
		return r, err
	}
	if origin < 0x80010000 || origin >= 0x801fffc0 || origin%4 != 0 {
		return r, fmt.Errorf("unaligned or out-of-range N20 origin")
	}
	var b n20PackedMips
	b.labels = map[string]int{}
	e := func(w uint32) {
		b.emit(w)
		if w>>26 == 35 || w>>26 == 36 {
			b.emit(0)
		}
	}
	jump := func(label string) { b.branch(4, 0, 0, label); e(0) }
	beq := func(rs, rt uint32, label string) { b.branch(4, rs, rt, label); e(0) }
	bne := func(rs, rt uint32, label string) { b.branch(5, rs, rt, label); e(0) }

	e(n20IType(9, 29, 29, -0x90))
	for x := uint32(16); x <= 23; x++ {
		e(n20IType(43, 29, x, int16(0x50+(x-16)*4)))
	}
	e(n20IType(43, 29, 31, 0x70))
	e(n20IType(9, 4, 16, 0)) // s0=source
	e(n20IType(9, 5, 17, 0)) // s1=output
	e(n20IType(9, 6, 18, 0)) // s2=capacity
	e(n20IType(12, 7, 19, 0xff))
	e(n20RType(0, 7, 8, 8, 2))
	e(n20IType(43, 29, 8, 0x4c))
	e(n20IType(9, 29, 21, 0x20))
	e(n20IType(9, 0, 22, 0))
	e(n20IType(9, 0, 23, 0))
	e(n20IType(43, 29, 0, 0x48))
	beq(19, 0, "fail")
	e(n20IType(35, 29, 8, 0x4c))
	e(n20IType(11, 8, 9, 6))
	beq(9, 0, "fail")
	e(n20IType(11, 19, 8, 6))
	beq(8, 0, "fail")
	b.label("char_loop")
	e(n20IType(36, 16, 8, 0))
	beq(8, 0, "finish_source")
	e(n20RType(23, 19, 12, 0, 0x2b))
	beq(12, 0, "fail")
	e(n20IType(36, 16, 9, 1))
	beq(9, 0, "fail")
	e(n20IType(9, 0, 10, 0x82))
	bne(8, 10, "check_kata_sokuon")
	e(n20IType(9, 0, 10, 0xc1))
	beq(9, 10, "sokuon")
	b.label("check_kata_sokuon")
	e(n20IType(9, 0, 10, 0x83))
	bne(8, 10, "check_long_mark")
	e(n20IType(9, 0, 10, 0x62))
	beq(9, 10, "sokuon")
	b.label("check_long_mark")
	e(n20IType(9, 0, 10, 0x81))
	bne(8, 10, "check_wave_dash")
	e(n20IType(9, 0, 10, 0x5b))
	beq(9, 10, "long_mark")
	b.label("check_wave_dash")
	// '～' CP932 8160: emit one ASCII '~' and consume one CP932 codepoint.
	e(n20IType(9, 0, 10, 0x81))
	bne(8, 10, "lookup_digraph_start")
	e(n20IType(9, 0, 10, 0x60))
	bne(9, 10, "lookup_digraph_start")
	e(n20IType(9, 0, 10, 0x7e))
	e(n20IType(40, 29, 10, 0x40))
	e(n20IType(9, 29, 14, 0x40))
	e(n20IType(9, 0, 13, 1)) // t5 = ASCII length
	e(n20IType(9, 0, 15, 1)) // t7 = consumed kana
	jump("append_syllable")
	b.label("lookup_digraph_start")
	// Normalise a CP932 katakana pair (lead,trail) to hiragana. The table
	// stores only canonical hiragana records; every kata/mixed spelling still
	// maps. The core works on two bytes, so the pair is adjusted together:
	// 0x83 0x40..0x7e -> 0x82 trail-0xA1; 0x83 0x80..0x93 -> 0x82 trail-0xA2;
	// 0x83 0x94..0x96 (ヴ/ヵ/ヶ) are left untouched.
	normPair := func(lead, trail uint32) {
		tag := fmt.Sprintf("nrm_%d_%d", lead, trail)
		e(n20ITypeU(13, 0, 1, 0x83)) // ori at,zero,0x83
		bne(lead, 1, tag+"_done")
		e(n20IType(11, trail, 1, 0x40)) // sltiu at,trail,0x40
		bne(1, 0, tag+"_done")
		e(n20IType(11, trail, 1, 0x7f)) // sltiu at,trail,0x7f
		beq(1, 0, tag+"_a2")
		e(n20IType(9, trail, trail, -0xa1))
		e(n20IType(12, trail, trail, 0xff))
		e(n20ITypeU(13, 0, lead, 0x82))
		beq(0, 0, tag+"_done")
		e(0)
		b.label(tag + "_a2")
		e(n20IType(11, trail, 1, 0x80)) // sltiu at,trail,0x80
		beq(1, 0, tag+"_ck94")
		beq(0, 0, tag+"_done") // 0x7f is an invalid CP932 gap
		e(0)
		b.label(tag + "_ck94")
		e(n20IType(11, trail, 1, 0x94)) // sltiu at,trail,0x94
		beq(1, 0, tag+"_done")
		e(n20IType(9, trail, trail, -0xa2))
		e(n20IType(12, trail, trail, 0xff))
		e(n20ITypeU(13, 0, lead, 0x82))
		b.label(tag + "_done")
	}
	normPair(8, 9) // current lead/trail (the simple key is lead<<8|trail)
	e(n20IType(36, 16, 10, 2))
	beq(10, 0, "lookup_simple_init")
	e(n20IType(9, 23, 11, 1))
	e(n20RType(11, 19, 12, 0, 0x2b))
	beq(12, 0, "lookup_simple_init")
	e(n20IType(36, 16, 11, 3))
	beq(11, 0, "fail")
	normPair(10, 11) // next lead/trail
	type n20Ref struct{ hi, lo, off int }
	var refs []n20Ref
	addrRef := func(dst uint32, off int) {
		hi := len(b.words)
		e(n20IType(15, 0, dst, 0))
		lo := len(b.words)
		e(n20IType(13, dst, dst, 0))
		refs = append(refs, n20Ref{hi, lo, off})
	}
	packedDecode := func(digraph bool) {
		e(n20IType(36, 20, 12, 1))
		e(n20IType(36, 20, 14, 2))
		e(n20RType(0, 14, 14, 8, 0))
		e(n20RType(12, 14, 12, 0, 0x25))
		e(n20IType(36, 20, 14, 3))
		e(n20RType(0, 14, 14, 16, 0))
		e(n20RType(12, 14, 12, 0, 0x25))
		shift := uint32(15)
		base := uint32(0)
		if digraph {
			shift, base = 19, 4
		}
		e(n20RType(0, 12, 13, shift, 2))
		e(n20IType(12, 13, 13, 3))
		addrRef(24, table.AlphabetOff)
		for i := uint32(0); i < 3; i++ {
			e(n20RType(0, 12, 14, base+5*i, 2))
			e(n20IType(12, 14, 14, 31))
			e(n20RType(24, 14, 14, 0, 0x21))
			e(n20IType(36, 14, 15, 0))
			e(n20IType(40, 29, 15, int16(0x40+i)))
		}
		e(n20IType(9, 29, 14, 0x40))
		n := int16(1)
		if digraph {
			n = 2
		}
		e(n20IType(9, 0, 15, n))
		jump("append_syllable")
	}
	addrRef(20, table.DigraphOffset+2)
	e(n20IType(9, 0, 13, int16(len(table.Digraph))))
	e(n20IType(13, 0, 14, int16(table.Digraph[0].first)))
	e(n20IType(43, 29, 14, 0x44))
	b.label("digraph_loop")
	beq(13, 0, "lookup_simple_init")
	e(n20IType(36, 20, 14, 0))
	e(n20IType(35, 29, 12, 0x44))
	e(n20RType(12, 14, 12, 0, 0x21))
	e(n20IType(43, 29, 12, 0x44))
	e(n20RType(0, 8, 14, 8, 0))
	e(n20RType(14, 9, 14, 0, 0x25))
	bne(12, 14, "digraph_next")
	e(n20IType(36, 20, 14, 1))
	e(n20IType(12, 14, 14, 15))
	e(n20RType(0, 14, 14, 1, 0))
	addrRef(24, table.SecondsOffset)
	e(n20RType(24, 14, 24, 0, 0x21))
	e(n20IType(36, 24, 14, 0))
	bne(14, 10, "digraph_next")
	e(n20IType(36, 24, 14, 1))
	bne(14, 11, "digraph_next")
	packedDecode(true)
	b.label("digraph_next")
	e(n20IType(9, 20, 20, 4))
	e(n20IType(9, 13, 13, -1))
	jump("digraph_loop")
	b.label("lookup_simple_init")
	addrRef(20, table.SimpleOffset+2)
	e(n20IType(9, 0, 11, int16(len(table.Simple))))
	e(n20IType(13, 0, 14, int16(table.Simple[0].code)))
	e(n20IType(43, 29, 14, 0x44))
	b.label("simple_loop")
	beq(11, 0, "fail")
	e(n20IType(36, 20, 14, 0))
	e(n20IType(35, 29, 12, 0x44))
	e(n20RType(12, 14, 12, 0, 0x21))
	e(n20IType(43, 29, 12, 0x44))
	e(n20RType(0, 8, 14, 8, 0))
	e(n20RType(14, 9, 14, 0, 0x25))
	bne(12, 14, "simple_next")
	packedDecode(false)
	b.label("simple_next")
	e(n20IType(9, 20, 20, 4))
	e(n20IType(9, 11, 11, -1))
	jump("simple_loop")
	b.label("sokuon")
	e(n20IType(35, 29, 10, 0x48))
	bne(10, 0, "fail")
	e(n20IType(9, 0, 10, 1))
	e(n20IType(43, 29, 10, 0x48))
	e(n20IType(9, 16, 16, 2))
	e(n20IType(9, 23, 23, 1))
	jump("char_loop")
	b.label("long_mark")
	e(n20IType(35, 29, 10, 0x48))
	bne(10, 0, "fail")
	beq(22, 0, "fail")
	e(n20IType(9, 21, 10, -1))
	b.label("vowel_scan")
	e(n20IType(36, 10, 11, 0))
	for _, v := range []int16{'a', 'e', 'i', 'o', 'u'} {
		e(n20IType(9, 0, 12, v))
		beq(11, 12, "long_append")
	}
	e(n20IType(9, 29, 12, 0x20))
	beq(10, 12, "fail")
	e(n20IType(9, 10, 10, -1))
	jump("vowel_scan")
	b.label("long_append")
	e(n20IType(40, 21, 11, 0))
	e(n20IType(9, 21, 21, 1))
	e(n20IType(9, 22, 22, 1))
	e(n20IType(9, 16, 16, 2))
	e(n20IType(9, 23, 23, 1))
	jump("char_loop")
	b.label("append_syllable")
	e(n20IType(35, 29, 10, 0x48))
	beq(10, 0, "append_chars")
	e(n20IType(36, 14, 11, 0))
	e(n20IType(9, 0, 12, int16('c')))
	bne(11, 12, "not_ch")
	e(n20IType(36, 14, 12, 1))
	e(n20IType(9, 0, 10, int16('h')))
	bne(12, 10, "check_consonant")
	e(n20IType(9, 0, 11, int16('c')))
	jump("write_geminate")
	b.label("not_ch")
	b.label("check_consonant")
	e(n20IType(11, 11, 12, int16('a')))
	bne(12, 0, "fail")
	e(n20IType(11, 11, 12, int16('z'+1)))
	beq(12, 0, "fail")
	for _, v := range []int16{'a', 'e', 'i', 'o', 'u'} {
		e(n20IType(9, 0, 12, v))
		beq(11, 12, "fail")
	}
	b.label("write_geminate")
	e(n20IType(40, 21, 11, 0))
	e(n20IType(9, 21, 21, 1))
	e(n20IType(9, 22, 22, 1))
	e(n20IType(43, 29, 0, 0x48))
	b.label("append_chars")
	e(n20IType(36, 14, 11, 0))
	e(n20IType(40, 21, 11, 0))
	e(n20IType(9, 21, 21, 1))
	e(n20IType(9, 22, 22, 1))
	e(n20IType(9, 14, 14, 1))
	e(n20IType(9, 13, 13, -1))
	bne(13, 0, "append_chars")
	e(n20RType(0, 15, 10, 1, 0))
	e(n20RType(16, 10, 16, 0, 0x21))
	e(n20RType(23, 15, 23, 0, 0x21))
	jump("char_loop")
	b.label("finish_source")
	e(n20IType(35, 29, 10, 0x48))
	bne(10, 0, "fail")
	beq(23, 0, "fail")
	e(n20IType(35, 29, 8, 0x4c))
	beq(8, 0, "preflight")
	e(n20RType(0, 8, 8, 3, 0))
	hi := len(b.words)
	e(n20IType(15, 0, 9, 0))
	lo := len(b.words)
	e(n20IType(13, 9, 9, 0))
	refs = append(refs, n20Ref{hi, lo, table.SuffixOffset})
	e(n20RType(9, 8, 9, 0, 0x21))
	e(n20IType(36, 9, 10, 0))
	e(n20IType(9, 9, 9, 1))
	b.label("append_suffix")
	beq(10, 0, "preflight")
	e(n20IType(11, 22, 11, 32))
	beq(11, 0, "fail")
	e(n20IType(36, 9, 12, 0))
	e(n20IType(40, 21, 12, 0))
	e(n20IType(9, 21, 21, 1))
	e(n20IType(9, 22, 22, 1))
	e(n20IType(9, 9, 9, 1))
	e(n20IType(9, 10, 10, -1))
	jump("append_suffix")
	b.label("preflight")
	e(n20IType(9, 22, 8, 1))
	e(n20IType(12, 8, 8, -2))
	e(n20IType(9, 8, 9, 1))
	e(n20RType(18, 9, 10, 0, 0x2b))
	bne(10, 0, "fail")
	e(n20IType(9, 0, 11, 0))
	e(n20IType(9, 29, 12, 0x20))
	b.label("encode_loop")
	beq(11, 8, "finish_success")
	e(n20RType(11, 22, 13, 0, 0x2b))
	bne(13, 0, "actual_letter")
	e(n20IType(9, 0, 14, 0x20))
	jump("store_letter")
	b.label("actual_letter")
	e(n20IType(36, 12, 14, 0))
	b.label("store_letter")
	bne(11, 0, "not_first")
	e(n20IType(11, 14, 15, 97))
	bne(15, 0, "not_first")
	e(n20IType(11, 14, 15, 123))
	beq(15, 0, "not_first")
	e(n20IType(9, 14, 14, -32))
	b.label("not_first")
	e(n20IType(13, 14, 14, 0x80))
	e(n20IType(40, 17, 14, 0))
	e(n20IType(9, 17, 17, 1))
	e(n20IType(9, 12, 12, 1))
	e(n20IType(9, 11, 11, 1))
	jump("encode_loop")
	b.label("finish_success")
	e(n20IType(40, 17, 0, 0))
	e(n20IType(9, 9, 2, 0))
	jump("restore")
	b.label("fail")
	e(n20IType(9, 0, 2, 0))
	b.label("restore")
	for x := uint32(16); x <= 23; x++ {
		e(n20IType(35, 29, x, int16(0x50+(x-16)*4)))
	}
	e(n20IType(35, 29, 31, 0x70))
	e(0x03e00008)
	e(n20IType(9, 29, 29, 0x90))
	if err := b.resolve(); err != nil {
		return r, err
	}
	r.CodeBytes = len(b.words) * 4
	r.TableBytes = len(table.Bytes)
	r.ProgramBytes = r.CodeBytes + r.TableBytes
	r.SimpleEntries = len(table.Simple)
	r.DigraphEntries = len(table.Digraph)
	r.SecondsEntries = len(table.Seconds)
	r.AlphabetEntries = len(table.Letters)
	r.WaveDashInCode = true
	r.KatakanaNormal = true
	r.TableSHA = sha(table.Bytes)
	if r.CodeBytes != N20PackedCodeBytes || r.TableBytes != N20PackedTableBytes ||
		r.ProgramBytes != N20PackedProgramBytes ||
		r.SimpleEntries != N20PackedSimpleEntries || r.DigraphEntries != N20PackedDigraphEntries ||
		r.SecondsEntries != N20PackedSecondsEntries || r.AlphabetEntries != N20PackedAlphabetCount ||
		r.TableSHA != N20PackedTableSHA {
		return r, fmt.Errorf("N20 romanizer geometry drift code=%d table=%d program=%d simple=%d digraph=%d seconds=%d letters=%d sha=%s",
			r.CodeBytes, r.TableBytes, r.ProgramBytes, r.SimpleEntries, r.DigraphEntries,
			r.SecondsEntries, r.AlphabetEntries, r.TableSHA)
	}
	base := origin + uint32(r.CodeBytes)
	for _, ref := range refs {
		target := base + uint32(ref.off)
		b.words[ref.hi] = n20IType(15, 0, (b.words[ref.hi]>>16)&31, int16(target>>16))
		b.words[ref.lo] = n20IType(13, (b.words[ref.lo]>>21)&31, (b.words[ref.lo]>>16)&31, int16(target&0xffff))
	}
	r.Binary = make([]byte, 0, r.ProgramBytes)
	for _, w := range b.words {
		var slot [4]byte
		binary.LittleEndian.PutUint32(slot[:], w)
		r.Binary = append(r.Binary, slot[:]...)
	}
	r.Binary = append(r.Binary, table.Bytes...)
	r.Words = append([]uint32(nil), b.words...)
	if origin+uint32(len(r.Binary)) > 0x80200000 {
		return r, fmt.Errorf("N20 core extends beyond analysis region")
	}
	return r, nil
}
