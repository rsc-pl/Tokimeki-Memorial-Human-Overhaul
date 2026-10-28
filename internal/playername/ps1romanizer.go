package playername

// previous version: offline-assembled R3000A/PS1 kana-to-pair-font core.
// This is NOT a hook, executable-space discovery or ISO patch. Handles simple
// kana, supported two-kana digraphs, sokuon and long-vowel mark, using the same
// transliteration tables as the host Go romanizer. The caller must provide a
// separately owned and verified output buffer. No original game data is written.
import (
	"encoding/binary"
	"fmt"
	"sort"
)

type PS1RomanizerCore struct {
	Entry                      uint32   `json:"hypothetical_entry"`
	ProgramHexLE               string   `json:"program_hex_little_endian"`
	ProgramBytes               int      `json:"program_bytes"`
	CodeBytes                  int      `json:"code_bytes"`
	TableOffset                int      `json:"table_offset"`
	TableEntries               int      `json:"table_entries"`
	DigraphEntries             int      `json:"digraph_entries"`
	MaxKana                    int      `json:"max_kana"`
	ScratchBytes               int      `json:"scratch_bytes"`
	SupportedSimpleKanaOnly    bool     `json:"supported_simple_kana_only"`
	SupportedDigraphs          bool     `json:"supported_digraphs"`
	SupportedSokuon            bool     `json:"supported_sokuon"`
	SupportedLongVowels        bool     `json:"supported_long_vowels"`
	SupportedSuffixSelector    bool     `json:"supported_suffix_selector"`
	SupportedTwoFieldAssembly  bool     `json:"supported_two_field_assembly"`
	LoadDelayNops              bool     `json:"load_delay_nops"`
	TwoFieldJoinModes          []string `json:"two_field_join_modes,omitempty"`
	SuffixSelectorValues       []string `json:"suffix_selector_values"`
	WritesDestinationOnFailure bool     `json:"writes_destination_on_failure"`
	Installed                  bool     `json:"installed"`
	SafeToPatch                bool     `json:"safe_to_patch"`
	Words                      []uint32 `json:"-"`
	Binary                     []byte   `json:"-"`
}

type kanaTableEntry struct {
	code  uint16
	latin string
}

// The table is generated from the existing host romanizer's single-kana
// syllables, so it cannot silently disagree with that established mapping.
func buildPS1KanaTable() []kanaTableEntry {
	var entries []kanaTableEntry
	for code, r := range cp932Kana {
		normalized := hira(r)
		// Small vowels, small ya/yu/yo, double consonants, long-vowel signs,
		// punctuation and standalone interpuncts require contextual parsing.
		if _, isSmall := contracted[normalized]; isSmall {
			continue
		}
		if normalized == 'っ' || normalized == 'ー' {
			continue
		}
		latin, ok := syllables[normalized]
		if !ok || len(latin) < 1 || len(latin) > 3 {
			continue
		}
		entries = append(entries, kanaTableEntry{code, latin})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].code < entries[j].code })
	return entries
}

// Digraphs are built from the existing host map and CP932 table, including
// mixed hira/kata spellings: Go normalizes EACH code point before lookup.
// A record is [2-byte CP932 first][2-byte CP932 second][ASCII length][3 Latin].
type kanaDigraphEntry struct {
	first, second uint16
	latin         string
}

func buildPS1DigraphTable() []kanaDigraphEntry {
	var out []kanaDigraphEntry
	for firstCode, firstRune := range cp932Kana {
		for secondCode, secondRune := range cp932Kana {
			compound := string([]rune{hira(firstRune), hira(secondRune)})
			if latin, ok := digraph[compound]; ok && len(latin) > 0 && len(latin) <= 3 {
				out = append(out, kanaDigraphEntry{firstCode, secondCode, latin})
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].first == out[j].first {
			return out[i].second < out[j].second
		}
		return out[i].first < out[j].first
	})
	return out
}

func rType(rs, rt, rd, shamt, funct uint32) uint32 {
	return rs<<21 | rt<<16 | rd<<11 | shamt<<6 | funct
}

// BuildPS1RomanizerCore emits a non-installed CP932-to-English pair-font
// converter at a *hypothetical* address. Signature: a0=CP932 NUL string,
// a1=independent output, a2=capacity incl NUL, a3=(suffixSelector<<8)|maxKana.
// Low byte is maxKana 1..5, high bits select 0=none, 1=-kun,
// 2=-san, 3=-chan, 4=-sama, 5=-senpai. A legacy a3=1..5 is unchanged.
// The suffix is supplied explicitly by the calling context, NEVER guessed from
// a player's actual kana, and appended BEFORE pair-font encoding.
// On success v0=bytes including NUL. On any failure v0=0 and the destination
// is untouched. The source MUST be valid addressable memory for the field;
// neither code-cave nor field ownership is established by this generator.
func BuildPS1RomanizerCore(origin uint32) (PS1RomanizerCore, error) {
	return buildPS1RomanizerCore(origin, false, false, false)
}

// BuildPS1NamePairCore emits a SEPARATE, non-installed two-field converter.
// O32 ABI: a0=surname CP932 NUL, a1=output, a2=capacity including NUL,
// a3=(explicitSuffixSelector<<8)|surnameMaxKana (1..3),
// incoming sp+0x10=given-name CP932 NUL pointer, incoming sp+0x14=
// (joinMode<<8)|givenMaxKana (1..3). joinMode 0 concatenates without space,
// joinMode 1 joins with ONE ASCII space and capitalizes given-name initial.
// Both sources are immutable; output must be disjoint, independently owned,
// and large enough. This ABI is for OFFLINE tests ONLY: there is no game hook.
func BuildPS1NamePairCore(origin uint32) (PS1RomanizerCore, error) {
	return buildPS1RomanizerCore(origin, true, true, false)
}

// BuildPS1SafeSingleCore emits a separate previous version single-field converter with
// explicit MIPS-I load-delay slots. The previous version legacy binary is deliberately
// preserved for reproducibility, but MUST NOT be selected for console use:
// its eager-load tests did not model R3000A's one-instruction load hazard.
// This safe variant remains offline / NOT patch-ready until a real hook and
// output ownership have been independently proven.
func BuildPS1SafeSingleCore(origin uint32) (PS1RomanizerCore, error) {
	return buildPS1RomanizerCore(origin, false, true, false)
}

// BuildPS1PackedSafeSingleCore builds the executable, R3000A-load-delay-safe
// single-field core backed by the authenticated 1,424-byte packed table.
// It is an offline candidate, never a game patch or a proof of RAM ownership.
func BuildPS1PackedSafeSingleCore(origin uint32) (PS1RomanizerCore, error) {
	return buildPS1RomanizerCore(origin, false, true, true)
}

func buildPS1RomanizerCore(origin uint32, pair bool, safeLoads bool, packed bool) (PS1RomanizerCore, error) {
	r := PS1RomanizerCore{Entry: origin, MaxKana: 5, ScratchBytes: 32,
		SupportedSimpleKanaOnly: false, SupportedDigraphs: true, SupportedSokuon: true,
		SupportedLongVowels: true, SupportedSuffixSelector: true,
		SuffixSelectorValues: []string{"", "-kun", "-san", "-chan", "-sama", "-senpai"},
		Installed:            false, SafeToPatch: false, WritesDestinationOnFailure: false}
	r.LoadDelayNops = safeLoads
	if pair {
		r.SupportedTwoFieldAssembly = true
		r.LoadDelayNops = true
		r.TwoFieldJoinModes = []string{"concatenated", "single_space"}
	}
	if packed && (pair || !safeLoads) {
		return r, fmt.Errorf("packed requires single safe-load mode")
	}
	if origin < 0x80010000 || origin >= 0x801fffc0 || (!packed && origin > 0x801ff000) || origin%4 != 0 {
		return r, fmt.Errorf("unaligned or out-of-range hypothetical KSEG0 origin")
	}
	simple := buildPS1KanaTable()
	compounds := buildPS1DigraphTable()
	if len(simple) == 0 || len(simple) > 255 || len(compounds) == 0 || len(compounds) > 255 {
		return r, fmt.Errorf("invalid kana/digraph lookup table")
	}
	var b mipsBuf
	b.labels = map[string]int{}
	// previous version safe single + previous version two-field: a NOP after EVERY load so the
	// R3000A load-delay slot cannot consume an old register value. Retain
	// the previous version legacy no-NOP binary solely for regression comparison.
	e := func(w uint32) {
		b.emit(w)
		if safeLoads && (w>>26 == 35 || w>>26 == 36) {
			b.emit(0)
		}
	}
	jump := func(label string) { b.branch(4, 0, 0, label); e(0) }
	beq := func(rs, rt uint32, label string) { b.branch(4, rs, rt, label); e(0) }
	bne := func(rs, rt uint32, label string) { b.branch(5, rs, rt, label); e(0) }
	// Nonvolatile registers and ra saved/restored, 16 B O32 outgoing arg area.
	e(iType(9, 29, 29, -0x90))
	for x := uint32(16); x <= 23; x++ {
		e(iType(43, 29, x, int16(0x50+(x-16)*4)))
	}
	e(iType(43, 29, 31, 0x70))
	e(iType(9, 4, 16, 0)) // s0=source
	e(iType(9, 5, 17, 0)) // s1=output
	e(iType(9, 6, 18, 0)) // s2=capacity
	// a3 packed ABI: [suffix selector in high bits | maxKana in low byte].
	// Store selector in our stack, because s4 is reused for table pointers.
	e(iType(12, 7, 19, 0xff)) // andi s3,a3,0xff => maxKana
	e(rType(0, 7, 8, 8, 2))   // srl t0,a3,8 => suffix selector
	e(iType(43, 29, 8, 0x4c)) // sw t0,0x4c(sp)
	e(iType(9, 29, 21, 0x20)) // s5=scratch cursor
	e(iType(9, 0, 22, 0))     // s6=roman bytes
	e(iType(9, 0, 23, 0))     // s7=consumed kana
	e(iType(43, 29, 0, 0x48)) // pending-sokuon (word), initially zero
	if pair {
		// Incoming O32 stack args are at 0xa0/0xa4 AFTER our 0x90 frame.
		e(iType(35, 29, 8, 0xa0)) // given CP932 source
		beq(8, 0, "fail")
		e(iType(43, 29, 8, 0x80)) // save given pointer
		e(iType(35, 29, 8, 0xa4)) // packed given max + join
		e(iType(12, 8, 9, 0xff))  // t1=givenMax
		beq(9, 0, "fail")
		e(iType(11, 9, 10, 4)) // givenMax <4
		beq(10, 0, "fail")
		e(iType(43, 29, 9, 0x7c)) // save givenMax
		e(rType(0, 8, 8, 8, 2))   // shift right 8 => joinMode
		e(iType(11, 8, 10, 2))    // only 0 and 1 supported
		beq(10, 0, "fail")
		e(iType(43, 29, 8, 0x78)) // save joinMode
		e(iType(43, 29, 0, 0x74)) // phase 0 surname
		e(iType(9, 29, 8, 0x20))
		e(iType(43, 29, 8, 0x88)) // current field ASCII start for vowel mark
		e(iType(9, 0, 8, -1))
		e(iType(43, 29, 8, 0x84)) // no second capitalization unless join=1
		// Pair mode enforces surname max 1..3, without relaxing legacy 1..5.
		e(iType(11, 19, 8, 4))
		beq(8, 0, "fail")
	}
	beq(19, 0, "fail")
	e(iType(35, 29, 8, 0x4c)) // suffix selector
	e(iType(11, 8, 9, 6))     // sltiu t1,t0,6
	beq(9, 0, "fail")         // reject unsupported high bits/selector
	e(iType(11, 19, 8, 6))
	beq(8, 0, "fail")
	b.label("char_loop")
	e(iType(36, 16, 8, 0)) // t0 = CP932 lead
	beq(8, 0, "finish_source")
	e(rType(23, 19, 12, 0, 0x2b)) // t4=s7 < max
	beq(12, 0, "fail")
	e(iType(36, 16, 9, 1)) // t1=trail
	beq(9, 0, "fail")
	// っ/ッ = set a pending gemination; checked against next expanded syllable.
	e(iType(9, 0, 10, 0x82))
	bne(8, 10, "check_kata_sokuon")
	e(iType(9, 0, 10, 0xc1))
	beq(9, 10, "sokuon")
	b.label("check_kata_sokuon")
	e(iType(9, 0, 10, 0x83))
	bne(8, 10, "check_long_mark")
	e(iType(9, 0, 10, 0x62))
	beq(9, 10, "sokuon")
	b.label("check_long_mark")
	// 'ー' CP932 815B: duplicate last vowel (not necessarily last letter).
	e(iType(9, 0, 10, 0x81))
	bne(8, 10, "lookup_digraph_start")
	e(iType(9, 0, 10, 0x5b))
	beq(9, 10, "long_mark")
	b.label("lookup_digraph_start")
	// Only try digraph if another 2-byte code follows. Guard max count.
	e(iType(36, 16, 10, 2)) // t2=next lead
	beq(10, 0, "lookup_simple_init")
	e(iType(9, 23, 11, 1))
	e(rType(11, 19, 12, 0, 0x2b)) // t4=(consumed+1)<max
	beq(12, 0, "lookup_simple_init")
	e(iType(36, 16, 11, 3)) // t3=next trail
	beq(11, 0, "fail")
	// 0x40..0x43 holds one decoded ASCII syllable; 0x44 holds the packed
	// cumulative CP932 key. Both are outside the scratch [0x20,0x40).
	type romanizerCaseRef struct{ hi, lo, off int }
	var romanizerCaseRefs []romanizerCaseRef
	addrRef := func(dst uint32, off int) {
		hi := len(b.words)
		e(iType(15, 0, dst, 0))
		lo := len(b.words)
		e(iType(13, dst, dst, 0))
		romanizerCaseRefs = append(romanizerCaseRefs, romanizerCaseRef{hi, lo, off})
	}
	packedDecode := func(digraph bool) {
		// LE24 packed payload at record offsets 1..3 -> t4.
		e(iType(36, 20, 12, 1))
		e(iType(36, 20, 14, 2))
		e(rType(0, 14, 14, 8, 0))
		e(rType(12, 14, 12, 0, 0x25))
		e(iType(36, 20, 14, 3))
		e(rType(0, 14, 14, 16, 0))
		e(rType(12, 14, 12, 0, 0x25))
		shift := uint32(15)
		base := uint32(0)
		if digraph {
			shift, base = 19, 4
		}
		e(rType(0, 12, 13, shift, 2)) // length = payload >> (15/19)
		e(iType(12, 13, 13, 3))
		addrRef(24, 1344) // alphabet position in packed table
		for i := uint32(0); i < 3; i++ {
			e(rType(0, 12, 14, base+5*i, 2))
			e(iType(12, 14, 14, 31))
			e(rType(24, 14, 14, 0, 0x21))
			e(iType(36, 14, 15, 0))
			e(iType(40, 29, 15, int16(0x40+i)))
		}
		e(iType(9, 29, 14, 0x40)) // t6 ASCII ptr
		n := int16(1)
		if digraph {
			n = 2
		}
		e(iType(9, 0, 15, n)) // t7 consumed kana
		jump("append_syllable")
	}
	if packed {
		addrRef(20, 576) // digraph delta records
		e(iType(9, 0, 13, int16(len(compounds))))
		e(iType(13, 0, 14, int16(compounds[0].first)))
		e(iType(43, 29, 14, 0x44))
		b.label("digraph_loop")
		beq(13, 0, "lookup_simple_init")
		e(iType(36, 20, 14, 0)) // delta
		e(iType(35, 29, 12, 0x44))
		e(rType(12, 14, 12, 0, 0x21))
		e(iType(43, 29, 12, 0x44))
		e(rType(0, 8, 14, 8, 0))
		e(rType(14, 9, 14, 0, 0x25))
		bne(12, 14, "digraph_next")
		// Packed second-code index (payload low nibble) -> BE16 table.
		e(iType(36, 20, 14, 1))
		e(iType(12, 14, 14, 15))
		e(rType(0, 14, 14, 1, 0))
		addrRef(24, 1312)
		e(rType(24, 14, 24, 0, 0x21))
		e(iType(36, 24, 14, 0))
		bne(14, 10, "digraph_next")
		e(iType(36, 24, 14, 1))
		bne(14, 11, "digraph_next")
		packedDecode(true)
		b.label("digraph_next")
		e(iType(9, 20, 20, 4))
		e(iType(9, 13, 13, -1))
		jump("digraph_loop")
		b.label("lookup_simple_init")
		addrRef(20, 2) // simple delta records
		e(iType(9, 0, 11, int16(len(simple))))
		e(iType(13, 0, 14, int16(simple[0].code)))
		e(iType(43, 29, 14, 0x44))
		b.label("simple_loop")
		beq(11, 0, "fail")
		e(iType(36, 20, 14, 0))
		e(iType(35, 29, 12, 0x44))
		e(rType(12, 14, 12, 0, 0x21))
		e(iType(43, 29, 12, 0x44))
		e(rType(0, 8, 14, 8, 0))
		e(rType(14, 9, 14, 0, 0x25))
		bne(12, 14, "simple_next")
		packedDecode(false)
		b.label("simple_next")
		e(iType(9, 20, 20, 4))
		e(iType(9, 11, 11, -1))
		jump("simple_loop")
	} else {
		digHi := len(b.words)
		e(iType(15, 0, 20, 0))
		digLo := len(b.words)
		e(iType(13, 20, 20, 0))
		romanizerCaseRefs = append(romanizerCaseRefs, romanizerCaseRef{digHi, digLo, -2})
		e(iType(9, 0, 13, int16(len(compounds))))
		b.label("digraph_loop")
		beq(13, 0, "lookup_simple_init")
		e(iType(36, 20, 14, 0))
		bne(14, 8, "digraph_next")
		e(iType(36, 20, 14, 1))
		bne(14, 9, "digraph_next")
		e(iType(36, 20, 14, 2))
		bne(14, 10, "digraph_next")
		e(iType(36, 20, 14, 3))
		bne(14, 11, "digraph_next")
		e(iType(36, 20, 13, 4))
		e(iType(9, 20, 14, 5))
		e(iType(9, 0, 15, 2))
		jump("append_syllable")
		b.label("digraph_next")
		e(iType(9, 20, 20, 8))
		e(iType(9, 13, 13, -1))
		jump("digraph_loop")
		b.label("lookup_simple_init")
		simHi := len(b.words)
		e(iType(15, 0, 20, 0))
		simLo := len(b.words)
		e(iType(13, 20, 20, 0))
		romanizerCaseRefs = append(romanizerCaseRefs, romanizerCaseRef{simHi, simLo, -1})
		e(iType(9, 0, 11, int16(len(simple))))
		b.label("simple_loop")
		beq(11, 0, "fail")
		e(iType(36, 20, 10, 0))
		bne(10, 8, "simple_next")
		e(iType(36, 20, 10, 1))
		bne(10, 9, "simple_next")
		e(iType(36, 20, 13, 2))
		e(iType(9, 20, 14, 3))
		e(iType(9, 0, 15, 1))
		jump("append_syllable")
		b.label("simple_next")
		e(iType(9, 20, 20, 8))
		e(iType(9, 11, 11, -1))
		jump("simple_loop")
	}
	b.label("sokuon")
	e(iType(35, 29, 10, 0x48))
	bne(10, 0, "fail") // repeat sokuon not supported by host
	e(iType(9, 0, 10, 1))
	e(iType(43, 29, 10, 0x48))
	e(iType(9, 16, 16, 2))
	e(iType(9, 23, 23, 1))
	jump("char_loop")
	b.label("long_mark")
	// Pending sokuon before vowel mark is invalid.
	e(iType(35, 29, 10, 0x48))
	bne(10, 0, "fail")
	beq(22, 0, "fail")
	if pair {
		e(iType(11, 22, 12, 32)) // scratch bound for long mark
		beq(12, 0, "fail")
	}
	e(iType(9, 21, 10, -1)) // scan scratch backwards
	b.label("vowel_scan")
	if pair {
		e(iType(35, 29, 12, 0x88))
		e(rType(10, 12, 13, 0, 0x2b)) // t5 = cursor < segment start
		bne(13, 0, "fail")
	}
	e(iType(36, 10, 11, 0))
	// Five explicit comparisons, each -> append vowel.
	for _, v := range []int16{'a', 'e', 'i', 'o', 'u'} {
		e(iType(9, 0, 12, v))
		beq(11, 12, "long_append")
	}
	e(iType(9, 29, 12, 0x20))
	beq(10, 12, "fail")
	e(iType(9, 10, 10, -1))
	jump("vowel_scan")
	b.label("long_append")
	e(iType(40, 21, 11, 0))
	e(iType(9, 21, 21, 1))
	e(iType(9, 22, 22, 1))
	e(iType(9, 16, 16, 2))
	e(iType(9, 23, 23, 1))
	jump("char_loop")
	b.label("append_syllable")
	// t6 points at ASCII, t5 length, t7 consumed codepoints.
	// For pending っ, generate consonant before the next syllable; 'ch' -> 'c'.
	e(iType(35, 29, 10, 0x48))
	beq(10, 0, "append_chars")
	e(iType(36, 14, 11, 0)) // first Latin byte
	// If 'ch...' -> prepend 'c'; else prepend any consonant other than vowel.
	e(iType(9, 0, 12, int16('c')))
	bne(11, 12, "not_ch")
	e(iType(36, 14, 12, 1))
	e(iType(9, 0, 10, int16('h')))
	bne(12, 10, "check_consonant")
	e(iType(9, 0, 11, int16('c')))
	jump("write_geminate")
	b.label("not_ch")
	b.label("check_consonant")
	// a/e/i/o/u cannot geminate; c..z non-vowels can.
	e(iType(11, 11, 12, int16('a')))
	bne(12, 0, "fail")
	e(iType(11, 11, 12, int16('z'+1)))
	beq(12, 0, "fail")
	for _, v := range []int16{'a', 'e', 'i', 'o', 'u'} {
		e(iType(9, 0, 12, v))
		beq(11, 12, "fail")
	}
	b.label("write_geminate")
	if pair {
		e(iType(11, 22, 12, 32))
		beq(12, 0, "fail")
	}
	e(iType(40, 21, 11, 0))
	e(iType(9, 21, 21, 1))
	e(iType(9, 22, 22, 1))
	e(iType(43, 29, 0, 0x48))
	b.label("append_chars")
	if pair {
		e(iType(11, 22, 12, 32))
		beq(12, 0, "fail")
	}
	e(iType(36, 14, 11, 0))
	e(iType(40, 21, 11, 0))
	e(iType(9, 21, 21, 1))
	e(iType(9, 22, 22, 1))
	e(iType(9, 14, 14, 1))
	e(iType(9, 13, 13, -1))
	bne(13, 0, "append_chars")
	// advance source pointer by 2/4 and consumed codepoint count by 1/2
	e(rType(0, 15, 10, 1, 0))     // sll t2,t7,1
	e(rType(16, 10, 16, 0, 0x21)) // addu s0,s0,t2
	e(rType(23, 15, 23, 0, 0x21)) // addu s7,s7,t7
	jump("char_loop")
	b.label("finish_source")
	e(iType(35, 29, 10, 0x48))
	bne(10, 0, "fail")
	beq(23, 0, "fail")
	if pair {
		// End of surname: switch to given name only once; source/scratch
		// bytes stay separate. A nonempty second field is checked below.
		e(iType(35, 29, 8, 0x74)) // phase 0 surname, 1 given
		bne(8, 0, "both_fields_done")
		e(iType(9, 0, 8, 1))
		e(iType(43, 29, 8, 0x74)) // phase=1
		e(iType(35, 29, 8, 0x78)) // joinMode
		beq(8, 0, "start_given")
		// Append a literal separator to scratch BEFORE pair packing.
		e(iType(11, 22, 10, 32))
		beq(10, 0, "fail")
		e(iType(9, 0, 10, 0x20))
		e(iType(40, 21, 10, 0))
		e(iType(9, 21, 21, 1))
		e(iType(9, 22, 22, 1))
		e(iType(43, 29, 22, 0x84)) // capitalize second name at ASCII index
		b.label("start_given")
		e(iType(43, 29, 21, 0x88)) // prevent ー from looking into surname
		e(iType(35, 29, 16, 0x80)) // source = given
		e(iType(35, 29, 19, 0x7c)) // maxKana = given max
		e(iType(9, 0, 23, 0))      // consumed count reset
		jump("char_loop")
		b.label("both_fields_done")
	}
	// previous version: append an explicitly selected ASCII honorific to the local scratch.
	// All changes are SCRATCH ONLY until final capacity preflight succeeds.
	e(iType(35, 29, 8, 0x4c)) // selector
	beq(8, 0, "preflight")
	e(rType(0, 8, 8, 3, 0)) // sll t0,t0,3 => suffix table record 8 bytes
	suffixHi := len(b.words)
	e(iType(15, 0, 9, 0))
	suffixLo := len(b.words)
	e(iType(13, 9, 9, 0))
	romanizerCaseRefs = append(romanizerCaseRefs, romanizerCaseRef{suffixHi, suffixLo, -3})
	e(rType(9, 8, 9, 0, 0x21)) // addu t1,t1,t0
	e(iType(36, 9, 10, 0))     // t2=length (<=7)
	e(iType(9, 9, 9, 1))       // t1 points at ASCII
	b.label("append_suffix")
	beq(10, 0, "preflight")
	e(iType(11, 22, 11, 32)) // ensure scratch has free byte
	beq(11, 0, "fail")
	e(iType(36, 9, 12, 0))
	e(iType(40, 21, 12, 0))
	e(iType(9, 21, 21, 1))
	e(iType(9, 22, 22, 1))
	e(iType(9, 9, 9, 1))
	e(iType(9, 10, 10, -1))
	jump("append_suffix")
	b.label("preflight")
	// preflight FINAL byte count incl paired padding and NUL.
	e(iType(9, 22, 8, 1))
	e(iType(12, 8, 8, -2))
	e(iType(9, 8, 9, 1))
	e(rType(18, 9, 10, 0, 0x2b))
	bne(10, 0, "fail")
	e(iType(9, 0, 11, 0))
	e(iType(9, 29, 12, 0x20))
	b.label("encode_loop")
	beq(11, 8, "finish_success")
	e(rType(11, 22, 13, 0, 0x2b))
	bne(13, 0, "actual_letter")
	e(iType(9, 0, 14, 0x20))
	jump("store_letter")
	b.label("actual_letter")
	e(iType(36, 12, 14, 0))
	b.label("store_letter")
	if pair {
		beq(11, 0, "capitalize_initial")
		e(iType(35, 29, 24, 0x84)) // t8; preserve t0 = encoded length
		bne(11, 24, "not_first")
		b.label("capitalize_initial")
	} else {
		bne(11, 0, "not_first")
	}
	e(iType(11, 14, 15, 97))
	bne(15, 0, "not_first")
	e(iType(11, 14, 15, 123))
	beq(15, 0, "not_first")
	e(iType(9, 14, 14, -32))
	b.label("not_first")
	e(iType(13, 14, 14, 0x80))
	e(iType(40, 17, 14, 0))
	e(iType(9, 17, 17, 1))
	e(iType(9, 12, 12, 1))
	e(iType(9, 11, 11, 1))
	jump("encode_loop")
	b.label("finish_success")
	e(iType(40, 17, 0, 0))
	e(iType(9, 9, 2, 0))
	jump("restore")
	b.label("fail")
	e(iType(9, 0, 2, 0))
	b.label("restore")
	for x := uint32(16); x <= 23; x++ {
		e(iType(35, 29, x, int16(0x50+(x-16)*4)))
	}
	e(iType(35, 29, 31, 0x70))
	e(0x03e00008)
	e(iType(9, 29, 29, 0x90))
	if err := b.resolve(); err != nil {
		return r, err
	}
	r.CodeBytes = len(b.words) * 4
	r.TableOffset = r.CodeBytes
	var blob []byte
	if packed {
		data, err := BuildPS1PackedRomanizationTable()
		if err != nil {
			return r, err
		}
		base := origin + uint32(r.CodeBytes)
		for _, ref := range romanizerCaseRefs {
			offset := ref.off
			if offset == -3 {
				offset = 1376
			}
			if offset < 0 {
				return r, fmt.Errorf("invalid packed-table address")
			}
			target := base + uint32(offset)
			b.words[ref.hi] = iType(15, 0, (b.words[ref.hi]>>16)&31, int16(target>>16))
			b.words[ref.lo] = iType(13, (b.words[ref.lo]>>21)&31, (b.words[ref.lo]>>16)&31, int16(target&0xffff))
		}
		blob = make([]byte, 0, r.CodeBytes+len(data))
		for _, w := range b.words {
			var slot [4]byte
			binary.LittleEndian.PutUint32(slot[:], w)
			blob = append(blob, slot[:]...)
		}
		blob = append(blob, data...)
	} else {
		simpleAddr := origin + uint32(r.CodeBytes)
		digAddr := simpleAddr + uint32(len(simple)*8)
		suffixAddr := digAddr + uint32(len(compounds)*8)
		for _, ref := range romanizerCaseRefs {
			var target uint32
			switch ref.off {
			case -1:
				target = simpleAddr
			case -2:
				target = digAddr
			case -3:
				target = suffixAddr
			default:
				return r, fmt.Errorf("bad reference")
			}
			b.words[ref.hi] = iType(15, 0, (b.words[ref.hi]>>16)&31, int16(target>>16))
			b.words[ref.lo] = iType(13, (b.words[ref.lo]>>21)&31, (b.words[ref.lo]>>16)&31, int16(target&0xffff))
		}
		blob = make([]byte, 0, len(b.words)*4+(len(simple)+len(compounds))*8)
		for _, w := range b.words {
			var slot [4]byte
			binary.LittleEndian.PutUint32(slot[:], w)
			blob = append(blob, slot[:]...)
		}
		for _, k := range simple {
			blob = append(blob, byte(k.code>>8), byte(k.code), byte(len(k.latin)))
			var ascii [3]byte
			copy(ascii[:], k.latin)
			blob = append(blob, ascii[:]...)
			blob = append(blob, 0, 0)
		}
		for _, k := range compounds {
			blob = append(blob, byte(k.first>>8), byte(k.first), byte(k.second>>8), byte(k.second), byte(len(k.latin)))
			var ascii [3]byte
			copy(ascii[:], k.latin)
			blob = append(blob, ascii[:]...)
		}
		for _, suffix := range r.SuffixSelectorValues {
			if len(suffix) > 7 {
				return r, fmt.Errorf("suffix exceeds fixed slot")
			}
			record := [8]byte{byte(len(suffix))}
			copy(record[1:], suffix)
			blob = append(blob, record[:]...)
		}
	}
	if origin+uint32(len(blob)) > 0x80200000 {
		return r, fmt.Errorf("core extends beyond analysis region")
	}
	r.TableEntries = len(simple)
	r.DigraphEntries = len(compounds)
	r.ProgramBytes = len(blob)
	r.ProgramHexLE = fmt.Sprintf("%x", blob)
	r.Words = append([]uint32(nil), b.words...)
	r.Binary = blob
	return r, nil
}
