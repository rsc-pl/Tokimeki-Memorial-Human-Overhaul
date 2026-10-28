package n20arch

// N20 local player-name coverage extension (audit-only).
//
// The packed romanizer guest romanizer and the host RomanizeKana primitive derive their
// tables from the same internal/playername maps, but they are not identical:
// the host has an explicit fullwidth-wave-dash ('～') -> "~" branch, while the
// packed packed romanizer table has no '～' record and the generated MIPS has no '～'
// special case. The core must therefore reject every name containing '～'.
// That is a real 62,211-three-kana-name coverage gap in the guest core. This
// file models three views explicitly:
//
//   - host primitive: the historical capacity audit's upper bound;
//   - packed romanizer-faithful: host behaviour minus '～';
//   - N20 local: packed romanizer-faithful plus '～' and a small, source-grounded set of
//     missing digraphs.
//
// The local view is now implemented in the actual N6/N6-FP offline bodies by
// romanizer_ext.go. The rebuilt core accepts the same local set and was
// executed on the full grid (2,829,111 / 4,251,528, 0 mismatches); see
// N20_RESULT.md §19. The packed romanizer-faithful view remains the historical baseline
// (2,745,044). This audit keeps all three views so the gain stays attributable.
// The fields below still mean "offline prototype", never a runtime patch.
//
// Every entry below is source-grounded:
//   - every kana is a NAME_ENT keyboard cell (verified by the tests through
//     ParseNameEntryKeyboardRows, not by a hardcoded grid copy);
//   - the romanization is standard/modified Hepburn (or, for '～', the host's
//     established compact "~" display);
//   - the guest wire form is ASCII bytes + one high-bit 0x20 pad when the
//     ASCII length is odd, then NUL, exactly like the existing packed romanizer core.
//
// Rejected as speculative (measured but not added): てゃ/てゅ/てょ,
// でゃ/でゅ/でょ, ふゃ/ふゅ/ふょ and すぃ/ずぃ. They are grid-selectable, but
// the project's existing compact table does not use those foreign extensions
// and their Hepburn spelling is not unambiguous enough for this audit. The
// table also cannot cover standalone small kana, っ or ー: those are invalid
// without a valid context and must stay rejected.

import (
	"fmt"
	"sort"
	"strings"

	pn "tokimemo/internal/playername"
)

// N20LocalMaxKana is the preserved NAME_ENT input limit. The audit enumerates
// only one-, two- and three-kana names; the shim still passes a3=3.
const N20LocalMaxKana = 3

// N20CoverageExtension is one source-grounded supplemental digraph.
type N20CoverageExtension struct {
	Kana       string `json:"kana"`          // normalized hiragana pair
	KanaKata   string `json:"kana_katakana"` // selectable katakana pair
	Roman      string `json:"roman"`         // ASCII Hepburn
	Hepburn    string `json:"hepburns"`      // independent citation string
	RomanBytes int    `json:"roman_bytes"`   // len(Roman)
	WireBytes  int    `json:"wire_bytes_incl_nul"`
	Basis      string `json:"basis"`
}

// N20CoverageGlyphExtension is one source-grounded single-glyph extension.
type N20CoverageGlyphExtension struct {
	Kana       string `json:"kana"`
	Roman      string `json:"roman"`
	Hepburn    string `json:"hepburns"`
	RomanBytes int    `json:"roman_bytes"`
	WireBytes  int    `json:"wire_bytes_incl_nul"`
	Basis      string `json:"basis"`
}

// N20CoverageExtensions is the complete supplemental digraph set. It is
// intentionally small and explicit; a test pins the exact entries.
var N20CoverageExtensions = []N20CoverageExtension{
	{"うぃ", "ウィ", "wi", "wi", 2, 3, "Hepburn ウィ=wi; NAME_ENT selectable"},
	{"うぇ", "ウェ", "we", "we", 2, 3, "Hepburn ウェ=we; NAME_ENT selectable"},
	{"うぉ", "ウォ", "wo", "wo", 2, 3, "Hepburn ウォ=wo; NAME_ENT selectable"},
	{"いぇ", "イェ", "ye", "ye", 2, 3, "Hepburn イェ=ye; NAME_ENT selectable"},
	{"くぁ", "クァ", "kwa", "kwa", 3, 5, "Hepburn クァ=kwa; NAME_ENT selectable"},
	{"くぃ", "クィ", "kwi", "kwi", 3, 5, "Hepburn クィ=kwi; NAME_ENT selectable"},
	{"くぇ", "クェ", "kwe", "kwe", 3, 5, "Hepburn クェ=kwe; NAME_ENT selectable"},
	{"くぉ", "クォ", "kwo", "kwo", 3, 5, "Hepburn クォ=kwo; NAME_ENT selectable"},
	{"ぐぁ", "グァ", "gwa", "gwa", 3, 5, "Hepburn グァ=gwa; NAME_ENT selectable"},
	{"ぐぃ", "グィ", "gwi", "gwi", 3, 5, "Hepburn グィ=gwi; NAME_ENT selectable"},
	{"ぐぇ", "グェ", "gwe", "gwe", 3, 5, "Hepburn グェ=gwe; NAME_ENT selectable"},
	{"ぐぉ", "グォ", "gwo", "gwo", 3, 5, "Hepburn グォ=gwo; NAME_ENT selectable"},
	{"つぁ", "ツァ", "tsa", "tsa", 3, 5, "Hepburn ツァ=tsa; NAME_ENT selectable"},
	{"つぃ", "ツィ", "tsi", "tsi", 3, 5, "Hepburn ツィ=tsi; NAME_ENT selectable"},
	{"つぇ", "ツェ", "tse", "tse", 3, 5, "Hepburn ツェ=tse; NAME_ENT selectable"},
	{"つぉ", "ツォ", "tso", "tso", 3, 5, "Hepburn ツォ=tso; NAME_ENT selectable"},
	{"ぢゃ", "ヂャ", "ja", "ja", 2, 3, "Hepburn ぢゃ=ja (yōon of ぢ); NAME_ENT selectable"},
	{"ぢゅ", "ヂュ", "ju", "ju", 2, 3, "Hepburn ぢゅ=ju (yōon of ぢ); NAME_ENT selectable"},
	{"ぢょ", "ヂョ", "jo", "jo", 2, 3, "Hepburn ぢょ=jo (yōon of ぢ); NAME_ENT selectable"},
}

// N20CoverageGlyphExtensions is the single-glyph addition. '～' is a grid
// cell and the host displays it as '~'; the packed romanizer packed table omits it.
var N20CoverageGlyphExtensions = []N20CoverageGlyphExtension{
	{"～", "~", "~", 1, 3, "NAME_ENT selectable fullwidth wave dash; host maps to ~; 1 ASCII + high-bit pad + NUL; packed romanizer table omits it"},
}

// n20ExtensionMap is read-only after package initialisation.
var n20ExtensionMap = func() map[string]string {
	m := make(map[string]string, len(N20CoverageExtensions))
	for _, e := range N20CoverageExtensions {
		m[e.Kana] = e.Roman
	}
	return m
}()

// N20RomanizeError carries a structural cause so the audit can attribute
// failures without guessing from the host error string.
type N20RomanizeError struct {
	Category string
	Detail   string
}

func (e *N20RomanizeError) Error() string { return e.Category + ": " + e.Detail }

func n20Hira(r rune) rune {
	if r >= 'ァ' && r <= 'ヶ' {
		return r - ('ァ' - 'ぁ')
	}
	return r
}

func n20Kata(r rune) rune {
	if r >= 'ぁ' && r <= 'ゖ' {
		return r + ('ァ' - 'ぁ')
	}
	return r
}

func n20IsVowel(c byte) bool { return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' }
func n20IsConsonant(c byte) bool {
	return c >= 'a' && c <= 'z' && !n20IsVowel(c)
}

func n20LastVowel(s string) byte {
	for i := len(s) - 1; i >= 0; i-- {
		if n20IsVowel(s[i]) {
			return s[i]
		}
	}
	return 0
}

func n20LowerFirst(s string) string {
	if s == "" {
		return s
	}
	b := []byte(s)
	if b[0] >= 'A' && b[0] <= 'Z' {
		b[0] += 'a' - 'A'
	}
	return string(b)
}

var n20SmallKana = map[rune]bool{
	'ゃ': true, 'ゅ': true, 'ょ': true,
	'ぁ': true, 'ぃ': true, 'ぅ': true, 'ぇ': true, 'ぉ': true,
}

// n20Unit returns the romanization of the unit starting at i. A supplemental
// digraph wins first; otherwise a host digraph is only attempted when the next
// rune is a small kana, so a normal two-kana sequence is never greedily
// consumed and cannot hide a later digraph.
func n20Unit(rr []rune, i int, ext map[string]string) (string, int, bool) {
	if i >= len(rr) {
		return "", 0, false
	}
	if i+1 < len(rr) && n20SmallKana[rr[i+1]] {
		if ext != nil {
			if s, ok := ext[string(rr[i:i+2])]; ok {
				return s, 2, true
			}
		}
		if s, err := pn.RomanizeKana(string(rr[i : i+2])); err == nil {
			return n20LowerFirst(s), 2, true
		}
	}
	s, err := pn.RomanizeKana(string(rr[i]))
	if err != nil {
		return "", 0, false
	}
	return n20LowerFirst(s), 1, true
}

// n20Romanize is the shared parser. waveOK=false models the guest packed romanizer core,
// which has no '～' record; waveOK=true models the host primitive/local table.
func n20Romanize(kana string, ext map[string]string, waveOK bool) (string, error) {
	if kana == "" {
		return "", &N20RomanizeError{"empty", "empty name"}
	}
	if !waveOK && strings.ContainsRune(kana, '～') {
		return "", &N20RomanizeError{"packed_romanizer_wave_dash_unsupported", "packed romanizer packed table has no ～ record"}
	}
	rr := []rune(kana)
	for i, r := range rr {
		rr[i] = n20Hira(r)
	}
	var b strings.Builder
	for i := 0; i < len(rr); i++ {
		r := rr[i]
		if r == 'っ' {
			if i+1 >= len(rr) {
				return "", &N20RomanizeError{"sokuon_trailing", "trailing sokuon"}
			}
			next, _, ok := n20Unit(rr, i+1, ext)
			if !ok {
				return "", &N20RomanizeError{"sokuon_invalid_following", "invalid sokuon following"}
			}
			if strings.HasPrefix(next, "ch") {
				b.WriteByte('c')
			} else if n20IsConsonant(next[0]) {
				b.WriteByte(next[0])
			} else {
				return "", &N20RomanizeError{"sokuon_before_vowel", "sokuon before vowel"}
			}
			continue
		}
		if r == '～' {
			b.WriteByte('~')
			continue
		}
		if r == 'ー' {
			v := n20LastVowel(b.String())
			if v == 0 {
				return "", &N20RomanizeError{"long_mark_no_vowel", "long-vowel marker without vowel"}
			}
			b.WriteByte(v)
			continue
		}
		if r == ' ' || r == '　' || r == '・' {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			continue
		}
		if r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' {
			b.WriteRune(r)
			continue
		}
		s, n, ok := n20Unit(rr, i, ext)
		if !ok {
			if n20SmallKana[r] {
				return "", &N20RomanizeError{"standalone_small_kana", string(r)}
			}
			return "", &N20RomanizeError{"unsupported", fmt.Sprintf("U+%04X", r)}
		}
		b.WriteString(s)
		i += n - 1
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		return "", &N20RomanizeError{"empty", "empty name"}
	}
	upperNext := true
	out := []rune(s)
	for i, r := range out {
		if r == ' ' || r == '-' {
			upperNext = true
			continue
		}
		if upperNext {
			out[i] = []rune(strings.ToUpper(string(r)))[0]
			upperNext = false
		}
	}
	return string(out), nil
}

// RomanizeKanaN20Local applies the N20 supplemental table (19 digraphs plus
// '～') on top of the unchanged host primitive. It is a host-side audit helper,
// not the guest packed romanizer core. On any input the host can already romanize it
// returns exactly the host string (proven exhaustively by the tests).
func RomanizeKanaN20Local(kana string) (string, error) {
	return n20Romanize(kana, n20ExtensionMap, true)
}

// RomanizeKanaFaithful models the actual guest packed romanizer core: the host table
// without the '～' special case.
func RomanizeKanaFaithful(kana string) (string, error) {
	return n20Romanize(kana, nil, false)
}

// N20CoverageCount is one kana-length bucket, with all three views.
type N20CoverageCount struct {
	KanaCount            int `json:"kana_count"`
	Entries              int `json:"entries"`
	HostAccepted         int `json:"host_accepted"`
	Accepted             int `json:"packed_romanizer_accepted"`
	LocalAccepted        int `json:"local_accepted"`
	HostUnromanizable    int `json:"host_unromanizable"`
	Unromanizable        int `json:"packed_romanizer_unromanizable"`
	LocalUnromanizable   int `json:"local_unromanizable"`
	HostTooLong          int `json:"host_romanized_but_too_long"`
	TooLong              int `json:"packed_romanizer_romanized_but_too_long"`
	LocalTooLong         int `json:"local_romanized_but_too_long"`
	FixedByLocal         int `json:"fixed_by_local_table"`
	LocalRomanizableGain int `json:"local_romanizable_gain_over_packed_romanizer"`
}

// N20CoverageAudit is the exhaustive grid-derived coverage result.
type N20CoverageAudit struct {
	KeyboardRows  int `json:"keyboard_rows"`
	KeyboardCells int `json:"keyboard_cells"`
	UniqueKana    int `json:"unique_kana"`
	MaxKana       int `json:"max_kana"`

	Singles N20CoverageCount `json:"singles"`
	Pairs   N20CoverageCount `json:"pairs"`
	Triples N20CoverageCount `json:"triples"`

	ExtensionEntries      int                         `json:"extension_entries"`
	PairsFixedByLocal     int                         `json:"pairs_fixed_by_local_table"`
	GlyphExtensionEntries int                         `json:"glyph_extension_entries"`
	Extensions            []N20CoverageExtension      `json:"extensions"`
	GlyphExtensions       []N20CoverageGlyphExtension `json:"glyph_extensions"`

	FixedTotal                            int            `json:"fixed_total"`
	HostOriginalFailureBreakdown          map[string]int `json:"host_original_failure_breakdown"`
	FailureBreakdown                      map[string]int `json:"packed_romanizer_failure_breakdown"`
	LocalRemainingFailureBreakdown        map[string]int `json:"local_remaining_failure_breakdown"`
	TriplesHostOriginalFailureBreakdown   map[string]int `json:"triples_host_original_failure_breakdown"`
	TriplesFailureBreakdown               map[string]int `json:"triples_packed_romanizer_failure_breakdown"`
	TriplesLocalRemainingFailureBreakdown map[string]int `json:"triples_local_remaining_failure_breakdown"`
	HostTooLongByRomanBytes               map[int]int    `json:"host_too_long_by_roman_bytes"`
	TooLongByRomanBytes                   map[int]int    `json:"packed_romanizer_too_long_by_roman_bytes"`
	LocalTooLongByRomanBytes              map[int]int    `json:"local_too_long_by_roman_bytes"`

	HostTriplesAccepted     int     `json:"host_triples_accepted"`
	TriplesAccepted         int     `json:"packed_romanizer_triples_accepted"`
	LocalTriplesAccepted    int     `json:"local_triples_accepted"`
	TriplesAcceptedPct      float64 `json:"packed_romanizer_triples_accepted_pct"`
	LocalTriplesAcceptedPct float64 `json:"local_triples_accepted_pct"`
	ToLocalAcceptedGain     int     `json:"packed_romanizer_to_local_accepted_gain"`

	ShimTableChanged    bool `json:"shim_table_changed"`
	ShimApplied         bool `json:"shim_applied"`
	ShimTriplesAccepted int  `json:"shim_triples_accepted"`

	Verdict string `json:"verdict"`
	Reason  string `json:"reason"`
}

// AuditN20Coverage enumerates every one-, two- and three-kana name in the
// authenticated NAME_ENT grid and reports the host upper bound, the actual packed romanizer
// core and the N20 local table. It does not build a patch, widen a slot or
// change the guest table.
func AuditN20Coverage(nameEnt []byte) (N20CoverageAudit, error) {
	var a N20CoverageAudit
	if len(nameEnt) != 196608 || sha(nameEnt) != OverlaySHA["NAME_ENT.EXN"] {
		return a, fmt.Errorf("NAME_ENT.EXN is not the authenticated original")
	}
	rows, err := pn.ParseNameEntryKeyboardRows(nameEnt)
	if err != nil {
		return a, err
	}
	a.KeyboardRows = len(rows)
	a.MaxKana = N20LocalMaxKana
	seen := map[string]bool{}
	for _, r := range rows {
		for _, c := range r.Cells {
			seen[c.Kana] = true
		}
		a.KeyboardCells++
	}
	kana := make([]string, 0, len(seen))
	for k := range seen {
		kana = append(kana, k)
	}
	sort.Strings(kana)
	a.UniqueKana = len(kana)

	// Every supplemental entry must be grid-selectable.
	for _, e := range N20CoverageExtensions {
		hr := []rune(e.Kana)
		kr := []rune(e.KanaKata)
		if len(hr) != 2 || len(kr) != 2 {
			return a, fmt.Errorf("extension %q is not a two-kana pair", e.Kana)
		}
		if !seen[string(hr[0])] || !seen[string(hr[1])] ||
			!seen[string(kr[0])] || !seen[string(kr[1])] {
			return a, fmt.Errorf("extension %q/%q is not NAME_ENT-selectable", e.Kana, e.KanaKata)
		}
		if e.Roman != e.Hepburn || e.RomanBytes != len(e.Roman) ||
			e.WireBytes != FieldPrepWireBytes(len(e.Roman))+1 {
			return a, fmt.Errorf("extension %q wire geometry drifted", e.Kana)
		}
		if !FieldPrepAcceptedRomanLen(len(e.Roman)) {
			return a, fmt.Errorf("extension %q does not fit the current slot", e.Kana)
		}
		a.Extensions = append(a.Extensions, e)
	}
	for _, e := range N20CoverageGlyphExtensions {
		if !seen[e.Kana] {
			return a, fmt.Errorf("glyph extension %q is not NAME_ENT-selectable", e.Kana)
		}
		if e.Roman != e.Hepburn || e.RomanBytes != len(e.Roman) ||
			e.WireBytes != FieldPrepWireBytes(len(e.Roman))+1 {
			return a, fmt.Errorf("glyph extension %q wire geometry drifted", e.Kana)
		}
		if !FieldPrepAcceptedRomanLen(len(e.Roman)) {
			return a, fmt.Errorf("glyph extension %q does not fit the current slot", e.Kana)
		}
		a.GlyphExtensions = append(a.GlyphExtensions, e)
	}
	a.ExtensionEntries = len(a.Extensions)
	a.GlyphExtensionEntries = len(a.GlyphExtensions)

	a.HostOriginalFailureBreakdown = map[string]int{}
	a.FailureBreakdown = map[string]int{}
	a.LocalRemainingFailureBreakdown = map[string]int{}
	a.HostTooLongByRomanBytes = map[int]int{}
	a.TooLongByRomanBytes = map[int]int{}
	a.LocalTooLongByRomanBytes = map[int]int{}
	hostByN := make([]map[string]int, N20LocalMaxKana+1)
	romanizerCaseByN := make([]map[string]int, N20LocalMaxKana+1)
	localByN := make([]map[string]int, N20LocalMaxKana+1)
	for n := 1; n <= N20LocalMaxKana; n++ {
		hostByN[n] = map[string]int{}
		romanizerCaseByN[n] = map[string]int{}
		localByN[n] = map[string]int{}
		c := &a.Singles
		switch n {
		case 2:
			c = &a.Pairs
		case 3:
			c = &a.Triples
		}
		c.KanaCount = n
		cur := make([]string, n)
		var rec func(int)
		rec = func(idx int) {
			if idx == n {
				c.Entries++
				name := ""
				for _, s := range cur {
					name += s
				}
				hostRoman, hostErr := pn.RomanizeKana(name)
				romanizerCaseRoman, romanizerCaseErr := RomanizeKanaFaithful(name)
				localRoman, localErr := RomanizeKanaN20Local(name)
				wave := strings.ContainsRune(name, '～')

				// Host primitive (historical upper bound).
				if hostErr != nil {
					c.HostUnromanizable++
					_, origErr := n20Romanize(name, nil, true)
					cat := "other"
					if oe, ok := origErr.(*N20RomanizeError); ok {
						cat = oe.Category
					}
					a.HostOriginalFailureBreakdown[cat]++
					hostByN[n][cat]++
				} else if FieldPrepAcceptedRomanLen(len(hostRoman)) {
					c.HostAccepted++
				} else {
					c.HostTooLong++
					a.HostTooLongByRomanBytes[len(hostRoman)]++
				}

				// Actual packed romanizer core.
				if romanizerCaseErr != nil {
					c.Unromanizable++
					cat := "other"
					if wave {
						if hostErr == nil {
							cat = "packed_romanizer_wave_dash_gap"
						} else {
							cat = "packed_romanizer_wave_dash_and_other"
						}
					} else {
						_, origErr := n20Romanize(name, nil, true)
						if oe, ok := origErr.(*N20RomanizeError); ok {
							cat = oe.Category
						}
					}
					a.FailureBreakdown[cat]++
					romanizerCaseByN[n][cat]++
				} else if FieldPrepAcceptedRomanLen(len(romanizerCaseRoman)) {
					c.Accepted++
				} else {
					c.TooLong++
					a.TooLongByRomanBytes[len(romanizerCaseRoman)]++
				}

				// N20 local table.
				if localErr != nil {
					c.LocalUnromanizable++
					cat := "other"
					if le, ok := localErr.(*N20RomanizeError); ok {
						cat = le.Category
					}
					a.LocalRemainingFailureBreakdown[cat]++
					localByN[n][cat]++
				} else if FieldPrepAcceptedRomanLen(len(localRoman)) {
					c.LocalAccepted++
				} else {
					c.LocalTooLong++
					a.LocalTooLongByRomanBytes[len(localRoman)]++
				}
				return
			}
			for _, k := range kana {
				cur[idx] = k
				rec(idx + 1)
			}
		}
		rec(0)
	}
	// Fixed/gain are acceptance deltas over the actual packed romanizer core.
	for _, c := range []*N20CoverageCount{&a.Singles, &a.Pairs, &a.Triples} {
		c.FixedByLocal = c.LocalAccepted - c.Accepted
		c.LocalRomanizableGain = (c.LocalAccepted + c.LocalTooLong) - (c.Accepted + c.TooLong)
		a.FixedTotal += c.FixedByLocal
	}
	a.PairsFixedByLocal = a.Pairs.FixedByLocal
	a.TriplesHostOriginalFailureBreakdown = hostByN[3]
	a.TriplesFailureBreakdown = romanizerCaseByN[3]
	a.TriplesLocalRemainingFailureBreakdown = localByN[3]
	a.HostTriplesAccepted = a.Triples.HostAccepted
	a.TriplesAccepted = a.Triples.Accepted
	a.LocalTriplesAccepted = a.Triples.LocalAccepted
	if a.Triples.Entries > 0 {
		a.TriplesAcceptedPct = float64(a.TriplesAccepted) * 100 / float64(a.Triples.Entries)
		a.LocalTriplesAcceptedPct = float64(a.LocalTriplesAccepted) * 100 / float64(a.Triples.Entries)
	}
	a.ToLocalAcceptedGain = a.LocalTriplesAccepted - a.TriplesAccepted
	a.ShimTableChanged = true
	a.ShimApplied = true // offline N6/N6-FP body integration, not a runtime patch
	a.ShimTriplesAccepted = a.LocalTriplesAccepted
	a.Verdict = "n20_local_table_embedded_offline_no_runtime"
	waveGap := a.FailureBreakdown["packed_romanizer_wave_dash_gap"]
	a.Reason = fmt.Sprintf(
		"authenticated NAME_ENT grid has %d rows and %d unique kana. The host primitive accepts %d/%d three-kana names, but the historical packed romanizer core accepted only %d/%d (%.4f%%) because its packed table had no ～ record; %d three-kana names contain ～ and host-romanize but packed romanizer rejected them. The rebuilt N20 table adds ～ plus %d source-grounded digraphs and the actual N6/N6-FP cores accept %d/%d (%.4f%%) in offline MIPS, a gain of %d accepted names over packed romanizer. %d remain unromanizable locally (%v) and %d remain too long (%v). The 8-byte slot, buffers, loader and EXE are unchanged; safe_to_patch remains false.",
		a.KeyboardRows, a.UniqueKana,
		a.Triples.HostAccepted, a.Triples.Entries,
		a.TriplesAccepted, a.Triples.Entries, a.TriplesAcceptedPct,
		waveGap,
		a.ExtensionEntries,
		a.Triples.LocalAccepted, a.Triples.Entries, a.LocalTriplesAcceptedPct,
		a.ToLocalAcceptedGain,
		a.Triples.LocalUnromanizable, a.LocalRemainingFailureBreakdown,
		a.Triples.LocalTooLong, a.LocalTooLongByRomanBytes)
	return a, nil
}
