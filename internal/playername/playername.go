// Package playername provides strict, allocation-limited decoding and Hepburn-style
// transcription of the kana portions of PS1 CP932 player-name fields.
// This is a host-side component, NOT an injected PlayStation runtime hook.
package playername

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"
)

// cp932Kana is deliberately restricted to kana and punctuation. Unexpected Kanji,
// unmapped bytes and invalid double-byte pairs MUST fail instead of guessing.
var cp932Kana = map[uint16]rune{
	0x8140: '\u3000',
	0x8145: '・',
	0x815B: 'ー',
	0x8160: '～', // CP932 fullwidth wave dash, distinct from kana vowel-length marker
	0x829F: 'ぁ',
	0x82A0: 'あ',
	0x82A1: 'ぃ',
	0x82A2: 'い',
	0x82A3: 'ぅ',
	0x82A4: 'う',
	0x82A5: 'ぇ',
	0x82A6: 'え',
	0x82A7: 'ぉ',
	0x82A8: 'お',
	0x82A9: 'か',
	0x82AA: 'が',
	0x82AB: 'き',
	0x82AC: 'ぎ',
	0x82AD: 'く',
	0x82AE: 'ぐ',
	0x82AF: 'け',
	0x82B0: 'げ',
	0x82B1: 'こ',
	0x82B2: 'ご',
	0x82B3: 'さ',
	0x82B4: 'ざ',
	0x82B5: 'し',
	0x82B6: 'じ',
	0x82B7: 'す',
	0x82B8: 'ず',
	0x82B9: 'せ',
	0x82BA: 'ぜ',
	0x82BB: 'そ',
	0x82BC: 'ぞ',
	0x82BD: 'た',
	0x82BE: 'だ',
	0x82BF: 'ち',
	0x82C0: 'ぢ',
	0x82C1: 'っ',
	0x82C2: 'つ',
	0x82C3: 'づ',
	0x82C4: 'て',
	0x82C5: 'で',
	0x82C6: 'と',
	0x82C7: 'ど',
	0x82C8: 'な',
	0x82C9: 'に',
	0x82CA: 'ぬ',
	0x82CB: 'ね',
	0x82CC: 'の',
	0x82CD: 'は',
	0x82CE: 'ば',
	0x82CF: 'ぱ',
	0x82D0: 'ひ',
	0x82D1: 'び',
	0x82D2: 'ぴ',
	0x82D3: 'ふ',
	0x82D4: 'ぶ',
	0x82D5: 'ぷ',
	0x82D6: 'へ',
	0x82D7: 'べ',
	0x82D8: 'ぺ',
	0x82D9: 'ほ',
	0x82DA: 'ぼ',
	0x82DB: 'ぽ',
	0x82DC: 'ま',
	0x82DD: 'み',
	0x82DE: 'む',
	0x82DF: 'め',
	0x82E0: 'も',
	0x82E1: 'ゃ',
	0x82E2: 'や',
	0x82E3: 'ゅ',
	0x82E4: 'ゆ',
	0x82E5: 'ょ',
	0x82E6: 'よ',
	0x82E7: 'ら',
	0x82E8: 'り',
	0x82E9: 'る',
	0x82EA: 'れ',
	0x82EB: 'ろ',
	0x82EC: 'ゎ',
	0x82ED: 'わ',
	0x82EE: 'ゐ',
	0x82EF: 'ゑ',
	0x82F0: 'を',
	0x82F1: 'ん',
	0x8340: 'ァ',
	0x8341: 'ア',
	0x8342: 'ィ',
	0x8343: 'イ',
	0x8344: 'ゥ',
	0x8345: 'ウ',
	0x8346: 'ェ',
	0x8347: 'エ',
	0x8348: 'ォ',
	0x8349: 'オ',
	0x834A: 'カ',
	0x834B: 'ガ',
	0x834C: 'キ',
	0x834D: 'ギ',
	0x834E: 'ク',
	0x834F: 'グ',
	0x8350: 'ケ',
	0x8351: 'ゲ',
	0x8352: 'コ',
	0x8353: 'ゴ',
	0x8354: 'サ',
	0x8355: 'ザ',
	0x8356: 'シ',
	0x8357: 'ジ',
	0x8358: 'ス',
	0x8359: 'ズ',
	0x835A: 'セ',
	0x835B: 'ゼ',
	0x835C: 'ソ',
	0x835D: 'ゾ',
	0x835E: 'タ',
	0x835F: 'ダ',
	0x8360: 'チ',
	0x8361: 'ヂ',
	0x8362: 'ッ',
	0x8363: 'ツ',
	0x8364: 'ヅ',
	0x8365: 'テ',
	0x8366: 'デ',
	0x8367: 'ト',
	0x8368: 'ド',
	0x8369: 'ナ',
	0x836A: 'ニ',
	0x836B: 'ヌ',
	0x836C: 'ネ',
	0x836D: 'ノ',
	0x836E: 'ハ',
	0x836F: 'バ',
	0x8370: 'パ',
	0x8371: 'ヒ',
	0x8372: 'ビ',
	0x8373: 'ピ',
	0x8374: 'フ',
	0x8375: 'ブ',
	0x8376: 'プ',
	0x8377: 'ヘ',
	0x8378: 'ベ',
	0x8379: 'ペ',
	0x837A: 'ホ',
	0x837B: 'ボ',
	0x837C: 'ポ',
	0x837D: 'マ',
	0x837E: 'ミ',
	0x8380: 'ム',
	0x8381: 'メ',
	0x8382: 'モ',
	0x8383: 'ャ',
	0x8384: 'ヤ',
	0x8385: 'ュ',
	0x8386: 'ユ',
	0x8387: 'ョ',
	0x8388: 'ヨ',
	0x8389: 'ラ',
	0x838A: 'リ',
	0x838B: 'ル',
	0x838C: 'レ',
	0x838D: 'ロ',
	0x838E: 'ヮ',
	0x838F: 'ワ',
	0x8390: 'ヰ',
	0x8391: 'ヱ',
	0x8392: 'ヲ',
	0x8393: 'ン',
	0x8394: 'ヴ',
	0x8395: 'ヵ',
	0x8396: 'ヶ',
}

// DecodeCP932Kana decodes an exact CP932 string, optionally ending at the first
// NUL. Bytes following a NUL are not read or transliterated. The name field
// itself is never modified. All unsupported values produce an error.
func DecodeCP932Kana(raw []byte) (string, error) {
	if len(raw) > 128 {
		return "", errors.New("CP932 field exceeds 128-byte engineering bound")
	}
	var b strings.Builder
	for i := 0; i < len(raw); {
		v := raw[i]
		if v == 0 {
			break
		}
		if v < 0x80 {
			if v < 0x20 || v > 0x7E {
				return "", fmt.Errorf("unsupported control 0x%02x at byte %d", v, i)
			}
			b.WriteByte(v)
			i++
			continue
		}
		if i+1 >= len(raw) {
			return "", fmt.Errorf("truncated CP932 pair at byte %d", i)
		}
		key := uint16(v)<<8 | uint16(raw[i+1])
		c, ok := cp932Kana[key]
		if !ok {
			return "", fmt.Errorf("unsupported CP932 pair 0x%04x at byte %d", key, i)
		}
		b.WriteRune(c)
		i += 2
	}
	return b.String(), nil
}

var syllables = map[rune]string{
	'あ': "a", 'い': "i", 'う': "u", 'え': "e", 'お': "o",
	'か': "ka", 'き': "ki", 'く': "ku", 'け': "ke", 'こ': "ko",
	'が': "ga", 'ぎ': "gi", 'ぐ': "gu", 'げ': "ge", 'ご': "go",
	'さ': "sa", 'し': "shi", 'す': "su", 'せ': "se", 'そ': "so",
	'ざ': "za", 'じ': "ji", 'ず': "zu", 'ぜ': "ze", 'ぞ': "zo",
	'た': "ta", 'ち': "chi", 'つ': "tsu", 'て': "te", 'と': "to",
	'だ': "da", 'ぢ': "ji", 'づ': "zu", 'で': "de", 'ど': "do",
	'な': "na", 'に': "ni", 'ぬ': "nu", 'ね': "ne", 'の': "no",
	'は': "ha", 'ひ': "hi", 'ふ': "fu", 'へ': "he", 'ほ': "ho",
	'ば': "ba", 'び': "bi", 'ぶ': "bu", 'べ': "be", 'ぼ': "bo",
	'ぱ': "pa", 'ぴ': "pi", 'ぷ': "pu", 'ぺ': "pe", 'ぽ': "po",
	'ま': "ma", 'み': "mi", 'む': "mu", 'め': "me", 'も': "mo",
	'や': "ya", 'ゆ': "yu", 'よ': "yo",
	'ら': "ra", 'り': "ri", 'る': "ru", 'れ': "re", 'ろ': "ro",
	'わ': "wa", 'を': "o", 'ん': "n", 'ゔ': "vu",
	'ぁ': "a", 'ぃ': "i", 'ぅ': "u", 'ぇ': "e", 'ぉ': "o",
}
var contracted = map[rune]string{'ゃ': "a", 'ゅ': "u", 'ょ': "o", 'ぁ': "a", 'ぃ': "i", 'ぅ': "u", 'ぇ': "e", 'ぉ': "o"}
var digraph = map[string]string{
	"きゃ": "kya", "きゅ": "kyu", "きょ": "kyo", "ぎゃ": "gya", "ぎゅ": "gyu", "ぎょ": "gyo",
	"しゃ": "sha", "しゅ": "shu", "しょ": "sho", "じゃ": "ja", "じゅ": "ju", "じょ": "jo",
	"ちゃ": "cha", "ちゅ": "chu", "ちょ": "cho", "にゃ": "nya", "にゅ": "nyu", "にょ": "nyo",
	"ひゃ": "hya", "ひゅ": "hyu", "ひょ": "hyo", "びゃ": "bya", "びゅ": "byu", "びょ": "byo",
	"ぴゃ": "pya", "ぴゅ": "pyu", "ぴょ": "pyo", "みゃ": "mya", "みゅ": "myu", "みょ": "myo",
	"りゃ": "rya", "りゅ": "ryu", "りょ": "ryo",
	"ふぁ": "fa", "ふぃ": "fi", "ふぇ": "fe", "ふぉ": "fo", "てぃ": "ti", "でぃ": "di",
	"とぅ": "tu", "どぅ": "du", "しぇ": "she", "ちぇ": "che", "じぇ": "je",
	"ゔぁ": "va", "ゔぃ": "vi", "ゔぇ": "ve", "ゔぉ": "vo",
}

func hira(r rune) rune {
	if r >= 'ァ' && r <= 'ヶ' {
		return r - ('ァ' - 'ぁ')
	}
	return r
}
func isVowel(c byte) bool { return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u' }
func lastVowel(s string) byte {
	for i := len(s) - 1; i >= 0; i-- {
		if isVowel(s[i]) {
			return s[i]
		}
	}
	return 0
}
func isConsonant(c byte) bool { return c >= 'a' && c <= 'z' && !isVowel(c) }

// RomanizeKana returns ASCII Hepburn-style spelling without changing long-vowel
// conventions into unrequested macrons. Ambiguous or unsupported glyphs fail.
// This is a linguistic conversion primitive, NOT a runtime buffer-capacity proof.
func RomanizeKana(kana string) (string, error) {
	if len(kana) > 512 {
		return "", errors.New("name exceeds preview bound")
	}
	if kana == "" {
		return "", errors.New("empty name")
	}
	rr := []rune(kana)
	for i, r := range rr {
		rr[i] = hira(r)
	}
	var b strings.Builder
	for i := 0; i < len(rr); i++ {
		r := rr[i]
		if r == 'っ' {
			if i+1 >= len(rr) {
				return "", fmt.Errorf("trailing sokuon")
			}
			next := ""
			if i+2 < len(rr) {
				next = digraph[string(rr[i+1:i+3])]
			}
			if next == "" {
				next = syllables[rr[i+1]]
			}
			if next == "" {
				return "", fmt.Errorf("invalid sokuon following %q", rr[i+1])
			}
			if strings.HasPrefix(next, "ch") {
				b.WriteByte('c')
			} else if isConsonant(next[0]) {
				b.WriteByte(next[0])
			} else {
				return "", errors.New("sokuon before vowel")
			}
			continue
		}
		if r == '～' {
			// This is the selectable fullwidth wave mark, not a chōonpu.
			// Never extend the previous vowel or turn it into '-'.
			b.WriteByte('~')
			continue
		}
		if r == 'ー' {
			v := lastVowel(b.String())
			if v == 0 {
				return "", errors.New("long-vowel marker without vowel")
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
		if i+1 < len(rr) {
			if d, ok := digraph[string(rr[i:i+2])]; ok {
				b.WriteString(d)
				i++
				continue
			}
		}
		// Compact game-display spelling omits Hepburn separator apostrophes.
		// Strict romanization with apostrophes is not the preferred in-game UI form.
		if r == 'ん' {
			if i+1 < len(rr) {
				n := rr[i+1]
				if n == 'あ' || n == 'い' || n == 'う' || n == 'え' || n == 'お' || n == 'や' || n == 'ゆ' || n == 'よ' || n == 'な' || n == 'に' || n == 'ぬ' || n == 'ね' || n == 'の' {
					b.WriteByte('n')
					continue
				}
			}
			b.WriteByte('n')
			continue
		}
		if _, ok := contracted[r]; ok {
			return "", fmt.Errorf("standalone small kana %q", r)
		}
		v, ok := syllables[r]
		if !ok {
			return "", fmt.Errorf("unsupported name character U+%04X", r)
		}
		b.WriteString(v)
	}
	s := strings.TrimSpace(b.String())
	if s == "" {
		return "", errors.New("empty name")
	}
	if !utf8.ValidString(s) {
		return "", errors.New("invalid transcription")
	}
	// Name segments are capitalized, honorifics are appended separately.
	upperNext := true
	result := []rune(s)
	for i, r := range result {
		if r == ' ' || r == '-' {
			upperNext = true
			continue
		}
		if upperNext {
			result[i] = unicode.ToUpper(r)
			upperNext = false
		}
	}
	return string(result), nil
}

var honorifics = map[string]string{"": "", "君": "-kun", "くん": "-kun", "クン": "-kun", "さん": "-san", "サン": "-san", "ちゃん": "-chan", "チャン": "-chan", "様": "-sama", "さま": "-sama", "先輩": "-senpai", "せんぱい": "-senpai"}

// AddressName returns natural English text around a Japanese name and its
// separately identified honorific. Never infer the honorific from name gender.
func AddressName(name, suffix string) (string, error) {
	h, ok := honorifics[suffix]
	if !ok {
		return "", fmt.Errorf("unrecognized honorific %q", suffix)
	}
	r, err := RomanizeKana(name)
	if err != nil {
		return "", err
	}
	return r + h, nil
}

// DecodeAddressCP932 handles a single raw PS1 field that already contains
// both player kana and a Japanese honorific. It also supports names with no
// honorific; the exact supported suffix is removed before kana decoding.
// Callers must still prove where game memory stores this field.
func DecodeAddressCP932(raw []byte) (string, error) {
	if len(raw) > 128 {
		return "", errors.New("CP932 field exceeds 128-byte engineering bound")
	}
	if i := bytes.IndexByte(raw, 0); i >= 0 {
		raw = raw[:i]
	}
	if len(raw) == 0 {
		return "", errors.New("empty CP932 player address")
	}
	for _, candidate := range cp932Suffixes {
		if len(raw) > len(candidate.bytes) && bytes.HasSuffix(raw, candidate.bytes) {
			kana, e := DecodeCP932Kana(raw[:len(raw)-len(candidate.bytes)])
			if e != nil {
				return "", e
			}
			return AddressName(kana, candidate.jp)
		}
	}
	kana, e := DecodeCP932Kana(raw)
	if e != nil {
		return "", e
	}
	return AddressName(kana, "")
}

type rawSuffix struct {
	jp    string
	bytes []byte
}

var cp932Suffixes = []rawSuffix{
	{"せんぱい", []byte{0x82, 0xb9, 0x82, 0xf1, 0x82, 0xcf, 0x82, 0xa2}},
	{"ちゃん", []byte{0x82, 0xbf, 0x82, 0xe1, 0x82, 0xf1}},
	{"さん", []byte{0x82, 0xb3, 0x82, 0xf1}},
	{"くん", []byte{0x82, 0xad, 0x82, 0xf1}},
	{"君", []byte{0x8c, 0x4e}},
	{"様", []byte{0x97, 0x6c}},
}

var unicodeToCP932Kana = func() map[rune]uint16 {
	m := make(map[rune]uint16, len(cp932Kana))
	for k, r := range cp932Kana {
		m[r] = k
	}
	return m
}()

// EncodeCP932Kana encodes only the known kana subset and plain ASCII into the
// exact byte sequence used for read-only RAM searching. It has no NUL terminator.
func EncodeCP932Kana(kana string) ([]byte, error) {
	if len(kana) == 0 || len(kana) > 128 {
		return nil, errors.New("invalid kana query length")
	}
	out := make([]byte, 0, 2*len(kana))
	for _, r := range kana {
		if r >= 32 && r <= 126 {
			out = append(out, byte(r))
			continue
		}
		code, ok := unicodeToCP932Kana[r]
		if !ok {
			return nil, fmt.Errorf("name character U+%04X cannot be encoded as kana CP932", r)
		}
		out = append(out, byte(code>>8), byte(code))
	}
	return out, nil
}

// FindNameInBytes finds exact byte matches, including overlapping ones, with
// bounded output. Caller is responsible for clipping to PS1 RAM and finding
// actual runtime ownership before any attempt to change memory.
func FindNameInBytes(haystack, needle []byte, maxMatches int) []int {
	if len(needle) == 0 || maxMatches <= 0 {
		return nil
	}
	matches := make([]int, 0)
	for pos := 0; pos+len(needle) <= len(haystack) && len(matches) < maxMatches; {
		i := bytes.Index(haystack[pos:], needle)
		if i < 0 {
			break
		}
		hit := pos + i
		matches = append(matches, hit)
		pos = hit + 1
	}
	return matches
}
