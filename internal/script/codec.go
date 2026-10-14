package script

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const MaxCells = 28
const lineBreak byte = 0x20
const choice byte = 'q'
const skip byte = 'n'
const blankCode uint16 = 0x8140
const supported = " !\"%&'()+,-./0123456789:;?ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
const controls = " qmMAWOFYSPpG"

var labels = map[byte]int{'>': 4, '<': 4, '-': 6, '+': 2}
var tokenCells = map[byte]int{'P': 12, 'p': 6, 'm': 6, 'F': 12, 'G': 10, 'Y': 6, 'S': 18, 'O': 18, 'W': 18, 'A': 18, 'M': 18, 'n': 0}
var tokenPattern = regexp.MustCompile(`\{([A-Za-z])\}|\n`)
var structCodes = regexp.MustCompile(`\{[A-Za-z]\}`)

// PairEncoder tracks whether English pair glyphs require the renderer hook.
// Literal pairs of two spaces are encoded as the original game's blank glyph.
type PairEncoder struct{ Used bool }

func (p *PairEncoder) Encode(s string) ([]byte, error) {
	for _, r := range s {
		if !strings.ContainsRune(supported, r) {
			return nil, fmt.Errorf("unsupported pair-font character %q", r)
		}
	}
	if len(s)%2 != 0 {
		s += " "
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); i += 2 {
		if s[i:i+2] == "  " {
			out = append(out, byte(blankCode>>8), byte(blankCode&0xff))
		} else {
			out = append(out, s[i]|0x80, s[i+1]|0x80)
			p.Used = true
		}
	}
	return out, nil
}

// takeLabel matches a leading {>label}, {<label}, {-label}, or {+label}.
// A non-prefix label or malformed syntax is kept as literal input.
func takeLabel(text string) (prefix byte, label, body string, ok bool) {
	if len(text) < 3 || text[0] != '{' {
		return 0, "", text, false
	}
	if _, found := labels[text[1]]; !found {
		return 0, "", text, false
	}
	end := strings.IndexByte(text, '}')
	if end < 0 || strings.ContainsAny(text[2:end], "{}\n") {
		return 0, "", text, false
	}
	return text[1], text[2:end], text[end+1:], true
}

// split iterates control tokens using the Python implementation's exact grammar:
// newline and {one ASCII letter}. Other braces are encoded as literal text.
func split(text string, part func(string) error, control func(byte) error) error {
	matches := tokenPattern.FindAllStringIndex(text, -1)
	cursor := 0
	for _, m := range matches {
		if m[0] > cursor {
			if e := part(text[cursor:m[0]]); e != nil {
				return e
			}
		}
		piece := text[m[0]:m[1]]
		code := lineBreak
		if piece != "\n" {
			code = piece[1]
			if !strings.ContainsRune(controls, rune(code)) && code != skip {
				return fmt.Errorf("unknown control code %s", piece)
			}
		}
		if e := control(code); e != nil {
			return e
		}
		cursor = m[1]
	}
	if cursor < len(text) {
		return part(text[cursor:])
	}
	return nil
}

func EncodeOriginal(text string) ([]byte, error) {
	_, _, _ = utf8.RuneCountInString(text), lineBreak, choice
	var b bytes.Buffer
	if prefix, label, rest, ok := takeLabel(text); ok {
		b.WriteByte(prefix)
		raw, e := encodeJIS(label)
		if e != nil {
			return nil, e
		}
		b.Write(raw)
		text = rest
	}
	e := split(text, func(s string) error {
		raw, e := encodeJIS(s)
		if e == nil {
			b.Write(raw)
		}
		return e
	}, func(c byte) error { b.WriteByte(c); return nil })
	if e != nil {
		return nil, e
	}
	return b.Bytes(), nil
}

func EncodeEnglish(text string, p *PairEncoder) ([]byte, []int, error) {
	if p == nil {
		p = &PairEncoder{}
	}
	var out bytes.Buffer
	widths := []int{0}
	if prefix, label, rest, ok := takeLabel(text); ok {
		n := labels[prefix]
		var raw []byte
		var e error
		ascii := true
		for _, r := range label {
			if r >= 127 {
				ascii = false
				break
			}
		}
		if ascii {
			if len(label) > n {
				return nil, nil, fmt.Errorf("label %q longer than %d", label, n)
			}
			raw, e = p.Encode(label + strings.Repeat(" ", n-len(label)))
		} else {
			raw, e = encodeJIS(label)
		}
		if e != nil {
			return nil, nil, e
		}
		if len(raw) != n {
			return nil, nil, fmt.Errorf("label %q must take %d bytes", label, n)
		}
		out.WriteByte(prefix)
		out.Write(raw)
		text = rest
	}
	e := split(text, func(s string) error {
		// Divide contiguous ASCII printables (0x20-0x7e) and non-ASCII runs.
		for len(s) > 0 {
			ascii := s[0] >= 0x20 && s[0] <= 0x7e
			end := 0
			for end < len(s) {
				r, size := utf8.DecodeRuneInString(s[end:])
				a := r >= 0x20 && r <= 0x7e
				if a != ascii {
					break
				}
				end += size
			}
			var b []byte
			var err error
			if ascii {
				b, err = p.Encode(s[:end])
			} else {
				b, err = encodeJIS(s[:end])
				if err == nil {
					for i := 0; i < len(b); i += 2 {
						if i+1 >= len(b) || !isLead(b[i]) {
							return fmt.Errorf("%q is not full-width Shift-JIS", s[:end])
						}
					}
				}
			}
			if err != nil {
				return err
			}
			out.Write(b)
			widths[len(widths)-1] += len(b)
			s = s[end:]
		}
		return nil
	}, func(c byte) error {
		out.WriteByte(c)
		if c == lineBreak || c == choice {
			widths = append(widths, 0)
		} else {
			widths[len(widths)-1] += tokenCells[c]
		}
		return nil
	})
	if e != nil {
		return nil, nil, e
	}
	return out.Bytes(), widths, nil
}

func Decode(raw []byte) (string, error) {
	var b strings.Builder
	if len(raw) > 0 {
		if n, ok := labels[raw[0]]; ok && len(raw) > 1+n {
			label, e := decodeJIS(raw[1 : 1+n])
			if e == nil {
				b.WriteByte('{')
				b.WriteByte(raw[0])
				b.WriteString(label)
				b.WriteByte('}')
				raw = raw[1+n:]
			}
		}
	}
	for i := 0; i < len(raw); {
		c := raw[i]
		if c == lineBreak {
			b.WriteByte('\n')
			i++
			continue
		}
		if strings.IndexByte(controls, c) >= 0 {
			fmt.Fprintf(&b, "{%c}", c)
			i++
			continue
		}
		if c == skip {
			end := bytes.IndexByte(raw[i:], choice)
			if end < 0 {
				end = len(raw) - i
			}
			segment := raw[i : i+end]
			all := len(segment) > 0
			for _, v := range segment {
				if v != skip {
					all = false
					break
				}
			}
			if all {
				b.WriteString("{n}")
				i++
				continue
			}
		}
		if isLead(c) && i+1 < len(raw) {
			str, e := decodeJIS(raw[i : i+2])
			if e != nil {
				return "", e
			}
			b.WriteString(str)
			i += 2
			continue
		}
		return "", fmt.Errorf("byte %#x at offset %d is not dialogue text", c, i)
	}
	return b.String(), nil
}

func Structure(text string) string {
	parts := []string{}
	if prefix, _, rest, ok := takeLabel(text); ok {
		parts = append(parts, "label"+string(prefix))
		text = rest
	}
	for _, line := range strings.Split(text, "\n") {
		opts := []string{}
		for _, opt := range strings.Split(line, "{q}") {
			body := opt
			n := 0
			for strings.HasSuffix(body, "{n}") {
				body = body[:len(body)-3]
				n++
			}
			codes := structCodes.FindAllString(body, -1)
			sort.Strings(codes)
			for _, c := range codes {
				if c == "{n}" {
					codes = append(codes, "<n not at the end>")
					break
				}
			}
			val := strings.Join(codes, "")
			if n > 0 {
				val += fmt.Sprintf("$n%d", n)
			}
			opts = append(opts, val)
		}
		parts = append(parts, strings.Join(opts, "|"))
	}
	return strings.Join(parts, "/")
}
