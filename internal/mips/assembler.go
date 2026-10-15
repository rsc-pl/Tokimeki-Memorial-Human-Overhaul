// Package mips assembles the deliberately small subset of MIPS I/R3000 used
// by the Tokimeki PS1 renderer. Instructions occupy exactly one 32-bit word.
// The caller, not the assembler, is responsible for delay slots.
package mips

import (
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

var regNames = strings.Fields("zero at v0 v1 a0 a1 a2 a3 t0 t1 t2 t3 t4 t5 t6 t7 s0 s1 s2 s3 s4 s5 s6 s7 t8 t9 k0 k1 gp sp fp ra")
var regs = func() map[string]uint32 {
	m := make(map[string]uint32)
	for i, n := range regNames {
		m[n] = uint32(i)
	}
	return m
}()
var labelRE = regexp.MustCompile(`^([A-Za-z_]\w*):\s*(.*)$`)
var exprRE = regexp.MustCompile(`^%(hi|lo)\((.+)\)$`)
var memRE = regexp.MustCompile(`^(.*)\(([^()]+)\)$`)

type opDef struct {
	kind          string
	opcode, funct uint32
}

var ops = map[string]opDef{
	"sll": {"shift", 0, 0}, "srl": {"shift", 0, 2}, "sra": {"shift", 0, 3},
	"addu": {"r3", 0, 0x21}, "subu": {"r3", 0, 0x23}, "and": {"r3", 0, 0x24}, "or": {"r3", 0, 0x25}, "xor": {"r3", 0, 0x26}, "slt": {"r3", 0, 0x2a}, "sltu": {"r3", 0, 0x2b},
	"addiu": {"imm", 9, 0}, "slti": {"imm", 10, 0}, "sltiu": {"imm", 11, 0}, "andi": {"imm", 12, 0}, "ori": {"imm", 13, 0},
	"lui": {"lui", 15, 0}, "lb": {"mem", 32, 0}, "lh": {"mem", 33, 0}, "lw": {"mem", 35, 0}, "lbu": {"mem", 36, 0}, "lhu": {"mem", 37, 0},
	"sb": {"mem", 40, 0}, "sh": {"mem", 41, 0}, "sw": {"mem", 43, 0}, "beq": {"branch2", 4, 0}, "bne": {"branch2", 5, 0},
	"beqz": {"branch1", 4, 0}, "bnez": {"branch1", 5, 0}, "j": {"jump", 2, 0}, "jal": {"jump", 3, 0},
	"jr": {"jr", 0, 8}, "move": {"move", 0, 0x21}, "nop": {"nop", 0, 0},
}

func register(name string) (uint32, error) {
	r, ok := regs[strings.TrimPrefix(strings.TrimSpace(name), "$")]
	if !ok {
		return 0, fmt.Errorf("unknown register %q", name)
	}
	return r, nil
}
func value(text string, symbols map[string]int64) (int64, error) {
	text = strings.TrimSpace(text)
	if m := exprRE.FindStringSubmatch(text); m != nil {
		v, e := value(m[2], symbols)
		if e != nil {
			return 0, e
		}
		if m[1] == "hi" {
			return ((v + 0x8000) >> 16) & 0xffff, nil
		}
		return v & 0xffff, nil
	}
	if v, ok := symbols[text]; ok {
		return v, nil
	}
	v, e := strconv.ParseInt(text, 0, 64)
	if e == nil {
		return v, nil
	}
	u, e := strconv.ParseUint(text, 0, 64)
	if e == nil && u <= 0xffffffff {
		return int64(u), nil
	}
	return 0, fmt.Errorf("unknown symbol %q", text)
}
func immediate(v int64, signed bool) (uint32, error) {
	lo := int64(0)
	if signed {
		lo = -0x8000
	}
	if v < lo || v > 0xffff {
		return 0, fmt.Errorf("immediate %#x doesn't fit in 16 bits", v)
	}
	return uint32(v) & 0xffff, nil
}
func splitLine(line string) (string, []string) {
	i := strings.IndexAny(line, " \t")
	if i < 0 {
		return line, nil
	}
	name := line[:i]
	rest := strings.TrimSpace(line[i+1:])
	if rest == "" {
		return name, nil
	}
	a := strings.Split(rest, ",")
	for i := range a {
		a[i] = strings.TrimSpace(a[i])
	}
	return name, a
}

// Assemble compiles source at the given virtual address, using supplied symbols.
// It rejects missing/extraneous operands, invalid alignment and unreachable jumps.
// Symbol resolution and 16-bit immediates follow legacy tokipatch/mips.py.
func Assemble(source string, origin uint32, external map[string]int64) ([]byte, error) {
	symbols := make(map[string]int64, len(external))
	for k, v := range external {
		symbols[k] = v
	}
	var lines []string
	for _, raw := range strings.Split(source, "\n") {
		if i := strings.IndexAny(raw, "#;"); i >= 0 {
			raw = raw[:i]
		}
		s := strings.TrimSpace(raw)
		for s != "" {
			m := labelRE.FindStringSubmatch(s)
			if m == nil {
				lines = append(lines, s)
				break
			}
			if _, ok := symbols[m[1]]; ok {
				return nil, fmt.Errorf("duplicate label %q", m[1])
			}
			symbols[m[1]] = int64(origin) + int64(len(lines))*4
			s = strings.TrimSpace(m[2])
		}
	}
	if len(lines) > int((^uint32(0)-origin)/4) {
		return nil, fmt.Errorf("program address overflow")
	}
	out := make([]byte, 4*len(lines))
	for i, line := range lines {
		name, args := splitLine(line)
		def, ok := ops[name]
		if !ok {
			return nil, fmt.Errorf("%q: unknown instruction", line)
		}
		count := map[string]int{"nop": 0, "shift": 3, "r3": 3, "move": 2, "imm": 3, "lui": 2, "mem": 2, "branch1": 2, "branch2": 3, "jump": 1, "jr": 1}[def.kind]
		if len(args) != count {
			return nil, fmt.Errorf("%q: expected %d operands, got %d", line, count, len(args))
		}
		r := func(k int) (uint32, error) { return register(args[k]) }
		v := func(k int) (int64, error) { return value(args[k], symbols) }
		var w uint32
		var err error
		switch def.kind {
		case "nop":
			w = 0
		case "shift":
			var rd, rt uint32
			var sa int64
			if rd, err = r(0); err != nil {
				break
			}
			if rt, err = r(1); err != nil {
				break
			}
			if sa, err = v(2); err != nil {
				break
			}
			if sa < 0 || sa >= 32 {
				err = fmt.Errorf("shift amount out of range")
				break
			}
			w = (rt << 16) | (rd << 11) | (uint32(sa) << 6) | def.funct
		case "r3":
			var rd, rs, rt uint32
			if rd, err = r(0); err != nil {
				break
			}
			if rs, err = r(1); err != nil {
				break
			}
			if rt, err = r(2); err != nil {
				break
			}
			w = (rs << 21) | (rt << 16) | (rd << 11) | def.funct
		case "move":
			var rd, rs uint32
			if rd, err = r(0); err != nil {
				break
			}
			if rs, err = r(1); err != nil {
				break
			}
			w = (rs << 21) | (rd << 11) | def.funct
		case "imm":
			var rt, rs, imm uint32
			var x int64
			if rt, err = r(0); err != nil {
				break
			}
			if rs, err = r(1); err != nil {
				break
			}
			if x, err = v(2); err != nil {
				break
			}
			imm, err = immediate(x, def.opcode == 9 || def.opcode == 10 || def.opcode == 11)
			if err != nil {
				break
			}
			w = (def.opcode << 26) | (rs << 21) | (rt << 16) | imm
		case "lui":
			var rt, imm uint32
			var x int64
			if rt, err = r(0); err != nil {
				break
			}
			if x, err = v(1); err != nil {
				break
			}
			imm, err = immediate(x, false)
			if err != nil {
				break
			}
			w = (def.opcode << 26) | (rt << 16) | imm
		case "mem":
			var rt, base, imm uint32
			var x int64
			if rt, err = r(0); err != nil {
				break
			}
			m := memRE.FindStringSubmatch(args[1])
			if m == nil {
				err = fmt.Errorf("expected offset(base)")
				break
			}
			if base, err = register(m[2]); err != nil {
				break
			}
			s := strings.TrimSpace(m[1])
			if s == "" {
				s = "0"
			}
			if x, err = value(s, symbols); err != nil {
				break
			}
			if x >= 0x8000 && x <= 0xffff {
				x -= 0x10000
			}
			imm, err = immediate(x, true)
			if err != nil {
				break
			}
			w = (def.opcode << 26) | (base << 21) | (rt << 16) | imm
		case "branch1", "branch2":
			var rs, rt, imm uint32
			var target int64
			if rs, err = r(0); err != nil {
				break
			}
			if def.kind == "branch2" {
				if rt, err = r(1); err != nil {
					break
				}
			}
			if target, err = v(len(args) - 1); err != nil {
				break
			}
			delta := target - (int64(origin) + int64(i)*4 + 4)
			if delta%4 != 0 {
				err = fmt.Errorf("misaligned branch target")
				break
			}
			imm, err = immediate(delta/4, true)
			if err != nil {
				break
			}
			w = (def.opcode << 26) | (rs << 21) | (rt << 16) | imm
		case "jump":
			var target int64
			if target, err = v(0); err != nil {
				break
			}
			pc := int64(origin) + int64(i)*4
			if target < 0 || target > 0xffffffff || target%4 != 0 || (target&0xf0000000) != ((pc+4)&0xf0000000) {
				err = fmt.Errorf("jump target %#x unreachable from %#x", target, pc)
				break
			}
			w = (def.opcode << 26) | (uint32(target>>2) & 0x3ffffff)
		case "jr":
			var rs uint32
			rs, err = r(0)
			if err != nil {
				break
			}
			w = (rs << 21) | def.funct
		}
		if err != nil {
			return nil, fmt.Errorf("%q: %w", line, err)
		}
		binary.LittleEndian.PutUint32(out[i*4:], w)
	}
	return out, nil
}
