package n20arch

import (
	"encoding/binary"
	"fmt"
)

// Machine is a deliberately small R3000A subset used only for the offline
// window/stub/boot/overlay prototype. It models branch-delay slots and the
// one-instruction load delay, but not interrupt/DMA/cache/BIOS behavior.
type Machine struct {
	Reg  [32]uint32
	HI   uint32 // R3000A HI/LO (used by retail glyph VRAM uploader)
	LO   uint32
	Mem  []byte
	PC   uint32
	RA   uint32
	SP   uint32
	Stop map[uint32]string
	// Last is a bounded PC trace.
	Last []uint32
	// LowSP records the lowest $sp observed during Run. It is a local
	// measurement of the executed frames only; it is not a whole-game stack
	// low-water mark.
	LowSP uint32
	// OnQueue is called when the retail queue sentinel is reached.
	OnQueue func(*Machine)
	// OnBIOS models a BIOS A0/B0/C vector call. It must return true when it
	// handled the call; Run then resumes at $ra.
	OnBIOS func(*Machine) bool
	// Hooks are test-only stand-ins for retail routines. A hook runs instead
	// of the instruction at its PC and must advance PC itself (usually to
	// $ra). Existing tests leave this nil.
	Hooks map[uint32]func(*Machine)
	// Memcpy/Flush are modeled only when the PC reaches the original addresses.
	memcpyAddr uint32
	flushAddr  uint32
	steps      int
}

func NewMachine() *Machine {
	return &Machine{Mem: make([]byte, 0x200000), Stop: map[uint32]string{},
		LowSP: 0xFFFFFFFF, memcpyAddr: 0x800AE0A0, flushAddr: 0x80042458}
}

func (m *Machine) off(a uint32) (int, error) {
	if a < 0x80000000 || a >= 0x80200000 {
		return 0, fmt.Errorf("address outside prototype RAM: %08x", a)
	}
	return int(a - 0x80000000), nil
}

func (m *Machine) L32(a uint32) uint32 {
	o, err := m.off(a)
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint32(m.Mem[o:])
}
func (m *Machine) S32(a, v uint32) {
	o, err := m.off(a)
	if err != nil {
		panic(err)
	}
	binary.LittleEndian.PutUint32(m.Mem[o:], v)
}
func (m *Machine) L16(a uint32) uint16 {
	o, err := m.off(a)
	if err != nil {
		panic(err)
	}
	return binary.LittleEndian.Uint16(m.Mem[o:])
}
func (m *Machine) S16(a uint32, v uint16) {
	o, err := m.off(a)
	if err != nil {
		panic(err)
	}
	binary.LittleEndian.PutUint16(m.Mem[o:], v)
}
func (m *Machine) L8(a uint32) byte {
	o, err := m.off(a)
	if err != nil {
		panic(err)
	}
	return m.Mem[o]
}
func (m *Machine) S8(a uint32, v byte) {
	o, err := m.off(a)
	if err != nil {
		panic(err)
	}
	m.Mem[o] = v
}

func (m *Machine) Load(addr uint32, b []byte) {
	o, err := m.off(addr)
	if err != nil {
		panic(err)
	}
	copy(m.Mem[o:], b)
}

func sext16(v uint32) uint32 {
	if v&0x8000 != 0 {
		return v | 0xFFFF0000
	}
	return v
}

// Run executes until a stop address, an unhandled instruction, or maxSteps.
func (m *Machine) Run(start uint32, maxSteps int) (uint32, error) {
	m.PC = start
	var pendingReg int = -1
	var pendingVal uint32
	var delayTarget uint32
	var inDelay bool
	for i := 0; i < maxSteps; i++ {
		pc := m.PC
		if label, ok := m.Stop[pc]; ok {
			return pc, fmt.Errorf("stop:%s", label)
		}
		if m.LowSP == 0 || m.Reg[29] < m.LowSP {
			m.LowSP = m.Reg[29]
		}
		if m.OnBIOS != nil && (pc == 0xA0 || pc == 0xB0 || pc == 0xC) {
			if m.OnBIOS(m) {
				m.PC = m.Reg[31]
				continue
			}
		}
		if m.Hooks != nil {
			if h, ok := m.Hooks[pc]; ok {
				h(m)
				continue
			}
		}
		if pc == m.memcpyAddr {
			// memcpy(a0,a1,a2), return to ra.
			n := m.Reg[6]
			src, dst := m.Reg[5], m.Reg[4]
			for j := uint32(0); j < n; j++ {
				o1, e1 := m.off(src + j)
				o2, e2 := m.off(dst + j)
				if e1 != nil || e2 != nil {
					return pc, fmt.Errorf("memcpy bounds")
				}
				m.Mem[o2] = m.Mem[o1]
			}
			m.PC = m.Reg[31]
			continue
		}
		if pc == m.flushAddr {
			m.PC = m.Reg[31]
			continue
		}
		w := m.L32(pc)
		op := w >> 26
		rs := (w >> 21) & 31
		rt := (w >> 16) & 31
		rd := (w >> 11) & 31
		sh := (w >> 6) & 31
		fn := w & 63
		imm := w & 0xFFFF

		isDelay := inDelay
		inDelay = false
		// Retire the previous load after the current instruction has read
		// its source registers (R3000A one-instruction load delay).
		retire := func() {
			if pendingReg >= 0 {
				m.Reg[pendingReg] = pendingVal
				pendingReg = -1
			}
		}

		next := pc + 4
		loadReg := -1
		var loadVal uint32
		switch op {
		case 0x0F: // lui
			m.Reg[rt] = imm << 16
		case 0x0D: // ori
			m.Reg[rt] = m.Reg[rs] | imm
		case 0x09: // addiu
			m.Reg[rt] = m.Reg[rs] + sext16(imm)
		case 0x0A: // slti
			if int32(m.Reg[rs]) < int32(sext16(imm)) {
				m.Reg[rt] = 1
			} else {
				m.Reg[rt] = 0
			}
		case 0x0B: // sltiu
			if m.Reg[rs] < sext16(imm) {
				m.Reg[rt] = 1
			} else {
				m.Reg[rt] = 0
			}
		case 0x0C: // andi
			m.Reg[rt] = m.Reg[rs] & imm
		case 0x23: // lw
			loadReg, loadVal = int(rt), m.L32(m.Reg[rs]+sext16(imm))
		case 0x21: // lh
			v := uint32(m.L16(m.Reg[rs] + sext16(imm)))
			if v&0x8000 != 0 {
				v |= 0xFFFF0000
			}
			loadReg, loadVal = int(rt), v
		case 0x25: // lhu
			loadReg, loadVal = int(rt), uint32(m.L16(m.Reg[rs]+sext16(imm)))
		case 0x24: // lbu
			o, _ := m.off(m.Reg[rs] + sext16(imm))
			loadReg, loadVal = int(rt), uint32(m.Mem[o])
		case 0x2B: // sw
			m.S32(m.Reg[rs]+sext16(imm), m.Reg[rt])
		case 0x29: // sh
			m.S16(m.Reg[rs]+sext16(imm), uint16(m.Reg[rt]))
		case 0x28: // sb
			m.S8(m.Reg[rs]+sext16(imm), byte(m.Reg[rt]))
		case 0x04: // beq
			if m.Reg[rs] == m.Reg[rt] {
				if isDelay {
					return pc, fmt.Errorf("branch in delay slot at %08x", pc)
				}
				delayTarget = pc + 4 + (sext16(imm) << 2)
				inDelay = true
			}
		case 0x05: // bne
			if m.Reg[rs] != m.Reg[rt] {
				if isDelay {
					return pc, fmt.Errorf("branch in delay slot at %08x", pc)
				}
				delayTarget = pc + 4 + (sext16(imm) << 2)
				inDelay = true
			}
		case 0x06: // blez
			if int32(m.Reg[rs]) <= 0 {
				if isDelay {
					return pc, fmt.Errorf("branch in delay slot at %08x", pc)
				}
				delayTarget = pc + 4 + (sext16(imm) << 2)
				inDelay = true
			}
		case 0x07: // bgtz
			if int32(m.Reg[rs]) > 0 {
				if isDelay {
					return pc, fmt.Errorf("branch in delay slot at %08x", pc)
				}
				delayTarget = pc + 4 + (sext16(imm) << 2)
				inDelay = true
			}
		case 0x02: // j
			if isDelay {
				return pc, fmt.Errorf("jump in delay slot at %08x", pc)
			}
			delayTarget = (pc+4)&0xF0000000 | ((w & 0x03FFFFFF) << 2)
			inDelay = true
		case 0x03: // jal
			if isDelay {
				return pc, fmt.Errorf("jump in delay slot at %08x", pc)
			}
			delayTarget = (pc+4)&0xF0000000 | ((w & 0x03FFFFFF) << 2)
			inDelay = true
			m.Reg[31] = pc + 8
		case 0x00:
			switch fn {
			case 0x00: // sll
				m.Reg[rd] = m.Reg[rt] << sh
			case 0x02: // srl
				m.Reg[rd] = m.Reg[rt] >> sh
			case 0x04: // sllv
				m.Reg[rd] = m.Reg[rt] << (m.Reg[rs] & 31)
			case 0x03: // sra
				m.Reg[rd] = uint32(int32(m.Reg[rt]) >> sh)
			case 0x08: // jr
				if isDelay {
					return pc, fmt.Errorf("jr in delay slot at %08x", pc)
				}
				delayTarget = m.Reg[rs]
				inDelay = true
			case 0x09: // jalr
				if isDelay {
					return pc, fmt.Errorf("jalr in delay slot at %08x", pc)
				}
				delayTarget = m.Reg[rs]
				inDelay = true
				m.Reg[rd] = pc + 8
			case 0x19: // multu
				product := uint64(m.Reg[rs]) * uint64(m.Reg[rt])
				m.HI, m.LO = uint32(product>>32), uint32(product)
			case 0x12: // mflo
				m.Reg[rd] = m.LO
			case 0x10: // mfhi
				m.Reg[rd] = m.HI
			case 0x21: // addu
				m.Reg[rd] = m.Reg[rs] + m.Reg[rt]
			case 0x23: // subu
				m.Reg[rd] = m.Reg[rs] - m.Reg[rt]
			case 0x26: // xor
				m.Reg[rd] = m.Reg[rs] ^ m.Reg[rt]
			case 0x2B: // sltu
				if m.Reg[rs] < m.Reg[rt] {
					m.Reg[rd] = 1
				} else {
					m.Reg[rd] = 0
				}
			case 0x2A: // slt
				if int32(m.Reg[rs]) < int32(m.Reg[rt]) {
					m.Reg[rd] = 1
				} else {
					m.Reg[rd] = 0
				}
			case 0x24: // and
				m.Reg[rd] = m.Reg[rs] & m.Reg[rt]
			case 0x25: // or
				m.Reg[rd] = m.Reg[rs] | m.Reg[rt]
			default:
				return pc, fmt.Errorf("unsupported funct %02x at %08x", fn, pc)
			}
		default:
			return pc, fmt.Errorf("unsupported op %02x at %08x", op, pc)
		}
		retire()
		if loadReg >= 0 {
			pendingReg, pendingVal = loadReg, loadVal
		}
		m.Last = append(m.Last, pc)
		if len(m.Last) > 256 {
			m.Last = m.Last[len(m.Last)-256:]
		}
		if isDelay {
			m.PC = delayTarget
		} else if inDelay {
			m.PC = next
		} else {
			m.PC = next
		}
		m.steps++
	}
	return m.PC, fmt.Errorf("step limit at %08x", m.PC)
}

// Steps returns the executed instruction count.
func (m *Machine) Steps() int { return m.steps }
