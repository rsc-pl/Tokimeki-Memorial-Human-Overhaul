package playername

// Relocatable, non-installed MIPS R3000A queue-call wrapper prototype.
// The stub is a *byte-preserving* staging bridge, not a kana romanizer. It
// cannot guard against parser overflows that occurred before queue dispatch.
// Never install it in a disc image without independent site/code-space proofs.
import (
	"encoding/binary"
	"errors"
	"fmt"
)

// PS1QueueBridge exposes machine words for offline ABI review and tests.
// It is NOT patch-ready: it has no injectible address, token selector, runtime
// converter, verified cave, or transactional installer.
type PS1QueueBridge struct {
	Words              []uint32
	HexLE              string
	Entry              uint32
	OriginalQueue      uint32
	StackBytes         int
	ScratchOffset      int
	ScratchBytes       int
	OriginalArg5Offset int
	NewArg5Offset      int
	Relocatable        bool
	SafeToPatch        bool
}

type mipsBranch struct {
	at    int
	label string
}
type mipsBuf struct {
	words    []uint32
	labels   map[string]int
	branches []mipsBranch
}

func (b *mipsBuf) emit(w uint32)  { b.words = append(b.words, w) }
func (b *mipsBuf) label(s string) { b.labels[s] = len(b.words) }
func (b *mipsBuf) branch(op, rs, rt uint32, label string) {
	b.branches = append(b.branches, mipsBranch{len(b.words), label})
	b.emit((op << 26) | (rs << 21) | (rt << 16))
}
func iType(op, rs, rt uint32, imm int16) uint32 {
	return (op << 26) | (rs << 21) | (rt << 16) | uint32(uint16(imm))
}
func (b *mipsBuf) resolve() error {
	for _, v := range b.branches {
		to, ok := b.labels[v.label]
		if !ok {
			return fmt.Errorf("undefined MIPS label %s", v.label)
		}
		disp := to - v.at - 1
		if disp < -32768 || disp > 32767 {
			return errors.New("MIPS branch range")
		}
		b.words[v.at] |= uint32(uint16(int16(disp)))
	}
	return nil
}

// BuildPS1QueueBridge emits a call-scoped copy/fallback skeleton at a supplied
// *hypothetical* KSEG0 address. It copies a source string only if a NUL is
// found within 64 bytes. Otherwise it calls the original queue unchanged.
// All five original arguments are preserved, including the O32 stack arg at
// caller $sp+0x10; the queue return registers are passed through unchanged.
func BuildPS1QueueBridge(origin, originalQueue uint32) (PS1QueueBridge, error) {
	return buildPS1QueueBridge(origin, originalQueue, false)
}

// BuildPS1SafeQueueBridge emits the independently guarded R3000A-safe form.
// The original diagnostic byte stream is retained unchanged for reproducibility.
// Every lw/lbu is followed by a NOP so a dependent instruction cannot consume
// the previous register value. This is STILL post-parser, not an installable hook.
func BuildPS1SafeQueueBridge(origin, originalQueue uint32) (PS1QueueBridge, error) {
	return buildPS1QueueBridge(origin, originalQueue, true)
}

func buildPS1QueueBridge(origin, originalQueue uint32, safeLoads bool) (PS1QueueBridge, error) {
	r := PS1QueueBridge{Entry: origin, OriginalQueue: originalQueue, StackBytes: 0x90, ScratchOffset: 0x20, ScratchBytes: 64, OriginalArg5Offset: 0x10, NewArg5Offset: 0x10, SafeToPatch: false, Relocatable: true}
	if origin%4 != 0 || originalQueue%4 != 0 || origin < 0x80010000 || origin > 0x801fffff || originalQueue < 0x80010000 || originalQueue > 0x801fffff {
		return r, errors.New("addresses must be aligned PS1 KSEG0 original code; not an injection approval")
	}
	// MIPS R3000A/O32, numbers: sp=29, ra=31, a0..a3=4..7, t0..t4=8..12.
	var b = mipsBuf{labels: map[string]int{}}
	emit := func(w uint32) {
		b.emit(w)
		if safeLoads && (w>>26 == 35 || w>>26 == 36) {
			b.emit(0) // MIPS-I load delay; extra instruction even before jr ra
		}
	}
	emit(iType(9, 29, 29, -0x90)) // addiu sp,sp,-0x90
	emit(iType(43, 29, 31, 0x8c)) // sw ra,0x8c(sp)
	for n := uint32(4); n <= 7; n++ {
		emit(iType(43, 29, n, int16(0x70+4*(n-4))))
	}
	emit(iType(35, 29, 12, 0xa0)) // lw t4,old_sp+0x10
	emit(iType(43, 29, 12, 0x10)) // sw t4,new_sp+0x10; callee arg5
	emit(iType(9, 7, 8, 0))       // t0 = source $a3
	emit(iType(9, 0, 9, 0))       // t1 = 0
	b.label("scan")
	emit(iType(36, 8, 10, 0)) // lbu t2,0(t0)
	b.branch(4, 10, 0, "scan_done")
	emit(0)
	emit(iType(9, 9, 9, 1))    // addiu t1,t1,1
	emit(iType(11, 9, 11, 64)) // sltiu t3,t1,64
	b.branch(4, 11, 0, "fallback")
	emit(0)
	emit(iType(9, 8, 8, 1))
	b.branch(4, 0, 0, "scan")
	emit(0)
	b.label("scan_done")
	emit(iType(9, 7, 8, 0))      // reset src
	emit(iType(9, 29, 12, 0x20)) // own scratch
	b.label("copy")
	emit(iType(36, 8, 10, 0))
	emit(iType(40, 12, 10, 0))
	b.branch(4, 10, 0, "staged")
	emit(0)
	emit(iType(9, 8, 8, 1))
	emit(iType(9, 12, 12, 1))
	b.branch(4, 0, 0, "copy")
	emit(0)
	b.label("staged")
	emit(iType(9, 29, 7, 0x20)) // a3 = scratch
	b.branch(4, 0, 0, "invoke")
	emit(0)
	b.label("fallback")
	emit(iType(35, 29, 7, 0x7c)) // a3 original
	b.label("invoke")
	for n := uint32(4); n <= 6; n++ {
		emit(iType(35, 29, n, int16(0x70+4*(n-4))))
	}
	// JAL encodes within 256 MiB region; KSEG0 original queue is in same region.
	emit(0x0c000000 | ((originalQueue >> 2) & 0x03ffffff))
	emit(0) // MIPS delay slot, no clobber of 5th argument
	emit(iType(35, 29, 31, 0x8c))
	emit(0x03e00008)             // jr ra
	emit(iType(9, 29, 29, 0x90)) // delay slot restore sp
	if err := b.resolve(); err != nil {
		return r, err
	}
	if origin+uint32(len(b.words)*4) > 0x80200000 {
		return r, errors.New("stub extends outside checked KSEG0 interval")
	}
	var raw = []byte{}
	for _, w := range b.words {
		var buf [4]byte
		binary.LittleEndian.PutUint32(buf[:], w)
		raw = append(raw, buf[:]...)
	}
	r.Words = b.words
	r.HexLE = fmt.Sprintf("%x", raw)
	return r, nil
}
