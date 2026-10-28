package n20arch

// Standalone R3000A/MIPS-I terminal queue adapter for both
// renderer final JAL sites 0x80082700/0x80082724. Not installed until an
// authenticated persistent executable placement has been established.
// EXE must never call replaceable overlay memory unconditionally.
// The retail queue consumes the text pointer synchronously.
import "fmt"

const (
	c10QueueFrame   = 0xf0
	c10QueueScratch = 0x20
	c10QueueCap     = 112
)

func BuildC10TerminalQueueAdapter(base uint32) ([]byte, error) {
	if base&3 != 0 {
		return nil, fmt.Errorf("misaligned adapter address %#x", base)
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, i int16) { w(olADDIU(d, s, i)) }
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	sw := func(d uint32, o int16) { w(olSW(d, 29, o)) }
	lw := func(d uint32, o int16) { w(olLW(d, 29, o)); w(0) }
	beq := func(x, y uint32, l string) { a.b(4, x, y, l); w(0) }
	bne := func(x, y uint32, l string) { a.b(5, x, y, l); w(0) }
	add(29, 29, -c10QueueFrame)
	for i, r := range []uint32{16, 17, 18, 19} {
		sw(r, int16(0xa0+i*4))
	}
	sw(31, 0xbc)
	mov(16, 4)
	mov(17, 5)
	mov(18, 6)
	mov(19, 7)
	// Original fifth O32 argument at old SP+0x10; nested retail queue
	// observes our new SP+0x10 instead. Copy it exactly.
	lw(12, c10QueueFrame+0x10)
	sw(12, 0x10)
	beq(19, 0, "retail")
	w(olLUI(8, C10ResidentGuard+0x10000))
	lo := uint16(C10ResidentGuard & 0xffff)
	w(olLW(9, 8, int16(lo)))
	w(0)
	w(olLUI(10, C10Magic))
	w(olORI(10, 10, C10Magic&0xffff))
	bne(9, 10, "retail")
	lo = uint16((C10ResidentGuard + 4) & 0xffff)
	w(olLW(9, 8, int16(lo)))
	w(0)
	add(10, 0, C10ResidentBodyBytes)
	bne(9, 10, "retail")
	mov(4, 19)
	add(5, 29, c10QueueScratch)
	add(6, 0, c10QueueCap)
	w(jalWord(C10F2PEntry))
	w(0)
	bne(2, 0, "converted")
	mov(4, 19)
	add(5, 29, c10QueueScratch)
	add(6, 0, c10QueueCap)
	w(jalWord(C10F3Entry))
	w(0)
	beq(2, 0, "retail")
	a.label("converted")
	add(19, 29, c10QueueScratch)
	a.label("retail")
	mov(4, 16)
	mov(5, 17)
	mov(6, 18)
	mov(7, 19)
	w(jalWord(optionQueueRetail))
	w(0)
	// Queue v0/v1 pass through unchanged; callee-saved values restored.
	for i, r := range []uint32{16, 17, 18, 19} {
		lw(r, int16(0xa0+i*4))
	}
	lw(31, 0xbc)
	w(olJR(31))
	add(29, 29, c10QueueFrame)
	a.resolve()
	out := words(a.words...)
	if len(out) > C10ResidentGuardBytes-16 {
		return nil, fmt.Errorf("adapter %d bytes exceeds the 240-byte resident guard tail", len(out))
	}
	return out, nil
}
