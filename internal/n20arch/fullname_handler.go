package n20arch

// Overlay-local full-name handler ("N6-FN").
//
// This is a latent capability, not a route. The authenticated inventory shows
// that the 59 overlay JALs once labelled "fullname" reach the talk runner
// 0x80082764, not a name builder, and that the real full-name expansion is
// inside EXE renderer 0x80081190. Overlays do call that renderer (19 direct
// JALs), but only as a generic text draw: the text pointer is the caller's
// buffer, the surname/given fields are never passed, and 'P'/'p'/'m'/'F' are
// expanded inside the callee. The handler is nevertheless built into the same
// verified body as the speaker shim so that a real overlay-owned callsite can
// be served without a second architecture:
//
//   - the guard verifier covers the handler bytes with the same sum32/xor32;
//   - the handler is entered only from a stub placed in the guard's spare
//     bytes (0x80160EE4..0x80160EFB) and verified in place;
//   - callsite, guard and body are one overlay image, so they share one
//     load lifetime, exactly like the speaker route.
//
// ABI (deliberately close to the packed romanizer romanizer):
//   a0 = surname field pointer (NUL-terminated, 1..3 CP932 kana)
//   a1 = given field pointer   (NUL-terminated, 1..3 CP932 kana)
//   a2 = destination buffer    (at least 28 bytes, 4-aligned)
//   a3 = capacity in bytes, must be >= 28
//   t0 = honorific selector: 0 none, 1 "-san", 2 "-kun", 3 "-chan"
//   v0 = 1 on success, 0 on failure. On failure the destination content is
//        unspecified beyond the bytes written so far; the caller must pass the
//        original retail string instead. Nothing is read outside the two
//        fields, the destination or the handler frame.
// Preserves ra, sp, gp, fp, s0-s7; clobbers t0-t9, a0-a3, v0/v1.
//
// The output is the guest romanizer's half-width wire form: high-bit ASCII,
// one high-bit space between family and given, and an optional high-bit
// honourific. Family comes first, given second, matching the JP source order.
// A trailing romanizer pad space on the family field is stripped so the join
// never produces a double space.

import (
	"encoding/binary"
	"fmt"
)

const (
	OLFullNameStubRAM     uint32 = 0x80160EE4 // 24 B in the guard's spare tail
	OLFullNameStubBytes          = 24
	OLFullNameMaxField           = 10 // roman letters per 3-kana field, inclusive
	OLFullNameMinCapacity        = 28 // 10+1+10+5+1+NUL slack
	OLFullNameFrame              = 0x60
)

var fullNameHonorifics = [4]string{"", "-san", "-kun", "-chan"}

func olLBU(rt, base uint32, off int16) uint32 { return olIType(0x24, base, rt, uint16(off)) }
func olSB(rt, base uint32, off int16) uint32  { return olIType(0x28, base, rt, uint16(off)) }
func olSLTIU(rt, rs uint32, imm int16) uint32 {
	return olIType(0x0B, rs, rt, uint16(imm))
}
func olSUBU(rd, rs, rt uint32) uint32 { return olRType(rs, rt, rd, 0x23) }

// buildFullNameHandler emits the handler. Entry is returned separately so the
// body builder can place it after the speaker shim.
func buildFullNameHandler(romanizer uint32) ([]byte, error) {
	a := &miniAsm{labels: map[string]int{}}
	w := func(v uint32) { a.w(v) }
	mov := func(dst, src uint32) { w(olAddu(dst, src, 0)) }

	w(olADDIU(29, 29, -OLFullNameFrame))
	w(olSW(31, 29, 0x40))
	w(olSW(16, 29, 0x44))
	w(olSW(17, 29, 0x48))
	w(olSW(18, 29, 0x4C))
	w(olSW(19, 29, 0x50))
	w(olSW(20, 29, 0x54))
	mov(19, 4) // s3 = surname pointer
	mov(20, 5) // s4 = given pointer
	mov(16, 6) // s0 = destination
	mov(17, 7) // s1 = capacity
	mov(18, 8) // s2 = honourific selector
	// Capacity gate. 28 bytes covers 10 + 1 + 10 + 5 + NUL.
	w(olSLTIU(1, 17, OLFullNameMinCapacity))
	a.b(5, 1, 0, "fail")
	w(0)
	// Surname -> 0x20(sp).
	mov(4, 19)
	w(olADDIU(5, 29, 0x20))
	w(olADDIU(6, 0, 16))
	w(olADDIU(7, 0, 3)) // max 3 kana, no suffix
	w(jalWord(romanizer))
	w(0)
	a.b(4, 2, 0, "fail")
	w(0)
	// Given -> 0x30(sp).
	mov(4, 20)
	w(olADDIU(5, 29, 0x30))
	w(olADDIU(6, 0, 16))
	w(olADDIU(7, 0, 3))
	w(jalWord(romanizer))
	w(0)
	a.b(4, 2, 0, "fail")
	w(0)

	// Copy the family field: t5 = cursor, t1 = copied bytes, t3 = source.
	mov(13, 16)
	w(olAddu(9, 0, 0))
	w(olADDIU(3, 29, 0x20))
	a.label("fam_loop")
	w(olLBU(12, 3, 0))
	w(0) // R3000A load delay: the branch must not read the stale t4
	a.b(4, 12, 0, "fam_done")
	w(0)
	w(olSLTIU(1, 9, OLFullNameMaxField))
	a.b(4, 1, 0, "fail") // a family longer than 10 letters fails closed
	w(0)
	w(olSB(12, 13, 0))
	w(olADDIU(13, 13, 1))
	w(olADDIU(9, 9, 1))
	w(olADDIU(3, 3, 1))
	a.b(4, 0, 0, "fam_loop")
	w(0)
	a.label("fam_done")
	a.b(4, 9, 0, "fail") // empty family
	w(0)
	// Strip one trailing high-bit pad space from the family romanization.
	w(olADDIU(3, 13, -1))
	w(olLBU(12, 3, 0))
	w(0)
	w(olADDIU(1, 0, 0xA0))
	a.b(5, 12, 1, "no_pad")
	w(0)
	w(olADDIU(13, 13, -1))
	a.label("no_pad")
	// One high-bit space separator.
	w(olADDIU(12, 0, 0xA0))
	w(olSB(12, 13, 0))
	w(olADDIU(13, 13, 1))
	// Copy the given field.
	w(olAddu(9, 0, 0))
	w(olADDIU(3, 29, 0x30))
	a.label("giv_loop")
	w(olLBU(12, 3, 0))
	w(0)
	a.b(4, 12, 0, "giv_done")
	w(0)
	w(olSLTIU(1, 9, OLFullNameMaxField))
	a.b(4, 1, 0, "fail")
	w(0)
	w(olSB(12, 13, 0))
	w(olADDIU(13, 13, 1))
	w(olADDIU(9, 9, 1))
	w(olADDIU(3, 3, 1))
	a.b(4, 0, 0, "giv_loop")
	w(0)
	a.label("giv_done")
	a.b(4, 9, 0, "fail")
	w(0)
	// Strip one trailing romanizer pad space from the given field too, so a
	// following honourific never inherits a double space.
	w(olADDIU(3, 13, -1))
	w(olLBU(12, 3, 0))
	w(0)
	w(olADDIU(1, 0, 0xA0))
	a.b(5, 12, 1, "no_giv_pad")
	w(0)
	w(olADDIU(13, 13, -1))
	a.label("no_giv_pad")
	// Honourific. Only selectors 0..3 are accepted; anything else fails
	// closed rather than guessing a JP form of address.
	a.b(4, 18, 0, "term")
	w(0)
	w(olADDIU(1, 0, 1))
	a.b(4, 18, 1, "suf_san")
	w(0)
	w(olADDIU(1, 0, 2))
	a.b(4, 18, 1, "suf_kun")
	w(0)
	w(olADDIU(1, 0, 3))
	a.b(4, 18, 1, "suf_chan")
	w(0)
	a.b(4, 0, 0, "fail")
	w(0)
	emit := func(s string) {
		for i := 0; i < len(s); i++ {
			w(olADDIU(12, 0, int16(0x80|s[i])))
			w(olSB(12, 13, 0))
			w(olADDIU(13, 13, 1))
		}
	}
	a.label("suf_san")
	emit("-san")
	a.b(4, 0, 0, "term")
	w(0)
	a.label("suf_kun")
	emit("-kun")
	a.b(4, 0, 0, "term")
	w(0)
	a.label("suf_chan")
	emit("-chan")
	a.label("term")
	w(olSB(0, 13, 0))
	// Bounds: written = cursor - destination must be < capacity.
	w(olSUBU(12, 13, 16))
	w(olRType(12, 17, 1, 0x2B)) // sltu at, written, capacity
	a.b(4, 1, 0, "fail")
	w(0)
	w(olADDIU(2, 0, 1))
	a.b(4, 0, 0, "done")
	w(0)
	a.label("fail")
	w(olAddu(2, 0, 0))
	a.label("done")
	w(olLW(31, 29, 0x40))
	w(olLW(16, 29, 0x44))
	w(olLW(17, 29, 0x48))
	w(olLW(18, 29, 0x4C))
	w(olLW(19, 29, 0x50))
	w(olLW(20, 29, 0x54))
	a.w(olJR(31))
	w(olADDIU(29, 29, OLFullNameFrame))
	a.resolve()
	if len(a.words)*4 > 0x300 {
		return nil, fmt.Errorf("full-name handler unexpectedly large: %d B", len(a.words)*4)
	}
	return words(a.words...), nil
}

// BuildFullNameDispatchStub emits the 24 B guard-tail stub that verifies the
// body and enters the full-name handler. originalTarget is the retail routine
// the patched call site originally called; it is the fail-closed destination.
func BuildFullNameDispatchStub(originalTarget, bodyRAM uint32) ([]byte, error) {
	off := bodyRAM - OLBodyBase
	if off < 0 || off > 0x7FFF {
		return nil, fmt.Errorf("full-name body offset %d does not fit addiu", off)
	}
	a := &miniAsm{labels: map[string]int{}}
	a.w(olLUI(14, originalTarget))
	a.w(olORI(14, 14, originalTarget))
	a.w(olAddu(12, 14, 0))
	a.w(olADDIU(11, 0, int16(off)))
	a.w(jWord(OLVerifierRAM))
	a.w(0)
	b := words(a.words...)
	if len(b) != OLFullNameStubBytes {
		return nil, fmt.Errorf("dispatch stub is %d B, want %d", len(b), OLFullNameStubBytes)
	}
	return b, nil
}

// FullNameHandlerInfo is the measured shape of the handler.
type FullNameHandlerInfo struct {
	Entry           uint32   `json:"entry"`
	CodeBytes       int      `json:"code_bytes"`
	FrameBytes      int      `json:"frame_bytes"`
	MaxFieldLetters int      `json:"max_field_letters"`
	MinCapacity     int      `json:"min_capacity"`
	Honorifics      []string `json:"honorifics"`
	StubEntry       uint32   `json:"stub_entry"`
	StubBytes       int      `json:"stub_bytes"`
	AvailableSpare  int      `json:"available_spare_after_handler"`
	BodyCapacity    int      `json:"body_capacity"`
	Installed       bool     `json:"installed"`
}

// FullNameHandlerInfoFor reports the handler geometry after it has been placed
// in a module body.
func FullNameHandlerInfoFor(m OverlayLocalModule) FullNameHandlerInfo {
	return FullNameHandlerInfo{
		Entry: m.FullNameBodyRAM, CodeBytes: m.FullNameBytes, FrameBytes: OLFullNameFrame,
		MaxFieldLetters: OLFullNameMaxField, MinCapacity: OLFullNameMinCapacity,
		Honorifics: fullNameHonorifics[:], StubEntry: OLFullNameStubRAM, StubBytes: OLFullNameStubBytes,
		AvailableSpare: OLBodyCapacity - (int(m.FullNameBodyRAM-OLBodyBase) + m.FullNameBytes),
		BodyCapacity:   OLBodyCapacity, Installed: false,
	}
}

// InstallFullNameRoute builds an in-memory patched overlay for a *real*
// overlay-owned call site. It refuses anything that is not an authenticated
// original, refuses the wrong call word, and writes the stub into the guard's
// spare bytes, so no byte outside the declared regions changes. It is not used
// by the selected architecture because no real site exists.
func InstallFullNameRoute(src []byte, name string, site OverlayCallsite, fallback uint32) ([]byte, []byte, error) {
	if len(src) != 196608 || sha(src) != OverlaySHA[name] {
		return nil, nil, fmt.Errorf("overlay %s is not the authenticated original", name)
	}
	if site.Overlay != name || site.Target != 0x80082764 {
		return nil, nil, fmt.Errorf("site %s %08x is not a talk-runner/full-name site", site.Overlay, site.PC)
	}
	m, err := BuildOverlayLocalModule()
	if err != nil {
		return nil, nil, err
	}
	stub, err := BuildFullNameDispatchStub(fallback, m.FullNameBodyRAM)
	if err != nil {
		return nil, nil, err
	}
	guard := append([]byte(nil), m.Guard...)
	copy(guard[OLFullNameStubRAM-OLGuardBase:], stub)
	d := append([]byte(nil), src...)
	if binary.LittleEndian.Uint32(d[site.FileOff:]) != jalWord(site.Target) {
		return nil, nil, fmt.Errorf("%s+0x%x is not the authenticated JAL", name, site.FileOff)
	}
	copy(d[OLPayloadFileOff:OLGuardFileEnd], guard)
	copy(d[OLBodyFileOff:OLBodyFileOff+len(m.Body)], m.Body)
	binary.LittleEndian.PutUint32(d[site.FileOff:], jalWord(OLFullNameStubRAM))
	ck := packedTableChecksum(d)
	d[0x2FFFC] = byte(ck >> 8)
	d[0x2FFFD] = byte(ck)
	if binary.BigEndian.Uint16(d[0x2FFFC:]) != packedTableChecksum(d) {
		return nil, nil, fmt.Errorf("checksum damaged")
	}
	return d, guard, nil
}
