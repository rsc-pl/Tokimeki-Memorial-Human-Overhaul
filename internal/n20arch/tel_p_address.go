package n20arch

// TEL-local address conversion applies only to authenticated second-greeting
// callers and their selected source rows. The original address producer chooses
// given or family name followed by 君 or さん in a local stack field. Conversion
// requires an exact match to the corresponding saved name and chosen suffix.
// Saved fields, shared P data, parser, speaker and tables remain untouched;
// unmatched forms continue through the native renderer.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	telPAddressShim    uint32 = OverlaySlotBase + 0x2b000
	telPAddressFileOff        = 0x2b000
	telPAddressWindow         = 0x1000
	telPAddressFrame   int16  = 0xf0
	telPAddressSrcMax  int16  = 96
	telPAddressRetail  uint32 = 0x80050e8c
	telPAddressNativeP uint32 = 0x80051508
)

type telPAddressSite struct{ pc, table uint32 }

var telPAddressSites = [...]telPAddressSite{
	{0x801359c4, 0x80140ad8},
	{0x80135da8, 0x80140ad8},
	{0x80136064, 0x80140ad8},
	{0x8013614c, 0x80140ad8},
	{0x80136234, 0x80140d18},
	{0x8013631c, 0x80140f0c},
}
var telPAddressTables = [...]struct {
	addr  uint32
	count int
	pMask uint16 // Original table rows with the dynamic P name token.
}{
	{0x80140ad8, 11, 0x05fe}, {0x80140d18, 11, 0x07ff}, {0x80140f0c, 11, 0x077f},
}

func telPAddressSource(exe, tel []byte) error {
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA || len(tel) != 196608 || sha(tel) != OverlaySHA["TEL.EXN"] {
		return fmt.Errorf("TEL P address: unauthenticated retail image")
	}
	// Original phone speaker table: index 2 is Himoo, index 3 Katagiri.
	for index, want := range map[uint32][]byte{2: {0x95, 0x52, 0x8f, 0x8f, 0}, 3: {0x95, 0xd0, 0x8b, 0xcb, 0}} {
		ptr := binary.LittleEndian.Uint32(exe[0x800b35f4-Base+index*4:])
		if ptr < Base || ptr-Base+uint32(len(want)) > uint32(len(exe)) || !bytes.Equal(exe[ptr-Base:ptr-Base+uint32(len(want))], want) {
			return fmt.Errorf("TEL P address: original speaker table drift at %d", index)
		}
	}
	for _, s := range telPAddressSites {
		for pc, want := range map[uint32]uint32{
			s.pc - 4: (0x8c840000 | (s.table & 0xffff)),
			s.pc:     jalWord(telPAddressRetail),
			s.pc + 4: 0x00002825, // a1 = 0, original delay instruction
		} {
			if binary.LittleEndian.Uint32(tel[pc-OverlaySlotBase:]) != want {
				return fmt.Errorf("TEL P address: caller drift at %#x", pc)
			}
		}
	}
	for _, tb := range telPAddressTables {
		countP := 0
		var nativeMask uint16
		for i := 0; i < tb.count; i++ {
			ptr := binary.LittleEndian.Uint32(tel[tb.addr-OverlaySlotBase+uint32(i*4):])
			if ptr < 0x801407f0 || ptr > 0x80140ef4 {
				return fmt.Errorf("TEL P address: table pointer drift %#x entry %d", tb.addr, i)
			}
			raw := tel[ptr-OverlaySlotBase:]
			end := bytes.IndexByte(raw[:telPAddressSrcMax], 0)
			if end < 0 || end == 0 {
				return fmt.Errorf("TEL P address: unterminated table text %#x", ptr)
			}
			if bytes.Count(raw[:end], []byte{'P'}) > 1 {
				return fmt.Errorf("TEL P address: unexpected multiple P %#x", ptr)
			}
			if bytes.Count(raw[:end], []byte{'P'}) == 1 {
				countP++
				nativeMask |= 1 << i
			}
		}
		if nativeMask != tb.pMask {
			return fmt.Errorf("TEL P address: original row-mask drift at %#x: %#x", tb.addr, nativeMask)
		}
		if countP < tb.count-2 {
			return fmt.Errorf("TEL P address: expected source family lost %#x count %d", tb.addr, countP)
		}
	}
	if !allZero(tel[telPAddressFileOff : telPAddressFileOff+telPAddressWindow]) {
		return fmt.Errorf("TEL P address: retail code window occupied")
	}
	return nil
}

func telPAddressPayload() ([]byte, error) {
	mod, err := BuildOverlayLocalModule()
	if err != nil {
		return nil, err
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	mov := func(d, s uint32) { w(olAddu(d, s, 0)) }
	sw := func(t, b uint32, i int16) { w(olSW(t, b, i)) }
	lw := func(t, b uint32, i int16) { w(olLW(t, b, i)); w(0) }
	lbu := func(t, b uint32, i int16) { w(olLBU(t, b, i)); w(0) }
	sb := func(t, b uint32, i int16) { w(olSB(t, b, i)) }
	beq := func(x, y uint32, label string) { a.b(4, x, y, label); w(0) }
	bne := func(x, y uint32, label string) { a.b(5, x, y, label); w(0) }
	jump := func(label string) { beq(0, 0, label) }

	// 0x10..0x1f name conversion; 0x20..0x9f assembled line (128B),
	// 0xa0..0xbc preserved s0..s7, 0xc0..0xcc arguments, 0xd0 ra,
	// 0xd4/d8 return registers, 0xe0..0xef native P scratch.
	// The outbound 0x00..0x0f ABI argument area remains unused as scratch.
	add(29, 29, -telPAddressFrame)
	for i, r := range []uint32{16, 17, 18, 19, 20, 21, 22, 23} {
		sw(r, 29, int16(0xa0+4*i))
	}
	for i, r := range []uint32{4, 5, 6, 7} {
		sw(r, 29, int16(0xc0+4*i))
	}
	sw(31, 29, 0xd0)
	mov(16, 4) // original source
	mov(17, 5) // mode
	mov(18, 6) // character index
	mov(19, 7) // auxiliary input
	bne(17, 0, "retail")
	// Source pointer stays in the authenticated TEL data region.
	w(olLUI(8, 0x801407f0))
	w(olORI(8, 8, 0x07f0))
	w(olRType(16, 8, 9, 0x2b))
	bne(9, 0, "retail")
	w(olLUI(8, 0x80140ef4))
	w(olORI(8, 8, 0x0ef4))
	w(olRType(8, 16, 9, 0x2b))
	bne(9, 0, "retail")
	// Bounded NUL/single P validation; only the actual table-loaded a0 is used.
	mov(20, 16)
	mov(23, 0)
	mov(22, 0) // bound newline controls; every odd-position break may need one pair-pad
	add(21, 0, telPAddressSrcMax)
	a.label("scan")
	lbu(8, 20, 0)
	beq(8, 0, "scanned")
	add(9, 0, 0x50)
	bne(8, 9, "scan_break")
	add(23, 23, 1)
	a.label("scan_break")
	// At most four 0x20 line-break controls: src <=95 + name/suffix <=15,
	// four parity bytes and a final pair pad always fit 128B staging.
	add(9, 0, 0x20)
	bne(8, 9, "scan_next")
	add(22, 22, 1)
	w(olSLTIU(10, 22, 5))
	beq(10, 0, "retail")
	a.label("scan_next")
	add(20, 20, 1)
	add(21, 21, -1)
	bne(21, 0, "scan")
	jump("retail")
	a.label("scanned")
	add(9, 0, 1)
	bne(23, 9, "retail")
	// Bind each eligible caller's return address to its own original table.
	// A source from another TEL table must not acquire this caller's P form,
	// even when the indexed character and text are otherwise individually valid.
	// The original JAL saves caller PC+8 in ra; authenticate it before any
	// nested call can replace ra. Unknown callers fall through unchanged.
	w(olSLTIU(8, 18, 11))
	beq(8, 0, "retail")
	w(olRType(0, 18, 9, 0) | (2 << 6)) // t1 = character index * 4
	for i, site := range telPAddressSites {
		returnPC := site.pc + 8
		w(olLUI(8, returnPC))
		w(olORI(8, 8, returnPC&0xffff))
		bne(31, 8, fmt.Sprintf("caller_next_%d", i))
		if site.table == telPAddressTables[2].addr {
			w(olSLTIU(8, 18, int16(telPAddressTables[2].count)))
			beq(8, 0, "retail")
		}
		w(olLUI(10, site.table))
		w(olORI(10, 10, site.table&0xffff))
		w(olAddu(10, 10, 9))
		lw(11, 10, 0)
		bne(11, 16, "retail")
		// The English text may contain an ordinary capital P. Only a row
		// with an original retail P control marker may trigger substitution.
		for _, tb := range telPAddressTables {
			if tb.addr == site.table {
				add(10, 0, int16(tb.pMask))
				break
			}
		}
		jump("caller_verified")
		a.label(fmt.Sprintf("caller_next_%d", i))
	}
	jump("retail")
	a.label("caller_verified")
	// Shift the original P-row mask by the selected character index. If the
	// original row had no P, the present English capital P is ordinary text.
	w(olRType(18, 10, 8, 6))  // srlv t0,t2,a2
	w(olIType(0x0c, 8, 8, 1)) // andi t0,t0,1
	beq(8, 0, "retail")
	// Native retail P producer: a0=private 16-byte stack field,
	// a1=the same script index the original caller passes as a2.
	// This selects nickname/family/given/suffix through original game logic,
	// without mutating the global prepared field or any saved name.
	for _, off := range []int16{0xe0, 0xe4, 0xe8, 0xec} {
		sw(0, 29, off)
	}
	add(4, 29, 0xe0)
	mov(5, 18)
	w(jalWord(telPAddressNativeP))
	w(0)
	// Match the native producer's exact saved name and suffix, independently
	// of character index. Unrecognized nickname/address forms remain retail.
	mov(23, 0) // 0: given + 君, 1: family + さん, 2: family + 君, 3: given + さん
	a.label("try_name")
	add(20, 29, 0xe0)
	beq(23, 0, "select_given")
	add(8, 0, 3)
	beq(23, 8, "select_given")
	w(olLUI(21, OLA0SurnameField))
	w(olORI(21, 21, OLA0SurnameField&0xffff))
	jump("name_selected")
	a.label("select_given")
	w(olLUI(21, OLFieldPrepSavedGiv))
	w(olORI(21, 21, OLFieldPrepSavedGiv&0xffff))
	a.label("name_selected")
	mov(22, 0) // exact saved 2-byte kana, max six bytes
	a.label("compare")
	lbu(8, 21, 0)
	beq(8, 0, "at_suffix")
	lbu(9, 20, 0)
	bne(8, 9, "next_name")
	add(22, 22, 1)
	add(21, 21, 1)
	add(20, 20, 1)
	add(8, 0, 7)
	w(olRType(22, 8, 9, 0x2b))
	beq(9, 0, "next_name")
	jump("compare")
	a.label("at_suffix")
	w(olSLTIU(8, 22, 2))
	bne(8, 0, "next_name")
	w(olIType(0x0c, 22, 8, 1))
	bne(8, 0, "next_name")
	w(olIType(0x0c, 23, 9, 1)) // odd forms carry さん
	beq(9, 0, "check_kun")
	for i, v := range []int16{0x82, 0xb3, 0x82, 0xf1, 0} {
		lbu(8, 20, int16(i))
		add(9, 0, v)
		bne(8, 9, "next_name")
	}
	jump("form_matched")
	a.label("check_kun")
	for i, v := range []int16{0x8c, 0x4e, 0} {
		lbu(8, 20, int16(i))
		add(9, 0, v)
		bne(8, 9, "next_name")
	}
	jump("form_matched")
	a.label("next_name")
	add(23, 23, 1)
	w(olSLTIU(8, 23, 4))
	beq(8, 0, "retail")
	jump("try_name")
	a.label("form_matched")
	// Fail closed if the TEL-local N6 converter has not been installed.
	w(olLUI(8, OLGuardBase))
	lw(9, 8, int16(OLGuardBase&0xffff))
	add(10, 0, int16(OLMagicWord))
	bne(9, 10, "retail")
	lw(9, 8, int16((OLGuardBase+4)&0xffff))
	add(10, 0, int16(mod.BodyLen))
	bne(9, 10, "retail")
	beq(23, 0, "convert_given")
	add(8, 0, 3)
	beq(23, 8, "convert_given")
	w(olLUI(4, OLA0SurnameField))
	w(olORI(4, 4, OLA0SurnameField&0xffff))
	jump("convert_selected")
	a.label("convert_given")
	w(olLUI(4, OLFieldPrepSavedGiv))
	w(olORI(4, 4, OLFieldPrepSavedGiv&0xffff))
	a.label("convert_selected")
	add(5, 29, 0x10)
	add(6, 0, 16)
	add(7, 0, 3)
	w(jalWord(OLBodyBase))
	w(0)
	add(22, 2, -1)
	w(olSLTIU(8, 22, 13))
	beq(8, 0, "retail")
	w(olSLTIU(8, 22, 2))
	bne(8, 0, "retail")
	w(olIType(0x0c, 22, 8, 1))
	bne(8, 0, "retail")
	add(9, 29, 0x10)
	w(olAddu(10, 9, 22))
	lbu(8, 10, 0)
	bne(8, 0, "retail")
	mov(11, 22)
	a.label("validate_latin")
	lbu(8, 9, 0)
	add(8, 8, -0xa0)
	w(olSLTIU(10, 8, 0x5b))
	beq(10, 0, "retail")
	add(9, 9, 1)
	add(11, 11, -1)
	bne(11, 0, "validate_latin")
	lbu(8, 9, -1)
	add(9, 0, 0xa0)
	bne(8, 9, "name_ready")
	add(22, 22, -1)
	a.label("name_ready")
	beq(22, 0, "retail")
	// Copy source prefix and suffix to a private 128B staging line.
	mov(20, 16)
	add(21, 29, 0x20)
	mov(24, 21) // start of current wrapper line, reset at each structural newline
	a.label("prefix")
	lbu(8, 20, 0)
	add(9, 0, 0x50)
	beq(8, 9, "prefix_done")
	// Retail 0x80050E8C recognizes control 0x20 only at an EVEN byte
	// offset. The N6 Latin name can flip the parity of the source line.
	// 0xA0 is the existing invisible pair-pad, not a text newline.
	add(9, 0, 0x20)
	bne(8, 9, "prefix_write")
	w(olSUBU(10, 21, 24)) // parity within the current wrapper line
	w(olIType(0x0c, 10, 10, 1))
	beq(10, 0, "prefix_write")
	add(9, 0, 0xa0)
	sb(9, 21, 0)
	add(21, 21, 1)
	a.label("prefix_write")
	sb(8, 21, 0)
	add(20, 20, 1)
	add(21, 21, 1)
	add(9, 0, 0x20)
	bne(8, 9, "prefix_next")
	mov(24, 21) // native wrapper resets its byte index after a split
	a.label("prefix_next")
	jump("prefix")
	a.label("prefix_done")
	add(20, 20, 1) // skip P
	add(9, 29, 0x10)
	mov(10, 22)
	a.label("copy_name")
	beq(10, 0, "name_done")
	lbu(8, 9, 0)
	sb(8, 21, 0)
	add(9, 9, 1)
	add(21, 21, 1)
	add(10, 10, -1)
	jump("copy_name")
	a.label("name_done")
	add(8, 0, 0xad)
	sb(8, 21, 0)
	add(21, 21, 1)
	w(olIType(0x0c, 23, 9, 1))
	beq(9, 0, "append_kun")
	for _, v := range []int16{0xf3, 0xe1, 0xee} {
		add(8, 0, v)
		sb(8, 21, 0)
		add(21, 21, 1)
	}
	jump("suffix")
	a.label("append_kun")
	for _, v := range []int16{0xeb, 0xf5, 0xee} {
		add(8, 0, v)
		sb(8, 21, 0)
		add(21, 21, 1)
	}
	a.label("suffix")
	lbu(8, 20, 0)
	beq(8, 0, "suffix_done")
	// Retail 0x80050E8C recognizes control 0x20 only at an EVEN byte
	// offset. The N6 Latin name can flip the parity of the source line.
	// 0xA0 is the existing invisible pair-pad, not a text newline.
	add(9, 0, 0x20)
	bne(8, 9, "suffix_write")
	w(olSUBU(10, 21, 24)) // parity within the current wrapper line
	w(olIType(0x0c, 10, 10, 1))
	beq(10, 0, "suffix_write")
	add(9, 0, 0xa0)
	sb(9, 21, 0)
	add(21, 21, 1)
	a.label("suffix_write")
	sb(8, 21, 0)
	add(20, 20, 1)
	add(21, 21, 1)
	add(9, 0, 0x20)
	bne(8, 9, "suffix_next")
	mov(24, 21) // next delimiter counts from this new line start
	a.label("suffix_next")
	jump("suffix")
	a.label("suffix_done")
	add(8, 29, 0x20)
	w(olSUBU(9, 21, 8))
	w(olIType(0x0c, 9, 10, 1))
	beq(10, 0, "write_nul")
	add(8, 0, 0xa0)
	sb(8, 21, 0)
	add(21, 21, 1)
	a.label("write_nul")
	sb(0, 21, 0)
	add(4, 29, 0x20)
	jump("invoke")
	a.label("retail")
	mov(4, 16)
	a.label("invoke")
	mov(5, 17)
	mov(6, 18)
	mov(7, 19)
	w(jalWord(telDialogueWrapperClone))
	w(0)
	sw(2, 29, 0xd4)
	sw(3, 29, 0xd8)
	for i, r := range []uint32{16, 17, 18, 19, 20, 21, 22, 23} {
		w(olLW(r, 29, int16(0xa0+4*i)))
	}
	w(olLW(31, 29, 0xd0))
	w(olLW(2, 29, 0xd4))
	w(olLW(3, 29, 0xd8))
	w(olJR(31))
	add(29, 29, telPAddressFrame)
	a.resolve()
	a.resolveJLabels(telPAddressShim)
	code := words(a.words...)
	if len(code) > telPAddressWindow {
		return nil, fmt.Errorf("TEL P address helper too large %d", len(code))
	}
	out := make([]byte, telPAddressWindow)
	if len(code) > telGirlSuffixShimOffset {
		return nil, fmt.Errorf("TEL scoped name helper overlaps local address code")
	}
	girl, err := telGirlSuffixPayload()
	if err != nil {
		return nil, err
	}
	copy(out, code)
	copy(out[telGirlSuffixShimOffset:], girl)
	return out, nil
}

func telPAddressPatch(exe, original, composed []byte) ([]byte, []byte, error) {
	if err := telPAddressSource(exe, original); err != nil {
		return nil, nil, err
	}
	code, err := telPAddressPayload()
	if err != nil {
		return nil, nil, err
	}
	if len(composed) != len(original) || !allZero(composed[telPAddressFileOff:telPAddressFileOff+telPAddressWindow]) {
		return nil, nil, fmt.Errorf("TEL P address staged window not empty")
	}
	mod, err := BuildOverlayLocalModule()
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(composed[OLPayloadFileOff:OLGuardFileEnd], mod.Guard) || !bytes.Equal(composed[OLBodyFileOff:OLBodyFileOff+len(mod.Body)], mod.Body) {
		return nil, nil, fmt.Errorf("TEL P address N6 body unavailable")
	}
	out := bytes.Clone(composed)
	copy(out[telPAddressFileOff:], code)
	for _, site := range telPAddressSites {
		off := site.pc - OverlaySlotBase
		if binary.LittleEndian.Uint32(out[off:]) != jalWord(telDialogueWrapperClone) || binary.LittleEndian.Uint32(out[off+4:]) != 0x00002825 {
			return nil, nil, fmt.Errorf("TEL P address cloned-wrapper call drift %#x", site.pc)
		}
		binary.LittleEndian.PutUint32(out[off:], jalWord(telPAddressShim))
	}
	if err := telGirlSuffixPatch(original, out); err != nil {
		return nil, nil, err
	}
	return code, out, nil
}

// VerifyTELPAddressFinalSources checks the *translated* source tables consumed
// by the existing six TEL hooks. The patch planner can repack text and move
// pointers: authentic retail addresses alone cannot prove the installed
// English line still contains the P control token. Rows without retail P may
// legitimately contain an ordinary ASCII capital P, which the MIPS row mask
// explicitly excludes from substitution.
func VerifyTELPAddressFinalSources(original, composed []byte) error {
	if len(original) != 196608 || sha(original) != OverlaySHA["TEL.EXN"] || len(composed) != len(original) {
		return fmt.Errorf("TEL P address final source: unauthenticated original or output size")
	}
	for _, tb := range telPAddressTables {
		for index := 0; index < tb.count; index++ {
			off := int(tb.addr-OverlaySlotBase) + index*4
			ptr := binary.LittleEndian.Uint32(composed[off:])
			if ptr < 0x801407f0 || ptr > 0x80140ef4 {
				return fmt.Errorf("TEL P address final source: table %#x[%d] pointer %#x outside original text block", tb.addr, index, ptr)
			}
			start := int(ptr - OverlaySlotBase)
			max := int(telPAddressSrcMax)
			if max > len(composed)-start {
				return fmt.Errorf("TEL P address final source: table %#x[%d] truncated", tb.addr, index)
			}
			end := bytes.IndexByte(composed[start:start+max], 0)
			if end < 1 {
				return fmt.Errorf("TEL P address final source: table %#x[%d] lacks bounded nonempty terminator", tb.addr, index)
			}
			if (tb.pMask>>index)&1 != 0 && bytes.Count(composed[start:start+end], []byte{'P'}) != 1 {
				return fmt.Errorf("TEL P address final source: table %#x[%d] lost unique P control token", tb.addr, index)
			}
		}
	}
	return nil
}

// VerifyTELPAddressInstalled checks the final overlay bytes after they have
// been read back from the built data track. It does not establish whether the
// emulator loaded that track or whether a particular dialogue executed.
func VerifyTELPAddressInstalled(composed []byte) (int, error) {
	if len(composed) != 196608 {
		return 0, fmt.Errorf("TEL P address built overlay length %d", len(composed))
	}
	code, err := telPAddressPayload()
	if err != nil {
		return 0, err
	}
	if !bytes.Equal(composed[telPAddressFileOff:telPAddressFileOff+len(code)], code) {
		return 0, fmt.Errorf("TEL P address built overlay payload differs")
	}
	for _, site := range telPAddressSites {
		off := site.pc - OverlaySlotBase
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telPAddressShim) ||
			binary.LittleEndian.Uint32(composed[off+4:]) != 0x00002825 {
			return 0, fmt.Errorf("TEL P address built overlay caller drift at %#x", site.pc)
		}
	}
	for _, site := range telGirlSuffixSites {
		off := site.pc - OverlaySlotBase
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telGirlSuffixShim) || binary.LittleEndian.Uint32(composed[off+4:]) != site.delay {
			return 0, fmt.Errorf("TEL scoped name installed call drift %#x", site.pc)
		}
	}
	return len(telPAddressSites), nil
}

func verifyTELPAddress(exe, original, composed, expected []byte) error {
	if err := telPAddressSource(exe, original); err != nil {
		return err
	}
	code, err := telPAddressPayload()
	if err != nil {
		return err
	}
	if !bytes.Equal(code, expected) || !bytes.Equal(composed[telPAddressFileOff:telPAddressFileOff+len(code)], code) {
		return fmt.Errorf("TEL P address generated payload drift")
	}
	for _, site := range telPAddressSites {
		off := site.pc - OverlaySlotBase
		if binary.LittleEndian.Uint32(composed[off:]) != jalWord(telPAddressShim) || binary.LittleEndian.Uint32(composed[off+4:]) != 0x00002825 {
			return fmt.Errorf("TEL P address site drift %#x", site.pc)
		}
	}
	if err := telGirlSuffixVerify(original, composed); err != nil {
		return err
	}
	return nil
}
