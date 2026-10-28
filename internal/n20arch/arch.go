// Package n20arch is an ISOLATED, OFFLINE-ONLY prototype for the corrected
// N20 delivery architecture. It never opens a game image, save, emulator or
// production builder. Retail bytes are read only when a caller explicitly
// supplies a private path through an environment variable in tests.
//
// An earlier, rejected layout placed a persistent 4,032 B core at 0x801FF000 and
// disabled the original BIOS heap. Both choices are REJECTED here:
//   - the original InitHeap(0x801FF800,0x7F0) heap overlaps that core by
//     1,984 B and its use is not disproved; previous version/overlay status are inconclusive;
//   - the four boot words that implement the SP switch and InitHeap call are
//     preserved byte-identically, including the SP-derived store to
//     0x80125124.
//
// The corrected module is fully overlay-local: it lives in the authenticated
// overlay payload window at 0x80160E00, which the original operation-6 loader
// already owns and replaces on every scene load. There is no resident code,
// no boot patch, no preload call and no ENDING-first ordering assumption.
// safe_to_patch remains false.
package n20arch

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	pn "tokimemo/internal/playername"
)

const (
	// Overlay-local module. PayloadBase holds the 4 B "N5" header; the module
	// itself starts at ModuleBase and executes in place in the loaded slot.
	PayloadBase     uint32 = 0x80160E00
	ModuleBase      uint32 = 0x80160E04
	ModuleRomanizer uint32 = 0x80160FC0
	ModuleSpeaker   uint32 = 0x80161B74
	ModuleLen              = 3644
	ModuleSHA              = "e6a8f6d33d43cc7a2a8150712aba2b3433cd9503083e53f916b4c24dc0f96a20"

	// Payload header "N5\0\0" followed by the 3,644 B module. The runtime
	// verifier covers exactly these 3,648 B (912 words), never the window.
	PayloadMagicWord  uint32 = 0x0000354E
	PayloadCheckBytes        = 3648
	PayloadCheckWords        = PayloadCheckBytes / 4
	PayloadSum32      uint32 = 0xf53afbb5
	PayloadXOR32      uint32 = 0x385991d1

	// Identical 288 B dispatch window in every overlay. Only two class stubs
	// are needed because only the five source-proven routes are hooked.
	WindowStart      uint32 = 0x80161EDC
	WindowBytes             = 288
	FormatterStubRAM uint32 = 0x80161EDC
	SpeakerStubRAM   uint32 = 0x80161EE4
	VerifierRAM      uint32 = 0x80161EEC
	VerifierBytes           = 116

	// Overlay file offsets (RAM base 0x80132000).
	WindowFileOff   = 0x2FEDC
	PayloadFileOff  = 0x2EE00
	PayloadCapacity = 4312

	// Retail addresses.
	OriginalQueue   uint32 = 0x8004E788
	SurnameField    uint32 = 0x800E6354
	GivenField      uint32 = 0x800E635C
	SanCallerReturn uint32 = 0x80081DD0
	// HISTORICAL-UNUSED: the old labels "fullname return A/B" were wrong.
	// Both words are renderer 0x80081190 queue exits (jal 0x8004E788), not
	// full-name entries; see N20_RESULT.md §12.6. Kept for audit only and
	// referenced by no code.
	FullnameReturnA    uint32 = 0x80082708
	FullnameReturnB    uint32 = 0x8008272C
	ForbiddenOldBase   uint32 = 0x800E3800
	ForbiddenOldEnd    uint32 = 0x800E5B10
	OverlaySlotBase    uint32 = 0x80132000
	OverlaySlotEnd     uint32 = 0x80162000
	OverlayLoadSectors        = 96
	StackTop           uint32 = 0x801FEFF0
	BootBSSStart       uint32 = 0x800E60A0
	BootBSSEnd         uint32 = 0x8012B538

	// Original BIOS heap and the rejected persistent claim.
	OriginalHeapStart  uint32 = 0x801FF800
	OriginalHeapEnd    uint32 = 0x801FFFF0
	RejectedTopRAMBase uint32 = 0x801FF000
	RejectedTopRAMEnd  uint32 = 0x801FFFC0

	// EndingFirstProven is false: the cold-boot scene byte at 0x800E738E is
	// zero in boot-cleared BSS, but the loader's default LBA 0x994A is not
	// authenticated as ENDING.EXN by any source available offline.
	EndingFirstProven = false
)

// RetailHook is one authenticated original JAL/delay pair that is redirected
// to the overlay-local window. Only the five source-backed formatter/speaker
// routes are hooked. The san and full-name JALs remain untouched retail calls.
type RetailHook struct {
	Name    string
	PC      uint32
	DelayPC uint32
	Target  uint32
	Class   string
}

var RetailHooks = []RetailHook{
	{"formatter_a", 0x8007F7D4, 0x8007F7D8, FormatterStubRAM, "formatter"},
	{"formatter_b", 0x8007F898, 0x8007F89C, FormatterStubRAM, "formatter"},
	{"formatter_c", 0x8007F95C, 0x8007F960, FormatterStubRAM, "formatter"},
	{"formatter_d", 0x80080C30, 0x80080C34, FormatterStubRAM, "formatter"},
	{"speaker", 0x80050E74, 0x80050E78, SpeakerStubRAM, "speaker"},
}

// PreservedBootWords are authenticated original words that the corrected
// architecture never changes. They implement the boot stack switch, the
// SP-derived store to 0x80125124 and InitHeap(0x801FF800,0x7F0).
var PreservedBootWords = []struct {
	PC   uint32
	Word uint32
	What string
}{
	{0x800420E4, 0x3C018012, "lui at,0x8012"},
	{0x800420EC, 0xAC225124, "sw v0,0x5124(at) (old SP)"},
	{0x800420F0, 0x3484F800, "addiu a0,a0,0xF800 (heap base)"},
	{0x800420F8, 0x240507F0, "addiu a1,zero,0x7F0 (heap size)"},
}

// PreloadSites is intentionally empty. The corrected design does not hook
// either original FlushCache caller.
var PreloadSites = []uint32{}

// RejectedBootPatch records the superseded four-word patch so the evidence can
// show why it is not applied.
var RejectedBootPatch = []struct {
	PC       uint32
	Original uint32
	OldNew   uint32
}{
	{0x800420E4, 0x3C018012, 0x3C018020},
	{0x800420EC, 0xAC225124, 0xAC20FFC4},
	{0x800420F0, 0x3484F800, 0x3484FFC0},
	{0x800420F8, 0x240507F0, 0x24050000},
}

type Core struct {
	Module    []byte
	ModuleSHA string
	Payload   []byte
	Sum32     uint32
	XOR32     uint32
	Verifier  []byte
	Window    []byte
	WindowSHA string
}

// BuildCore rebuilds the verified five-route program at the overlay-local
// base, then builds the 3,648 B checked payload and 288 B window.
func BuildCore() (Core, error) {
	var c Core
	bridge, err := pn.BuildPS1FormatterBridgeFourRoutes(ModuleBase, ModuleRomanizer)
	if err != nil {
		return c, err
	}
	if bridge.CodeBytes != 444 || len(bridge.Binary) != 444 {
		return c, fmt.Errorf("bridge geometry %d/%d", bridge.CodeBytes, len(bridge.Binary))
	}
	packed, err := pn.BuildPS1PackedSafeSingleCore(ModuleRomanizer)
	if err != nil {
		return c, err
	}
	if packed.CodeBytes != 1572 || packed.ProgramBytes != 2996 || len(packed.Binary) != 2996 {
		return c, fmt.Errorf("packed core geometry %d/%d/%d", packed.CodeBytes, packed.ProgramBytes, len(packed.Binary))
	}
	speaker, err := pn.BuildPS1SpeakerQueueWrapper(ModuleSpeaker, pn.PS1SpeakerQueueDependencies{
		Romanizer: ModuleRomanizer, OriginalQueue: OriginalQueue,
		SurnameField: SurnameField, CallerReturn: 0x80050E7C,
	})
	if err != nil {
		return c, err
	}
	if speaker.CodeBytes != 204 || len(speaker.Binary) != 204 {
		return c, fmt.Errorf("speaker geometry %d/%d", speaker.CodeBytes, len(speaker.Binary))
	}
	c.Module = append(append(append([]byte{}, bridge.Binary...), packed.Binary...), speaker.Binary...)
	if len(c.Module) != ModuleLen {
		return c, fmt.Errorf("module length %d", len(c.Module))
	}
	c.ModuleSHA = sha(c.Module)
	if c.ModuleSHA != ModuleSHA {
		return c, fmt.Errorf("module SHA drift: %s", c.ModuleSHA)
	}
	c.Payload = make([]byte, PayloadCapacity)
	binary.LittleEndian.PutUint32(c.Payload[:4], PayloadMagicWord)
	copy(c.Payload[4:], c.Module)
	for i := 0; i < PayloadCheckBytes; i += 4 {
		w := binary.LittleEndian.Uint32(c.Payload[i:])
		c.Sum32 += w
		c.XOR32 ^= w
	}
	if c.Sum32 != PayloadSum32 || c.XOR32 != PayloadXOR32 {
		return c, fmt.Errorf("payload moments drift sum=%08x xor=%08x", c.Sum32, c.XOR32)
	}
	c.Verifier = buildVerifier(c.Sum32, c.XOR32)
	if len(c.Verifier) != VerifierBytes {
		return c, fmt.Errorf("verifier length %d", len(c.Verifier))
	}
	c.Window = buildWindow(c.Verifier)
	if len(c.Window) != WindowBytes {
		return c, fmt.Errorf("window length %d", len(c.Window))
	}
	c.WindowSHA = sha(c.Window)
	return c, nil
}

// buildWindow places the two class stubs at the start of the 288 B window and
// the range verifier immediately after them. The rest stays zero.
func buildWindow(verifier []byte) []byte {
	w := make([]byte, WindowBytes)
	binary.LittleEndian.PutUint32(w[0:], jWord(VerifierRAM))
	binary.LittleEndian.PutUint32(w[4:], 0x240B0000) // addiu t3,zero,0 (module entry)
	binary.LittleEndian.PutUint32(w[8:], jWord(VerifierRAM))
	binary.LittleEndian.PutUint32(w[12:], 0x240B0D70) // addiu t3,zero,0xD70 (speaker entry)
	copy(w[16:], verifier)
	return w
}

// buildVerifier is the compact 116 B runtime range verifier. It checks the
// magic and sum32/xor32 over exactly PayloadCheckBytes at PayloadBase, then
// enters the module at ModuleBase+t3. It preserves a0-a3, sp and ra and only
// clobbers t0-t9. Failure tails to the retail queue with J (not JAL).
func buildVerifier(sum32, xor32 uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	a.w(0x3C088016) // lui t0,0x8016
	a.w(0x25080E00) // addiu t0,t0,0x0E00
	a.w(0x250A0004) // addiu t2,t0,0x0004 (module base)
	a.w(0x8D0E0000) // lw t6,0(t0)
	a.w(0x3C190000) // lui t9,magic_hi
	a.w(0x37390000 | (PayloadMagicWord & 0xffff))
	a.b(5, 14, 25, "fail")              // bne t6,t9,fail
	a.w(0)                              // nop
	a.w(0x340D0000 | PayloadCheckWords) // ori t5,zero,912
	a.w(0x00004821)                     // addu t1,zero,zero
	a.w(0x00007821)                     // addu t7,zero,zero
	a.w(0x3C0C0000 | (sum32 >> 16))
	a.w(0x358C0000 | (sum32 & 0xffff))
	a.w(0x3C190000 | (xor32 >> 16))
	a.w(0x37390000 | (xor32 & 0xffff))
	a.label("loop")
	a.w(0x8D0E0000)        // lw t6,0(t0)
	a.w(0x25ADFFFF)        // addiu t5,t5,-1
	a.w(0x012E4821)        // addu t1,t1,t6
	a.w(0x01EE7826)        // xor t7,t7,t6
	a.b(5, 13, 0, "loop")  // bne t5,zero,loop
	a.w(0x25080004)        // delay: addiu t0,t0,4
	a.b(5, 9, 12, "fail")  // bne t1,t4,fail
	a.w(0)                 // nop
	a.b(5, 15, 25, "fail") // bne t7,t9,fail
	a.w(0x016A5821)        // delay: addu t3,t3,t2
	a.w(0x01600008)        // jr t3
	a.w(0)                 // nop
	a.label("fail")
	a.w(jWord(OriginalQueue))
	a.w(0)
	a.resolve()
	return words(a.words...)
}

// miniAsm is a tiny label/branch helper used only for the fixed verifier. It
// keeps the branch offsets independently checkable instead of hand-counting.
type miniAsm struct {
	words  []uint32
	labels map[string]int
	fix    []fixup
	jfix   []jfixup
}
type fixup struct {
	idx   int
	label string
}
type jfixup struct {
	idx   int
	label string
}

func (a *miniAsm) w(v uint32)     { a.words = append(a.words, v) }
func (a *miniAsm) label(n string) { a.labels[n] = len(a.words) }
func (a *miniAsm) b(op, rs, rt uint32, label string) {
	a.fix = append(a.fix, fixup{idx: len(a.words), label: label})
	a.words = append(a.words, op<<26|rs<<21|rt<<16)
}
func (a *miniAsm) resolve() {
	for _, f := range a.fix {
		target := a.labels[f.label]
		off := target - (f.idx + 1)
		a.words[f.idx] |= uint32(off) & 0xffff
	}
}

// j appends an absolute J to a label. The target is an absolute word address,
// so it is resolved after resolve() with the module's base.
func (a *miniAsm) j(label string) {
	a.jfix = append(a.jfix, jfixup{idx: len(a.words), label: label})
	a.words = append(a.words, 0)
}

// resolveJLabels rewrites every recorded J placeholder using base and the
// label word index.
func (a *miniAsm) resolveJLabels(base uint32) {
	for _, f := range a.jfix {
		target := base + uint32(a.labels[f.label]*4)
		a.words[f.idx] = jWord(target)
	}
}

func words(ws ...uint32) []byte {
	b := make([]byte, 4*len(ws))
	for i, w := range ws {
		binary.LittleEndian.PutUint32(b[4*i:], w)
	}
	return b
}

func jWord(target uint32) uint32   { return 0x08000000 | ((target >> 2) & 0x03FFFFFF) }
func jalWord(target uint32) uint32 { return 0x0C000000 | ((target >> 2) & 0x03FFFFFF) }
func sha(b []byte) string          { return fmt.Sprintf("%x", sha256.Sum256(b)) }

// Payload returns the 4,312 B overlay payload: "N5", the module and zero tail.
func (c Core) PayloadBytes() []byte { return append([]byte(nil), c.Payload...) }

// RefuseForbidden rejects the historical previous version address and the rejected
// persistent top-of-RAM claim before any build.
func RefuseForbidden(base uint32) error {
	if base >= ForbiddenOldBase && base < ForbiddenOldEnd {
		return fmt.Errorf("previous version: %08x intersects original scratch/record table", base)
	}
	if base >= RejectedTopRAMBase && base < RejectedTopRAMEnd {
		return fmt.Errorf("N20: %08x is in the rejected unproven top-of-RAM claim", base)
	}
	return nil
}
