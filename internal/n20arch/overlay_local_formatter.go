package n20arch

// overlay formatter OFFLINE ONLY. overlay dispatch's plain XOR is commutative: changing the same bit in
// two instructions is invisible. This stronger 16-instruction MIPS-I check
// folds each instruction word into an order-sensitive reversible recurrence,
// and stores its inverse-derived seed in the existing local header field.
// It does not establish runtime code ownership or prevent TOCTOU/DMA writes.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	OverlayFormatterBlocked              = true
	OverlayFormatterBlockedReason        = "overlay formatter OFFLINE ONLY: order-dependent 32-bit C10 integrity sentinel detects two-word XOR cancellation, but executable overlay ownership/TOCTOU, 4 fallback overlays, full English and real game runtime remain UNPROVEN; safe_to_patch=false, runtime_pass=false."
	overlayFormatterIncrement                  uint32 = 0x00005a77
)

type OverlayFormatterIntegrityCandidate struct {
	OverlayDispatchIntegrityCandidate
	OrderSensitiveSentinel bool
}

// Recurrence for each word in image order: x=(x XOR word)+constant (mod 2^32).
// Backward inversion computes the seed that leaves zero after all 950 words.
// The result is a non-cryptographic accidental-corruption sentinel, NOT a MAC.
func overlayFormatterBodySeed(local []byte) (uint32, error) {
	if len(local) != C10ResidentBytes || binary.LittleEndian.Uint32(local[0:]) != C10Magic || binary.LittleEndian.Uint32(local[4:]) != C10ResidentBodyBytes {
		return 0, fmt.Errorf("overlay formatter image header/size mismatch")
	}
	var sum, xor uint32
	for i := C10ResidentGuardBytes; i < len(local); i += 4 {
		v := binary.LittleEndian.Uint32(local[i:])
		sum += v
		xor ^= v
	}
	if binary.LittleEndian.Uint32(local[8:]) != sum || binary.LittleEndian.Uint32(local[12:]) != xor {
		return 0, fmt.Errorf("overlay formatter overlay dispatch source checksum mismatch")
	}
	var seed uint32
	for i := len(local) - 4; i >= C10ResidentGuardBytes; i -= 4 {
		seed = (seed - overlayFormatterIncrement) ^ binary.LittleEndian.Uint32(local[i:])
	}
	return seed, nil
}

func overlayFormatterVerifierWords() []uint32 {
	// EXACT 64 B; t6/t7 established by authentic overlay dispatch F1/terminal stubs.
	// MIPS-I load delay after header load covered by the counter load,
	// and after the body load by pointer increment. The branch delay
	// updates the rolling state on EVERY iteration, including the last.
	return []uint32{
		olLUI(8, 0x80160000),
		olADDIU(8, 8, -256),
		olLW(10, 8, -244), // t2 = inverse seed at image+12
		olADDIU(9, 0, C10ResidentBodyBytes/4),
		olLW(11, 8, 0),
		olADDIU(8, 8, 4),
		olRType(10, 11, 10, 0x26), // xor t2,t2,t3
		olADDIU(9, 9, -1),
		olIType(5, 9, 0, uint16(0xfffb)),     // bne t1,zero -> LW at index 4
		olADDIU(10, 10, int16(overlayFormatterIncrement)), // checked branch-delay state update
		olIType(5, 10, 0, 3),                 // nonzero -> retail
		0,
		olJR(14), 0,
		olJR(15), 0,
	}
}

func PlanOverlayLocalOrderIntegrityOffline(exe []byte, originals map[string][]byte) (OverlayFormatterIntegrityCandidate, error) {
	var empty OverlayFormatterIntegrityCandidate
	overlayDispatchStage, err := PlanOverlayLocalIntegrityOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	seed, err := overlayFormatterBodySeed(overlayDispatchStage.LocalImage)
	if err != nil {
		return empty, err
	}
	out := OverlayFormatterIntegrityCandidate{OverlayDispatchIntegrityCandidate: overlayDispatchStage}
	out.LocalImage = bytes.Clone(overlayDispatchStage.LocalImage)
	binary.LittleEndian.PutUint32(out.LocalImage[12:], seed)
	// Audit the exact rolling digest independently before distributing it.
	state := seed
	for at := C10ResidentGuardBytes; at < len(out.LocalImage); at += 4 {
		state = (state ^ binary.LittleEndian.Uint32(out.LocalImage[at:])) + overlayFormatterIncrement
	}
	if state != 0 {
		return empty, fmt.Errorf("overlay formatter inverse seed roundtrip mismatch")
	}
	out.Overlays = make(map[string][]byte, len(overlayDispatchStage.Overlays))
	carrier := map[string]bool{}
	for _, name := range overlayDispatchStage.Carriers {
		carrier[name] = true
	}
	for name, prev := range overlayDispatchStage.Overlays {
		next := bytes.Clone(prev)
		if carrier[name] {
			at := C10DistributedSourceFileOff
			if !bytes.Equal(prev[at:at+C10ResidentBytes], overlayDispatchStage.LocalImage) {
				return empty, fmt.Errorf("overlay formatter source mismatch %s", name)
			}
			copy(next[at:at+C10ResidentBytes], out.LocalImage)
			binary.BigEndian.PutUint16(next[len(next)-4:], packedTableChecksum(next))
		} else if !bytes.Equal(next, prev) {
			return empty, fmt.Errorf("overlay formatter fallback changed %s", name)
		}
		out.Overlays[name] = next
	}
	if len(overlayDispatchStage.Carriers) != 22 || len(overlayDispatchStage.FallbackOverlays) != 4 {
		return empty, fmt.Errorf("overlay formatter carrier census changed")
	}
	out.EnglishEXE = bytes.Clone(overlayDispatchStage.EnglishEXE)
	words := overlayFormatterVerifierWords()
	if len(words) != 16 {
		return empty, fmt.Errorf("overlay formatter verifier length")
	}
	at := int(overlayDispatchVerifier - 0x80040800)
	if at < 0 || at+64 > len(out.EnglishEXE) {
		return empty, fmt.Errorf("overlay formatter EXE verifier location invalid")
	}
	// Confine change precisely to the verifier. No permanent RAM writes.
	for i, w := range words {
		binary.LittleEndian.PutUint32(out.EnglishEXE[at+i*4:], w)
	}
	out.OrderSensitiveSentinel = true
	out.Blocked, out.BlockedReason = true, OverlayFormatterBlockedReason
	out.SafeToPatch, out.RuntimePass = false, false
	return out, nil
}
