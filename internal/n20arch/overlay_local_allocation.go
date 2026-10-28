package n20arch

// overlay allocation exploratory relocation: execute the C10 body DIRECTLY inside an
// authenticated overlay's high-tail source, rather than copying it to the
// unowned persistent 0x8012D200 RAM. This is an OFFLINE, fail-closed candidate;
// only 22/26 overlays have the required window. Four fall back to retail.
// The result must NEVER be used as a game image or as RAM-lifetime proof.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	OverlayBase          uint32 = C10DistributedSourceRAM
	OverlayEnd           uint32 = OverlayBase + C10ResidentBytes
	OverlayBlocked              = true
	OverlayBlockedReason        = "overlay allocation offline overlay-local alternative: 22/26 source windows, 4 retail fallbacks; runtime overlay RAM/DMA/IRQ ownership, GPU, full name coverage remain UNVERIFIED. safe_to_patch=false, runtime_pass=false."
)

type OverlayLocalCandidate struct {
	CombinedQACandidate
	LocalImage                 []byte
	Carriers                   []string
	FallbackOverlays           []string
	PersistentPromotionRemoved bool
}

// Relocation is intentional, exact, and self-auditing. The six internal
// LUI+ORI targets and one header LUI+LW are on a strict instruction allowlist,
// as are the eight internal J/JALs. Unknown internal references abort rather
// than silently emitting a wrong-address executable.
func residentRelocationRelocateResidentImage(image []byte) ([]byte, error) {
	if len(image) != C10ResidentBytes || OverlayBase&3 != 0 || OverlayEnd > OverlaySlotBase+OverlayLoadSectors*2048 {
		return nil, fmt.Errorf("overlay allocation source/overlay geometry mismatch")
	}
	out := bytes.Clone(image)
	offset := OverlayBase - C10ResidentGuard
	expectedJ := map[int]uint32{
		0x88: C10F2PEntry, 0xa4: C10F3Entry,
		0x100: 0x8012DCF0, 0x108: 0x8012DDB0, 0x110: 0x8012E194,
		0xb28: c10ResidentRomanizer, 0xe48: c10ResidentRomanizer, 0xfc8: 0x8012DDB0,
	}
	expectedLiteral := map[int]uint32{
		0x348: 0x8012DB74, 0x39c: 0x8012DC80, 0x3f8: 0x8012DCA0,
		0x468: 0x8012DA52, 0x4dc: 0x8012DCA0, 0x714: 0x8012DCC0,
	}
	if binary.LittleEndian.Uint32(out[0x4c:]) != 0x3c088013 || binary.LittleEndian.Uint32(out[0x50:]) != 0x8d09d200 {
		return nil, fmt.Errorf("overlay allocation resident adapter header address drift")
	}
	binary.LittleEndian.PutUint32(out[0x4c:], olLUI(8, OverlayBase+0x10000))
	binary.LittleEndian.PutUint32(out[0x50:], olLW(9, 8, int16(uint16Low(OverlayBase))))
	if binary.LittleEndian.Uint32(out[0x68:]) != olLW(9, 8, int16(uint16Low(C10ResidentGuard+4))) {
		return nil, fmt.Errorf("overlay allocation resident adapter header length address drift")
	}
	binary.LittleEndian.PutUint32(out[0x68:], olLW(9, 8, int16(uint16Low(OverlayBase+4))))
	for at, old := range expectedLiteral {
		w := binary.LittleEndian.Uint32(out[at:])
		nxt := binary.LittleEndian.Uint32(out[at+4:])
		if w>>26 != 15 || nxt>>26 != 13 || (w>>16&31) != (nxt>>21&31) || (w>>16&31) != (nxt>>16&31) || uint32(w&0xffff)<<16|uint32(nxt&0xffff) != old {
			return nil, fmt.Errorf("overlay allocation internal pointer drift at +%#x", at)
		}
		addr := old + offset
		binary.LittleEndian.PutUint32(out[at:], olLUI((w>>16)&31, addr))
		binary.LittleEndian.PutUint32(out[at+4:], olORI((w>>16)&31, (w>>16)&31, addr&0xffff))
	}
	for at, old := range expectedJ {
		w := binary.LittleEndian.Uint32(out[at:])
		op := w >> 26
		if (op != 2 && op != 3) || (uint32(0x80000000)|(w&0x3ffffff)<<2) != old {
			return nil, fmt.Errorf("overlay allocation intra-jump drift at +%#x", at)
		}
		target := old + offset
		binary.LittleEndian.PutUint32(out[at:], op<<26|((target>>2)&0x3ffffff))
	}
	// Independently enumerate all remaining references to the former window.
	// Do not blindly relocate data that merely looks like instructions.
	for at := 0; at < len(out); at += 4 {
		v := binary.LittleEndian.Uint32(out[at:])
		op := v >> 26
		if op == 2 || op == 3 {
			addr := uint32(0x80000000) | (v&0x3ffffff)<<2
			if addr >= C10ResidentGuard && addr < C10ResidentEnd {
				return nil, fmt.Errorf("overlay allocation unknown old resident jump at +%#x", at)
			}
		}
		// Old absolute references through LUI+ORI must not survive.
		if op == 15 && v&0xffff == 0x8012 && at+4 < len(out) {
			next := binary.LittleEndian.Uint32(out[at+4:])
			if next>>26 == 13 && (v>>16&31) == (next>>21&31) && (v>>16&31) == (next>>16&31) {
				ptr := uint32(v&0xffff)<<16 | uint32(next&0xffff)
				if ptr >= C10ResidentGuard && ptr < C10ResidentEnd {
					return nil, fmt.Errorf("overlay allocation unrelocated absolute at +%#x", at)
				}
			}
		}
	}
	// Recompute the relocated body attestation; the old code checksum MUST
	// NOT be copied unchanged after relocating internal instructions.
	var sum, xor uint32
	for at := C10ResidentGuardBytes; at < len(out); at += 4 {
		v := binary.LittleEndian.Uint32(out[at:])
		sum += v
		xor ^= v
	}
	binary.LittleEndian.PutUint32(out[8:], sum)
	binary.LittleEndian.PutUint32(out[12:], xor)
	if binary.LittleEndian.Uint32(out[0:]) != C10Magic || binary.LittleEndian.Uint32(out[4:]) != C10ResidentBodyBytes {
		return nil, fmt.Errorf("overlay allocation marker drift")
	}
	return out, nil
}

func residentRelocationRelocateGuard(original []byte, originalEntry, relocatedEntry uint32) ([]byte, error) {
	if len(original) < 24 {
		return nil, fmt.Errorf("overlay allocation short EXE guard")
	}
	out := bytes.Clone(original)
	if binary.LittleEndian.Uint32(out[:]) != olLUI(8, C10ResidentGuard+0x10000) ||
		binary.LittleEndian.Uint32(out[4:]) != olLW(9, 8, int16(uint16Low(C10ResidentGuard))) {
		return nil, fmt.Errorf("overlay allocation EXE guard source drift")
	}
	binary.LittleEndian.PutUint32(out[:], olLUI(8, OverlayBase+0x10000))
	binary.LittleEndian.PutUint32(out[4:], olLW(9, 8, int16(uint16Low(OverlayBase))))
	if len(out) == 52 {
		if binary.LittleEndian.Uint32(out[20:]) != olLW(9, 8, int16(uint16Low(C10ResidentGuard+4))) {
			return nil, fmt.Errorf("overlay allocation EXE F1 length pointer drift")
		}
		binary.LittleEndian.PutUint32(out[20:], olLW(9, 8, int16(uint16Low(OverlayBase+4))))
	}
	edits := 0
	for i := 8; i < len(out); i += 4 {
		v := binary.LittleEndian.Uint32(out[i:])
		if v == jWord(originalEntry) {
			binary.LittleEndian.PutUint32(out[i:], jWord(relocatedEntry))
			edits++
		}
	}
	if edits != 1 {
		return nil, fmt.Errorf("overlay allocation EXE guard target count=%d", edits)
	}
	return out, nil
}

// PLAN ONLY: reuse combined romanization's authenticated translation-independent N20 candidate.
// Neither original bytes nor the persistent C10 destination are written.
func PlanOverlayLocalOffline(exe []byte, originals map[string][]byte) (OverlayLocalCandidate, error) {
	var out OverlayLocalCandidate
	combinedRomanizerImage, e := PlanCombinedQAOffline(exe, originals)
	if e != nil {
		return out, e
	}
	resident, _, _, _, _, e := buildUnifiedResident(originals["GYOZI.EXN"])
	if e != nil {
		return out, e
	}
	local, e := residentRelocationRelocateResidentImage(resident)
	if e != nil {
		return out, e
	}
	out.CombinedQACandidate = combinedRomanizerImage
	out.LocalImage = local
	out.EnglishEXE = bytes.Clone(combinedRomanizerImage.EnglishEXE)
	out.Overlays = make(map[string][]byte, len(combinedRomanizerImage.Overlays))
	guardAt := int(C10EXEGuardF1 - 0x80040800)
	f1, e := BuildC10EXEGuardF1()
	if e != nil {
		return OverlayLocalCandidate{}, e
	}
	terminal, e := BuildC10EXETerminalGate()
	if e != nil {
		return OverlayLocalCandidate{}, e
	}
	f1Local, e := residentRelocationRelocateGuard(f1, C10F1Entry, OverlayBase+C10ResidentGuardBytes)
	if e != nil {
		return OverlayLocalCandidate{}, e
	}
	terminalLocal, e := residentRelocationRelocateGuard(terminal, C10QueueAdapterEntry, OverlayBase+16)
	if e != nil {
		return OverlayLocalCandidate{}, e
	}
	if !bytes.Equal(out.EnglishEXE[guardAt:guardAt+len(f1)], f1) ||
		!bytes.Equal(out.EnglishEXE[guardAt+C10EXEGuardTailBytes-len(terminal):guardAt+C10EXEGuardTailBytes], terminal) ||
		binary.LittleEndian.Uint32(out.EnglishEXE[int(c10State3Call-0x80040800):]) != jalWord(C10EXELoaderGate) {
		return OverlayLocalCandidate{}, fmt.Errorf("overlay allocation combined romanization EXE guard/preimage drift")
	}
	copy(out.EnglishEXE[guardAt:], f1Local)
	clear(out.EnglishEXE[guardAt+len(f1) : guardAt+C10EXEGuardTailBytes-len(terminal)])
	copy(out.EnglishEXE[guardAt+C10EXEGuardTailBytes-len(terminal):], terminalLocal)
	binary.LittleEndian.PutUint32(out.EnglishEXE[int(c10State3Call-0x80040800):], c10State3Old)
	for _, key := range sortedCombinedOverlayKeys(combinedRomanizerImage.Overlays) {
		orig, now := originals[key], bytes.Clone(combinedRomanizerImage.Overlays[key])
		if len(orig) != len(now) || !bytes.Equal(now[c10BridgeFileOff:c10BridgeFileOff+c10BridgeBytes], combinedRomanizerImage.Overlays["GYOZI.EXN"][c10BridgeFileOff:c10BridgeFileOff+c10BridgeBytes]) {
			return OverlayLocalCandidate{}, fmt.Errorf("overlay allocation bridge integrity %s", key)
		}
		// Remove *all* promotion bridges. overlay allocation never copies executable
		// bytes into the old persistent RAM destination.
		copy(now[c10BridgeFileOff:c10BridgeFileOff+c10BridgeBytes], orig[c10BridgeFileOff:c10BridgeFileOff+c10BridgeBytes])
		if c10DistributedSourceEligible(orig) {
			if !bytes.Equal(now[C10DistributedSourceFileOff:C10DistributedSourceEnd], resident) {
				return OverlayLocalCandidate{}, fmt.Errorf("overlay allocation source provenance %s", key)
			}
			copy(now[C10DistributedSourceFileOff:C10DistributedSourceEnd], local)
			out.Carriers = append(out.Carriers, key)
		} else {
			if !bytes.Equal(now[C10DistributedSourceFileOff:C10DistributedSourceEnd], orig[C10DistributedSourceFileOff:C10DistributedSourceEnd]) {
				return OverlayLocalCandidate{}, fmt.Errorf("overlay allocation occupied source %s", key)
			}
			out.FallbackOverlays = append(out.FallbackOverlays, key)
		}
		if key == "TEL.EXN" {
			oldSuffix := uint32(0x8012DDB0)
			newSuffix := oldSuffix + (OverlayBase - C10ResidentGuard)
			expected, e := telephoneNameLocalPhoneWrapper(1048, oldSuffix)
			if e != nil {
				return OverlayLocalCandidate{}, e
			}
			replacement, e := telephoneNameLocalPhoneWrapper(1048, newSuffix)
			if e != nil {
				return OverlayLocalCandidate{}, e
			}
			at := TELLocalFileOff + 0x10
			if !bytes.Equal(now[at:at+len(expected)], expected) {
				return OverlayLocalCandidate{}, fmt.Errorf("overlay allocation TEL preimage drift")
			}
			copy(now[at:], replacement)
			// The TEL-local 1048B fullname helper was compiled with a JAL
			// back to the OLD C10 romanizer. Without fixing this site a
			// local F3 dispatch would enter invalid persistent RAM.
			sourceAt := TELLocalFileOff + 0x100
			patched := 0
			for i := 0; i < 1048; i += 4 {
				v := binary.LittleEndian.Uint32(now[sourceAt+i:])
				op := v >> 26
				if (op == 2 || op == 3) && (uint32(0x80000000)|(v&0x03ffffff)<<2) == c10ResidentRomanizer {
					binary.LittleEndian.PutUint32(now[sourceAt+i:], op<<26|((OverlayBase+C10ResidentGuardBytes+32)>>2)&0x03ffffff)
					patched++
				}
			}
			if patched != 2 {
				return OverlayLocalCandidate{}, fmt.Errorf("overlay allocation TEL embedded romanizer relocation count=%d", patched)
			}
		}
		binary.BigEndian.PutUint16(now[len(now)-4:], packedTableChecksum(now))
		out.Overlays[key] = now
	}
	if len(out.Carriers) != 22 || len(out.FallbackOverlays) != 4 || len(out.Overlays) != 26 {
		return OverlayLocalCandidate{}, fmt.Errorf("overlay allocation local carrier census changed: %d/%d", len(out.Carriers), len(out.FallbackOverlays))
	}
	out.PersistentPromotionRemoved = true
	out.Blocked, out.BlockedReason = true, OverlayBlockedReason
	out.SafeToPatch, out.RuntimePass = false, false
	return out, nil
}
