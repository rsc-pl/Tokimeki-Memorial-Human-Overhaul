package n20arch

// tail guard OFFLINE only: overlay formatter's order-sensitive integrity sentinel covered only
// [image+256, image+4056) but execution also jumps into the 240-byte terminal
// adapter in [image+16, image+256). Reuse the same 64-byte EXE checker to
// validate all 4040 executable image bytes. The first 16 bytes are metadata
// (magic, body length, existing checksum/seed). Still NOT a runtime/DMA/IRQ
// ownership proof, nor permission to build an ISO.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	TailGuardBlockedReason = "tail guard OFFLINE ONLY: 4040-byte adapter+body rolling integrity check, 22/26 overlay carriers and 4 retail fallbacks; executable overlay ownership/TOCTOU/DMA/IRQ/cache, narrator and complete English gameplay UNPROVEN; safe_to_patch=false, runtime_pass=false"
	ExecutableBytes        = C10ResidentBytes - 16
)

type GuardTailCandidate struct {
	InterposedCandidate
	GuardTailCovered        bool
	VerifiedExecutableBytes int
	OriginalOLHHelpTables   OLHHelpAudit
}

func tailGuardExecutableSeed(src []byte) (uint32, error) {
	if len(src) != C10ResidentBytes || binary.LittleEndian.Uint32(src) != C10Magic || binary.LittleEndian.Uint32(src[4:]) != C10ResidentBodyBytes {
		return 0, fmt.Errorf("tail guard header/size mismatch")
	}
	var seed uint32
	for i := len(src) - 4; i >= 16; i -= 4 {
		seed = (seed - overlayFormatterIncrement) ^ binary.LittleEndian.Uint32(src[i:])
	}
	return seed, nil
}

func tailGuardVerifierWords() []uint32 {
	old := overlayFormatterVerifierWords()
	next := append([]uint32(nil), old...)
	// t0=image+16 instead of body image+256; load inverse seed at image+12.
	next[1] = olADDIU(8, 8, -496)
	next[2] = olLW(10, 8, -4)
	next[3] = olADDIU(9, 0, ExecutableBytes/4)
	return next
}

func PlanGuardTailIntegrityOffline(exe []byte, originals map[string][]byte) (GuardTailCandidate, error) {
	var empty GuardTailCandidate
	formatterInterpositionStage, err := PlanInterposedSurnameOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	olh, err := AuditOLHStaticHelpTables(originals["OLH.EXN"])
	if err != nil {
		return empty, err
	}
	seed, err := tailGuardExecutableSeed(formatterInterpositionStage.LocalImage)
	if err != nil {
		return empty, err
	}
	out := GuardTailCandidate{InterposedCandidate: formatterInterpositionStage, GuardTailCovered: true, VerifiedExecutableBytes: ExecutableBytes, OriginalOLHHelpTables: olh}
	out.LocalImage = bytes.Clone(formatterInterpositionStage.LocalImage)
	binary.LittleEndian.PutUint32(out.LocalImage[12:], seed)
	state := seed
	for i := 16; i < len(out.LocalImage); i += 4 {
		state = (state ^ binary.LittleEndian.Uint32(out.LocalImage[i:])) + overlayFormatterIncrement
	}
	if state != 0 {
		return empty, fmt.Errorf("tail guard inverse checksum mismatch")
	}
	out.Overlays = make(map[string][]byte, len(formatterInterpositionStage.Overlays))
	carriers := map[string]bool{}
	for _, name := range formatterInterpositionStage.Carriers {
		carriers[name] = true
	}
	for name, prior := range formatterInterpositionStage.Overlays {
		next := bytes.Clone(prior)
		if carriers[name] {
			if !bytes.Equal(next[C10DistributedSourceFileOff:C10DistributedSourceEnd], formatterInterpositionStage.LocalImage) {
				return empty, fmt.Errorf("tail guard source mismatch %s", name)
			}
			copy(next[C10DistributedSourceFileOff:C10DistributedSourceEnd], out.LocalImage)
			binary.BigEndian.PutUint16(next[len(next)-4:], packedTableChecksum(next))
		}
		out.Overlays[name] = next
	}
	if len(carriers) != 22 || len(formatterInterpositionStage.FallbackOverlays) != 4 || len(out.Overlays) != 26 {
		return empty, fmt.Errorf("tail guard carrier count drift")
	}
	out.EnglishEXE = bytes.Clone(formatterInterpositionStage.EnglishEXE)
	at := int(overlayDispatchVerifier - 0x80040800)
	if at < 0 || at+64 > len(out.EnglishEXE) {
		return empty, fmt.Errorf("tail guard EXE checker bounds")
	}
	priorWords := overlayFormatterVerifierWords()
	nextWords := tailGuardVerifierWords()
	if len(priorWords) != 16 || len(nextWords) != 16 {
		return empty, fmt.Errorf("tail guard checker code size")
	}
	for i, w := range priorWords {
		if binary.LittleEndian.Uint32(out.EnglishEXE[at+i*4:]) != w {
			return empty, fmt.Errorf("tail guard prior verifier drift at %d", i)
		}
		binary.LittleEndian.PutUint32(out.EnglishEXE[at+i*4:], nextWords[i])
	}
	out.Blocked = true
	out.BlockedReason = TailGuardBlockedReason
	out.SafeToPatch = false
	out.RuntimePass = false
	return out, nil
}
