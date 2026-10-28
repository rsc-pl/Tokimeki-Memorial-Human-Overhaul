package n20arch

// exam integrity freezes the two owner-accepted exam labels exam outputs during the PRIVATE
// full-English image build. It is a source-authenticated byte-integrity gate,
// not another MIPS hook, an assertion of runtime safety, or an edit to game data.
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// This accepted digest is pinned to the exam labels code bytes independently of the
// current planner. The original ETC local payload is separate from EN script
// data and remains constant across source-owned translations/GEKO policies.
// If anyone revises exam labels's executable helper, that requires a distinct owner
// QA/approval; the gate must refuse silent changes even if the new planner
// would otherwise happily reconstruct its own changed output.
const examPayloadOwnerAcceptedETCPayloadSHA256 = "9619dcf15044552ba00f9ea5b6e7b110ed4ff97e30ac0896d1bf8850696fa384"

// VerifyFrozenETC takes a pre-exam labels, English source-owned ETC overlay and
// the final composed candidate. It demands the exact authorized exam labels delta,
// including both JAL/delay pairs, the complete integrity-checked local module,
// checksum and all unrelated translated bytes. It rejects partial hooks,
// payload drift, aliasing and even correctly re-checksummed corruption.
func VerifyFrozenETC(originalEXE, retailETC, englishBefore, finalETC []byte) error {
	if len(englishBefore) != len(retailETC) || len(finalETC) != len(retailETC) {
		return fmt.Errorf("exam integrity ETC image size mismatch")
	}
	if bytes.Equal(englishBefore, finalETC) {
		return fmt.Errorf("exam integrity both accepted exam fixes are absent")
	}
	expected, err := PlanETCExamPrivateOverlay(originalEXE, retailETC, englishBefore)
	if err != nil {
		return fmt.Errorf("exam integrity authenticated exam labels provenance refused: %w", err)
	}
	if expected.SafeToPatch || expected.RuntimePass ||
		len(expected.PatchedCallsites) != 2 ||
		expected.PatchedCallsites[0] != ETCJoinSite ||
		expected.PatchedCallsites[1] != ETCCaptionSite {
		return fmt.Errorf("exam integrity invalid exam labels authorization/safety contract")
	}
	for _, site := range []struct{ pc, target, delay uint32 }{
		{ETCJoinSite, ETCTableStub, 0x24060008},
		{ETCCaptionSite, OLStubRAM, OLSpeakerDelay},
	} {
		off := int(site.pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(finalETC[off:]) != jalWord(site.target) ||
			binary.LittleEndian.Uint32(finalETC[off+4:]) != site.delay {
			return fmt.Errorf("exam integrity accepted exam JAL/delay drift at %#x", site.pc)
		}
	}
	payloadSum := sha256.Sum256(finalETC[OLPayloadFileOff:OLPayloadEndOff])
	if hex.EncodeToString(payloadSum[:]) != examPayloadOwnerAcceptedETCPayloadSHA256 {
		return fmt.Errorf("exam integrity frozen owner-tested ETC N6/N20 payload code digest changed")
	}
	if !bytes.Equal(expected.Overlay, finalETC) {
		first := -1
		for i := range finalETC {
			if expected.Overlay[i] != finalETC[i] {
				first = i
				break
			}
		}
		return fmt.Errorf("exam integrity owner-accepted exam image changed at ETC offset %#x", first)
	}
	return nil
}
