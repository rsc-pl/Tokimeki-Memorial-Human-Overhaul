package n20arch

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// VerifyNPCLabelGeometryBaseline prevents the owner-rejected speaker geometry
// speaker-X experiment from re-entering a private integrated build.
// It is a verification-only boundary: no bytes are written or repositioned.
// The native six-site label geometry still fails for long surnames; PASS
// here is NOT a layout PASS or general safety certification.
func VerifyNPCLabelGeometryBaseline(retailEXE, englishEXE []byte) error {
	const retailDigest = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	sum := sha256.Sum256(retailEXE)
	if hex.EncodeToString(sum[:]) != retailDigest || len(retailEXE) != 667648 || len(englishEXE) != len(retailEXE) {
		return fmt.Errorf("layout restoration authenticated original EXE or merged EXE invalid")
	}
	for i, site := range npcNameQueueNPCNameQueues {
		for _, pc := range []uint32{site.NameBasePC, site.NameShiftPC} {
			off := int(pc - 0x80040800)
			original := binary.LittleEndian.Uint32(retailEXE[off : off+4])
			actual := binary.LittleEndian.Uint32(englishEXE[off : off+4])
			if actual != original {
				return fmt.Errorf("layout restoration rejected NPC label X patch or other layout modification at site %d PC %08x", i, pc)
			}
		}
	}
	return nil
}
