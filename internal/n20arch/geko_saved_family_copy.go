package n20arch

// The three source-authenticated GEKO duplicate-family writes copy the saved
// CP932 surname into the relocated 12-byte N20 working field, after which the
// retail fallback alone leaves kana behind. This source-specific adapter first
// preserves the original strcpy semantics, then attempts the same bounded
// packed-pair conversion used by SHOUGATU. No GEKO NPC-name mirrors are added.
// The reported March DATE->Activity consumer remains unproven: runtime PASS is
// not asserted and the rest of the working-name paths are unchanged.
import (
	"encoding/binary"
	"fmt"
)

var gekoSavedFamilyCalls = [...]uint32{0x80141160, 0x80141290, 0x8014145c}

func gekoSavedFamilyAuthenticatedPatches(original, composed []byte) ([]n20RelocWord, error) {
	const owner = "GEKO.EXN"
	if len(original) != OverlayLoadSectors*2048 || sha(original) != OverlaySHA[owner] || len(composed) != len(original) {
		return nil, fmt.Errorf("GEKO saved-family original identity mismatch")
	}
	words := make([]n20RelocWord, 0, len(gekoSavedFamilyCalls))
	for _, pc := range gekoSavedFamilyCalls {
		off := int(pc - OverlaySlotBase)
		if off < 12 || off+8 > len(original) {
			return nil, fmt.Errorf("GEKO saved-family PC outside overlay %#x", pc)
		}
		// The verified source is the three-instruction saved-slot materialization:
		// lui a1,0x800e; addiu a1,a1,0x6354; jal retail strcpy.
		if binary.LittleEndian.Uint32(original[off-12:]) != 0x3c05800e ||
			binary.LittleEndian.Uint32(original[off-4:]) != 0x24a56354 ||
			binary.LittleEndian.Uint32(original[off:]) != jalWord(shouFamilySHOUCopyOld) ||
			binary.LittleEndian.Uint32(original[off+4:]) != 0x2484a16c ||
			binary.LittleEndian.Uint32(composed[off:]) != jalWord(shouFamilySHOUCopyOld) ||
			binary.LittleEndian.Uint32(composed[off+4:]) != n20RelocADDIUWord(0x2484a16c, N20RelocFamilyAddr) {
			return nil, fmt.Errorf("GEKO saved-family source/callsite drift at %#x", pc)
		}
		words = append(words, n20RelocWord{Owner: owner, PC: pc, Old: jalWord(shouFamilySHOUCopyOld), New: jalWord(shouFamilySHOUStub), Kind: "jal", Role: "GEKO guarded duplicate player-family copy"})
	}
	for _, w := range words {
		binary.LittleEndian.PutUint32(composed[int(w.PC-OverlaySlotBase):], w.New)
	}
	ck := packedTableChecksum(composed)
	composed[0x2fffc], composed[0x2fffd] = byte(ck>>8), byte(ck)
	return words, nil
}
