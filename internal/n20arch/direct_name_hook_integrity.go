package n20arch

// direct name hooks is a read-only, private-image build gate for the 15 already installed
// overlay-local direct player-name queue calls. It does not create additional
// hooks or infer which screenshot used them. Refuse a build that silently
// falls back to raw CP932 at any of these authenticated sites.
import (
	"encoding/binary"
	"fmt"
)

// VerifyDirectSavedNameHooks verifies the complete source-attested set of
// direct queue callsites against the ALREADY merged N20 overlay images.
// Inputs are original authenticated EXNs and the candidate validation images.
// It verifies family/given/nickname as separate source fields, original JAL
// delay words, target stub, and the candidate carrier checksum. It writes no
// bytes, cannot approve release safety, and does not touch source names.
func VerifyDirectSavedNameHooks(originals, composed map[string][]byte) error {
	sites, err := ScanDirectSavedNameQueueSites(originals)
	if err != nil {
		return fmt.Errorf("direct name hooks source: %w", err)
	}
	if len(sites) != 15 {
		return fmt.Errorf("direct name hooks expected 15 authenticated direct player-name sites; got %d", len(sites))
	}
	counts := map[string]map[string]int{}
	expected := map[string]map[string]int{
		"BUNKAKEN.EXN": {"surname": 1, "given": 1},
		"BUNKASAI.EXN": {"surname": 2, "given": 1},
		"MASTER.EXN":   {"surname": 4},
		"OPTION.EXN":   {"surname": 2, "given": 2, "nickname": 2},
	}
	for _, s := range sites {
		if expected[s.Overlay][s.Field] == 0 {
			return fmt.Errorf("direct name hooks unexpected field source at %s %#x (%s)", s.Overlay, s.PC, s.Field)
		}
		d, ok := composed[s.Overlay]
		if !ok || len(d) != OverlayLoadSectors*2048 {
			return fmt.Errorf("direct name hooks missing or invalid installed %s", s.Overlay)
		}
		if binary.BigEndian.Uint16(d[len(d)-4:]) != packedTableChecksum(d) || d[len(d)-2] != 0x12 || d[len(d)-1] != 0x10 {
			return fmt.Errorf("direct name hooks invalid installed checksum/trailer in %s", s.Overlay)
		}
		if counts[s.Overlay] == nil {
			counts[s.Overlay] = map[string]int{}
		}
		counts[s.Overlay][s.Field]++
		off := int(s.PC - OverlaySlotBase)
		want := jalWord(directQueueStubRAM)
		if s.Overlay == "OPTION.EXN" {
			want = jalWord(OLStubRAM)
		}
		if binary.LittleEndian.Uint32(d[off:]) != want || binary.LittleEndian.Uint32(d[off+4:]) != s.Delay {
			return fmt.Errorf("direct name hooks lost player-name hook/retail delay %s %#x field=%s", s.Overlay, s.PC, s.Field)
		}
		if binary.LittleEndian.Uint32(d[off-20:]) != olLUI(7, s.Source) || binary.LittleEndian.Uint32(d[off-16:]) != olADDIU(7, 7, int16(s.Source&0xffff)) {
			return fmt.Errorf("direct name hooks changed source name field %s %#x", s.Overlay, s.PC)
		}
	}
	for owner, fields := range expected {
		for field, n := range fields {
			if counts[owner][field] != n {
				return fmt.Errorf("direct name hooks %s/%s count %d, expected %d", owner, field, counts[owner][field], n)
			}
		}
	}
	return nil
}
