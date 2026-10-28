package n20arch

// activity formatter source-backed bridge between the earlier four-route formatter name-formatting logic and
// the CURRENT overlay formatter packed romanizer. This intentionally remains a detached,
// OFFLINE MIPS component. The four original EXE queue sites are left retail:
// no proven permanent EXE entry gate/executable placement exists for this
// bridge, and the owner's activity-screen identity is not established.
import (
	"encoding/binary"
	"fmt"
	pn "tokimemo/internal/playername"
)

const (
	FormatterTestEntry uint32 = 0x80170000 // simulator ONLY, never install here
	FormatterBlocked          = true
)

type FormatterCandidate struct {
	Bridge            []byte
	Entry             uint32
	Romanizer         uint32
	SourceQueueSites  []uint32
	SourceReturnSites []uint32
	OriginalQueueJAL  uint32
	ReadOnly          bool
	SafeToPatch       bool
	RuntimePass       bool
	BlockedReason     string
}

// PrepareActivityFormatterOffline binds the HISTORICALLY vetted four-route formatter
// four-return formatter to the overlay formatter actual packed romanizer in memory, checking
// *all four* original queue sites and current merged code before proceeding.
// It does not allocate or write any executable region in a game image.
func PrepareActivityFormatterOffline(originalEXE []byte, current []byte) (FormatterCandidate, error) {
	var out FormatterCandidate
	if sha(originalEXE) != "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae" || len(originalEXE) != len(current) {
		return out, fmt.Errorf("activity formatter original EXE authentication/geometry failed")
	}
	sites := []uint32{0x8007F7D4, 0x8007F898, 0x8007F95C, 0x80080C30}
	returns := []uint32{0x8007F7DC, 0x8007F8A0, 0x8007F964, 0x80080C38}
	for _, pc := range sites {
		at := int(pc - 0x80040800)
		if at < 0 || at+8 > len(originalEXE) {
			return out, fmt.Errorf("activity formatter formatter PC outside EXE %#x", pc)
		}
		for _, b := range [][]byte{originalEXE, current} {
			if binary.LittleEndian.Uint32(b[at:]) != jalWord(optionQueueRetail) || binary.LittleEndian.Uint32(b[at+4:]) != olSW(0, 29, 0x10) {
				return out, fmt.Errorf("activity formatter original queue JAL/fifth-argument preimage drift at %#x", pc)
			}
		}
	}
	romanizer := OverlayBase + C10ResidentGuardBytes + 32
	bridge, err := pn.BuildPS1FormatterBridgeFourRoutes(FormatterTestEntry, romanizer)
	if err != nil {
		return out, err
	}
	if bridge.CodeBytes <= 0 || len(bridge.Binary) != bridge.CodeBytes || bridge.FrameBytes != 0xc0 || bridge.BoundedPrivatePairBytes != 64 {
		return out, fmt.Errorf("activity formatter bridge ABI geometry drift")
	}
	out = FormatterCandidate{Bridge: bridge.Binary, Entry: bridge.Entry, Romanizer: romanizer,
		SourceQueueSites: sites, SourceReturnSites: returns, OriginalQueueJAL: jalWord(optionQueueRetail),
		ReadOnly: true, SafeToPatch: false, RuntimePass: false,
		BlockedReason: "Four EXE formatter routes can execute the earlier bounded four-route formatter bridge with the current overlay formatter romanizer OFFLINE; no authenticated cold-safe EXE entry, module memory lifetime, and exact observed activity-sink identity remain proven. No image or hooks."}
	return out, nil
}
