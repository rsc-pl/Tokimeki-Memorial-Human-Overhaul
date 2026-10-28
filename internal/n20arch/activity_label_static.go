package n20arch

// tail guard source-authenticated correction to activity source: the six OLH loops reading
// a3=*(s2) are not arbitrary runtime-populated name-pointer arrays. Their
// s2 registers are loaded from six static overlay-local address tables.
// These contain 47 original pointers to bounded local help/menu strings and
// one NULL sentinel. It is NOT proof that runtime code never changes those
// strings; it rules out this *direct pointer source* as a saved-name field.
// No new hook, game image, user text, or translation is written.
import (
	"encoding/binary"
	"fmt"
)

type OLHHelpTable struct {
	QueuePC                uint32
	TableAddress           uint32
	OriginalStringPointers []uint32
	Entries                int
}

type OLHHelpAudit struct {
	Tables                             []OLHHelpTable
	StaticPointers                     int
	NullSentinels                      int
	ProvenDirectPlayerNameSources      int
	StillUnknownDownstreamSubstitution bool
	SafeToPatch                        bool
	RuntimePass                        bool
}

var tailGuardOLHHelpSources = [...]struct {
	pc, table uint32
	count     int
}{
	{0x801321e8, 0x80139ee0, 8},
	{0x80132580, 0x8013a700, 8},
	{0x80133ce0, 0x8013b740, 8},
	{0x80134660, 0x8013bf60, 8},
	{0x80135c20, 0x8013cea0, 7},
	{0x80136640, 0x8013d6c0, 8},
}

func AuditOLHStaticHelpTables(olh []byte) (OLHHelpAudit, error) {
	var out OLHHelpAudit
	previous, err := AuditOLHQueueOrigins(olh)
	if err != nil {
		return out, err
	}
	byPC := make(map[uint32]OLHSource, len(previous.Sources))
	for _, s := range previous.Sources {
		byPC[s.CallPC] = s
	}
	for _, item := range tailGuardOLHHelpSources {
		if prev, ok := byPC[item.pc]; !ok || prev.Kind != OLHExternalRegister {
			return OLHHelpAudit{}, fmt.Errorf("tail guard OLH source classification drift at %#x", item.pc)
		}
		at := int(item.pc - OverlaySlotBase)
		if at < 0x48 || at+8 > len(olh) {
			return OLHHelpAudit{}, fmt.Errorf("tail guard invalid OLH PC %#x", item.pc)
		}
		// The exact original pair loads s2 with a constant pointer to its
		// help/menu table; this is not a dynamic RAM reference.
		loWord := binary.LittleEndian.Uint32(olh[at-0x44:])
		hiWord := binary.LittleEndian.Uint32(olh[at-0x48:])
		if hiWord>>26 != 15 || (hiWord>>16)&31 != 18 || loWord>>26 != 9 || (loWord>>21)&31 != 18 || (loWord>>16)&31 != 18 ||
			binary.LittleEndian.Uint32(olh[at-8:]) != olLW(7, 18, 0) {
			return OLHHelpAudit{}, fmt.Errorf("tail guard s2/a3 provenance drift at %#x", item.pc)
		}
		resolved := uint32(int64(hiWord&0xffff)<<16 + int64(int16(loWord&0xffff)))
		if resolved != item.table {
			return OLHHelpAudit{}, fmt.Errorf("tail guard help table moved %#x -> %#x", item.pc, resolved)
		}
		off := int(resolved - OverlaySlotBase)
		if off < 0 || off+8*4 > len(olh) {
			return OLHHelpAudit{}, fmt.Errorf("tail guard table outside overlay %#x", resolved)
		}
		table := OLHHelpTable{QueuePC: item.pc, TableAddress: resolved}
		for i := 0; i < 8; i++ {
			ptr := binary.LittleEndian.Uint32(olh[off+i*4:])
			if i >= item.count {
				if ptr != 0 {
					return OLHHelpAudit{}, fmt.Errorf("tail guard expected NULL sentinel at %#x index %d", resolved, i)
				}
				out.NullSentinels++
				continue
			}
			target := int64(ptr) - int64(OverlaySlotBase)
			if ptr == OLA0SurnameField || ptr == OLFieldPrepSavedGiv || ptr == 0x800e6364 || target < 0 || target >= int64(len(olh)) {
				return OLHHelpAudit{}, fmt.Errorf("tail guard unexpected player/foreign text pointer %#x", ptr)
			}
			// Original strings each have their own <=256 byte cell, with a
			// nonempty NUL-terminated byte sequence; never chase into RAM.
			if olh[target] == 0 {
				return OLHHelpAudit{}, fmt.Errorf("tail guard empty help string %#x", ptr)
			}
			end := int(target)
			for end < int(target)+256 && end < len(olh) && olh[end] != 0 {
				end++
			}
			if end >= int(target)+256 || end >= len(olh) {
				return OLHHelpAudit{}, fmt.Errorf("tail guard unterminated menu string %#x", ptr)
			}
			table.OriginalStringPointers = append(table.OriginalStringPointers, ptr)
			out.StaticPointers++
		}
		table.Entries = len(table.OriginalStringPointers)
		out.Tables = append(out.Tables, table)
	}
	if len(out.Tables) != 6 || out.StaticPointers != 47 || out.NullSentinels != 1 || previous.RegisterLoaded != 6 {
		return OLHHelpAudit{}, fmt.Errorf("tail guard six table census drift")
	}
	out.StillUnknownDownstreamSubstitution = true
	return out, nil
}

// The 4200-byte candidate 0x800E2500..0x800E3568 is an ORIGINAL GAME
// state/data work area, not a zero-filled executable cave. Source code both
// reads/writes the start and references its bounds in the original EXE table.
func AuditEXEWorkBufferNotFree(original []byte) error {
	if _, err := VerifyRetailEXE(original); err != nil {
		return err
	}
	for _, wit := range []struct{ pc, expected uint32 }{
		{0x800ad418, 0x3c10800e}, {0x800ad41c, 0x26102500},
		{0x800ad424, 0x96020000}, // lhu v0,0(s0): dynamic game state
		{0x800ad4f8, 0x3c11800e}, {0x800ad4fc, 0x26312500},
		{0x800ad514, 0x96220000},
		{0x800ad810, 0x3c10800e}, {0x800ad814, 0x26102500},
		{0x800ad81c, 0x96020000},
		{0x800ad8b0, 0x3c10800e}, {0x800ad8b4, 0x26102500},
		{0x800ad8bc, 0x96020000},
		{0x800e3584, 0x800e2500}, {0x800e3588, 0x800e3568},
	} {
		if wordAt(original, wit.pc) != wit.expected {
			return fmt.Errorf("tail guard original data-work evidence drift %#x", wit.pc)
		}
	}
	return nil
}
