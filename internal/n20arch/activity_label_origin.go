package n20arch

// activity source is a strict, source-authenticated provenance boundary for the 286
// original OLH.EXN queue callsites. The result is NOT a proof of a particular
// activity-screen consumer, a runtime hook, or a patch authorization.
import (
	"encoding/binary"
	"fmt"
)

const (
	OLHSourceLiteral    = "original_overlay_literal_pointer"
	OLHFixedTable       = "original_overlay_fixed_pointer_table"
	OLHIndexedTable     = "original_overlay_indexed_pointer_table"
	OLHExternalRegister = "s2_loaded_runtime_pointer"
)

type OLHSource struct {
	CallPC         uint32
	Kind           string
	PointerAddress uint32 // exact original literal/table address, 0 for indexed/s2
}

type OLHSourceAudit struct {
	Sources                      []OLHSource
	Literal                      int
	FixedTable                   int
	IndexedTable                 int
	RegisterLoaded               int
	ActualActivityConsumerProven bool
	SafeToPatch                  bool
	RuntimePass                  bool
}

// At each retail callsite a3 is last written by one of just three audited
// instruction templates. Count 227 literal data addresses, 51 source-backed fixed
// pointer-table loads, 2 indexed table loads and 6 a3=*(s2). A source pointer
// from literal data may still contain in-game tokens replaced downstream;
// never infer final displayed strings from this static classification.
func AuditOLHQueueOrigins(olh []byte) (OLHSourceAudit, error) {
	out := OLHSourceAudit{}
	n, _, err := nameEntryQueueAuthenticatedQueues("OLH.EXN", olh)
	if err != nil {
		return out, err
	}
	if n != 286 {
		return out, fmt.Errorf("activity source unexpected queue count %d", n)
	}
	const codeEnd = 0xb6e0
	word := func(at int) uint32 { return binary.LittleEndian.Uint32(olh[at:]) }
	for off := 20; off+8 <= codeEnd; off += 4 {
		if word(off) != jalWord(optionQueueRetail) {
			continue
		}
		before, earlier := word(off-16), word(off-20)
		pc := OverlaySlotBase + uint32(off)
		src := OLHSource{CallPC: pc}
		switch {
		case before>>26 == 9 && before>>21&31 == 7 && before>>16&31 == 7 && earlier>>26 == 15 && earlier>>16&31 == 7:
			// addiu a3,a3,signed-low after LUI a3,hi.
			low := int32(int16(before & 0xffff))
			addr := uint32(int64(earlier&0xffff)<<16 + int64(low))
			offset := int64(addr) - int64(OverlaySlotBase)
			if offset < 0 || offset+4 > int64(len(olh)) || olh[offset] == 0 {
				return OLHSourceAudit{}, fmt.Errorf("activity source literal pointer invalid at %08x -> %08x", pc, addr)
			}
			src.Kind, src.PointerAddress = OLHSourceLiteral, addr
			out.Literal++
		case before>>26 == 35 && before>>21&31 == 7 && before>>16&31 == 7 && earlier>>26 == 15 && earlier>>16&31 == 7:
			// Direct load of a pointer in the authenticated overlay.
			low := int32(int16(before & 0xffff))
			addr := uint32(int64(earlier&0xffff)<<16 + int64(low))
			offset := int64(addr) - int64(OverlaySlotBase)
			if offset < 0 || offset+4 > int64(len(olh)) {
				return OLHSourceAudit{}, fmt.Errorf("activity source table slot invalid %08x", pc)
			}
			pointed := word(int(offset))
			targetOff := int64(pointed) - int64(OverlaySlotBase)
			if targetOff < 0 || targetOff >= int64(len(olh)) || olh[targetOff] == 0 {
				return OLHSourceAudit{}, fmt.Errorf("activity source invalid fixed table pointer %08x -> %08x", pc, pointed)
			}
			src.Kind, src.PointerAddress = OLHFixedTable, addr
			out.FixedTable++
		case pc == 0x80133158 && word(off-28) == 0x8ce7af3c:
			// Last a3 write occurs 28 B before call, not at -16.
			addr := uint32(0x8013af3c)
			ptr := word(int(addr - OverlaySlotBase))
			ptrOff := int64(ptr) - int64(OverlaySlotBase)
			if ptrOff < 0 || ptrOff >= int64(len(olh)) || olh[ptrOff] == 0 {
				return OLHSourceAudit{}, fmt.Errorf("activity source delayed table pointer invalid")
			}
			src.Kind, src.PointerAddress = OLHFixedTable, addr
			out.FixedTable++
		case (pc == 0x80133110 || pc == 0x801350b0) && word(off-24) == 0x3c078014 && word(off-20) == 0x00ee3821 && before>>26 == 35:
			// a3 is loaded through base+an index register. The possible
			// value is NOT a unique fixed text pointer at compile time.
			src.Kind = OLHIndexedTable
			out.IndexedTable++

		case word(off-8) == olLW(7, 18, 0):
			// Caller gets a3 from a struct pointer held in callee-save s2.
			// This is not necessarily a saved player-name pointer.
			src.Kind = OLHExternalRegister
			out.RegisterLoaded++
		default:
			return OLHSourceAudit{}, fmt.Errorf("activity source unknown a3 producer at %08x (%08x/%08x)", pc, earlier, before)
		}
		out.Sources = append(out.Sources, src)
	}
	if len(out.Sources) != 286 || out.Literal != 227 || out.FixedTable != 51 || out.IndexedTable != 2 || out.RegisterLoaded != 6 {
		return OLHSourceAudit{}, fmt.Errorf("activity source source census changed all=%d literal=%d table=%d indexed=%d external=%d", len(out.Sources), out.Literal, out.FixedTable, out.IndexedTable, out.RegisterLoaded)
	}
	return out, nil
}
