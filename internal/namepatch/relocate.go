package namepatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/script"
)

// TableRequest is a technical relocation plan. The caller must supply a
// separately REVERSED/VERIFIED executable destination and its EXACT preimage.
// No address is selected automatically. This is NOT by itself proof that the
// target is runtime-safe; executable code and all consumers require proof.
type TableRequest struct {
	Base               uint32
	PoolStart, PoolEnd int
	TableOffset        int
	DestOffset         int
	DestBefore         []byte
	ExpectedSource     []string // current, original source table contents, by pointer index
	NewNames           []string // intended runtime strings, by pointer index
	ExpectedFileSHA256 [32]byte // hash of the original file, not an output copy
}

type RelocationResult struct {
	OldBytes          int `json:"old_bytes"`
	NewBytes          int `json:"new_bytes"`
	PointerCount      int `json:"pointer_count"`
	DestinationOffset int `json:"destination_offset"`
	ChangedBytes      int `json:"changed_bytes"`
	// Always false. Calling code must not infer scene QA from static checks.
	RuntimeValidated bool `json:"runtime_validated"`
}

// RelocateShortTable creates an isolated replacement file of the EXACT same
// length after complete byte-level checks. It changes 16 pointer-table entries
// but leaves the source strings intact. Any other reference to the original
// strings (or any MIPS immediate referencing them) fails closed.
func RelocateShortTable(file []byte, q TableRequest) ([]byte, RelocationResult, error) {
	var s RelocationResult
	fail := func(msg string) ([]byte, RelocationResult, error) {
		return nil, RelocationResult{}, fmt.Errorf("short-table relocation: %s", msg)
	}
	if len(file) < 64 || sha256.Sum256(file) != q.ExpectedFileSHA256 {
		return fail("unrecognized input SHA-256")
	}
	if q.Base == 0 || q.PoolStart < 0 || q.PoolEnd <= q.PoolStart || q.TableOffset < q.PoolEnd || q.TableOffset+4*Entries > len(file) || len(q.ExpectedSource) != Entries || len(q.NewNames) != Entries {
		return fail("invalid source table layout")
	}
	required, e := ShortNamesRequired(q.NewNames)
	if e != nil {
		return fail(e.Error())
	}
	if required > len(q.DestBefore) || q.DestOffset < 0 || q.DestOffset > len(file)-len(q.DestBefore) || len(q.DestBefore) == 0 {
		return fail("destination too small or outside file")
	}
	destEnd := q.DestOffset + len(q.DestBefore)
	if (q.DestOffset < q.PoolEnd && destEnd > q.PoolStart) ||
		(q.DestOffset < q.TableOffset+4*Entries && destEnd > q.TableOffset) {
		return fail("destination overlaps table or original pool")
	}
	if !bytes.Equal(file[q.DestOffset:destEnd], q.DestBefore) {
		return fail("destination preimage differs")
	}
	pointers := make([]int, Entries)
	for i, source := range q.ExpectedSource {
		p := binary.LittleEndian.Uint32(file[q.TableOffset+i*4:])
		if p < q.Base {
			return fail("pointer below executable base")
		}
		off := uint64(p - q.Base)
		if off < uint64(q.PoolStart) || off >= uint64(q.PoolEnd) {
			return fail("pointer outside verified source pool")
		}
		raw, e := (&script.PairEncoder{}).Encode(source)
		if e != nil {
			return fail(e.Error())
		}
		at := int(off)
		if at+len(raw) >= q.PoolEnd || !bytes.Equal(file[at:at+len(raw)], raw) || file[at+len(raw)] != 0 {
			return fail("source string or NUL mismatch")
		}
		pointers[i] = at
	}
	// The relocator only knows about the 16 indirect pointers. Reject any
	// additional absolute references; a raw LUI/ADDIU reference needs separate
	// instruction-site engineering, never speculative rewriting.
	oldTargets := map[uint32]bool{}
	for _, p := range pointers {
		oldTargets[q.Base+uint32(p)] = true
	}
	for off := 0; off+4 <= len(file); off += 4 {
		if off >= q.TableOffset && off < q.TableOffset+4*Entries {
			continue
		}
		if oldTargets[binary.LittleEndian.Uint32(file[off:])] {
			return fail("other direct reference to source string")
		}
	}
	idx := script.NewWordIndex(file)
	for _, p := range pointers {
		if len(idx.CodeReferences(q.Base, uint32(p), 8)) != 0 {
			return fail("code reference to old string")
		}
	}
	out := append([]byte(nil), file...)
	// Always include NUL, never rely on adjoining zero bytes.
	at := q.DestOffset
	for i, name := range q.NewNames {
		raw, e := (&script.PairEncoder{}).Encode(name)
		if e != nil {
			return fail(e.Error())
		}
		copy(out[at:], raw)
		out[at+len(raw)] = 0
		if uint64(at)+uint64(q.Base) > 0xffffffff {
			return fail("MIPS address overflow")
		}
		binary.LittleEndian.PutUint32(out[q.TableOffset+i*4:], q.Base+uint32(at))
		at += len(raw) + 1
	}
	s.OldBytes = q.PoolEnd - q.PoolStart
	s.NewBytes = required
	s.PointerCount = Entries
	s.DestinationOffset = q.DestOffset
	for i := range out {
		if out[i] != file[i] {
			s.ChangedBytes++
		}
	}
	return out, s, nil
}
