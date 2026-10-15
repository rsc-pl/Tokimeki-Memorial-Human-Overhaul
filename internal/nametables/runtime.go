package nametables

import (
	"fmt"
	"tokimemo/internal/script"
)

// Observed EXE/GEKO addresses from R03/R04, independently observed during R07.
// They are storage STARTS, not verified object boundaries or guaranteed live
// lifetimes. This analyzer only establishes where an unbounded copy reaches.
const (
	BufferA = uint32(0x800CA188)
	BufferB = uint32(0x800CA190)
	BufferC = uint32(0x800CA19C)
)

type CopySpan struct {
	Destination          uint32   `json:"destination"`
	EndExclusive         uint32   `json:"end_exclusive"`
	BytesWithNUL         int      `json:"bytes_with_nul"`
	IntersectsLaterStart bool     `json:"intersects_later_start"`
	CrossedStarts        []uint32 `json:"crossed_starts"`
}

// AnalyzeNameCopy evaluates a single copy/append byte footprint; it never
// asserts that observed addresses constitute independent fixed C allocations.
// appended is concatenated after the source; it may be empty. NUL is included.
func AnalyzeNameCopy(dest uint32, name, appended string) (CopySpan, error) {
	if dest != BufferA && dest != BufferB && dest != BufferC {
		return CopySpan{}, fmt.Errorf("unrecognized observed buffer %#x", dest)
	}
	if name == "" {
		return CopySpan{}, fmt.Errorf("empty copied name")
	}
	a, e := (&script.PairEncoder{}).Encode(name)
	if e != nil {
		return CopySpan{}, e
	}
	b := []byte{}
	if appended != "" {
		b, e = (&script.PairEncoder{}).Encode(appended)
		if e != nil {
			return CopySpan{}, e
		}
	}
	n := len(a) + len(b) + 1
	end := uint64(dest) + uint64(n)
	if end > uint64(^uint32(0)) {
		return CopySpan{}, fmt.Errorf("copy address overflow")
	}
	report := CopySpan{Destination: dest, EndExclusive: uint32(end), BytesWithNUL: n}
	for _, start := range []uint32{BufferB, BufferC} {
		if dest < start && uint64(start) < end {
			report.CrossedStarts = append(report.CrossedStarts, start)
		}
	}
	report.IntersectsLaterStart = len(report.CrossedStarts) != 0
	return report, nil
}
