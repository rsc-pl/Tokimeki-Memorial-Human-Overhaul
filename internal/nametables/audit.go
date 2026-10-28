// Source-preserving extraction of name-table composition primitives.
package nametables

import (
	"fmt"

	"strings"

	"tokimemo/internal/script"
)

const (
	EXE = "SLPM_86.053"

	Base         = uint32(0x80040800)
	ShortStart   = 0x72D78
	ShortEnd     = 0x72DF4
	PointerTable = 0x72DF4
	Entries      = 16
)

func ShortNamesRequired(names []string) (int, error) {
	if len(names) != Entries {
		return 0, fmt.Errorf("expected %d runtime names, got %d", Entries, len(names))
	}
	total := 0
	for i, name := range names {
		if name == "" || strings.ContainsAny(name, "\x00\n{}") {
			return 0, fmt.Errorf("short name %d invalid", i)
		}
		encoded, e := (&script.PairEncoder{}).Encode(name)
		if e != nil {
			return 0, fmt.Errorf("short name %d: %w", i, e)
		}
		total += len(encoded) + 1
	}
	return total, nil
}
