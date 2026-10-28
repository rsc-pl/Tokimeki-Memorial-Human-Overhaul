package namepatch

import (
	"crypto/sha256"
	"fmt"
	"tokimemo/internal/graphics"
)

// StageInRendererPool creates a reproducible binary candidate for the compact
// 16-pointer table using the already reserved, renderer-owned font tail.
// This primitive alone is not a complete N10 gameplay fix; adjacent RAM buffers and GEKO
// literal callers remain unresolved. Never publish as a production build.
func StageInRendererPool(patchedEXE []byte, current, desired []string) ([]byte, RelocationResult, error) {
	start, before, err := graphics.ReservedNamePool(patchedEXE)
	if err != nil {
		return nil, RelocationResult{}, fmt.Errorf("N10 renderer reservation: %w", err)
	}
	return RelocateShortTable(patchedEXE, TableRequest{
		Base: Base, PoolStart: ShortStart, PoolEnd: ShortEnd,
		TableOffset: PointerTable, DestOffset: start, DestBefore: before,
		ExpectedSource: current, NewNames: desired,
		ExpectedFileSHA256: sha256.Sum256(patchedEXE),
	})
}
