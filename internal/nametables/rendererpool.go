// Source-preserving extraction of name-table composition primitives.
package nametables

import (
	"crypto/sha256"
	"fmt"
	"tokimemo/internal/graphics"
)

func StageInRendererPool(patchedEXE []byte, current, desired []string) ([]byte, RelocationResult, error) {
	start, before, err := graphics.ReservedNamePool(patchedEXE)
	if err != nil {
		return nil, RelocationResult{}, fmt.Errorf("Name renderer reservation: %w", err)
	}
	return RelocateShortTable(patchedEXE, TableRequest{
		Base: Base, PoolStart: ShortStart, PoolEnd: ShortEnd,
		TableOffset: PointerTable, DestOffset: start, DestBefore: before,
		ExpectedSource: current, NewNames: desired,
		ExpectedFileSHA256: sha256.Sum256(patchedEXE),
	})
}
