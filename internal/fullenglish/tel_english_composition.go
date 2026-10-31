package fullenglish

import (
	"fmt"
	n "tokimemo/internal/n20arch"
)

// verifyTELNPCInlineLayout checks the FINAL public English output. The N20
// ancestor already installs the authenticated TEL renderer and its authenticated callsite JALs.
// Never call the mutating TEL stage here: doing so would install it twice.
func verifyTELNPCInlineLayout(exe []byte, retail map[string][]byte, physical map[string][]byte) error {
	const path = "CDROM/EXEDIR/TEL.EXN"
	original, okOriginal := retail["TEL.EXN"]
	current, okComposed := physical[path]
	if !okOriginal || !okComposed {
		return fmt.Errorf("missing authenticated TEL source or composed output")
	}
	return n.VerifyComposedTELNPCInlineLayout(exe, original, current)
}
