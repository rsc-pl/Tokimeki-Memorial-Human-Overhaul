package fullenglish

import (
	"fmt"
	n "tokimemo/internal/n20arch"
)

// Apply the DATE-only F1 alternative to the final merged images, so the
// preimages cover the actual English renderer and all loaded overlay variants.
func composeDATEActivitySurname(exe []byte, originals, physical map[string][]byte) error {
	current := make(map[string][]byte, len(originals))
	for name := range originals {
		p := "CDROM/EXEDIR/" + name
		// The merger omits byte-identical retail overlays from its delta map.
		current[name] = originals[name]
		if physical[p] != nil {
			current[name] = physical[p]
		}
	}
	if physical["CDROM/EXEDIR/DATE.EXN"] == nil {
		return fmt.Errorf("missing composed DATE overlay")
	}
	newEXE, newDATE, err := n.PlanDATEActivitySurname(exe, physical["SLPM_86.053"], originals, current)
	if err != nil {
		return err
	}
	physical["SLPM_86.053"] = newEXE
	physical["CDROM/EXEDIR/DATE.EXN"] = newDATE
	return nil
}
