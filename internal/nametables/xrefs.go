// Source-preserving extraction of name-table composition primitives.
package nametables

func isControlTransfer(w uint32) bool {
	op := w >> 26
	if op == 1 || op == 2 || op == 3 || op == 4 || op == 5 || op == 6 || op == 7 {
		return true
	}
	return op == 0 && (w&63 == 8 || w&63 == 9)
}
