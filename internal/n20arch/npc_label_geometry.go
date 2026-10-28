package n20arch

// speaker geometry NPC label geometry audit. This is non-installing code: it does not
// create executable patches or make ownership/VRAM safety claims. The queue
// width model is conditional on the observed 14-pixel pair-cell advance.
// A layout fix must handle the dialogue's own start position and wrapping;
// changing only the label position can clip long names at the left border.

// NPCNameQueue describes one of the six original EXE calls whose string
// source is the girl-name buffer A (0x800CA188). The remaining formatter
// families must never be conflated with this group.
type NPCNameQueue struct {
	FormatPC    uint32
	NameQueuePC uint32
	NameBasePC  uint32
	NameShiftPC uint32
	TextQueuePC uint32
	TextXPC     uint32
}

var npcNameQueueNPCNameQueues = [...]NPCNameQueue{
	{0x8007FBA0, 0x8007FBD4, 0x8007FBAC, 0x8007FBB0, 0x8007FBF8, 0x8007FBF4},
	{0x8007FC60, 0x8007FC94, 0x8007FC6C, 0x8007FC70, 0x8007FCB8, 0x8007FCB4},
	{0x8007FE64, 0x8007FE98, 0x8007FE70, 0x8007FE74, 0x8007FEBC, 0x8007FEB8},
	{0x800800BC, 0x800800F0, 0x800800C8, 0x800800CC, 0x80080114, 0x80080110},
	{0x8008017C, 0x800801B0, 0x80080188, 0x8008018C, 0x800801D4, 0x800801D0},
	{0x80081054, 0x80081088, 0x80081060, 0x80081064, 0x800810AC, 0x800810A8},
}

type NameGap struct {
	NameBytes        int
	PairCells        int
	NameX            int
	BodyX            int
	EstimatedEndX    int
	EstimatedOverlap int
	// Width is an estimate: source code verifies the cell count but not
	// every live VRAM glyph, spacing or frame boundary.
	WidthAssumption string
}

func EstimateNPCGap(pairBytes int) NameGap {
	if pairBytes <= 0 || pairBytes > 64 {
		return NameGap{}
	}
	cells := (pairBytes + 1) / 2
	labelX := -104 - 4*pairBytes
	end := labelX + 14*cells
	overlap := end - (-86)
	if overlap < 0 {
		overlap = 0
	}
	return NameGap{pairBytes, cells, labelX, -86, end, overlap, "14 pixels per two-byte glyph cell (not a VRAM proof)"}
}
