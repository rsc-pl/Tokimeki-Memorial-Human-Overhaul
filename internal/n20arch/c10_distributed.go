package n20arch

// resident module: private offline C10 source distribution across overlay-local high-tail
// empty space. This removes dependence on GYOZI specifically, while retaining
// the EXE's guarded original-target fallback and all integrated baseline code. It is
// NOT a claim of in-game memory ownership or a safe-to-patch verdict.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"tokimemo/internal/graphics"
)

const (
	C10DistributedSourceFileOff        = 0x2DE00
	C10DistributedSourceRAM     uint32 = OverlaySlotBase + C10DistributedSourceFileOff
	C10DistributedSourceEnd            = C10DistributedSourceFileOff + C10ResidentBytes
)

type C10DistributedCandidate struct {
	EnglishEXE     []byte
	Overlays       map[string][]byte
	SourceCarriers []string
	BridgeOnly     []string
	SourceBytes    int
	BridgeCount    int
	AddedEXEWords  []n20RelocWord
	SafeToPatch    bool
	RuntimePass    bool
}

// A full authenticated 4056-byte empty window is required. This is only a
// *static preimage gate*: future game writes/IRQ/DMA still need gameplay QA.
func c10DistributedSourceEligible(original []byte) bool {
	return len(original) == OverlayLoadSectors*2048 &&
		bytes.Equal(original[C10DistributedSourceFileOff:C10DistributedSourceEnd],
			make([]byte, C10ResidentBytes))
}

func PlanC10DistributedOffline(exe []byte, originals map[string][]byte) (C10DistributedCandidate, error) {
	var out C10DistributedCandidate
	if len(originals) != len(OverlaySHA) {
		return out, fmt.Errorf("expected 26 authenticated overlays, got %d", len(originals))
	}
	// This generator makes exactly the same checked resident image as an earlier validated image.
	source, err := PlanC10GyoziSource(originals["GYOZI.EXN"])
	if err != nil {
		return out, err
	}
	bridge, err := BuildC10PromotionBridgeAt(source.SourceImage, C10DistributedSourceRAM)
	if err != nil {
		return out, err
	}
	h5, err := N20DirectQueueCoResident(exe, originals)
	if err != nil {
		return out, fmt.Errorf("integrated baseline: %w", err)
	}
	eng, err := graphics.InstallRenderer(h5.PatchedEXE)
	if err != nil {
		return out, err
	}
	gates, err := PlanC10DualEXEGates(exe, eng, bridge)
	if err != nil {
		return out, err
	}
	out.EnglishEXE = gates.EnglishEXE
	out.AddedEXEWords = gates.Words
	out.Overlays = make(map[string][]byte, len(originals))
	keys := make([]string, 0, len(originals))
	for n := range originals {
		keys = append(keys, n)
	}
	sort.Strings(keys)
	for _, n := range keys {
		original := originals[n]
		if len(original) != OverlayLoadSectors*2048 || sha(original) != OverlaySHA[n] {
			return C10DistributedCandidate{}, fmt.Errorf("untrusted source overlay %s", n)
		}
		// Install bridge only after integrated overlay-local patches. The separate
		// 4056-byte source is eligible even on N6/N6-FP carriers.
		d := bytes.Clone(h5.PatchedOverlays[n])
		if c10DistributedSourceEligible(original) {
			if !bytes.Equal(d[C10DistributedSourceFileOff:C10DistributedSourceEnd],
				original[C10DistributedSourceFileOff:C10DistributedSourceEnd]) {
				return C10DistributedCandidate{}, fmt.Errorf("integrated baseline consumes C10 high-tail source in %s", n)
			}
			copy(d[C10DistributedSourceFileOff:], source.SourceImage)
			out.SourceCarriers = append(out.SourceCarriers, n)
		} else {
			out.BridgeOnly = append(out.BridgeOnly, n)
		}
		d, err = ApplyC10BridgeToOverlay(d, bridge)
		if err != nil {
			return C10DistributedCandidate{}, fmt.Errorf("bridge %s: %w", n, err)
		}
		if packedTableChecksum(d) != binary.BigEndian.Uint16(d[len(d)-4:]) {
			return C10DistributedCandidate{}, fmt.Errorf("bad checksum %s", n)
		}
		out.Overlays[n] = d
	}
	out.SourceBytes = len(source.SourceImage)
	out.BridgeCount = len(out.Overlays)
	// Refuse releasing the plan if its actual carrier inventory diverges.
	if len(out.SourceCarriers) != 22 || len(out.BridgeOnly) != 4 || out.BridgeCount != 26 || len(out.AddedEXEWords) != 3 {
		return C10DistributedCandidate{}, fmt.Errorf("carrier inventory drift %d/%d bridge %d", len(out.SourceCarriers), len(out.BridgeOnly), out.BridgeCount)
	}
	return out, nil
}

// GuardOnlyEXEDelta intentionally leaves the English font to the existing
// translation builder. This prevents the private N20/English byte merger from
// double-owning the renderer glyphs. It carries only the 180-byte guard tail
// and the three authenticated EXE JAL redirections into the N20 half.
func (d C10DistributedCandidate) GuardOnlyEXEDelta(h5EXE []byte) ([]byte, error) {
	if len(h5EXE) != len(d.EnglishEXE) || (len(d.AddedEXEWords) != 3 && len(d.AddedEXEWords) != 5 && len(d.AddedEXEWords) != 7 && len(d.AddedEXEWords) != 21) {
		return nil, fmt.Errorf("invalid EXE delta inputs")
	}
	installed, e := graphics.InstallRenderer(h5EXE)
	if e != nil {
		return nil, fmt.Errorf("renderer baseline: %w", e)
	}
	start, tail, e := graphics.ReservedNamePool(installed)
	if e != nil {
		return nil, e
	}
	if start != int(C10EXEGuardF1-0x80040800) || len(tail) != C10EXEGuardTailBytes {
		return nil, fmt.Errorf("guard-tail geometry changed")
	}
	allowed := make(map[int]bool)
	for i := start; i < start+len(tail); i++ {
		allowed[i] = true
	}
	for _, w := range d.AddedEXEWords {
		if w.Owner != "SLPM_86.053" {
			return nil, fmt.Errorf("foreign EXE hook %s", w.Owner)
		}
		off := int(w.PC - 0x80040800)
		if off < 0 || off+4 > len(installed) || binary.LittleEndian.Uint32(installed[off:]) != w.Old || binary.LittleEndian.Uint32(d.EnglishEXE[off:]) != w.New {
			return nil, fmt.Errorf("EXE hook drift at %08x", w.PC)
		}
		for i := off; i < off+4; i++ {
			allowed[i] = true
		}
	}
	for i := range installed {
		if installed[i] != d.EnglishEXE[i] && !allowed[i] {
			return nil, fmt.Errorf("unauthorised EXE difference at 0x%x", i)
		}
	}
	out := bytes.Clone(h5EXE)
	copy(out[start:start+len(tail)], d.EnglishEXE[start:start+len(tail)])
	for _, w := range d.AddedEXEWords {
		off := int(w.PC - 0x80040800)
		binary.LittleEndian.PutUint32(out[off:], w.New)
	}
	return out, nil
}
