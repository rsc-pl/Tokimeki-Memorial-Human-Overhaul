package n20arch

// speaker rendering OFFLINE-ONLY. Re-route C10 promotion from the uncommon scene-0xD0
// jalr target to the authenticated state-3 scene-select call. Reuse the
// same fixed EXE loader gate (88 B) and source bridge (288 B), so no new
// renderer reservation or resident RAM is consumed. All queue routing features remain
// intact. No claim of persistent-RAM ownership or gameplay PASS is made.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	c10State3Call uint32 = 0x80078A74
	c10State3Old  uint32 = 0x0C01E41C // jal 0x80079070
)

func BuildC10State3EXELoaderGate(bridge []byte) ([]byte, error) {
	gate, err := BuildC10EXELoaderGate(bridge)
	if err != nil {
		return nil, err
	}
	// The original queue routing gate's failure branch is a JR $t9. At the state-3
	// JAL site, $t9 is not the old callee: use the authenticated fixed call.
	i := len(gate) - 8
	if binary.LittleEndian.Uint32(gate[i:]) != olJR(25) ||
		binary.LittleEndian.Uint32(gate[i+4:]) != 0 {
		return nil, fmt.Errorf("unexpected queue routing loader-gate tail")
	}
	binary.LittleEndian.PutUint32(gate[i:], jWord(LoaderDispatchSel))
	return gate, nil
}

func PlanC10State3SharedQueueOffline(exe []byte, originals map[string][]byte) (C10DistributedCandidate, error) {
	d, err := PlanC10SharedQueueOffline(exe, originals)
	if err != nil {
		return d, err
	}
	if len(d.AddedEXEWords) != 7 || d.SafeToPatch || d.RuntimePass {
		return C10DistributedCandidate{}, fmt.Errorf("queue routing baseline drift")
	}
	if wordAt(exe, c10State3Call) != c10State3Old ||
		wordAt(exe, c10State3Call+4) != 0 ||
		wordAt(d.EnglishEXE, c10State3Call) != c10State3Old ||
		wordAt(d.EnglishEXE, c10State3Call+4) != 0 {
		return C10DistributedCandidate{}, fmt.Errorf("authenticated state-3 call/delay preimage mismatch")
	}
	source, err := PlanC10GyoziSource(originals["GYOZI.EXN"])
	if err != nil {
		return C10DistributedCandidate{}, err
	}
	originalBridge, err := BuildC10PromotionBridgeAt(source.SourceImage, C10DistributedSourceRAM)
	if err != nil {
		return C10DistributedCandidate{}, err
	}
	state3Bridge, err := BuildC10PromotionBridgeAtScene3(source.SourceImage, C10DistributedSourceRAM)
	if err != nil {
		return C10DistributedCandidate{}, err
	}
	state3Gate, err := BuildC10State3EXELoaderGate(state3Bridge)
	if err != nil {
		return C10DistributedCandidate{}, err
	}
	oldGate, err := BuildC10EXELoaderGate(originalBridge)
	if err != nil {
		return C10DistributedCandidate{}, err
	}
	gateOff := int(C10EXELoaderGate - 0x80040800)
	if !bytes.Equal(d.EnglishEXE[gateOff:gateOff+len(oldGate)], oldGate) {
		return C10DistributedCandidate{}, fmt.Errorf("queue routing EXE gate modified by other owner")
	}
	copy(d.EnglishEXE[gateOff:], state3Gate)
	// Unhook the scene-0xD0 jalr: speaker rendering should have exactly one meaningful
	// promotion trigger (the state-3 handler). It remains authentic retail.
	hookOff := int(c10RetailLoaderCall - 0x80040800)
	if binary.LittleEndian.Uint32(exe[hookOff:]) != 0x0320F809 ||
		binary.LittleEndian.Uint32(d.EnglishEXE[hookOff:]) != jalWord(C10EXELoaderGate) ||
		binary.LittleEndian.Uint32(exe[hookOff+4:]) != 0 {
		return C10DistributedCandidate{}, fmt.Errorf("old queue routing loader hook drift")
	}
	binary.LittleEndian.PutUint32(d.EnglishEXE[hookOff:], 0x0320F809)
	state3Off := int(c10State3Call - 0x80040800)
	binary.LittleEndian.PutUint32(d.EnglishEXE[state3Off:], jalWord(C10EXELoaderGate))
	var seen int
	updated := make([]n20RelocWord, 0, len(d.AddedEXEWords))
	for _, w := range d.AddedEXEWords {
		if w.PC == c10RetailLoaderCall {
			if w.Old != 0x0320F809 || w.New != jalWord(C10EXELoaderGate) {
				return C10DistributedCandidate{}, fmt.Errorf("old loader edit drift")
			}
			seen++
			continue
		}
		updated = append(updated, w)
	}
	if seen != 1 {
		return C10DistributedCandidate{}, fmt.Errorf("missing old trigger")
	}
	updated = append(updated, n20RelocWord{Owner: "SLPM_86.053", PC: c10State3Call,
		Old: c10State3Old, New: jalWord(C10EXELoaderGate), Kind: "c10_state3_promotion",
		Role: "authenticated loader state 3: check bridge/source, promote, execute original scene selector exactly once"})
	d.AddedEXEWords = updated
	for name, overlay := range d.Overlays {
		if !bytes.Equal(overlay[c10BridgeFileOff:c10BridgeFileOff+c10BridgeBytes], originalBridge) {
			return C10DistributedCandidate{}, fmt.Errorf("queue routing bridge mismatch in %s", name)
		}
		copy(overlay[c10BridgeFileOff:], state3Bridge)
		binary.BigEndian.PutUint16(overlay[len(overlay)-4:], packedTableChecksum(overlay))
		if packedTableChecksum(overlay) != binary.BigEndian.Uint16(overlay[len(overlay)-4:]) {
			return C10DistributedCandidate{}, fmt.Errorf("speaker rendering checksum failure in %s", name)
		}
	}
	if len(d.AddedEXEWords) != 7 || d.SourceBytes != C10ResidentBytes ||
		len(d.SourceCarriers) != 22 || len(d.BridgeOnly) != 4 || d.SafeToPatch || d.RuntimePass {
		return C10DistributedCandidate{}, fmt.Errorf("speaker rendering inventory/safety drift")
	}
	return d, nil
}
