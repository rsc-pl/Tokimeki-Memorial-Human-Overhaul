package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	answeringMachineBranch  = uint32(0x8013ac30)
	answeringMachineSpeaker = uint32(0x8013ad84)
)

// PlanAnsweringMachineSurname covers the native answering-machine narrator.
// Its surname LUI is in the incoming branch's delay slot, rather than
// immediately before the speaker JAL. The existing exact-pointer F1 gate
// can handle this call without changing the dialogue or TEL name producer.
func PlanAnsweringMachineSurname(original, current []byte) ([]byte, error) {
	if len(original) != 196608 || len(current) != len(original) || sha(original) != OverlaySHA["TEL.EXN"] {
		return nil, fmt.Errorf("answering machine source identity drift")
	}
	branch := int(answeringMachineBranch - OverlaySlotBase)
	call := int(answeringMachineSpeaker - OverlaySlotBase)
	if !bytes.Equal(original[branch:branch+8], words(0x10610054, OLSpeakerLUI)) ||
		!bytes.Equal(current[branch:branch+8], original[branch:branch+8]) ||
		!bytes.Equal(original[call:call+24], words(jalWord(OLOriginalSpeaker), OLSpeakerDelay, 0x3c048014, 0x2484fb54, 0x00002825, 0x0c0143a3)) ||
		!bytes.Equal(current[call:call+8], original[call:call+8]) ||
		binary.LittleEndian.Uint32(current[C10DistributedSourceFileOff:]) != C10Magic {
		return nil, fmt.Errorf("answering machine branch or speaker preimage drift: branch %x, call %x, carrier %08x", current[branch:branch+8], current[call:call+8], binary.LittleEndian.Uint32(current[C10DistributedSourceFileOff:]))
	}
	out := bytes.Clone(current)
	binary.LittleEndian.PutUint32(out[call:], jalWord(C10EXEGuardF1))
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	return out, nil
}
