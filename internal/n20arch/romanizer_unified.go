package n20arch

// romanization is a single, explicitly BLOCKED private resident image combining
// the width-aware 16-site F1 surname display and TEL-local telephone F3 full names.
// It does not establish safe runtime memory ownership or GPU/cache behaviour.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	UnifiedRomanizerExperimentEnabled = false
	UnifiedRomanizerBlocked           = true
	UnifiedRomanizerBlockedReason     = "romanization OFFLINE/BLOCKED: compact width-aware F1 and telephone F3 physically co-reside in 3800-byte C10, but resident RAM lifetime, DMA/IRQ/cache, queue GPU behaviour, and real gameplay remain unproven. safe_to_patch=false, runtime_pass=false."
)

type UnifiedCandidate struct {
	C10DistributedCandidate
	ResidentSource []byte
	ResidentUsed   int
	ShimBytes      int
	Dispatcher     []byte
	TELWrapper     []byte
	TELFullname    []byte
	Blocked        bool
	BlockedReason  string
}

func buildUnifiedResident(originalGYOZI []byte) (src []byte, used int, dispatcher, wrapper, fullname []byte, err error) {
	base, e := PlanC10GyoziSourceCompact(originalGYOZI)
	if e != nil {
		err = e
		return
	}
	if base.ShimBytes != 192 || base.ActualBodyBytes != 3732 {
		err = fmt.Errorf("romanization base geometry %d/%d", base.ShimBytes, base.ActualBodyBytes)
		return
	}
	fullname, e = BuildC10LineFullnamePrototype(c10ResidentRomanizer)
	if e != nil {
		err = e
		return
	}
	old := binary.LittleEndian.Uint32(base.SourceImage[C10ResidentGuardBytes+16:])
	if old>>26 != 2 || binary.LittleEndian.Uint32(base.SourceImage[C10ResidentGuardBytes+20:]) != olADDIU(14, 0, 2) {
		err = fmt.Errorf("romanization F3 preimage drift")
		return
	}
	suffixRAM := (C10ResidentBody & 0xf0000000) | ((old & 0x03ffffff) << 2)
	wrapper, e = telephoneNameLocalPhoneWrapper(len(fullname), suffixRAM)
	if e != nil {
		err = e
		return
	}
	dispatcherRAM := C10ResidentBody + uint32(base.ActualBodyBytes)
	dispatcher, e = telephoneNameResidentF3Dispatcher(len(fullname), suffixRAM, dispatcherRAM)
	if e != nil {
		err = e
		return
	}
	used = base.ActualBodyBytes + len(dispatcher)
	if used > C10ResidentBodyBytes || len(dispatcher) != 60 {
		err = fmt.Errorf("romanization combined geometry %d/%d", used, len(dispatcher))
		return
	}
	src = bytes.Clone(base.SourceImage)
	off := C10ResidentGuardBytes + base.ActualBodyBytes
	if !allZero(src[off : off+len(dispatcher)]) {
		err = fmt.Errorf("romanization resident dispatcher occupied")
		return
	}
	copy(src[off:], dispatcher)
	binary.LittleEndian.PutUint32(src[C10ResidentGuardBytes+16:], jWord(dispatcherRAM))
	var sum, xor uint32
	for i := C10ResidentGuardBytes; i < len(src); i += 4 {
		v := binary.LittleEndian.Uint32(src[i:])
		sum += v
		xor ^= v
	}
	binary.LittleEndian.PutUint32(src[8:], sum)
	binary.LittleEndian.PutUint32(src[12:], xor)
	return
}

func PlanUnifiedSurnameTELOffline(originalEXE []byte, originals map[string][]byte) (UnifiedCandidate, error) {
	var out UnifiedCandidate
	base, e := PlanWidthAwareSurnameOffline(originalEXE, originals)
	if e != nil {
		return out, e
	}
	src, used, disp, wrap, full, e := buildUnifiedResident(originals["GYOZI.EXN"])
	if e != nil {
		return out, e
	}
	if len(base.SourceCarriers) != 22 || len(base.BridgeOnly) != 4 || len(base.AddedEXEWords) != 21 {
		return out, fmt.Errorf("romanization speaker width carrier drift")
	}
	oldBridge, e := BuildC10PromotionBridgeAtScene3(base.ResidentSource, C10DistributedSourceRAM)
	if e != nil {
		return out, e
	}
	newBridge, e := BuildC10PromotionBridgeAtScene3(src, C10DistributedSourceRAM)
	if e != nil {
		return out, e
	}
	oldGate, e := BuildC10State3EXELoaderGate(oldBridge)
	if e != nil {
		return out, e
	}
	newGate, e := BuildC10State3EXELoaderGate(newBridge)
	if e != nil {
		return out, e
	}
	at := int(C10EXELoaderGate - 0x80040800)
	if !bytes.Equal(base.EnglishEXE[at:at+len(oldGate)], oldGate) || len(oldGate) != len(newGate) {
		return out, fmt.Errorf("romanization loader gate drift")
	}
	copy(base.EnglishEXE[at:], newGate)
	carriers := map[string]bool{}
	for _, n := range base.SourceCarriers {
		carriers[n] = true
	}
	if !carriers["TEL.EXN"] {
		return out, fmt.Errorf("romanization TEL source missing")
	}
	for n, d := range base.Overlays {
		if !bytes.Equal(d[c10BridgeFileOff:c10BridgeFileOff+len(oldBridge)], oldBridge) {
			return out, fmt.Errorf("romanization bridge %s drift", n)
		}
		copy(d[c10BridgeFileOff:], newBridge)
		if carriers[n] {
			if !bytes.Equal(d[C10DistributedSourceFileOff:C10DistributedSourceEnd], base.ResidentSource) {
				return out, fmt.Errorf("romanization resident source %s drift", n)
			}
			copy(d[C10DistributedSourceFileOff:], src)
		}
		if n == "TEL.EXN" {
			lo, hi := TELLocalFileOff, TELLocalFileOff+TELLocalWindowBytes
			if !allZero(originals[n][lo:hi]) || !allZero(d[lo:hi]) || lo+0x100+len(full) > hi {
				return out, fmt.Errorf("romanization TEL local ownership/capacity")
			}
			binary.LittleEndian.PutUint32(d[lo:], TELMarker)
			binary.LittleEndian.PutUint32(d[lo+4:], uint32(len(full)))
			copy(d[lo+0x10:], wrap)
			copy(d[lo+0x100:], full)
		}
		binary.BigEndian.PutUint16(d[len(d)-4:], packedTableChecksum(d))
		if binary.BigEndian.Uint16(d[len(d)-4:]) != packedTableChecksum(d) {
			return out, fmt.Errorf("romanization checksum %s", n)
		}
	}
	out.C10DistributedCandidate = base.C10DistributedCandidate
	out.ResidentSource = src
	out.ResidentUsed = used
	out.ShimBytes = 192
	out.Dispatcher = disp
	out.TELWrapper = wrap
	out.TELFullname = full
	out.Blocked = true
	out.BlockedReason = UnifiedRomanizerBlockedReason
	out.SafeToPatch = false
	out.RuntimePass = false
	return out, nil
}
