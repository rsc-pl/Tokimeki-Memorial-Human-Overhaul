package n20arch

// telephone: private, OFFLINE ONLY TEL-local unsuffixed player full-name route.
// This reuses speaker rendering's authenticated loader and resident module's existing four complete-line
// queues. Nothing in this file is enabled in the normal speaker rendering offline verification builder.
// The TEL overlay owns the executable prototype ONLY while TEL is loaded;
// the resident F3 dispatcher checks a TEL-only marker/length and otherwise
// tail-jumps to the original surname+san converter.
//
// IMPORTANT: zero bytes in a retail overlay establish file preimage, NOT
// runtime ownership. This remains an uninstalled diagnostic candidate.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const (
	TELLocalFileOff            = 0x23000
	TELMarkerRAM        uint32 = OverlaySlotBase + TELLocalFileOff
	TELMarker           uint32 = 0x4e210000
	TELWrapperRAM       uint32 = TELMarkerRAM + 0x10
	TELFullnameRAM      uint32 = TELMarkerRAM + 0x100
	TELLocalWindowBytes        = 0x1000
)

type TELCandidate struct {
	C10DistributedCandidate
	NewResidentSource  []byte
	NewBridge          []byte
	ResidentDispatcher []byte
	LocalWrapper       []byte
	LocalFullname      []byte
	PhoneCarriers      []string
	SafeToPatch        bool
	RuntimePass        bool
}

// This checks the disjoint TEL-local code before any resident redirection.
func telephoneNameLocalPhoneWrapper(fullnameBytes int, suffixRAM uint32) ([]byte, error) {
	if fullnameBytes != 1048 {
		return nil, fmt.Errorf("unexpected speaker rendering width %d", fullnameBytes)
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	add := func(d, s uint32, n int16) { w(olADDIU(d, s, n)) }
	lw := func(d uint32, off int16) { w(olLW(d, 29, off)); w(0) }
	add(29, 29, -0x30)
	w(olSW(31, 29, 0x2c))
	w(olSW(4, 29, 0x20))
	w(olSW(5, 29, 0x24))
	w(olSW(6, 29, 0x28))
	w(jalWord(TELFullnameRAM))
	w(0)
	a.b(5, 2, 0, "return")
	w(0) // succeeded, v0 is output size
	lw(4, 0x20)
	lw(5, 0x24)
	lw(6, 0x28)
	add(14, 0, 2)
	w(jalWord(suffixRAM))
	w(0) // try the original surname+san route
	a.label("return")
	lw(31, 0x2c)
	w(olJR(31))
	add(29, 29, 0x30)
	a.resolve()
	p := words(a.words...)
	if len(p) > 0xf0 {
		return nil, fmt.Errorf("telephone wrapper too long: %d", len(p))
	}
	return p, nil
}

// Emit a small bounded resident F3 dispatch. In non-TEL scenes it is exactly
// a tail call to the original resident module suffix converter, preserving a0/a1/a2.
// The marker alone does not establish integrity; the composition engine is still
// gated by authenticated source + full original overlay checksum.
func telephoneNameResidentF3Dispatcher(fullnameBytes int, suffixRAM uint32, origin uint32) ([]byte, error) {
	if fullnameBytes > 32767 || fullnameBytes < 1 {
		return nil, fmt.Errorf("bad local size")
	}
	a := &miniAsm{labels: map[string]int{}}
	w := func(x uint32) { a.w(x) }
	w(olLUI(8, TELMarkerRAM))
	w(olLW(9, 8, int16(TELMarkerRAM&0xffff)))
	w(0)
	w(olLUI(10, TELMarker))
	a.b(5, 9, 10, "suffix")
	w(0)
	w(olLW(9, 8, int16((TELMarkerRAM+4)&0xffff)))
	w(0)
	w(olADDIU(10, 0, int16(fullnameBytes)))
	a.b(5, 9, 10, "suffix")
	w(0)
	w(jWord(TELWrapperRAM))
	w(0)
	a.label("suffix")
	w(jWord(suffixRAM))
	w(olADDIU(14, 0, 2))
	a.resolve()
	b := words(a.words...)
	_ = origin
	if len(b) > 64 {
		return nil, fmt.Errorf("telephone dispatcher too large %d", len(b))
	}
	return b, nil
}

func telephoneNameResidentSource(original []byte) (source, dispatcher, wrapper, fullname []byte, err error) {
	base, err := PlanC10GyoziSource(original)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	fullname, err = BuildC10LineFullnamePrototype(c10ResidentRomanizer)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// The existing F3 entry points at the resident module suffix helper.
	old := binary.LittleEndian.Uint32(base.SourceImage[C10ResidentGuardBytes+16:])
	if old>>26 != 2 || binary.LittleEndian.Uint32(base.SourceImage[C10ResidentGuardBytes+20:]) != olADDIU(14, 0, 2) {
		return nil, nil, nil, nil, fmt.Errorf("unrecognized F3 preimage")
	}
	suffixRAM := (C10ResidentBody & 0xf0000000) | ((old & 0x03ffffff) << 2)
	wrapper, err = telephoneNameLocalPhoneWrapper(len(fullname), suffixRAM)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	dispatcherRAM := C10ResidentBody + uint32(base.ActualBodyBytes)
	if dispatcherRAM&3 != 0 {
		return nil, nil, nil, nil, fmt.Errorf("unaligned dispatcher")
	}
	dispatcher, err = telephoneNameResidentF3Dispatcher(len(fullname), suffixRAM, dispatcherRAM)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if int(dispatcherRAM-C10ResidentBody)+len(dispatcher) > C10ResidentBodyBytes {
		return nil, nil, nil, nil, fmt.Errorf("C10 resident room insufficient")
	}
	source = bytes.Clone(base.SourceImage)
	bodyOff := int(dispatcherRAM - C10ResidentBody)
	if !bytes.Equal(source[C10ResidentGuardBytes+bodyOff:C10ResidentGuardBytes+bodyOff+len(dispatcher)], make([]byte, len(dispatcher))) {
		return nil, nil, nil, nil, fmt.Errorf("occupied C10 tail")
	}
	copy(source[C10ResidentGuardBytes+bodyOff:], dispatcher)
	binary.LittleEndian.PutUint32(source[C10ResidentGuardBytes+16:], jWord(dispatcherRAM))
	// Existing guard length must remain exact. Recompute only its two integrity
	// fields; the resident's terminal adapter in guard bytes 16..255 is untouched.
	var sum, xor uint32
	for i := C10ResidentGuardBytes; i < len(source); i += 4 {
		v := binary.LittleEndian.Uint32(source[i:])
		sum += v
		xor ^= v
	}
	binary.LittleEndian.PutUint32(source[8:], sum)
	binary.LittleEndian.PutUint32(source[12:], xor)
	return source, dispatcher, wrapper, fullname, nil
}

// PlanTELFullnameOffline keeps speaker rendering intact and creates a separate complete
// validation image composition. No ROM writer or default builder consumes this.
func PlanTELFullnameOffline(exe []byte, original map[string][]byte) (TELCandidate, error) {
	var out TELCandidate
	telephoneCacheStage, err := PlanC10State3SharedQueueOffline(exe, original)
	if err != nil {
		return out, err
	}
	p, err := PlanC10GyoziSource(original["GYOZI.EXN"])
	if err != nil {
		return out, err
	}
	source, disp, wrap, full, err := telephoneNameResidentSource(original["GYOZI.EXN"])
	if err != nil {
		return out, err
	}
	if len(telephoneCacheStage.SourceCarriers) != 22 || len(telephoneCacheStage.BridgeOnly) != 4 || len(telephoneCacheStage.AddedEXEWords) != 7 {
		return out, fmt.Errorf("speaker rendering carrier inventory changed")
	}
	oldBridge, err := BuildC10PromotionBridgeAtScene3(p.SourceImage, C10DistributedSourceRAM)
	if err != nil {
		return out, err
	}
	newBridge, err := BuildC10PromotionBridgeAtScene3(source, C10DistributedSourceRAM)
	if err != nil {
		return out, err
	}
	oldGate, err := BuildC10State3EXELoaderGate(oldBridge)
	if err != nil {
		return out, err
	}
	newGate, err := BuildC10State3EXELoaderGate(newBridge)
	if err != nil {
		return out, err
	}
	gateOff := int(C10EXELoaderGate - 0x80040800)
	if !bytes.Equal(telephoneCacheStage.EnglishEXE[gateOff:gateOff+len(oldGate)], oldGate) || len(oldGate) != len(newGate) {
		return out, fmt.Errorf("speaker rendering loader gate drift")
	}
	copy(telephoneCacheStage.EnglishEXE[gateOff:], newGate)
	carrier := map[string]bool{}
	for _, n := range telephoneCacheStage.SourceCarriers {
		carrier[n] = true
	}
	if !carrier["TEL.EXN"] {
		return out, fmt.Errorf("TEL not eligible for source")
	}
	for n, d := range telephoneCacheStage.Overlays {
		if !bytes.Equal(d[c10BridgeFileOff:c10BridgeFileOff+c10BridgeBytes], oldBridge) {
			return out, fmt.Errorf("speaker rendering bridge drift: %s", n)
		}
		copy(d[c10BridgeFileOff:], newBridge)
		if carrier[n] {
			if !bytes.Equal(d[C10DistributedSourceFileOff:C10DistributedSourceEnd], p.SourceImage) {
				return out, fmt.Errorf("speaker rendering source drift: %s", n)
			}
			copy(d[C10DistributedSourceFileOff:], source)
		}
		if n == "TEL.EXN" {
			// Physical source preimage AND already-patched speaker rendering window must be empty.
			lo := TELLocalFileOff
			hi := lo + TELLocalWindowBytes
			z := make([]byte, hi-lo)
			if !bytes.Equal(original[n][lo:hi], z) || !bytes.Equal(d[lo:hi], z) {
				return out, fmt.Errorf("TEL local code region occupied")
			}
			if TELLocalFileOff+0x100+len(full) > hi {
				return out, fmt.Errorf("TEL fullname overflows local window")
			}
			binary.LittleEndian.PutUint32(d[lo:], TELMarker)
			binary.LittleEndian.PutUint32(d[lo+4:], uint32(len(full)))
			copy(d[lo+0x10:], wrap)
			copy(d[lo+0x100:], full)
			out.PhoneCarriers = []string{n}
		}
		binary.BigEndian.PutUint16(d[len(d)-4:], packedTableChecksum(d))
		if packedTableChecksum(d) != binary.BigEndian.Uint16(d[len(d)-4:]) {
			return out, fmt.Errorf("checksum failure: %s", n)
		}
	}
	telephoneCacheStage.SafeToPatch = false
	telephoneCacheStage.RuntimePass = false
	out.C10DistributedCandidate = telephoneCacheStage
	out.NewResidentSource = source
	out.NewBridge = newBridge
	out.ResidentDispatcher = disp
	out.LocalWrapper = wrap
	out.LocalFullname = full
	out.SafeToPatch = false
	out.RuntimePass = false
	return out, nil
}
