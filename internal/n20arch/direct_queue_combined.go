package n20arch

// Direct saved-name queue hooks composed in overlay memory.
//
// OPTION owns a separate module; BUNKAKEN/BUNKASAI/MASTER already own an
// N6-FP module. This composes the queue adapter *into the same existing body*
// and adds a second dispatch stub after the first verifier. The complete body
// checksum is recomputed and both stubs share the same verifier.
//
// This candidate is deliberately NOT connected to PlanIntegratedN20Build,
// the full-English image builder, or any public build command. It is not a
// claim that the retail queue consumes a stack-backed buffer synchronously.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	directQueueStubRAM    = OLGuardBase + 0xE0
	directQueueStubOffset = 0xE0
)

// N20DirectQueueCandidate is a private, in-memory extension of the verified
// integrated plan. Every original changed word and payload remains present;
// only 13 authenticated direct-name queue JALs and four module bodies change.
// Nickname calls (OPTION) and all 235 fieldprep JALs are unchanged.
type N20DirectQueueCandidate struct {
	PatchedEXE        []byte
	PatchedOverlays   map[string][]byte
	Base              N20IntegratedPlan
	Words             []N20ManifestWord
	ExtraSites        []DirectSavedNameQueueSite
	ChangedCarrierSHA map[string]string
	SafeToPatch       bool
	RuntimePass       bool
}

// N20DirectQueueCoResident creates a self-contained, fail-closed candidate.
// It accepts only the authenticated source EXE and original overlays and
// returns a fully privately composed byte map. No filesystem writes.
func N20DirectQueueCoResident(exe []byte, overlays map[string][]byte) (N20DirectQueueCandidate, error) {
	var result N20DirectQueueCandidate
	base, err := PlanIntegratedN20Build(exe, overlays)
	if err != nil {
		return result, fmt.Errorf("base integrated plan: %w", err)
	}
	result.Base = base
	result.PatchedEXE = bytes.Clone(base.PatchedEXE)
	result.PatchedOverlays = make(map[string][]byte, len(base.PatchedOverlays))
	for k, v := range base.PatchedOverlays {
		result.PatchedOverlays[k] = bytes.Clone(v)
	}
	sites, err := ScanDirectSavedNameQueueSites(overlays)
	if err != nil {
		return result, err
	}
	groups := map[string][]DirectSavedNameQueueSite{}
	for _, s := range sites {
		if s.Field == "nickname" {
			continue
		}
		groups[s.Overlay] = append(groups[s.Overlay], s)
	}
	want := map[string]int{"OPTION.EXN": 4, "BUNKAKEN.EXN": 2, "BUNKASAI.EXN": 3, "MASTER.EXN": 4}
	if len(groups) != len(want) {
		return result, fmt.Errorf("unexpected direct-name owners %d", len(groups))
	}
	for k, n := range want {
		if len(groups[k]) != n {
			return result, fmt.Errorf("%s direct callsites=%d expected=%d", k, len(groups[k]), n)
		}
	}

	option, err := PlanOptionNameCandidate(overlays["OPTION.EXN"])
	if err != nil {
		return result, err
	}
	if _, present := base.FieldPrep.FieldPrep.Patched["OPTION.EXN"]; present {
		return result, fmt.Errorf("OPTION unexpectedly already holds N6-FP")
	}
	if _, present := base.N6.Patched["OPTION.EXN"]; present {
		return result, fmt.Errorf("OPTION unexpectedly holds N6")
	}
	result.PatchedOverlays["OPTION.EXN"] = bytes.Clone(option.Overlay)
	result.ChangedCarrierSHA = map[string]string{"OPTION.EXN": sha(option.Overlay)}
	for _, name := range []string{"BUNKAKEN.EXN", "BUNKASAI.EXN", "MASTER.EXN"} {
		if _, ok := base.FieldPrep.FieldPrep.Patched[name]; !ok {
			return result, fmt.Errorf("%s is not a fieldprep carrier", name)
		}
		out, err := extendN20FPWithDirectQueue(overlays[name], base.PatchedOverlays[name], base.FieldPrep.Module, groups[name])
		if err != nil {
			return result, fmt.Errorf("%s: %w", name, err)
		}
		result.PatchedOverlays[name] = out
		result.ChangedCarrierSHA[name] = sha(out)
	}
	result.ExtraSites = make([]DirectSavedNameQueueSite, 0, 13)
	for _, name := range []string{"OPTION.EXN", "BUNKAKEN.EXN", "BUNKASAI.EXN", "MASTER.EXN"} {
		for _, s := range groups[name] {
			expected := jalWord(directQueueStubRAM)
			if name == "OPTION.EXN" {
				expected = jalWord(OLStubRAM)
			}
			off := int(s.PC - OverlaySlotBase)
			dst := result.PatchedOverlays[name]
			old := binary.LittleEndian.Uint32(overlays[name][off:])
			if old != jalWord(optionQueueRetail) || binary.LittleEndian.Uint32(dst[off:]) != expected || binary.LittleEndian.Uint32(dst[off+4:]) != s.Delay {
				return N20DirectQueueCandidate{}, fmt.Errorf("%s direct queue delta mismatch %08x", name, s.PC)
			}
			result.Words = append(result.Words, N20ManifestWord{Owner: name, PC: s.PC, Old: old, New: expected, Kind: "direct_saved_name_queue_jal", Role: s.Field, Reason: "same-overlay direct-name guard, retail queue fallback; runtime unverified"})
			result.ExtraSites = append(result.ExtraSites, s)
		}
	}
	if len(result.Words) != 13 {
		return N20DirectQueueCandidate{}, fmt.Errorf("direct queue word count=%d", len(result.Words))
	}
	sort.Slice(result.Words, func(i, j int) bool {
		if result.Words[i].Owner == result.Words[j].Owner {
			return result.Words[i].PC < result.Words[j].PC
		}
		return result.Words[i].Owner < result.Words[j].Owner
	})
	result.SafeToPatch = false
	result.RuntimePass = false
	return result, nil
}

func extendN20FPWithDirectQueue(original, fpOverlay []byte, fp OverlayFieldPrepModule, sites []DirectSavedNameQueueSite) ([]byte, error) {
	if len(original) != OverlayLoadSectors*2048 || sha(original) == "" || len(fpOverlay) != len(original) {
		return nil, fmt.Errorf("invalid carrier geometry")
	}
	if !bytes.Equal(fpOverlay[OLBodyFileOff:OLBodyFileOff+len(fp.Body)], fp.Body) {
		return nil, fmt.Errorf("integrated fieldprep body missing")
	}
	if len(sites) == 0 {
		return nil, fmt.Errorf("no direct-name queue sites")
	}
	verifierEnd := int(OLVerifierRAM-OLGuardBase) + fp.VerifierBytes
	if verifierEnd > directQueueStubOffset {
		return nil, fmt.Errorf("verifier %x collides with second stub %x", verifierEnd, directQueueStubOffset)
	}
	if directQueueStubOffset+24 > OLGuardBytes {
		return nil, fmt.Errorf("second stub exceeds guard")
	}
	adapterRAM := align16(OLBodyBase + uint32(len(fp.Body)))
	adapter, err := buildOptionQueueShim(OLBodyBase)
	if err != nil {
		return nil, err
	}
	body := make([]byte, int(adapterRAM-OLBodyBase)+len(adapter))
	copy(body, fp.Body)
	copy(body[int(adapterRAM-OLBodyBase):], adapter)
	for len(body)%16 != 0 {
		body = append(body, 0)
	}
	if len(body) > OLBodyCapacity {
		return nil, fmt.Errorf("co-resident body %d exceeds %d", len(body), OLBodyCapacity)
	}
	var sum, xor uint32
	for i := 0; i < len(body); i += 4 {
		w := binary.LittleEndian.Uint32(body[i:])
		sum += w
		xor ^= w
	}
	verifier, err := buildOverlayVerifierMagic(OLFieldPrepMagicWord, sum, xor, uint32(len(body)))
	if err != nil {
		return nil, err
	}
	if int(OLVerifierRAM-OLGuardBase)+len(verifier) > directQueueStubOffset {
		return nil, fmt.Errorf("new verifier collides with queue stub")
	}
	second, err := buildDispatchStub(optionQueueRetail, adapterRAM)
	if err != nil {
		return nil, err
	}
	if len(second) != 24 {
		return nil, fmt.Errorf("unexpected second stub size %d", len(second))
	}
	d := bytes.Clone(fpOverlay)
	// Preserve first stub and header semantics; replace verifier with one
	// checking the *combined* body and supply queue-specific original t4.
	binary.LittleEndian.PutUint32(d[OLPayloadFileOff:], OLFieldPrepMagicWord)
	binary.LittleEndian.PutUint32(d[OLPayloadFileOff+4:], uint32(len(body)))
	binary.LittleEndian.PutUint32(d[OLPayloadFileOff+8:], sum)
	binary.LittleEndian.PutUint32(d[OLPayloadFileOff+12:], xor)
	copy(d[OLPayloadFileOff+int(OLVerifierRAM-OLGuardBase):], verifier)
	copy(d[OLPayloadFileOff+directQueueStubOffset:], second)
	copy(d[OLBodyFileOff:], body)
	for _, s := range sites {
		if s.Overlay == "" || s.Field == "nickname" || (s.Source != OLA0SurnameField && s.Source != OLFieldPrepSavedGiv) {
			return nil, fmt.Errorf("unsupported name site %+v", s)
		}
		off := int(s.PC - OverlaySlotBase)
		if off < 20 || off+8 > OLPayloadFileOff {
			return nil, fmt.Errorf("queue site outside original code %08x", s.PC)
		}
		if binary.LittleEndian.Uint32(original[off:]) != jalWord(optionQueueRetail) || binary.LittleEndian.Uint32(d[off:]) != jalWord(optionQueueRetail) || binary.LittleEndian.Uint32(d[off+4:]) != s.Delay {
			return nil, fmt.Errorf("queue site preimage mismatch %08x", s.PC)
		}
		if binary.LittleEndian.Uint32(original[off-20:]) != olLUI(7, s.Source) || binary.LittleEndian.Uint32(original[off-16:]) != olADDIU(7, 7, int16(s.Source&0xffff)) {
			return nil, fmt.Errorf("queue site source mismatch %08x", s.PC)
		}
		binary.LittleEndian.PutUint32(d[off:], jalWord(directQueueStubRAM))
	}
	binary.BigEndian.PutUint16(d[len(d)-4:], packedTableChecksum(d))
	if binary.BigEndian.Uint16(d[len(d)-4:]) != packedTableChecksum(d) || !bytes.Equal(d[len(d)-2:], original[len(original)-2:]) {
		return nil, fmt.Errorf("invalid composed checksum/trailer")
	}
	// Exact delta accounting relative to the already integrated carrier.
	allowed := map[int]bool{}
	for _, s := range sites {
		allowed[int(s.PC-OverlaySlotBase)/4*4] = true
	}
	for i := range d {
		if d[i] == fpOverlay[i] {
			continue
		}
		if (i >= OLPayloadFileOff && i < OLPayloadEndOff) || i == len(d)-4 || i == len(d)-3 || allowed[(i/4)*4] {
			continue
		}
		return nil, fmt.Errorf("unplanned co-resident byte delta 0x%x", i)
	}
	return d, nil
}
