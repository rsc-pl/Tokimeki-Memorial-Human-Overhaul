package n20arch

// nickname — private, detached OPTION nickname presentation candidate.
// integrated telephone baseline intentionally left the two 0x800E6364 sources unchanged. This
// variant reuses the existing OPTION-local packed romanizer and dispatch gate,
// replacing only its bounded shim, verification metadata and two exact JALs.
// Never writes player fields, nickname storage or save records.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

var nicknameNicknameSites = []int{0x87c4, 0x8ee8}

type NicknameCandidate struct {
	Overlay     []byte
	Shim        []byte
	HookPCs     []uint32
	SafeToPatch bool
	RuntimePass bool
}

func PlanOptionNicknameOffline(original []byte) (NicknameCandidate, error) {
	var out NicknameCandidate
	baseline, err := PlanOptionNameCandidate(original)
	if err != nil {
		return out, err
	}
	for _, off := range nicknameNicknameSites {
		if binary.LittleEndian.Uint32(original[off:]) != jalWord(optionQueueRetail) ||
			binary.LittleEndian.Uint32(original[off+4:]) != olSW(0, 29, 0x10) ||
			binary.LittleEndian.Uint32(original[off-20:]) != olLUI(7, 0x800E6364) ||
			binary.LittleEndian.Uint32(original[off-16:]) != olADDIU(7, 7, 0x6364) {
			return out, fmt.Errorf("nickname nickname retail provenance mismatch at OPTION+%#x", off)
		}
	}
	shimRAM := align16(OLBodyBase + N20PackedProgramBytes)
	shim, err := buildOptionQueueShimVariant(OLBodyBase, true)
	if err != nil {
		return out, err
	}
	bodyLen := int(shimRAM-OLBodyBase) + len(shim)
	if bodyLen > OLBodyCapacity {
		return out, fmt.Errorf("nickname OPTION body too large: %d > %d", bodyLen, OLBodyCapacity)
	}
	body := make([]byte, (bodyLen+15)&^15)
	copy(body, baseline.Body[:int(shimRAM-OLBodyBase)])
	copy(body[int(shimRAM-OLBodyBase):], shim)
	var sum, xor uint32
	for i := 0; i < len(body); i += 4 {
		w := binary.LittleEndian.Uint32(body[i:])
		sum += w
		xor ^= w
	}
	verifier, err := buildOverlayVerifierMagic(optionMagic, sum, xor, uint32(len(body)))
	if err != nil {
		return out, err
	}
	if int(OLVerifierRAM-OLGuardBase)+len(verifier) > OLGuardBytes {
		return out, fmt.Errorf("nickname verifier exceeds guard")
	}
	d := bytes.Clone(baseline.Overlay)
	binary.LittleEndian.PutUint32(d[OLPayloadFileOff+4:], uint32(len(body)))
	binary.LittleEndian.PutUint32(d[OLPayloadFileOff+8:], sum)
	binary.LittleEndian.PutUint32(d[OLPayloadFileOff+12:], xor)
	// clear old verifier/body tail to ensure no stale code
	clear(d[OLPayloadFileOff+int(OLVerifierRAM-OLGuardBase) : OLPayloadFileOff+directQueueStubOffset])
	copy(d[OLPayloadFileOff+int(OLVerifierRAM-OLGuardBase):], verifier)
	clear(d[OLBodyFileOff : OLBodyFileOff+OLBodyCapacity])
	copy(d[OLBodyFileOff:], body)
	for _, off := range nicknameNicknameSites {
		binary.LittleEndian.PutUint32(d[off:], jalWord(OLStubRAM))
		out.HookPCs = append(out.HookPCs, OverlaySlotBase+uint32(off))
	}
	binary.BigEndian.PutUint16(d[len(d)-4:], packedTableChecksum(d))
	// Never change the four existing hooks or source fields.
	for _, site := range optionNameSites {
		if binary.LittleEndian.Uint32(d[site.Off:]) != jalWord(OLStubRAM) ||
			binary.LittleEndian.Uint32(d[site.Off+4:]) != olSW(0, 29, 0x10) {
			return NicknameCandidate{}, fmt.Errorf("nickname broke existing OPTION name call %#x", site.Off)
		}
	}
	// An absolute candidate byte-diff must be confined to the local module,
	// 2 new hook words and checksum; all original source kana are untouched.
	for i := range baseline.Overlay {
		if d[i] == baseline.Overlay[i] {
			continue
		}
		allowed := i >= OLPayloadFileOff && i < OLPayloadEndOff || i == len(d)-4 || i == len(d)-3
		for _, off := range nicknameNicknameSites {
			if i >= off && i < off+4 {
				allowed = true
			}
		}
		if !allowed {
			return NicknameCandidate{}, fmt.Errorf("nickname foreign OPTION edit +%#x", i)
		}
	}
	out.Overlay = d
	out.Shim = shim
	return out, nil
}

// Compose on the completed telephone+entry slot English candidate. OPTION is the only
// overlay changed here; entry slot NAME_ENT/TEL, 26 overlays and EXE are preserved.
func PlanCombinedNicknameOffline(exe []byte, orig map[string][]byte) (TELCandidate, SlotDrawCandidate, NicknameCandidate, error) {
	var empty TELCandidate
	// activity screen: refuse any new ambiguous activity UI route before composing the
	// already authenticated OPTION/telephone name hooks. This grants no runtime PASS.
	if _, err := AuditActivityDrawBoundary(orig["OPTION.EXN"], orig["OLH.EXN"]); err != nil {
		return empty, SlotDrawCandidate{}, NicknameCandidate{}, err
	}
	c, nameEntryQueueStage, err := PlanCombinedTELAndNameEntOffline(exe, orig)
	if err != nil {
		return empty, SlotDrawCandidate{}, NicknameCandidate{}, err
	}
	nick, err := PlanOptionNicknameOffline(orig["OPTION.EXN"])
	if err != nil {
		return empty, SlotDrawCandidate{}, NicknameCandidate{}, err
	}
	old := c.Overlays["OPTION.EXN"]
	// Exact integrated telephone baseline OPTION baseline, no silent overwrite of other features.
	baseline, err := PlanOptionNameCandidate(orig["OPTION.EXN"])
	if err != nil {
		return empty, SlotDrawCandidate{}, NicknameCandidate{}, err
	}
	// telephone also puts the C10 source into a separate, earlier OPTION window.
	// Preserve those bytes; merging whole overlays would silently erase C10.
	out := bytes.Clone(old)
	changed := 0
	for i, v := range nick.Overlay {
		if i >= len(nick.Overlay)-4 && i < len(nick.Overlay)-2 {
			continue // recompute aggregate checksum only after the merge
		}
		if v == baseline.Overlay[i] {
			if old[i] != baseline.Overlay[i] &&
				!((i >= C10DistributedSourceFileOff && i < C10DistributedSourceEnd) ||
					(i >= OLPayloadEndOff && i < len(nick.Overlay)-4)) {
				return empty, SlotDrawCandidate{}, NicknameCandidate{}, fmt.Errorf("nickname unexpected telephone OPTION ownership +%#x", i)
			}
			continue
		}
		if old[i] != baseline.Overlay[i] {
			return empty, SlotDrawCandidate{}, NicknameCandidate{}, fmt.Errorf("nickname overlapping C10 edit at OPTION+%#x", i)
		}
		out[i] = v
		changed++
	}
	if changed == 0 {
		return empty, SlotDrawCandidate{}, NicknameCandidate{}, fmt.Errorf("nickname no nickname change")
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	if !bytes.Equal(old[C10DistributedSourceFileOff:C10DistributedSourceEnd], out[C10DistributedSourceFileOff:C10DistributedSourceEnd]) {
		return empty, SlotDrawCandidate{}, NicknameCandidate{}, fmt.Errorf("nickname removed C10 source")
	}
	c.Overlays["OPTION.EXN"] = out
	c.SafeToPatch = false
	c.RuntimePass = false
	return c, nameEntryQueueStage, nick, nil
}
