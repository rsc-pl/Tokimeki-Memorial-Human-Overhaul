package n20arch

// speaker width joins the OpenCode width-aware speaker bridge resident F1 shim with the already
// source-authenticated speaker bridge 16-site caller expansion and the speaker rendering state-3
// delivery chain. This is an OFFLINE, BLOCKED candidate, never a ROM writer.
// In particular it DOES NOT claim co-residency with the 60-byte telephone telephone
// dispatcher: only 4 bytes remain after the width-aware resident source.

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const SpeakerWidthBlockedReason = "speaker width offline-only: width-aware F1 and all 16 exact surname callers compose with speaker rendering, but C10 resident lifetime, GPU/DMA/IRQ/cache and actual gameplay are unproved; the separate telephone telephone dispatcher cannot fit beside this F1 shim (4 B free vs 60 B required). safe_to_patch=false, runtime_pass=false."

type WidthCandidate struct {
	C10DistributedCandidate
	ResidentSource    []byte
	ShimEntry         uint32
	ShimBytes         int
	ResidentUsed      int
	TelephoneCombined bool
	Blocked           bool
	BlockedReason     string
}

func PlanWidthAwareSurnameOffline(exe []byte, originals map[string][]byte) (WidthCandidate, error) {
	var out WidthCandidate
	base, err := PlanExactSurnameF1Offline(exe, originals)
	if err != nil {
		return out, fmt.Errorf("speaker bridge exact surname base: %w", err)
	}
	old, err := PlanC10GyoziSource(originals["GYOZI.EXN"])
	if err != nil {
		return out, err
	}
	width, err := PlanSpeakerBridgeSource(originals["GYOZI.EXN"])
	if err != nil {
		return out, err
	}
	if width.ActualBodyBytes > C10ResidentBodyBytes || width.ActualBodyBytes < old.ActualBodyBytes ||
		len(width.SourceImage) != C10ResidentBytes || len(base.SourceCarriers) != 22 || len(base.BridgeOnly) != 4 ||
		len(base.AddedEXEWords) != 21 || base.SafeToPatch || base.RuntimePass {
		return out, fmt.Errorf("speaker width resident/count/safety drift")
	}
	// Do not overwrite resident module's 240-byte guard queue adapter or the romanizer.
	if !bytes.Equal(width.SourceImage[16:C10ResidentGuardBytes], old.SourceImage[16:C10ResidentGuardBytes]) ||
		!bytes.Equal(width.SourceImage[C10ResidentGuardBytes+32:C10ResidentGuardBytes+32+N20PackedProgramBytes],
			old.SourceImage[C10ResidentGuardBytes+32:C10ResidentGuardBytes+32+N20PackedProgramBytes]) {
		return out, fmt.Errorf("speaker width source changed queue adapter or romanizer")
	}
	oldBridge, err := BuildC10PromotionBridgeAtScene3(old.SourceImage, C10DistributedSourceRAM)
	if err != nil {
		return out, err
	}
	newBridge, err := BuildC10PromotionBridgeAtScene3(width.SourceImage, C10DistributedSourceRAM)
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
	if len(oldGate) != len(newGate) || len(oldBridge) != len(newBridge) {
		return out, fmt.Errorf("speaker width gate/bridge size drift")
	}
	gateOff := int(C10EXELoaderGate - 0x80040800)
	if !bytes.Equal(base.EnglishEXE[gateOff:gateOff+len(oldGate)], oldGate) {
		return out, fmt.Errorf("speaker width speaker rendering loader gate preimage drift")
	}
	copy(base.EnglishEXE[gateOff:], newGate)
	carriers := map[string]bool{}
	for _, name := range base.SourceCarriers {
		carriers[name] = true
	}
	for name, overlay := range base.Overlays {
		if !bytes.Equal(overlay[c10BridgeFileOff:c10BridgeFileOff+len(oldBridge)], oldBridge) {
			return out, fmt.Errorf("speaker width speaker rendering bridge drift in %s", name)
		}
		copy(overlay[c10BridgeFileOff:], newBridge)
		if carriers[name] {
			if !bytes.Equal(overlay[C10DistributedSourceFileOff:C10DistributedSourceEnd], old.SourceImage) {
				return out, fmt.Errorf("speaker width old resident source drift in %s", name)
			}
			copy(overlay[C10DistributedSourceFileOff:C10DistributedSourceEnd], width.SourceImage)
		}
		binary.BigEndian.PutUint16(overlay[len(overlay)-4:], packedTableChecksum(overlay))
		if packedTableChecksum(overlay) != binary.BigEndian.Uint16(overlay[len(overlay)-4:]) {
			return out, fmt.Errorf("speaker width overlay checksum %s", name)
		}
	}
	// Expose the physical incompatibility rather than claiming that telephone was
	// integrated: its 60-byte dispatcher cannot coexist in this C10 body.
	if C10ResidentBodyBytes-width.ActualBodyBytes >= 60 {
		return out, fmt.Errorf("speaker width co-residency assumption changed; audit telephone")
	}
	out.C10DistributedCandidate = base
	out.ResidentSource = width.SourceImage
	out.ShimEntry, out.ShimBytes, out.ResidentUsed = width.ShimEntry, width.ShimBytes, width.ActualBodyBytes
	out.TelephoneCombined = false
	out.Blocked = true
	out.BlockedReason = SpeakerWidthBlockedReason
	out.SafeToPatch, out.RuntimePass = false, false
	return out, nil
}
