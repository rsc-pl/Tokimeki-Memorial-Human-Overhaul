package n20arch

// formatter interposition extends the existing overlay formatter *offline* F1 surname renderer to three
// authenticated EXE calls previously excluded because the preceding
// instruction updates the saved display-style byte. The delay slot still
// computes a0 = saved surname. Patch ONLY each JAL; do not touch either the
// state write or delay slot. No new code/guest RAM allocation is introduced.
// This is a blocked source candidate, NOT permission to create an ISO.
import (
	"bytes"
	"encoding/binary"
	"fmt"
)

var formatterInterpositionInterposedPCs = [...]uint32{0x80073534, 0x80073628, 0x8007371c}

const RomanizerInterposerBlockedReason = "formatter interposition three additional authenticated surname EXE JALs reach the existing overlay formatter F1 gate OFFLINE; 22/26 C10 carriers, execution-time code ownership, DMA/IRQ/cache, real activity consumer and complete English runtime remain UNPROVEN; safe_to_patch=false, runtime_pass=false."

type InterposedCandidate struct {
	OverlayFormatterIntegrityCandidate
	NewlyRoutedSurnamePCs []uint32
	SpeakerSurnameCalls   int
}

func PlanInterposedSurnameOffline(exe []byte, originals map[string][]byte) (InterposedCandidate, error) {
	var empty InterposedCandidate
	// tail guard: block the old false "runtime-filled OLH name-pointer array"
	// assumption before producing even a read-only full-English formatter interposition plan.
	// This checks source provenance only; narrator output remains UNKNOWN.
	if _, e := AuditOLHStaticHelpTables(originals["OLH.EXN"]); e != nil {
		return empty, fmt.Errorf("tail guard original OLH help-menu provenance: %w", e)
	}
	if e := AuditEXEWorkBufferNotFree(exe); e != nil {
		return empty, fmt.Errorf("tail guard original EXE work-buffer ownership: %w", e)
	}
	p, err := PlanOverlayLocalOrderIntegrityOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	sites, err := speakerGeometrySpeakerSites(exe)
	if err != nil {
		return empty, err
	}
	if len(sites) != 21 || len(formatterInterpositionInterposedPCs) != 3 {
		return empty, fmt.Errorf("formatter interposition speaker site census mismatch")
	}
	out := InterposedCandidate{OverlayFormatterIntegrityCandidate: p}
	out.EnglishEXE = bytes.Clone(p.EnglishEXE)
	expected := map[uint32]bool{}
	for _, pc := range formatterInterpositionInterposedPCs {
		expected[pc] = true
	}
	for _, s := range sites {
		off := int(s.PC - 0x80040800)
		current := binary.LittleEndian.Uint32(out.EnglishEXE[off:])
		original := binary.LittleEndian.Uint32(exe[off:])
		if original != jalWord(OLOriginalSpeaker) || s.Delay != olADDIU(4, 4, 0x6354) {
			// Other speaker calls intentionally have a different delay.
			if s.Class != SiteOther {
				return empty, fmt.Errorf("formatter interposition speaker provenance mismatch at %#x", s.PC)
			}
			continue
		}
		switch s.Class {
		case SiteExact:
			if current != jalWord(C10EXEGuardF1) {
				return empty, fmt.Errorf("formatter interposition existing routed speaker lost at %#x", s.PC)
			}
			out.SpeakerSurnameCalls++
		case SiteInterposed:
			if !expected[s.PC] || current != jalWord(OLOriginalSpeaker) ||
				binary.LittleEndian.Uint32(exe[off-4:]) != 0xa0286375 ||
				binary.LittleEndian.Uint32(out.EnglishEXE[off-4:]) != 0xa0286375 ||
				binary.LittleEndian.Uint32(out.EnglishEXE[off+4:]) != s.Delay ||
				binary.LittleEndian.Uint32(exe[off-12:]) != olLUI(4, 0x800E0000) ||
				binary.LittleEndian.Uint32(exe[off-16:]) != olLUI(1, 0x800E0000) {
				return empty, fmt.Errorf("formatter interposition interposed original instruction chain mismatch at %#x", s.PC)
			}
			binary.LittleEndian.PutUint32(out.EnglishEXE[off:], jalWord(C10EXEGuardF1))
			out.NewlyRoutedSurnamePCs = append(out.NewlyRoutedSurnamePCs, s.PC)
			out.SpeakerSurnameCalls++
		case SiteOther:
			if current != original {
				return empty, fmt.Errorf("formatter interposition unrelated speaker changed at %#x", s.PC)
			}
		default:
			return empty, fmt.Errorf("formatter interposition unexpected speaker class %s", s.Class)
		}
	}
	if out.SpeakerSurnameCalls != 19 || len(out.NewlyRoutedSurnamePCs) != 3 {
		return empty, fmt.Errorf("formatter interposition speaker count %d new %d", out.SpeakerSurnameCalls, len(out.NewlyRoutedSurnamePCs))
	}
	for i := range out.EnglishEXE {
		if out.EnglishEXE[i] == p.EnglishEXE[i] {
			continue
		}
		if i%4 != 0 { // a rewritten JAL can differ in multiple bytes of same word
			at := uint32(i&^3) + 0x80040800
			if !expected[at] {
				return empty, fmt.Errorf("formatter interposition unexpected changed EXE byte %#x", i)
			}
			continue
		}
		at := uint32(i) + 0x80040800
		if !expected[at] {
			return empty, fmt.Errorf("formatter interposition unexpected changed EXE byte %#x", i)
		}
	}
	out.Blocked = true
	out.BlockedReason = RomanizerInterposerBlockedReason
	out.SafeToPatch = false
	out.RuntimePass = false
	return out, nil
}
