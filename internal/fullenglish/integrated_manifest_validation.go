package fullenglish

// Verify that every generated MIPS word and overlay payload matches its
// authenticated source, declared bounds and final checksum.
import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	n "tokimemo/internal/n20arch"
)

type qaReport struct {
	Schema                       int    `json:"schema"`
	Status                       string `json:"status"`
	SafeToPatch                  bool   `json:"safe_to_patch"`
	RuntimePass                  bool   `json:"runtime_pass"`
	ImageBuilt                   bool   `json:"image_built"`
	OriginalEXESHA               string `json:"original_exe_sha256"`
	PlannedEXESHA                string `json:"planned_exe_sha256"`
	OverlaySources               int    `json:"original_overlays"`
	ChangedOverlays              int    `json:"changed_overlays"`
	ChangedWords                 int    `json:"verified_word_changes"`
	PayloadRegions               int    `json:"verified_payload_regions"`
	SourceAndDestinationReadback bool   `json:"source_and_destination_readback"`
	Observation                  string `json:"observation"`
}

func hash(x []byte) string { h := sha256.Sum256(x); return hex.EncodeToString(h[:]) }

func verify(plan n.N20IntegratedPlan, exe []byte, original map[string][]byte) (qaReport, error) {
	var r qaReport
	m := plan.Manifest
	if plan.SafeToPatch || plan.RuntimePass || m.SafeToPatch || m.RuntimePass || m.Safety.ExclusiveRuntimeOwnershipProven {
		return r, errors.New("unexpected safety/runtime success flag in offline-only candidate")
	}
	if m.Schema != 2 || !m.Integrity.DeltaAuditPassed || m.Accounting.EXEEntryHooks != 0 || len(m.Words) != 413 || len(m.Regions) != 34 || len(original) != 26 || len(plan.PatchedOverlays) != 26 {
		return r, fmt.Errorf("manifest cardinality/schema/gate rejected: words=%d regions=%d", len(m.Words), len(m.Regions))
	}
	if m.Accounting.EXERelocationWords != 30 || m.Accounting.OverlayChangedWords != 383 || m.Carriers != 17 || m.SlotBytes != 12 || m.MaxInputKana != 3 {
		return r, errors.New("unexpected accounting or relocation geometry")
	}
	allowed := map[string]map[int]bool{"EXE": {}}
	for name := range original {
		allowed[name] = map[int]bool{}
	}
	// Make each source/original word and final word agree with the manifest.
	for _, w := range m.Words {
		owner := w.Owner
		source, found := original[owner]
		dest := plan.PatchedOverlays[owner]
		base := n.OverlaySlotBase
		if owner == "EXE" {
			source = exe
			dest = plan.PatchedEXE
			base = 0x80040800
			found = true
		}
		if !found || w.PC < base {
			return r, fmt.Errorf("word outside declared owner: %s %08x", owner, w.PC)
		}
		off := int(w.PC - base)
		if off < 0 || off+4 > len(source) || off+4 > len(dest) {
			return r, fmt.Errorf("word outside file: %s %08x", owner, w.PC)
		}
		if binary.LittleEndian.Uint32(source[off:]) != w.Old || binary.LittleEndian.Uint32(dest[off:]) != w.New || w.Old == w.New {
			return r, fmt.Errorf("modified word not read back: %s %08x", owner, w.PC)
		}
		for i := off; i < off+4; i++ {
			if allowed[owner][i] {
				return r, fmt.Errorf("overlapping word/region at %s+%x", owner, i)
			}
			allowed[owner][i] = true
		}
	}
	// Payloads must occupy authenticated zero areas only, and read back exactly.
	for _, region := range m.Regions {
		source, found := original[region.Owner]
		dest := plan.PatchedOverlays[region.Owner]
		if !found || region.Bytes <= 0 || region.FileOff < 0 || region.FileOff+region.Bytes > len(source) {
			return r, fmt.Errorf("payload bounds/owner invalid %s+%x", region.Owner, region.FileOff)
		}
		a, b := region.FileOff, region.FileOff+region.Bytes
		if hash(dest[a:b]) != region.SHA256 {
			return r, fmt.Errorf("payload SHA mismatch for %s %s", region.Owner, region.Kind)
		}
		for i := a; i < b; i++ {
			if source[i] != 0 || allowed[region.Owner][i] {
				return r, fmt.Errorf("payload nonzero or overlaps word %s+%x", region.Owner, i)
			}
			allowed[region.Owner][i] = true
		}
	}
	if hash(exe) != m.Integrity.SourceEXESHA || hash(plan.PatchedEXE) != m.Integrity.DestEXESHA {
		return r, errors.New("EXE source or destination SHA mismatch")
	}
	for i := range exe {
		if exe[i] != plan.PatchedEXE[i] && !allowed["EXE"][i] {
			return r, fmt.Errorf("unplanned EXE byte delta at %x", i)
		}
	}
	changed := 0
	names := make([]string, 0, len(original))
	for k := range original {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, name := range names {
		src := original[name]
		dest, ok := plan.PatchedOverlays[name]
		if !ok || len(src) != len(dest) || hash(src) != m.Integrity.SourceOverlays[name] || hash(dest) != m.Integrity.DestOverlays[name] {
			return r, fmt.Errorf("overlay source/target SHA or length mismatch %s", name)
		}
		if src[len(src)-2] != dest[len(dest)-2] || src[len(src)-1] != dest[len(dest)-1] {
			return r, fmt.Errorf("overlay trailer changed %s", name)
		}
		checksum := uint32(0)
		for _, b := range dest[:len(dest)-4] {
			checksum += uint32(b)
		}
		if uint16(checksum) != binary.BigEndian.Uint16(dest[len(dest)-4:]) || uint16(checksum) != m.Integrity.OverlayChecksums[name] {
			return r, fmt.Errorf("overlay checksum mismatch %s", name)
		}
		anyChanged := false
		for i := range src {
			if src[i] == dest[i] {
				continue
			}
			anyChanged = true
			// The two checksum bytes are the only deltas outside explicitly
			// manifested words and formerly-zero payload regions.
			if !allowed[name][i] && !(i >= len(src)-4 && i < len(src)-2) {
				return r, fmt.Errorf("unplanned overlay byte delta %s+%x", name, i)
			}
		}
		if anyChanged {
			changed++
		}
	}
	if changed != 17 {
		return r, fmt.Errorf("changed overlay count %d != 17", changed)
	}
	r = qaReport{Schema: 1, Status: "OFFLINE_PREFLIGHT_PASS", SafeToPatch: false, RuntimePass: false, ImageBuilt: false,
		OriginalEXESHA: hash(exe), PlannedEXESHA: hash(plan.PatchedEXE), OverlaySources: len(original), ChangedOverlays: changed,
		ChangedWords: len(m.Words), PayloadRegions: len(m.Regions), SourceAndDestinationReadback: true,
		Observation: "Read-only, in-memory check only; NOT proof of BSS ownership, image build, or gameplay QA"}
	return r, nil
}
