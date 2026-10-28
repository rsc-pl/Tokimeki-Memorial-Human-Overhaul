package n20arch

// combined romanization joins the real romanization F1+F3 candidate with the native name entry NAME_ENT keyboard and
// nickname OPTION nickname, without replacing whole overlays from older branches.
// The only output is an in-memory, BLOCKED candidate. No disc or runtime writes.
// romanization is the authoritative base; telephone is the authenticated common ancestor for
// the native name entry/nickname modifications. A conflicting byte is a hard failure.
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

const (
	CombinedRomanizerBlocked       = true
	CombinedRomanizerBlockedReason = "combined romanization integrated offline candidate only: residency, DMA/IRQ/cache and real GPU queue consumption are unproved. No ISO writer; safe_to_patch=false, runtime_pass=false."
)

type CombinedQACandidate struct {
	EnglishEXE              []byte
	Overlays                map[string][]byte
	ResidentUsed            int
	ExactSurnameCallsites   int
	KeyboardQueueCallsites  int
	OptionNicknameCallsites int
	ChangedNAMEENTBytes     int
	ChangedOPTIONBytes      int
	MergeChecksumValid      bool
	SafeToPatch             bool
	RuntimePass             bool
	Blocked                 bool
	BlockedReason           string
}

// combinedRomanizerMergeAuthenticated applies ONLY bytes changed between two fully
// constructed branches sharing an independently verified common ancestor.
// Trailer checksum is derived, never copied from either branch.
func combinedRomanizerMergeAuthenticated(base, next, target []byte) ([]byte, int, error) {
	if len(base) != OverlayLoadSectors*2048 || len(next) != len(base) || len(target) != len(base) {
		return nil, 0, fmt.Errorf("combined romanization overlay lengths mismatch")
	}
	out := bytes.Clone(target)
	changed := 0
	for i := range out {
		if i >= len(out)-4 && i < len(out)-2 {
			continue
		} // derived checksum
		if base[i] == next[i] {
			continue
		}
		if out[i] != base[i] && out[i] != next[i] {
			return nil, 0, fmt.Errorf("combined romanization conflicting overlay byte +%#x: ancestor %02x, romanization %02x, requested %02x", i, base[i], out[i], next[i])
		}
		if out[i] != next[i] {
			out[i] = next[i]
			changed++
		}
	}
	binary.BigEndian.PutUint16(out[len(out)-4:], packedTableChecksum(out))
	return out, changed, nil
}

func PlanCombinedQAOffline(exe []byte, originals map[string][]byte) (CombinedQACandidate, error) {
	var out CombinedQACandidate
	combinedNameStage, err := PlanUnifiedSurnameTELOffline(exe, originals)
	if err != nil {
		return out, fmt.Errorf("combined romanization romanization: %w", err)
	}
	if !combinedNameStage.Blocked || combinedNameStage.SafeToPatch || combinedNameStage.RuntimePass || combinedNameStage.ResidentUsed != 3792 || len(combinedNameStage.AddedEXEWords) != 21 {
		return out, fmt.Errorf("combined romanization wrong romanization baseline or unsafe status")
	}
	ancestor, err := PlanTELFullnameOffline(exe, originals)
	if err != nil {
		return out, fmt.Errorf("combined romanization telephone common ancestor: %w", err)
	}
	nameEntryCloneStage, name, err := PlanCombinedNativeGlyphChainOffline(exe, originals)
	if err != nil {
		return out, fmt.Errorf("combined romanization native name entry: %w", err)
	}
	nicknameStage, _, nick, err := PlanCombinedNicknameOffline(exe, originals)
	if err != nil {
		return out, fmt.Errorf("combined romanization nickname: %w", err)
	}
	nameEntryQueueStage, _, err := PlanCombinedTELAndNameEntOffline(exe, originals)
	if err != nil {
		return out, fmt.Errorf("combined romanization nickname: %w", err)
	}
	if len(name.QueueCalls) != 42 || len(nick.HookPCs) != 2 ||
		!bytes.Equal(ancestor.EnglishEXE, nameEntryCloneStage.EnglishEXE) ||
		!bytes.Equal(nameEntryQueueStage.EnglishEXE, nicknameStage.EnglishEXE) ||
		!name.OriginalInputIntact || name.RuntimePass || nick.RuntimePass {
		return out, fmt.Errorf("combined romanization inconsistent subplan provenance")
	}
	// Branch-level guarantee: native name entry may change NAME_ENT only, nickname may change
	// OPTION only, relative to the common ancestor. Catch hidden regressions.
	for key, original := range originals {
		if len(original) != OverlayLoadSectors*2048 || sha(original) != OverlaySHA[key] {
			return out, fmt.Errorf("combined romanization unauthenticated %s", key)
		}
		if key != "NAME_ENT.EXN" && !bytes.Equal(nicknameStage.Overlays[key], nameEntryCloneStage.Overlays[key]) {
			return out, fmt.Errorf("combined romanization native name entry unexpectedly changes %s", key)
		}
		if key != "OPTION.EXN" && !bytes.Equal(nameEntryQueueStage.Overlays[key], nicknameStage.Overlays[key]) {
			return out, fmt.Errorf("combined romanization nickname unexpectedly changes %s", key)
		}
	}
	out.EnglishEXE = bytes.Clone(combinedNameStage.EnglishEXE)
	out.Overlays = make(map[string][]byte, len(combinedNameStage.Overlays))
	for key, value := range combinedNameStage.Overlays {
		out.Overlays[key] = bytes.Clone(value)
	}
	out.Overlays["NAME_ENT.EXN"], out.ChangedNAMEENTBytes, err = combinedRomanizerMergeAuthenticated(
		ancestor.Overlays["NAME_ENT.EXN"], nameEntryCloneStage.Overlays["NAME_ENT.EXN"], out.Overlays["NAME_ENT.EXN"])
	if err != nil {
		return CombinedQACandidate{}, fmt.Errorf("combined romanization NAME_ENT merge: %w", err)
	}
	out.Overlays["OPTION.EXN"], out.ChangedOPTIONBytes, err = combinedRomanizerMergeAuthenticated(
		nameEntryQueueStage.Overlays["OPTION.EXN"], nicknameStage.Overlays["OPTION.EXN"], out.Overlays["OPTION.EXN"])
	if err != nil {
		return CombinedQACandidate{}, fmt.Errorf("combined romanization OPTION merge: %w", err)
	}
	// Every original C10 carrier and every source/bridge survives exactly.
	for _, key := range sortedCombinedOverlayKeys(combinedNameStage.Overlays) {
		a, b := combinedNameStage.Overlays[key], out.Overlays[key]
		if !bytes.Equal(a[c10BridgeFileOff:c10BridgeFileOff+c10BridgeBytes], b[c10BridgeFileOff:c10BridgeFileOff+c10BridgeBytes]) ||
			!bytes.Equal(a[C10DistributedSourceFileOff:C10DistributedSourceEnd], b[C10DistributedSourceFileOff:C10DistributedSourceEnd]) ||
			binary.BigEndian.Uint16(b[len(b)-4:]) != packedTableChecksum(b) {
			return CombinedQACandidate{}, fmt.Errorf("combined romanization C10 integrity lost in %s", key)
		}
	}
	if !bytes.Equal(combinedNameStage.Overlays["TEL.EXN"], out.Overlays["TEL.EXN"]) ||
		!bytes.Equal(out.Overlays["NAME_ENT.EXN"][nameEntryGridGridStart:nameEntryGridGridEnd], originals["NAME_ENT.EXN"][nameEntryGridGridStart:nameEntryGridGridEnd]) ||
		!bytes.Equal(out.Overlays["NAME_ENT.EXN"][nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+34*4], originals["NAME_ENT.EXN"][nameEntryGridGridPtrFileOff:nameEntryGridGridPtrFileOff+34*4]) {
		return CombinedQACandidate{}, fmt.Errorf("combined romanization original input or telephone lost")
	}
	for _, pc := range name.QueueCalls {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(out.Overlays["NAME_ENT.EXN"][off:]) != jalWord(QueueRAM) {
			return CombinedQACandidate{}, fmt.Errorf("combined romanization NAME_ENT hook lost %#x", pc)
		}
	}
	for _, pc := range nick.HookPCs {
		off := int(pc - OverlaySlotBase)
		if binary.LittleEndian.Uint32(out.Overlays["OPTION.EXN"][off:]) != jalWord(OLStubRAM) {
			return CombinedQACandidate{}, fmt.Errorf("combined romanization OPTION nickname hook lost %#x", pc)
		}
	}
	out.ResidentUsed = combinedNameStage.ResidentUsed
	out.ExactSurnameCallsites = 16
	out.KeyboardQueueCallsites = len(name.QueueCalls)
	out.OptionNicknameCallsites = len(nick.HookPCs)
	out.MergeChecksumValid = true
	out.Blocked, out.BlockedReason = true, CombinedRomanizerBlockedReason
	// Never export patched bytes as a runtime-authorized game image.
	out.SafeToPatch, out.RuntimePass = false, false
	return out, nil
}

func sortedCombinedOverlayKeys(m map[string][]byte) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
