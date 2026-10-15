package nametables

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"tokimemo/internal/script"
)

// GEKODetachedSuffixCandidate preserves BOTH original GEKO literals while
// staging a separate encoded English surname-honorific string. It is strictly
// nonbootable research: a zero-filled region is not evidence that the overlay
// never uses that region as code, RAM scratch or dynamic data.
type GEKODetachedSuffixCandidate struct {
	Status                        string `json:"status"`
	FileOffset                    int    `json:"file_offset"`
	RAMAddress                    uint32 `json:"ram_address"`
	Capacity                      int    `json:"capacity"`
	BytesWithNUL                  int    `json:"bytes_with_nul"`
	OriginalLiteralSlotsPreserved bool   `json:"original_literal_slots_preserved"`
	OldOrdinaryCallerPreserved    bool   `json:"old_ordinary_caller_preserved"`
	StaticDirectReferences        int    `json:"static_direct_references"`
	StaticDerivedReferences       int    `json:"static_derived_references"`
	StaticPointerEscapes          int    `json:"static_pointer_escapes"`
	RuntimeOwnershipProved        bool   `json:"runtime_ownership_proved"`
	SafeToBoot                    bool   `json:"safe_to_boot"`
}

const gekoOverlayRAMBase uint32 = 0x80132000

// StageGEKODetachedSuffixResearch checks the exact original retail GEKO,
// existing G25 combined source sites and an explicit, caller-chosen zero
// region. It never selects one from apparent padding. It does NOT certify
// ownership or runtime safety, and it never modifies the input slices.
func StageGEKODetachedSuffixResearch(original, combined []byte, gapOffset, gapSize int) ([]byte, GEKODetachedSuffixCandidate, error) {
	fail := func(reason string) ([]byte, GEKODetachedSuffixCandidate, error) {
		return nil, GEKODetachedSuffixCandidate{}, fmt.Errorf("detached GEKO suffix: %s", reason)
	}
	if fmt.Sprintf("%x", sha256.Sum256(original)) != verifiedRetailGEKOSHA256 {
		return fail("retail GEKO SHA-256 mismatch")
	}
	return stageGEKODetachedAfterIdentityProof(original, combined, gapOffset, gapSize)
}

// Internal function is used only by synthetic fixtures. Never expose it to
// disc-staging callers without the retail full-file digest gate above.
func stageGEKODetachedAfterIdentityProof(original, combined []byte, gapOffset, gapSize int) ([]byte, GEKODetachedSuffixCandidate, error) {
	fail := func(reason string) ([]byte, GEKODetachedSuffixCandidate, error) {
		return nil, GEKODetachedSuffixCandidate{}, fmt.Errorf("detached GEKO suffix: %s", reason)
	}
	// Reuse all G26/G27/G28 guards for the original source sites and pointer
	// escapes, but do NOT return or use its destructive adjacent-slot output.
	if _, _, err := stageGEKOAdjacentAfterIdentityProof(original, combined); err != nil {
		return fail(fmt.Sprintf("reviewed original callsites differ: %v", err))
	}
	if gapSize < 17 || gapSize > 4096 || gapOffset < 0 || gapOffset%4 != 0 ||
		gapSize > len(original) || gapOffset > len(original)-gapSize {
		return fail("unusable candidate geometry")
	}
	// G29's actual 0x15c84..0x2fffc zero expanse ends just FOUR
	// bytes before EOF (0x30000); an EOF-only test is insufficient.
	// Check the WHOLE contiguous run containing the caller's small slice.
	// This is a structural exclusion, not an interpretation of the trailer.
	if allZeroRange(original, gapOffset, gapOffset+gapSize) {
		lo, hi := zeroContainingExtent(original, gapOffset, gapSize)
		if hi == len(original) || (len(original)-hi <= 16 && hi-lo >= 4096) {
			return fail(fmt.Sprintf("source lies in trailing or near-trailer zero fill [%#x,%#x), not verified storage", lo, hi))
		}
	}
	if gapOffset < gekoAdjacentNamesEnd && gapOffset+gapSize > gekoAdjacentNamesStart {
		return fail("candidate would overwrite original surname literals")
	}
	if gapOffset < 0xf48c && gapOffset+gapSize > 0xf468 {
		return fail("candidate would overwrite reviewed callsites")
	}
	for i := gapOffset; i < gapOffset+gapSize; i++ {
		if original[i] != 0 || combined[i] != 0 {
			return fail(fmt.Sprintf("source region not zero at %#x", i))
		}
	}
	if uint64(gekoOverlayRAMBase)+uint64(gapOffset)+uint64(gapSize) > 0x100000000 {
		return fail("target address overflow")
	}
	start := gekoOverlayRAMBase + uint32(gapOffset)
	end := start + uint32(gapSize)
	// These scans only REDUCE confidence. Zero matches are NOT evidence of
	// code/data lifetime, DMA safety or complete indirect pointer coverage.
	direct, err := FindRAMReferences(original, start, end)
	if err != nil {
		return fail(err.Error())
	}
	derived, err := FindDerivedLiteralReferences(original, start, end, 32)
	if err != nil {
		return fail(err.Error())
	}
	escapes, err := FindGEKOPointerEscapes(original, start, end, 32)
	if err != nil {
		return fail(err.Error())
	}
	if len(direct)+len(derived)+len(escapes) != 0 {
		return fail(fmt.Sprintf("candidate region has references (direct=%d derived=%d escaped=%d)", len(direct), len(derived), len(escapes)))
	}
	// Reject direct MIPS jumps/branches into the proposed bytes. Linear
	// scanning can misread embedded data as code, which is an intentional
	// conservative false-positive. Indirect control transfers stay unknown.
	branches := FindGEKODirectControlTargets(original, start, end)
	if len(branches) > 0 {
		return fail(fmt.Sprintf("possible MIPS control-flow target into zero area: %#x -> %#x", branches[0].InstructionOffset, branches[0].TargetAddress))
	}
	for at := 0; at+4 <= len(original); at += 4 {
		word := binary.LittleEndian.Uint32(original[at:])
		if word >= start && word < end {
			return fail(fmt.Sprintf("candidate has aligned pointer word at %#x", at))
		}
	}
	encoded, err := (&script.PairEncoder{}).Encode("Tatebayashi-san")
	if err != nil {
		return fail(err.Error())
	}
	if len(encoded)+1 > gapSize {
		return fail("encoded suffix exceeds candidate")
	}
	candidate := bytes.Clone(combined)
	copy(candidate[gapOffset:], encoded)
	candidate[gapOffset+len(encoded)] = 0
	changed, _, err := RewriteGuardedAddressPairs(candidate, []AddressPair{{
		UpperOffset: 0xf47c, LowerOffset: 0xf480,
		UpperWord: 0x3c058014, LowerWord: 0x24a54b24,
		OldAddress: 0x80144b24, NewAddress: start,
	}})
	if err != nil {
		return fail(err.Error())
	}
	if !bytes.Equal(changed[gekoAdjacentNamesStart:gekoAdjacentNamesEnd], combined[gekoAdjacentNamesStart:gekoAdjacentNamesEnd]) ||
		!bytes.Equal(changed[0xf468:0xf474], combined[0xf468:0xf474]) {
		return fail("original literals or ordinary source call changed")
	}
	for i := range changed {
		if changed[i] != combined[i] && !((i >= gapOffset && i < gapOffset+gapSize) || (i >= 0xf47c && i < 0xf484)) {
			return fail(fmt.Sprintf("unexpected difference at %#x", i))
		}
	}
	return changed, GEKODetachedSuffixCandidate{
		Status:     "N10_GEKO_DETACHED_SUFFIX_RESEARCH_ONLY_DO_NOT_BOOT",
		FileOffset: gapOffset, RAMAddress: start, Capacity: gapSize,
		BytesWithNUL:                  len(encoded) + 1,
		OriginalLiteralSlotsPreserved: true, OldOrdinaryCallerPreserved: true,
		RuntimeOwnershipProved: false, SafeToBoot: false,
	}, nil
}
