package nametables

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"tokimemo/internal/script"
)

// GEKOAdjacentHonorificResearch is an isolated, NEVER-BOOT candidate. The two
// original GEKO fixed-name slots are adjacent (8 + 12 bytes). After the normal
// surname consumer has been redirected to the compact table, their combined
// 20-byte extent could store the 17-byte pair-font Tatebayashi-san string.
// This is not a proof that computed/indirect users of either slot are absent.
type GEKOAdjacentHonorificResearch struct {
	Status                    string `json:"status"`
	OriginalSlotsBytes        int    `json:"original_slots_bytes"`
	NewBytesWithNUL           int    `json:"new_bytes_with_nul"`
	NewSourceAddress          uint32 `json:"new_source_address"`
	RemainingBytes            int    `json:"remaining_bytes"`
	OrdinaryAliasUnchanged    bool   `json:"ordinary_alias_unchanged"`
	HonorificPreserved        bool   `json:"honorific_preserved"`
	UnknownIndirectConsumers  bool   `json:"unknown_indirect_consumers"`
	DirectCallerCensusMatched bool   `json:"direct_caller_census_matched"`
	NoAlignedPointerWords     bool   `json:"no_aligned_pointer_words"`
	DerivedSiteCandidates     int    `json:"derived_site_candidates"`
	DerivedUnknownCandidates  int    `json:"derived_unknown_candidates"`
	RuntimeApproved           bool   `json:"runtime_approved"`
	UnsafeToBoot              bool   `json:"unsafe_to_boot"`
	Complete                  bool   `json:"complete"`
}

const (
	gekoAdjacentNamesStart     = 0x12b1c
	gekoAdjacentNamesEnd       = 0x12b30
	gekoAdjacentOriginalSHA256 = "0bf5a812addac54f187ee0e047263fae16f5471b930fccdfc6b53b3188c6451f"
	verifiedRetailGEKOSHA256   = "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad"
)

// StageGEKOAdjacentHonorificResearch accepts a GEKO previously processed by the
// guarded G25 combined stage and the exact retail GEKO preimage. It refuses
// any unexpected changes to the two adjacent literal slots or their callsites.
// This is ONLY a byte-level research plan. It MUST NOT enter build/native-build.
func StageGEKOAdjacentHonorificResearch(originalGEKO, combinedGEKO []byte) ([]byte, GEKOAdjacentHonorificResearch, error) {
	if fmt.Sprintf("%x", sha256.Sum256(originalGEKO)) != verifiedRetailGEKOSHA256 {
		return nil, GEKOAdjacentHonorificResearch{}, fmt.Errorf("GEKO adjacent honorific: retail SHA-256 mismatch")
	}
	return stageGEKOAdjacentAfterIdentityProof(originalGEKO, combinedGEKO)
}

func stageGEKOAdjacentAfterIdentityProof(originalGEKO, combinedGEKO []byte) ([]byte, GEKOAdjacentHonorificResearch, error) {
	bad := func(msg string) ([]byte, GEKOAdjacentHonorificResearch, error) {
		return nil, GEKOAdjacentHonorificResearch{}, fmt.Errorf("GEKO adjacent honorific: %s", msg)
	}
	if len(originalGEKO) != len(combinedGEKO) || len(originalGEKO) < gekoAdjacentNamesEnd {
		return bad("incorrect GEKO geometry")
	}
	originalSlots := originalGEKO[gekoAdjacentNamesStart:gekoAdjacentNamesEnd]
	if fmt.Sprintf("%x", sha256.Sum256(originalSlots)) != gekoAdjacentOriginalSHA256 {
		return bad("original adjacent names differ")
	}
	if !bytes.Equal(originalSlots, combinedGEKO[gekoAdjacentNamesStart:gekoAdjacentNamesEnd]) {
		return bad("merged candidate has already modified either literal slot")
	}
	// Only the two specifically reviewed original direct source materializations
	// may address this 20-byte interval. This does NOT exclude computed aliases.
	refs, err := FindRAMReferences(originalGEKO, 0x80144b1c, 0x80144b30)
	if err != nil {
		return nil, GEKOAdjacentHonorificResearch{}, err
	}
	if len(refs) != 2 {
		return bad(fmt.Sprintf("original GEKO has %d direct candidates rather than exactly two", len(refs)))
	}
	seen := map[int]bool{}
	for _, ref := range refs {
		if ref.Kind != "address-construction" ||
			!(ref.UseOffset == 0xf46c && ref.Address == 0x80144b1c && ref.UpperOffset == 0xf468 ||
				ref.UseOffset == 0xf480 && ref.Address == 0x80144b24 && ref.UpperOffset == 0xf47c) {
			return bad(fmt.Sprintf("unexpected direct user of GEKO fixed literals at %#x", ref.UseOffset))
		}
		seen[ref.UseOffset] = true
	}
	if !seen[0xf46c] || !seen[0xf480] {
		return bad("missing known direct GEKO consumers")
	}
	// G27 independent forward provenance scan follows small address steps and
	// simple register aliases which FindRAMReferences can miss. This is a
	// conservative reject gate, NOT a proof that every indirect consumer was
	// discovered. Do not broaden the approved set without instruction review.
	derived, err := AuditGEKOLiteralProvenance(originalGEKO)
	if err != nil {
		return nil, GEKOAdjacentHonorificResearch{}, err
	}
	if derived.DirectKnown != 2 || derived.AdditionalCandidates != 0 || derived.ReviewedEscapes != 2 || derived.UnreviewedEscapes != 0 {
		return bad(fmt.Sprintf("derived GEKO name-source references unresolved: known=%d unexpected=%d known-escapes=%d unknown-escapes=%d", derived.DirectKnown, derived.AdditionalCandidates, derived.ReviewedEscapes, derived.UnreviewedEscapes))
	}
	// G22 found no aligned pointer words; require the same on this exact
	// retail preimage before considering even the research-only candidate.
	for at := 0; at+4 <= len(originalGEKO); at += 4 {
		word := binary.LittleEndian.Uint32(originalGEKO[at:])
		if word >= 0x80144b1c && word < 0x80144b30 {
			return bad(fmt.Sprintf("aligned pointer word to GEKO literal at %#x", at))
		}
	}
	// The *ordinary* surname call must have been redirected to the table by
	// the existing G23/G25 stage. The already-staged address can vary with the
	// new pool layout; reject an unchanged old address, and preserve the pair.
	ordinaryHi := binary.LittleEndian.Uint32(combinedGEKO[0xf468:])
	ordinaryLo := binary.LittleEndian.Uint32(combinedGEKO[0xf46c:])
	if (ordinaryHi>>16) != 0x3c05 || (ordinaryLo>>16) != 0x24a5 ||
		(ordinaryHi == 0x3c058014 && ordinaryLo == 0x24a54b1c) ||
		binary.LittleEndian.Uint32(combinedGEKO[0xf470:]) != 0x0c02b83c {
		return bad("ordinary surname caller is not the verified relocated alias")
	}
	ordinaryAddress := (ordinaryHi & 0xffff) << 16
	ordinaryAddress += uint32(int32(int16(ordinaryLo & 0xffff)))
	if ordinaryAddress < 0x8004ba78 || ordinaryAddress >= 0x8004bafc {
		return bad("ordinary surname does not target the guarded renderer pool")
	}
	// The G18 stage must have moved the destination B. Do not accidentally
	// accept a no-op or a different unreviewed caller configuration.
	if binary.LittleEndian.Uint32(combinedGEKO[0xf478:]) != 0x3c048005 ||
		binary.LittleEndian.Uint32(combinedGEKO[0xf488:]) != 0x2484bb0c {
		return bad("honorific destination B is not the exact verified G18 candidate")
	}
	// The *honorific* call must still be unmodified. This exact preimage is
	// essential: a different call might read the old second-slot offset.
	for _, site := range []struct {
		offset int
		word   uint32
	}{
		{0xf47c, 0x3c058014}, {0xf480, 0x24a54b24},
		{0xf484, 0x0c02b83c},
	} {
		if binary.LittleEndian.Uint32(originalGEKO[site.offset:]) != site.word ||
			binary.LittleEndian.Uint32(combinedGEKO[site.offset:]) != site.word {
			return bad(fmt.Sprintf("honorific caller changed at %#x", site.offset))
		}
	}
	raw, err := (&script.PairEncoder{}).Encode("Tatebayashi-san")
	if err != nil {
		return nil, GEKOAdjacentHonorificResearch{}, err
	}
	capacity := gekoAdjacentNamesEnd - gekoAdjacentNamesStart
	if len(raw)+1 > capacity {
		return bad("encoded suffix exceeds adjacent slots")
	}
	output := bytes.Clone(combinedGEKO)
	// Own the full 20-byte *research-only* extent, with no stale second
	// terminator. This necessarily removes both old slot strings, so unknown
	// computed readers remain a hard blocker for any real patch.
	clear(output[gekoAdjacentNamesStart:gekoAdjacentNamesEnd])
	copy(output[gekoAdjacentNamesStart:], raw)
	output[gekoAdjacentNamesStart+len(raw)] = 0
	newSource := uint32(0x80144b1c)
	pair := AddressPair{UpperOffset: 0xf47c, LowerOffset: 0xf480,
		UpperWord: 0x3c058014, LowerWord: 0x24a54b24,
		OldAddress: 0x80144b24, NewAddress: newSource}
	output, _, err = RewriteGuardedAddressPairs(output, []AddressPair{pair})
	if err != nil {
		return nil, GEKOAdjacentHonorificResearch{}, err
	}
	if binary.LittleEndian.Uint32(originalGEKO[0xf488:]) != 0x2484a190 ||
		!bytes.Equal(output[0xf468:0xf474], combinedGEKO[0xf468:0xf474]) ||
		!bytes.Equal(output[0xf484:0xf48c], combinedGEKO[0xf484:0xf48c]) {
		return bad("unrelated GEKO consumer changed")
	}
	// Ensure that the appended suffix was encoded without any semantic
	// truncation and the rest of the overlay remains word-for-word unchanged.
	if !bytes.Equal(output[gekoAdjacentNamesStart:gekoAdjacentNamesStart+len(raw)], raw) {
		return bad("encoded name did not survive")
	}
	for i := range output {
		if output[i] != combinedGEKO[i] && !(i >= gekoAdjacentNamesStart && i < gekoAdjacentNamesEnd || i >= 0xf47c && i < 0xf484) {
			return bad(fmt.Sprintf("unplanned binary difference at %#x", i))
		}
	}
	return output, GEKOAdjacentHonorificResearch{
		Status:             "N10_ADJACENT_GEKO_SUFFIX_RESEARCH_ONLY_NOT_BOOTABLE",
		OriginalSlotsBytes: capacity, NewBytesWithNUL: len(raw) + 1,
		NewSourceAddress: newSource, RemainingBytes: capacity - len(raw) - 1,
		OrdinaryAliasUnchanged: true, HonorificPreserved: true,
		UnknownIndirectConsumers: true, DirectCallerCensusMatched: true, NoAlignedPointerWords: true,
		DerivedSiteCandidates: len(derived.Hits), DerivedUnknownCandidates: derived.AdditionalCandidates,
		RuntimeApproved: false, UnsafeToBoot: true, Complete: false,
	}, nil
}
