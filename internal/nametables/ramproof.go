package nametables

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"

	"tokimemo/internal/graphics"
)

// N10's RAM probe never writes or sets breakpoints. It checks a *snapshot*,
// not lifetime or ownership. Two stable samples cannot rule out later writes.
const (
	NarrowRAMAddress        uint32 = 0x8004b778
	NarrowRAMBytes                 = 948
	RendererHookSite        uint32 = 0x8004f2cc
	N10TailRAMAddress       uint32 = 0x8004ba78
	N10CandidateARAMAddress uint32 = 0x8004bafc
	N10CandidateBRAMAddress uint32 = 0x8004bb0c
)

type RAMSnapshotAssessment struct {
	RendererSiteMatches bool   `json:"renderer_site_matches"`
	RendererFontMatches bool   `json:"renderer_font_matches"`
	PoolIsZero          bool   `json:"pool_is_zero"`
	NamePoolOccupied    bool   `json:"name_pool_occupied"`
	BufferAIsZero       bool   `json:"candidate_a_zero"`
	BufferBIsZero       bool   `json:"candidate_b_zero"`
	BufferASHA256       string `json:"candidate_a_sha256"`
	BufferBSHA256       string `json:"candidate_b_sha256"`
	TailSHA256          string `json:"tail_sha256"`
	Evidence            string `json:"evidence"`
	RuntimeSafe         bool   `json:"runtime_safe"`
}

// AssessRAMSnapshot examines exactly the English renderer's mapped hook/font
// and 180-byte N10 candidate tail. No RAM data appears in the report: only
// booleans and hashes. The function deliberately NEVER asserts runtime safety.
func AssessRAMSnapshot(site, narrow []byte) (RAMSnapshotAssessment, error) {
	if len(site) != 8 || len(narrow) != NarrowRAMBytes {
		return RAMSnapshotAssessment{}, fmt.Errorf("invalid RAM snapshot sizes: site=%d font=%d", len(site), len(narrow))
	}
	expectedSite, _, expectedFont, _, err := graphics.RendererBuild()
	if err != nil {
		return RAMSnapshotAssessment{}, err
	}
	if len(expectedFont) != 768 || len(narrow)-len(expectedFont) != 180 {
		return RAMSnapshotAssessment{}, fmt.Errorf("unexpected renderer font layout")
	}
	tail := narrow[len(expectedFont):]
	a := tail[N10CompactExpectedBytes : N10CompactExpectedBytes+N10BufferACapacity]
	b := tail[N10CompactExpectedBytes+N10BufferACapacity:]
	sum := func(v []byte) string { h := sha256.Sum256(v); return hex.EncodeToString(h[:]) }
	zero := func(v []byte) bool { return bytes.Count(v, []byte{0}) == len(v) }
	out := RAMSnapshotAssessment{
		RendererSiteMatches: bytes.Equal(site, expectedSite),
		RendererFontMatches: bytes.Equal(narrow[:len(expectedFont)], expectedFont),
		PoolIsZero:          zero(tail), NamePoolOccupied: !zero(tail[:N10CompactExpectedBytes]),
		BufferAIsZero: zero(a), BufferBIsZero: zero(b),
		BufferASHA256: sum(a), BufferBSHA256: sum(b), TailSHA256: sum(tail),
		Evidence:    "SINGLE_INSTANT_READ_ONLY; not an allocation, alias, writability or lifetime proof",
		RuntimeSafe: false,
	}
	return out, nil
}
