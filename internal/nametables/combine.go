package nametables

import (
	"bytes"
	"crypto/sha256"
	"fmt"
)

// CombinedResearchResult describes ONE consistent, research-only source pair.
// It deliberately does not include the retired-pool Tatebayashi-san experiment:
// the old pool's computed/indirect readers have not been ruled out.
// Nothing returned by this package is authorized for boot or production build.
type CombinedResearchResult struct {
	Status                      string                         `json:"status"`
	EXEABSites                  int                            `json:"exe_ab_sites"`
	GEKOABSites                 int                            `json:"geko_ab_sites"`
	EXEDirectSites              int                            `json:"exe_direct_sites"`
	EXEInheritedSites           int                            `json:"exe_inherited_sites"`
	GEKODirectSites             int                            `json:"geko_direct_sites"`
	EXEChangedBytes             int                            `json:"exe_changed_bytes"`
	GEKOChangedBytes            int                            `json:"geko_changed_bytes"`
	EXESHA256                   string                         `json:"exe_sha256"`
	GEKOSHA256                  string                         `json:"geko_sha256"`
	GEKOSuffixOriginalUnchanged bool                           `json:"geko_san_source_unchanged"`
	GEKOAdjacentSuffix          *GEKOAdjacentHonorificResearch `json:"geko_adjacent_suffix_research,omitempty"`
	GEKODetachedSuffix          *GEKODetachedSuffixCandidate   `json:"geko_detached_suffix_research,omitempty"`
	OldCompactPoolUnmodified    bool                           `json:"old_compact_pool_unmodified"`
	RuntimeApproved             bool                           `json:"runtime_approved"`
	Complete                    bool                           `json:"complete"`
	UnsafeToBoot                bool                           `json:"unsafe_to_boot"`
	Remaining                   []string                       `json:"remaining_proofs"`
}

// MergeDisjointByteEdits merges independently verified MIPS binary candidates
// with a WORD-LEVEL collision rule. Two edits of the same four-byte instruction
// are allowed only if both independently produce the exact same instruction.
// Byte-only conflict checks are unsafe: independently changing different
// immediate bytes in one instruction could create a hybrid instruction that
// neither original stage validated. Inputs are never modified on failure.
func MergeDisjointByteEdits(base []byte, candidates ...[]byte) ([]byte, int, error) {
	if len(candidates) == 0 {
		return nil, 0, fmt.Errorf("no candidate edits")
	}
	if len(base)%4 != 0 {
		return nil, 0, fmt.Errorf("MIPS candidate preimage is not word aligned")
	}
	out := bytes.Clone(base)
	owners := make(map[int]int)
	for n, candidate := range candidates {
		if len(candidate) != len(base) {
			return nil, 0, fmt.Errorf("candidate %d length mismatch", n)
		}
		for off := 0; off < len(base); off += 4 {
			oldWord := base[off : off+4]
			newWord := candidate[off : off+4]
			if bytes.Equal(oldWord, newWord) {
				continue
			}
			if earlier, exists := owners[off]; exists && !bytes.Equal(out[off:off+4], newWord) {
				return nil, 0, fmt.Errorf("conflicting instruction at offset %#x from stages %d and %d", off, earlier, n)
			}
			copy(out[off:off+4], newWord)
			owners[off] = n
		}
	}
	count := 0
	for i, v := range out {
		if v != base[i] {
			count++
		}
	}
	return out, count, nil
}

// CombinePartialN10Research runs the independently guarded G18 and G24 stages
// against the SAME already-staged G14 table EXE and original retail GEKO. The
// result contains their union, with a strict byte-level conflict check. GEKO's
// honorific-sensitive source is explicitly kept in its original form.
func CombinePartialN10Research(stagedEXE, originalGEKO []byte) ([]byte, []byte, CombinedResearchResult, error) {
	const gekoDigest = "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad"
	if fmt.Sprintf("%x", sha256.Sum256(originalGEKO)) != gekoDigest {
		return nil, nil, CombinedResearchResult{}, fmt.Errorf("combined N10 stage: unverified GEKO source revision")
	}
	return combinePartialAfterIdentityProof(stagedEXE, originalGEKO)
}

// Internal form is for synthetic test fixtures only; the public entry point
// always enforces the full original GEKO SHA-256.
func combinePartialAfterIdentityProof(stagedEXE, originalGEKO []byte) ([]byte, []byte, CombinedResearchResult, error) {
	fail := func(err error) ([]byte, []byte, CombinedResearchResult, error) {
		return nil, nil, CombinedResearchResult{}, err
	}
	abEXE, abGEKO, ab, err := stageABAfterIdentityProof(stagedEXE, originalGEKO)
	if err != nil {
		return fail(fmt.Errorf("A/B stage: %w", err))
	}
	aliasEXE, aliasGEKO, aliases, err := stageDirectFixedAliasesAfterIdentityProof(stagedEXE, originalGEKO)
	if err != nil {
		return fail(fmt.Errorf("fixed-name stage: %w", err))
	}
	ex, exChanges, err := MergeDisjointByteEdits(stagedEXE, abEXE, aliasEXE)
	if err != nil {
		return fail(fmt.Errorf("EXE merge: %w", err))
	}
	ge, geChanges, err := MergeDisjointByteEdits(originalGEKO, abGEKO, aliasGEKO)
	if err != nil {
		return fail(fmt.Errorf("GEKO merge: %w", err))
	}
	if !bytes.Equal(originalGEKO[0x12b24:0x12b30], ge[0x12b24:0x12b30]) {
		return fail(fmt.Errorf("honorific-bearing GEKO literal was overwritten"))
	}
	if !bytes.Equal(originalGEKO[0xf47c:0xf488], ge[0xf47c:0xf488]) {
		return fail(fmt.Errorf("honorific GEKO source address or JAL modified"))
	}
	if !bytes.Equal(stagedEXE[ShortStart:ShortEnd], ex[ShortStart:ShortEnd]) {
		return fail(fmt.Errorf("retired compact pool unexpectedly modified"))
	}
	return ex, ge, CombinedResearchResult{
		Status:     "N10_COMBINED_PARTIAL_RESEARCH_NOT_BOOTABLE",
		EXEABSites: ab.EXESites, GEKOABSites: ab.GEKOSites,
		EXEDirectSites: aliases.EXEDirectRewrites, EXEInheritedSites: aliases.EXEInheritedRewrites,
		GEKODirectSites: aliases.GEKODirectRewrites,
		EXEChangedBytes: exChanges, GEKOChangedBytes: geChanges,
		EXESHA256: fmt.Sprintf("%x", sha256.Sum256(ex)), GEKOSHA256: fmt.Sprintf("%x", sha256.Sum256(ge)),
		GEKOSuffixOriginalUnchanged: true, OldCompactPoolUnmodified: true,
		RuntimeApproved: false, Complete: false, UnsafeToBoot: true,
		Remaining: []string{
			"GEKO honorific-bearing Tatebayashi-san remains in its original short literal; full replacement NOT included",
			"Old compact-pool reuse is prohibited until computed/indirect consumers are excluded",
			"A/B writable ownership during all overlays is unproven; 6 matching G19 samples do not establish lifetime safety",
			"Indirect A/B references and all possible strcat suffix lengths remain unproven",
			"Dynamic {G} display limits and N20 player-name routes remain untested",
			"No isolated game image build or runtime approval exists",
		},
	}, nil
}
