package namepatch

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/graphics"
)

// N10's renderer-owned 180-byte tail is split into 132 bytes of compact
// surnames and a 48-byte prospective A/B workspace. The second area is a
// RESEARCH CANDIDATE, not a proven writable/live allocation. Buffer C is
// intentionally not moved; it has many unrelated GEKO consumers.
const (
	N10CompactExpectedBytes = 132
	N10BufferACapacity      = 16
	N10BufferBCapacity      = 32
)

type ABStageSummary struct {
	Status                     string   `json:"status"`
	CandidateA                 uint32   `json:"candidate_a"`
	CandidateB                 uint32   `json:"candidate_b"`
	OriginalC                  uint32   `json:"original_c_unchanged"`
	MaxNameBytesWithNUL        int      `json:"max_name_bytes_with_nul"`
	BRemainingAfterLongestName int      `json:"b_remaining_after_longest_name"`
	ACapacity                  int      `json:"a_capacity"`
	BCapacity                  int      `json:"b_capacity"`
	EXESites                   int      `json:"exe_direct_sites"`
	GEKOSites                  int      `json:"geko_direct_sites"`
	EXEHash                    string   `json:"candidate_exe_sha256"`
	GEKOHash                   string   `json:"candidate_geko_sha256"`
	CompleteCallerCoverage     bool     `json:"complete_caller_coverage"`
	RuntimeVerified            bool     `json:"runtime_verified"`
	UnsafeToBoot               bool     `json:"unsafe_to_boot"`
	Remaining                  []string `json:"remaining_proofs"`
}

// StageABResearchCandidates produces copies of an already-staged N10 English
// executable and original GEKO overlay. The copies redirect only verified
// direct A/B address materializations. It does not patch the production build,
// prove the renderer tail survives every runtime state, or provide a bootable
// candidate. Any difference in reference counts/signatures fails closed.
func StageABResearchCandidates(stagedEXE, originalGEKO []byte) ([]byte, []byte, ABStageSummary, error) {
	fail := func(e error) ([]byte, []byte, ABStageSummary, error) { return nil, nil, ABStageSummary{}, e }
	const gekoDigest = "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad"
	if fmt.Sprintf("%x", sha256.Sum256(originalGEKO)) != gekoDigest {
		return fail(fmt.Errorf("GEKO is not the verified PlayStation the Best overlay"))
	}
	return stageABAfterIdentityProof(stagedEXE, originalGEKO)
}

// Only the public entry point above authorizes the actual retail overlay.
// This split permits synthetic fixture tests without bundling copyrighted data.
func stageABAfterIdentityProof(stagedEXE, originalGEKO []byte) ([]byte, []byte, ABStageSummary, error) {
	fail := func(e error) ([]byte, []byte, ABStageSummary, error) { return nil, nil, ABStageSummary{}, e }
	start, tail, err := graphics.RendererNameTail(stagedEXE)
	if err != nil {
		return fail(err)
	}
	if len(tail) != N10CompactExpectedBytes+N10BufferACapacity+N10BufferBCapacity {
		return fail(fmt.Errorf("unexpected renderer reservation: %d bytes", len(tail)))
	}
	for _, v := range tail[N10CompactExpectedBytes:] {
		if v != 0 {
			return fail(fmt.Errorf("prospective A/B area has nonzero bytes"))
		}
	}
	// Each name can pass through the proposed 16-byte A buffer. Valid
	// aggregate pool size alone is NOT sufficient proof of per-name safety.
	maxNameBytes, err := MaxPackedNameBytesWithNUL(tail[:N10CompactExpectedBytes], Entries)
	if err != nil {
		return fail(err)
	}
	if maxNameBytes > N10BufferACapacity || maxNameBytes > N10BufferBCapacity {
		return fail(fmt.Errorf("N10 candidate contains %d-byte name including NUL: exceeds A=%d or B=%d", maxNameBytes, N10BufferACapacity, N10BufferBCapacity))
	}
	// The staged 16 pointers must describe exactly 132 bytes of complete,
	// consecutive, NUL-terminated strings at the renderer tail beginning.
	at := 0
	for i := 0; i < Entries; i++ {
		ptr := binary.LittleEndian.Uint32(stagedEXE[PointerTable+4*i:])
		want := Base + uint32(start+at)
		if ptr != want {
			return fail(fmt.Errorf("compact pointer %d: expected %#x, got %#x", i, want, ptr))
		}
		beg := at
		for at < N10CompactExpectedBytes && tail[at] != 0 {
			at++
		}
		if beg == at || at == N10CompactExpectedBytes {
			return fail(fmt.Errorf("unterminated or empty compact string %d", i))
		}
		at++ // NUL
	}
	if at > N10CompactExpectedBytes || !bytes.Equal(tail[at:N10CompactExpectedBytes], make([]byte, N10CompactExpectedBytes-at)) {
		return fail(fmt.Errorf("compact pool has nonzero slack after %d bytes", at))
	}
	a := Base + uint32(start+N10CompactExpectedBytes)
	b := a + N10BufferACapacity
	if b+N10BufferBCapacity != Base+uint32(start+len(tail)) {
		return fail(fmt.Errorf("invalid N10 candidate layout"))
	}
	exeAudit, err := AuditXrefs(EXE, stagedEXE)
	if err != nil {
		return fail(err)
	}
	gekoAudit, err := AuditXrefs(Geko, originalGEKO)
	if err != nil {
		return fail(err)
	}
	// Counts apply ONLY to the verified retail code; a changed language build
	// which introduces/changes materializations must be independently reviewed.
	ep, err := candidateABPairs(exeAudit, 20, 11, 9, a, b)
	if err != nil {
		return fail(fmt.Errorf("EXE: %w", err))
	}
	gp, err := candidateABPairs(gekoAudit, 6, 5, 1, a, b)
	if err != nil {
		return fail(fmt.Errorf("GEKO: %w", err))
	}
	newEXE, _, err := RewriteGuardedAddressPairs(stagedEXE, ep)
	if err != nil {
		return fail(fmt.Errorf("EXE rewrite: %w", err))
	}
	newGEKO, _, err := RewriteGuardedAddressPairs(originalGEKO, gp)
	if err != nil {
		return fail(fmt.Errorf("GEKO rewrite: %w", err))
	}
	// The resident C buffer, including every direct instruction referring to
	// it, must remain untouched. The two outputs are only for offline analysis.
	result := ABStageSummary{
		Status:     "AB_DIRECT_SITE_RESEARCH_ONLY_NOT_RUNTIME_APPROVED",
		CandidateA: a, CandidateB: b, OriginalC: BufferC,
		ACapacity: N10BufferACapacity, BCapacity: N10BufferBCapacity,
		MaxNameBytesWithNUL: maxNameBytes, BRemainingAfterLongestName: N10BufferBCapacity - maxNameBytes,
		EXESites: len(ep), GEKOSites: len(gp),
		EXEHash:      fmt.Sprintf("%x", sha256.Sum256(newEXE)),
		GEKOHash:     fmt.Sprintf("%x", sha256.Sum256(newGEKO)),
		UnsafeToBoot: true, CompleteCallerCoverage: false, RuntimeVerified: false,
		Remaining: []string{
			"The 48-byte renderer tail has not been proven to retain safe ownership and writability throughout gameplay",
			"Indirect aliases and additional overlays may read/write the original A/B addresses",
			"A/B string lengths including strcat suffixes are not bounded in all game contexts",
			"Four fixed Fujisaki literals and two GEKO literals remain unchanged",
			"Dynamic {G}, menu layout, and N20 player-name rendering remain unverified",
			"No live in-game test has validated the candidates",
		},
	}
	return newEXE, newGEKO, result, nil
}

func candidateABPairs(a XrefAudit, wantTotal, wantA, wantB int, newA, newB uint32) ([]AddressPair, error) {
	if a.ReviewedSitesMatched != a.ReviewedSitesRequired || a.SafeToRelocate {
		return nil, fmt.Errorf("invalid audit provenance")
	}
	if a.File == EXE && len(a.References) != 21 || a.File == Geko && len(a.References) != 51 {
		return nil, fmt.Errorf("unexpected total candidate count: %d", len(a.References))
	}
	pairs := []AddressPair{}
	na, nb := 0, 0
	for _, r := range a.References {
		if r.Address != BufferA && r.Address != BufferB {
			continue
		}
		if r.Kind != "address-construction" {
			return nil, fmt.Errorf("non-direct A/B use at %#x", r.UseOffset)
		}
		dest := newA
		if r.Address == BufferA {
			na++
		} else {
			nb++
			dest = newB
		}
		pairs = append(pairs, AddressPair{UpperOffset: r.UpperOffset, LowerOffset: r.UseOffset, UpperWord: r.UpperWord, LowerWord: r.UseWord, OldAddress: r.Address, NewAddress: dest})
	}
	if na != wantA || nb != wantB || len(pairs) != wantTotal {
		return nil, fmt.Errorf("A/B census mismatch: A=%d B=%d want %d/%d", na, nb, wantA, wantB)
	}
	return pairs, nil
}

// MaxPackedNameBytesWithNUL checks exact per-name capacity, independent of
// aggregate pool size. It does NOT authorize arbitrary strcat suffix lengths.
func MaxPackedNameBytesWithNUL(pool []byte, entries int) (int, error) {
	if entries < 1 || len(pool) < entries*2 {
		return 0, fmt.Errorf("invalid N10 pool geometry")
	}
	at, maxBytes := 0, 0
	for i := 0; i < entries; i++ {
		if at >= len(pool) {
			return 0, fmt.Errorf("N10 pool truncated at entry %d", i)
		}
		end := bytes.IndexByte(pool[at:], 0)
		if end <= 0 {
			return 0, fmt.Errorf("empty or unterminated N10 string %d", i)
		}
		size := end + 1
		if size > maxBytes {
			maxBytes = size
		}
		at += size
	}
	if at > len(pool) || !bytes.Equal(pool[at:], make([]byte, len(pool)-at)) {
		return 0, fmt.Errorf("N10 pool has nonzero bytes after %d", at)
	}
	return maxBytes, nil
}
