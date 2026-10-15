package nametables

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"tokimemo/internal/script"
)

const originalCompactPoolSHA256 = "d74be5e231878869ebe6b25686be14973b3c6779c32e99c0ec78a53c89bf442d"

// HonorificResearch records an *experimental* destination for a combined
// surname+honorific. It reuses a slice of the old (now pointer-relocated)
// compact table, and deliberately cannot prove absent hidden readers. This is
// NOT a safe candidate to boot, even after every guarded byte check passes.
type HonorificResearch struct {
	Text                     string `json:"research_string"`
	Destination              uint32 `json:"research_address"`
	BytesWithNUL             int    `json:"bytes_with_nul"`
	GEKOSites                int    `json:"geko_rewritten_sources"`
	OldCompactPoolReused     bool   `json:"old_compact_pool_reused"`
	UnknownIndirectConsumers bool   `json:"unknown_indirect_consumers"`
	Complete                 bool   `json:"complete"`
	RuntimeApproved          bool   `json:"runtime_approved"`
	UnsafeToBoot             bool   `json:"unsafe_to_boot"`
}

// StageHonorificResearch accepts only original PlayStation-the-Best compact
// pool bytes in an *already pointer-relocated* G14/G23 research EXE. A
// zero-residual-direct-pointer check does not exclude runtime-calculated
// consumers. This technique is therefore research ONLY; it must never be
// called by the image writer or production build.
func StageHonorificResearch(researchEXE, originalGEKO []byte) ([]byte, []byte, HonorificResearch, error) {
	if len(researchEXE) < ShortEnd || len(originalGEKO) < 0x12b30 {
		return nil, nil, HonorificResearch{}, fmt.Errorf("N10 honorific staging: truncated source")
	}
	if fmt.Sprintf("%x", sha256.Sum256(researchEXE[ShortStart:ShortEnd])) != originalCompactPoolSHA256 {
		return nil, nil, HonorificResearch{}, fmt.Errorf("N10 honorific staging: compact source preimage changed")
	}
	const gekoDigest = "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad"
	if fmt.Sprintf("%x", sha256.Sum256(originalGEKO)) != gekoDigest {
		return nil, nil, HonorificResearch{}, fmt.Errorf("N10 honorific staging: GEKO revision mismatch")
	}
	return stageHonorificAfterProof(researchEXE, originalGEKO, originalCompactPoolSHA256)
}

// stageHonorificAfterProof is split only to allow copyright-free fixtures.
func stageHonorificAfterProof(exe, geko []byte, expectedPoolHash string) ([]byte, []byte, HonorificResearch, error) {
	fail := func(e error) ([]byte, []byte, HonorificResearch, error) { return nil, nil, HonorificResearch{}, e }
	if len(exe) < PointerTable+4*Entries || len(geko) < 0x12b30 {
		return fail(fmt.Errorf("invalid N10 research image geometry"))
	}
	if fmt.Sprintf("%x", sha256.Sum256(exe[ShortStart:ShortEnd])) != expectedPoolHash {
		return fail(fmt.Errorf("old compact table preimage differs"))
	}
	// The pointer table MUST no longer reference the old compact pool.
	// It must be entirely in the guarded English font-tail reservation.
	for i := 0; i < Entries; i++ {
		p := binary.LittleEndian.Uint32(exe[PointerTable+4*i:])
		if p >= Base+ShortStart && p < Base+ShortEnd {
			return fail(fmt.Errorf("old compact table remains live at index %d", i))
		}
		if p < 0x8004ba78 || p >= 0x8004bafc {
			return fail(fmt.Errorf("unverified relocated compact pointer %d: %#x", i, p))
		}
	}
	// Fail closed on other aligned absolute pointer words targeting old pool.
	// This is NOT a proof that computed addresses don't exist.
	for i := 0; i+4 <= len(exe); i += 4 {
		if i >= ShortStart && i < ShortEnd {
			continue
		}
		p := binary.LittleEndian.Uint32(exe[i:])
		if p >= Base+ShortStart && p < Base+ShortEnd {
			return fail(fmt.Errorf("old compact pool has additional direct word reference at %#x", i))
		}
	}
	// Detect direct GEKO references to the retired compact pool as well.
	for i := 0; i+4 <= len(geko); i += 4 {
		p := binary.LittleEndian.Uint32(geko[i:])
		if p >= Base+ShortStart && p < Base+ShortEnd {
			return fail(fmt.Errorf("GEKO contains another direct retired-pool reference at %#x", i))
		}
	}
	// The old source is visibly kanji+san: 関林さん (four SJIS pairs), NUL.
	// Preserve -san as a *separate part* of the new string; do not alias
	// GEKO to an unsuffixed compact-table surname.
	oldSuffix := []byte{0x8a, 0xd9, 0x97, 0xd1, 0x82, 0xb3, 0x82, 0xf1, 0}
	if !bytes.Equal(geko[0x12b24:0x12b24+len(oldSuffix)], oldSuffix) {
		return fail(fmt.Errorf("GEKO source honorific mismatch"))
	}
	const fullName = "Tatebayashi-san"
	raw, err := (&script.PairEncoder{}).Encode(fullName)
	if err != nil {
		return fail(err)
	}
	if len(raw)+1 > ShortEnd-ShortStart {
		return fail(fmt.Errorf("honorific source exceeds retired pool"))
	}
	// Guard the original LUI/ADDIU/JAL consumer and its destination delay slot.
	if binary.LittleEndian.Uint32(geko[0xf47c:]) != 0x3c058014 ||
		binary.LittleEndian.Uint32(geko[0xf480:]) != 0x24a54b24 ||
		binary.LittleEndian.Uint32(geko[0xf484:]) != 0x0c02b83c ||
		binary.LittleEndian.Uint32(geko[0xf488:]) != 0x2484a190 {
		return fail(fmt.Errorf("GEKO honorific call instruction mismatch"))
	}
	outEXE := bytes.Clone(exe)
	copy(outEXE[ShortStart:], raw)
	outEXE[ShortStart+len(raw)] = 0
	target := Base + ShortStart
	rewrite := AddressPair{UpperOffset: 0xf47c, LowerOffset: 0xf480, UpperWord: 0x3c058014, LowerWord: 0x24a54b24, OldAddress: 0x80144b24, NewAddress: target}
	outGEKO, _, err := RewriteGuardedAddressPairs(geko, []AddressPair{rewrite})
	if err != nil {
		return fail(err)
	}
	if !bytes.Equal(outGEKO[0xf484:0xf48c], geko[0xf484:0xf48c]) {
		return fail(fmt.Errorf("GEKO call site changed outside address pair"))
	}
	return outEXE, outGEKO, HonorificResearch{
		Text: fullName, Destination: target, BytesWithNUL: len(raw) + 1, GEKOSites: 1,
		OldCompactPoolReused: true, UnknownIndirectConsumers: true,
		Complete: false, RuntimeApproved: false, UnsafeToBoot: true,
	}, nil
}
