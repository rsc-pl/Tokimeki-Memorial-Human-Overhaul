// Source-preserving extraction of name-table composition primitives.
package nametables

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"

	"tokimemo/internal/graphics"
	"tokimemo/internal/script"
)

type DirectAliasStage struct {
	Status               string   `json:"status"`
	EXEDirectRewrites    int      `json:"exe_direct_rewrites"`
	EXEInheritedRewrites int      `json:"exe_inherited_rewrites"`
	GEKODirectRewrites   int      `json:"geko_direct_rewrites"`
	FujisakiAddress      uint32   `json:"fujisaki_alias_address"`
	TatebayashiAddress   uint32   `json:"tatebayashi_alias_address"`
	UntouchedCases       []string `json:"untouched_cases"`
	RuntimeApproved      bool     `json:"runtime_approved"`
	Complete             bool     `json:"complete"`
	UnsafeToBoot         bool     `json:"unsafe_to_boot"`
}

var verifiedFixedDirectEXE = []AddressPair{
	{UpperOffset: 0x3FFB4, LowerOffset: 0x3FFBC, UpperWord: 0x3C04800B, LowerWord: 0x24842180, OldAddress: 0x800B2180},
	{UpperOffset: 0x3FFE4, LowerOffset: 0x3FFE8, UpperWord: 0x3C07800B, LowerWord: 0x24E72188, OldAddress: 0x800B2188},
	{UpperOffset: 0x40088, LowerOffset: 0x4008C, UpperWord: 0x3C07800B, LowerWord: 0x24E721A4, OldAddress: 0x800B21A4},
}
var verifiedFixedDirectGEKO = []AddressPair{
	{UpperOffset: 0xF468, LowerOffset: 0xF46C, UpperWord: 0x3C058014, LowerWord: 0x24A54B1C, OldAddress: 0x80144B1C},
}
var fixedConsumerCallsEXE = []struct {
	offset int
	word   uint32
}{
	{0x3FFC0, 0x0C02B838}, {0x3FFF4, 0x0C0139E2}, {0x40098, 0x0C0139E2},
}
var fixedConsumerCallsGEKO = []struct {
	offset int
	word   uint32
}{
	{0xF470, 0x0C02B83C},
}

func verifyCallWords(buf []byte, points []struct {
	offset int
	word   uint32
}) error {
	for _, p := range points {
		if p.offset < 0 || p.offset+4 > len(buf) || binary.LittleEndian.Uint32(buf[p.offset:]) != p.word {
			return fmt.Errorf("Name fixed literal consumer instruction mismatch at %#x", p.offset)
		}
	}
	return nil
}

func StageDirectFixedAliases(stagedEXE, originalGEKO []byte, sourceNames []string) ([]byte, []byte, DirectAliasStage, error) {
	fail := func(err error) ([]byte, []byte, DirectAliasStage, error) { return nil, nil, DirectAliasStage{}, err }
	const gekoDigest = "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad"
	if fmt.Sprintf("%x", sha256.Sum256(originalGEKO)) != gekoDigest {
		return fail(fmt.Errorf("Name GEKO revision is not verified"))
	}
	return stageDirectFixedAliasesAfterIdentityProof(stagedEXE, originalGEKO, sourceNames)
}

func stageDirectFixedAliasesAfterIdentityProof(stagedEXE, originalGEKO []byte, sourceNames []string) ([]byte, []byte, DirectAliasStage, error) {
	fail := func(err error) ([]byte, []byte, DirectAliasStage, error) { return nil, nil, DirectAliasStage{}, err }
	start, pool, err := graphics.RendererNameTail(stagedEXE)
	if err != nil {
		return fail(err)
	}
	if len(pool) != 180 {
		return fail(fmt.Errorf("unexpected renderer tail capacity %d", len(pool)))
	}

	at := 0
	addresses := [Entries]uint32{}
	for i := 0; i < Entries; i++ {
		if at >= NameCompactExpectedBytes {
			return fail(fmt.Errorf("Name string %d outside compact pool", i))
		}
		expect := Base + uint32(start+at)
		off := PointerTable + 4*i
		if off+4 > len(stagedEXE) || binary.LittleEndian.Uint32(stagedEXE[off:]) != expect {
			return fail(fmt.Errorf("Name compact pointer %d mismatch", i))
		}
		addresses[i] = expect
		end := bytes.IndexByte(pool[at:NameCompactExpectedBytes], 0)
		if end <= 0 {
			return fail(fmt.Errorf("missing NUL for compact surname %d", i))
		}
		at += end + 1
	}
	if at > NameCompactExpectedBytes || !bytes.Equal(pool[at:NameCompactExpectedBytes], make([]byte, NameCompactExpectedBytes-at)) {
		return fail(fmt.Errorf("Name compact pool has nonzero slack after %d bytes", at))
	}

	if len(sourceNames) != Entries {
		return fail(fmt.Errorf("expected 16 source-authored labels"))
	}
	labels := []string{sourceNames[0], sourceNames[11]}
	for _, entry := range []struct {
		index int
		value string
	}{{0, labels[0]}, {11, labels[1]}} {
		encoded, e := (&script.PairEncoder{}).Encode(entry.value)
		if e != nil {
			return fail(e)
		}
		off := int(addresses[entry.index] - Base)
		if off < 0 || off+len(encoded)+1 > len(stagedEXE) || !bytes.Equal(stagedEXE[off:off+len(encoded)], encoded) || stagedEXE[off+len(encoded)] != 0 {
			return fail(fmt.Errorf("Name surname %d is not the expected encoded %s", entry.index, entry.value))
		}
	}
	if err := verifyCallWords(stagedEXE, fixedConsumerCallsEXE); err != nil {
		return fail(err)
	}
	if err := verifyCallWords(originalGEKO, fixedConsumerCallsGEKO); err != nil {
		return fail(err)
	}
	exPairs := append([]AddressPair(nil), verifiedFixedDirectEXE...)
	for i := range exPairs {
		exPairs[i].NewAddress = addresses[0]
	}
	gePairs := append([]AddressPair(nil), verifiedFixedDirectGEKO...)
	for i := range gePairs {
		gePairs[i].NewAddress = addresses[11]
	}
	newEXE, _, err := RewriteGuardedAddressPairs(stagedEXE, exPairs)
	if err != nil {
		return fail(fmt.Errorf("resident EXE direct aliases: %w", err))
	}
	newGEKO, _, err := RewriteGuardedAddressPairs(originalGEKO, gePairs)
	if err != nil {
		return fail(fmt.Errorf("GEKO direct alias: %w", err))
	}
	newEXE, err = RewriteGuardedInheritedFujisaki(newEXE, addresses[0])
	if err != nil {
		return fail(fmt.Errorf("EXE inherited Fujisaki source: %w", err))
	}
	return newEXE, newGEKO, DirectAliasStage{
		Status:            "RESEARCH_PARTIAL_DIRECT_ALIASES_NOT_BOOTABLE",
		EXEDirectRewrites: 3, EXEInheritedRewrites: 1, GEKODirectRewrites: 1,
		FujisakiAddress: addresses[0], TatebayashiAddress: addresses[11],
		UntouchedCases: []string{
			"GEKO 0x12B24 carries Japanese -san and must not alias an unsuffixed name",
			"Other indirect/fixed-literal consumers and RAM copy destinations have not been proven",
		}, RuntimeApproved: false, Complete: false, UnsafeToBoot: true,
	}, nil
}
