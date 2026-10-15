package nametables

import (
	"encoding/binary"
	"fmt"
)

// LiteralAliasCensus inventories exact 32-bit little-endian words whose value
// equals one of the original N10 fixed-literal virtual addresses. This is a
// potential pointer-data queue, not proof that the word is data, reachable, or
// that modifying it would be safe. The compact-table indices describe an
// optional sharing strategy, not a patch: 0=Fujisaki, 11=Tatebayashi.
// The second GEKO literal currently includes an honorific in Japanese, so a
// raw alias to the unsuffixed common entry would lose information.
type LiteralAliasCensus struct {
	File                     string `json:"file"`
	OriginalOffset           int    `json:"original_offset"`
	OriginalRAMAddress       uint32 `json:"original_ram_address"`
	SharedSurnameIndex       int    `json:"shared_surname_index"`
	HonorificSensitive       bool   `json:"honorific_sensitive"`
	EXEWordCandidates        int    `json:"exe_word_candidates"`
	GEKOWordCandidates       int    `json:"geko_word_candidates"`
	EXEOffsetsSample         []int  `json:"exe_offsets_sample"`
	GEKOOffsetsSample        []int  `json:"geko_offsets_sample"`
	EntireConsumerGraphKnown bool   `json:"entire_consumer_graph_known"`
	EligibleToRedirect       bool   `json:"eligible_to_redirect"`
}

// ExactPointerWords never dereferences candidates and intentionally scans
// the whole file, including potential code bytes. A positive result is not a
// verified runtime consumer; a zero result cannot exclude computed addresses.
func ExactPointerWords(blob []byte, addr uint32, sampleLimit int) (int, []int, error) {
	if len(blob)%4 != 0 || sampleLimit < 0 || sampleLimit > 128 {
		return 0, nil, fmt.Errorf("invalid pointer census geometry")
	}
	total := 0
	offsets := make([]int, 0)
	for i := 0; i+4 <= len(blob); i += 4 {
		if binary.LittleEndian.Uint32(blob[i:]) != addr {
			continue
		}
		total++
		if len(offsets) < sampleLimit {
			offsets = append(offsets, i)
		}
	}
	return total, offsets, nil
}

// AuditLiteralAliases proposes *only* a classification of six historical
// fixed slots relative to the 16-name compact table. It makes NO changes and
// never asserts that direct or indirect callers have been fully inventoried.
func AuditLiteralAliases(exe, geko []byte) ([]LiteralAliasCensus, error) {
	if len(exe)%4 != 0 || len(geko)%4 != 0 {
		return nil, fmt.Errorf("unaligned retail files")
	}
	rows := make([]LiteralAliasCensus, 0, len(fixedLiteralSites))
	for n, site := range fixedLiteralSites {
		ec, eo, err := ExactPointerWords(exe, site.address, 32)
		if err != nil {
			return nil, err
		}
		gc, goff, err := ExactPointerWords(geko, site.address, 32)
		if err != nil {
			return nil, err
		}
		index := 0
		if n >= 4 {
			index = 11
		}
		rows = append(rows, LiteralAliasCensus{
			File: site.file, OriginalOffset: site.offset, OriginalRAMAddress: site.address,
			SharedSurnameIndex: index, HonorificSensitive: n == 5,
			EXEWordCandidates: ec, GEKOWordCandidates: gc,
			EXEOffsetsSample: eo, GEKOOffsetsSample: goff,
			EntireConsumerGraphKnown: false, EligibleToRedirect: false,
		})
	}
	return rows, nil
}
