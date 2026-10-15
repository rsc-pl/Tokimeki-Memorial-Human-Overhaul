package nametables

import (
	"bytes"
	"fmt"
)

// FixedLiteral is the original 6 N10 fixed-position surname sites. These are
// source addresses, not buffer addresses. Finding no direct xref does NOT mean
// the string is unused: it can be indexed through a structure or pointer table.
type FixedLiteral struct {
	File                              string `json:"file"`
	OriginalOffset                    int    `json:"original_offset"`
	RAMAddress                        uint32 `json:"original_ram_address"`
	SlotBytes                         int    `json:"original_slot_bytes"`
	OriginalBytesBeforeNUL            int    `json:"original_bytes_before_nul"`
	DirectAddressCandidates           int    `json:"direct_address_candidates"`
	PointerOrIndirectConsumersUnknown bool   `json:"pointer_or_indirect_consumers_unknown"`
	SafeToRewrite                     bool   `json:"safe_to_rewrite"`
}

var fixedLiteralSites = []struct {
	file     string
	offset   int
	address  uint32
	capacity int
}{
	{EXE, 0x71980, 0x800B2180, 8},
	{EXE, 0x71988, 0x800B2188, 8},
	{EXE, 0x7199C, 0x800B219C, 8},
	{EXE, 0x719A4, 0x800B21A4, 8},
	{Geko, 0x12B1C, 0x80144B1C, 8},
	{Geko, 0x12B24, 0x80144B24, 12},
}

// AuditFixedLiterals measures the original slots and enumerates direct MIPS
// address-construction candidates. Never expands a fixed slot or assumes that
// all consumers of a string have been discovered.
func AuditFixedLiterals(exe, geko []byte) ([]FixedLiteral, error) {
	if len(exe)%4 != 0 || len(geko)%4 != 0 {
		return nil, fmt.Errorf("N10 fixed literal binaries require aligned data")
	}
	er, err := FindRAMReferences(exe, 0x800B2180, 0x800B21A8)
	if err != nil {
		return nil, err
	}
	gr, err := FindRAMReferences(geko, 0x80144B1C, 0x80144B30)
	if err != nil {
		return nil, err
	}
	rows := make([]FixedLiteral, 0, len(fixedLiteralSites))
	for _, site := range fixedLiteralSites {
		raw, refs := exe, er
		if site.file == Geko {
			raw, refs = geko, gr
		}
		if site.offset < 0 || site.offset+site.capacity > len(raw) {
			return nil, fmt.Errorf("N10 fixed literal %#x outside %s", site.offset, site.file)
		}
		data := raw[site.offset : site.offset+site.capacity]
		end := bytes.IndexByte(data, 0)
		if end <= 0 {
			return nil, fmt.Errorf("N10 fixed literal %#x missing bounded NUL", site.offset)
		}
		row := FixedLiteral{File: site.file, OriginalOffset: site.offset, RAMAddress: site.address, SlotBytes: site.capacity, OriginalBytesBeforeNUL: end, PointerOrIndirectConsumersUnknown: true, SafeToRewrite: false}
		for _, ref := range refs {
			if ref.Address == site.address {
				row.DirectAddressCandidates++
			}
		}
		rows = append(rows, row)
	}
	return rows, nil
}
