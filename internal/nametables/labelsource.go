package nametables

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// LabelSource is a bounded inspection of bytes in the *original, resident*
// PS-X EXE. It is not proof that the same RAM address is immutable at runtime.
// No source text (which may be copyrighted) is placed in the report.
type LabelSource struct {
	RAMAddress      uint32 `json:"ram_address"`
	FileOffset      int    `json:"file_offset"`
	BytesBeforeNUL  int    `json:"bytes_before_nul"`
	ScanLimit       int    `json:"scan_limit"`
	NULTerminated   bool   `json:"nul_terminated"`
	OriginalEXEOnly bool   `json:"original_exe_only"`
}

// ResidentCStringLength translates a MIPS address to the original PS-X EXE
// section and measures a C-string with an explicit byte limit. In particular,
// RAM address - load address is NOT a file offset: the 0x800-byte PS-X header
// must be included. This rejects out-of-image and unterminated sources.
func ResidentCStringLength(exe []byte, addr uint32, max int) (LabelSource, error) {
	result := LabelSource{RAMAddress: addr, ScanLimit: max, OriginalEXEOnly: true}
	if max < 1 || max > 1024 || len(exe) < 0x800 || !bytes.HasPrefix(exe, []byte("PS-X EXE")) {
		return result, fmt.Errorf("invalid PS-X EXE or string scan bound")
	}
	load := binary.LittleEndian.Uint32(exe[0x18:])
	length := binary.LittleEndian.Uint32(exe[0x1c:])
	if length == 0 || uint64(length) > uint64(len(exe)-0x800) || addr < load || uint64(addr-load) >= uint64(length) {
		return result, fmt.Errorf("source %#x is outside original resident EXE", addr)
	}
	offset := uint64(0x800) + uint64(addr-load)
	remaining := int(uint64(length) - uint64(addr-load))
	if remaining > max {
		remaining = max
	}
	raw := exe[int(offset) : int(offset)+remaining]
	i := bytes.IndexByte(raw, 0)
	if i < 0 {
		return result, fmt.Errorf("source %#x not NUL-terminated within %d bytes", addr, remaining)
	}
	result.FileOffset = int(offset)
	result.BytesBeforeNUL = i
	result.NULTerminated = true
	return result, nil
}

// LabelCapacity evaluates a *specific* raw strcpy + strcat byte budget.
// The suffix must be measured from its actual RAM source independently:
// no dynamic path is certified by this calculation.
type LabelCapacity struct {
	Capacity                   int  `json:"capacity"`
	NameBytes                  int  `json:"name_bytes"`
	SuffixBytes                int  `json:"suffix_bytes"`
	RequiredWithNUL            int  `json:"required_with_nul"`
	Fits                       bool `json:"fits"`
	ProvenForAllRuntimeSources bool `json:"proven_for_all_runtime_sources"`
}

func CheckLabelCapacity(nameBytes, suffixBytes, capacity int) (LabelCapacity, error) {
	v := LabelCapacity{Capacity: capacity, NameBytes: nameBytes, SuffixBytes: suffixBytes, ProvenForAllRuntimeSources: false}
	if nameBytes < 1 || suffixBytes < 0 || capacity < 1 || nameBytes > 1024 || suffixBytes > 1024 {
		return v, fmt.Errorf("invalid byte count")
	}
	v.RequiredWithNUL = nameBytes + suffixBytes + 1
	v.Fits = v.RequiredWithNUL <= capacity
	return v, nil
}

// First N10 candidate is for a 16-byte A and a 32-byte B. For a 13-byte
// NUL-inclusive surname, B can append at most 19 raw bytes.
func CheckN10LongestLabelSuffix(suffixBytes int) (LabelCapacity, error) {
	return CheckLabelCapacity(13-1, suffixBytes, N10BufferBCapacity)
}
