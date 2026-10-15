package nametables

import "sort"

// GEKOZeroRun is merely a byte pattern in the original overlay. It is NOT
// evidence of reserved data memory or unused instructions.
type GEKOZeroRun struct {
	FileOffset           int    `json:"file_offset"`
	RAMAddress           uint32 `json:"ram_address"`
	Length               int    `json:"length"`
	OwnershipVerified    bool   `json:"ownership_verified"`
	ExtentKind           string `json:"extent_kind"`
	ExcludedForStaging   bool   `json:"excluded_for_staging"`
	DirectControlTargets int    `json:"direct_control_targets"`
}

// CandidateGEKOZeroRuns reports at most limit aligned 0x00-filled extents of
// minBytes bytes. It never infers code/data ownership or approves patching.
// Deliberately excludes the two known original literal slots and callsites.
func CandidateGEKOZeroRuns(original []byte, minBytes, limit int) []GEKOZeroRun {
	if minBytes < 17 || minBytes > 4096 || limit < 1 || limit > 200 {
		return nil
	}
	var list []GEKOZeroRun
	for i := 0; i < len(original); {
		if original[i] != 0 {
			i++
			continue
		}
		j := i + 1
		for j < len(original) && original[j] == 0 {
			j++
		}
		at := (i + 3) &^ 3
		if at < j && j-at >= minBytes && !overlapRange(at, j, gekoAdjacentNamesStart, gekoAdjacentNamesEnd) && !overlapRange(at, j, 0xf468, 0xf48c) {
			kind := "INTERIOR_ZERO_RUN_UNVERIFIED"
			excluded := j == len(original) || (len(original)-j <= 16 && j-i >= 4096)
			controls := len(FindGEKODirectControlTargets(original, gekoOverlayRAMBase+uint32(at), gekoOverlayRAMBase+uint32(j)))
			if excluded {
				kind = "TRAILING_OR_NEAR_TRAILER_ZERO_FILL_NOT_AN_ALLOCATION"
			}
			if controls > 0 && !excluded {
				kind = "DIRECT_MIPS_CONTROL_TARGET_REJECT"
			}
			list = append(list, GEKOZeroRun{FileOffset: at, RAMAddress: gekoOverlayRAMBase + uint32(at), Length: j - at, OwnershipVerified: false, ExtentKind: kind, ExcludedForStaging: excluded || controls > 0, DirectControlTargets: controls})
		}
		i = j
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].ExcludedForStaging != list[j].ExcludedForStaging {
			return !list[i].ExcludedForStaging
		}
		if list[i].Length != list[j].Length {
			return list[i].Length > list[j].Length
		}
		return list[i].FileOffset < list[j].FileOffset
	})
	if len(list) > limit {
		list = list[:limit]
	}
	return list
}
func overlapRange(a, b, c, d int) bool { return a < d && b > c }

// zeroContainingExtent must only be called for an in-bounds all-zero
// interval. It finds the entire connected zero-byte region, not just the
// caller-selected 17/24 bytes inside it.
func zeroContainingExtent(data []byte, start, size int) (int, int) {
	lo, hi := start, start+size
	for lo > 0 && data[lo-1] == 0 {
		lo--
	}
	for hi < len(data) && data[hi] == 0 {
		hi++
	}
	return lo, hi
}
func allZeroRange(data []byte, start, end int) bool {
	if start < 0 || end < start || end > len(data) {
		return false
	}
	for _, b := range data[start:end] {
		if b != 0 {
			return false
		}
	}
	return true
}
