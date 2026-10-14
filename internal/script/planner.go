package script

// Dialogue block relocation. This is an in-memory counterpart to
// legacy_scripts/tokipatch/patcher.py:apply_dialogue, deliberately separate
// from disc writing, executable hooks, and production build orchestration.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

type DialogueLine struct {
	Offset   int    `json:"offset"`
	Original string `json:"original"`
	Text     string `json:"text"`
}
type DialogueBlock struct {
	File           string         `json:"file"`
	Source         string         `json:"source"`
	Base           uint32         `json:"base"`
	MaxCells       int            `json:"max_cells"`
	ShareIdentical bool           `json:"share_identical"`
	Lines          []DialogueLine `json:"lines"`
}
type Placement struct {
	Offset   int   `json:"offset"`
	At       int   `json:"at"`
	Pinned   bool  `json:"pinned"`
	Pointers []int `json:"pointers"`
}
type PlanStats struct {
	Lines          int         `json:"lines"`
	Copies         int         `json:"copies"`
	BytesNeeded    int         `json:"bytes_needed"`
	BytesAvailable int         `json:"bytes_available"`
	UsedBestFit    bool        `json:"used_best_fit"`
	Placements     []Placement `json:"placements"`
}
type span struct{ lo, hi int }
type plannedLine struct {
	line     DialogueLine
	newText  []byte
	pointers []int
	movable  bool
	where    string
}

// ApplyDialogue validates and repacks one dialogue block using the pristine
// source for pointer/code-reference discovery and the writable data for
// original-byte verification. It returns stats and applies modifications only
// if the block has passed every check. A caller must keep each file's pristine
// bytes separately, even when applying multiple blocks in sequence.
func ApplyDialogue(original, data []byte, block DialogueBlock, pairs *PairEncoder) (PlanStats, error) {
	var result PlanStats
	if len(original) != len(data) {
		return result, fmt.Errorf("pristine and working file lengths differ")
	}
	if pairs == nil {
		pairs = &PairEncoder{}
	}
	maxCells := block.MaxCells
	if maxCells == 0 {
		maxCells = MaxCells
	}
	// Use a transactional scratch copy: errors must not leave half-written text.
	copyData := append([]byte(nil), data...)
	idx := NewWordIndex(original)
	var jobs []plannedLine
	slots := map[int]int{}
	input := append([]DialogueLine(nil), block.Lines...)
	sort.SliceStable(input, func(i, j int) bool { return input[i].Offset < input[j].Offset })
	for _, line := range input {
		if line.Text == "" {
			continue
		}
		where := fmt.Sprintf("%s: %s @ %#x", block.Source, block.File, line.Offset)
		raw, err := EncodeOriginal(line.Original)
		if err != nil {
			return result, fmt.Errorf("%s: original: %w", where, err)
		}
		end := line.Offset + len(raw)
		if line.Offset < 0 || end < line.Offset || end >= len(copyData) {
			return result, fmt.Errorf("%s: original outside file", where)
		}
		if !bytes.Equal(copyData[line.Offset:end], raw) || copyData[end] != 0 {
			return result, fmt.Errorf("%s: original text bytes or terminator differ", where)
		}
		capacity := len(raw) + 1
		for (line.Offset+capacity)%4 != 0 && line.Offset+capacity < len(copyData) && copyData[line.Offset+capacity] == 0 {
			capacity++
		}
		encoded, widths, err := EncodeEnglish(line.Text, pairs)
		if err != nil {
			return result, fmt.Errorf("%s: English: %w", where, err)
		}
		if Structure(line.Text) != Structure(line.Original) {
			return result, fmt.Errorf("%s: line breaks, choices or name codes differ", where)
		}
		// Python: original.rstrip("\n").endswith("）") != text.rstrip("\n ").endswith(")")
		orgThought := strings.HasSuffix(strings.TrimRight(line.Original, "\n"), "）")
		enThought := strings.HasSuffix(strings.TrimRight(line.Text, "\n "), ")")
		if orgThought != enThought {
			return result, fmt.Errorf("%s: thought closing bracket differs", where)
		}
		for n, w := range widths {
			if w > maxCells {
				return result, fmt.Errorf("%s: display line %d exceeds %d cells (%d)", where, n+1, maxCells, w)
			}
		}
		if line.Offset > int(^uint32(0))-int(block.Base) {
			return result, fmt.Errorf("%s: address overflow", where)
		}
		pointers := FindPointers(original, block.Base, uint32(line.Offset))
		movable := len(pointers) > 0 && len(idx.CodeReferences(block.Base, uint32(line.Offset), 8)) == 0
		if _, exists := slots[line.Offset]; exists {
			return result, fmt.Errorf("%s: duplicate original offset", where)
		}
		jobs = append(jobs, plannedLine{line, encoded, pointers, movable, where})
		slots[line.Offset] = line.Offset + capacity
	}
	var starts []int
	for pos := range slots {
		starts = append(starts, pos)
	}
	sort.Ints(starts)
	var spans []span
	for _, start := range starts {
		stop := slots[start]
		if len(spans) > 0 && spans[len(spans)-1].hi == start {
			spans[len(spans)-1].hi = stop
		} else {
			spans = append(spans, span{start, stop})
		}
	}
	for _, s := range spans {
		for _, ptr := range idx.PointersInto(block.Base, uint32(s.lo), uint32(s.hi)) {
			if _, good := slots[int(ptr.TargetOffset)]; !good {
				return result, fmt.Errorf("%s: %s word at %#x points inside text at %#x, not string start", block.Source, block.File, ptr.WordOffset, ptr.TargetOffset)
			}
		}
		clear(copyData[s.lo:s.hi])
	}
	take := func(free *[]span, start, size int) bool {
		for i, s := range *free {
			if s.lo <= start && size <= s.hi-start {
				next := append([]span(nil), (*free)[:i]...)
				next = append(next, (*free)[i+1:]...)
				if s.lo < start {
					next = append(next, span{s.lo, start})
				}
				if start+size < s.hi {
					next = append(next, span{start + size, s.hi})
				}
				sort.Slice(next, func(i, j int) bool { return next[i].lo < next[j].lo })
				*free = next
				return true
			}
		}
		return false
	}
	free := append([]span(nil), spans...)
	pinned := make(map[int]int)
	for _, job := range jobs {
		if job.movable {
			continue
		}
		cap := slots[job.line.Offset] - job.line.Offset
		if len(job.newText)+1 > cap {
			reason := "has no pointer to it"
			if len(job.pointers) > 0 {
				reason = "is referenced from code"
			}
			return result, fmt.Errorf("%s: string %s and needs %d bytes but has %d", job.where, reason, len(job.newText)+1, cap)
		}
		if !take(&free, job.line.Offset, len(job.newText)+1) {
			return result, fmt.Errorf("%s: pinned bytes are not free", job.where)
		}
		pinned[job.line.Offset] = job.line.Offset
	}
	for _, s := range spans {
		result.BytesAvailable += s.hi - s.lo
	}
	if block.ShareIdentical {
		unique := map[string]bool{}
		for _, job := range jobs {
			if !job.movable {
				result.BytesNeeded += len(job.newText) + 1
				continue
			}
			key := string(job.newText)
			if !unique[key] {
				unique[key] = true
				result.BytesNeeded += len(job.newText) + 1
			}
		}
	} else {
		for _, job := range jobs {
			result.BytesNeeded += len(job.newText) + 1
		}
	}
	pack := func(order []plannedLine, bestFit bool) map[int]int {
		available := append([]span(nil), free...)
		placed := make(map[int]int, len(jobs))
		for k, v := range pinned {
			placed[k] = v
		}
		shared := map[string]int{}
		for _, job := range order {
			if !job.movable {
				continue
			}
			key := string(job.newText)
			if block.ShareIdentical {
				if at, ok := shared[key]; ok {
					placed[job.line.Offset] = at
					continue
				}
			}
			required := len(job.newText) + 1
			bestIdx := -1
			for i, s := range available {
				if s.hi-s.lo < required {
					continue
				}
				if bestIdx < 0 || (bestFit && (s.hi-s.lo < available[bestIdx].hi-available[bestIdx].lo || (s.hi-s.lo == available[bestIdx].hi-available[bestIdx].lo && s.lo < available[bestIdx].lo))) {
					bestIdx = i
				}
			}
			if bestIdx < 0 {
				return nil
			}
			at := available[bestIdx].lo
			placed[job.line.Offset] = at
			shared[key] = at
			if !take(&available, at, required) {
				return nil
			}
		}
		return placed
	}
	placed := pack(jobs, false)
	if placed == nil {
		ordered := append([]plannedLine(nil), jobs...)
		sort.SliceStable(ordered, func(i, j int) bool {
			if len(ordered[i].newText) == len(ordered[j].newText) {
				return ordered[i].line.Offset < ordered[j].line.Offset
			}
			return len(ordered[i].newText) > len(ordered[j].newText)
		})
		placed = pack(ordered, true)
		result.UsedBestFit = true
	}
	if placed == nil {
		return result, fmt.Errorf("%s: %s: the English doesn't fit in original slots (%d needed, %d available)", block.Source, block.File, result.BytesNeeded, result.BytesAvailable)
	}
	for _, job := range jobs {
		at := placed[job.line.Offset]
		copy(copyData[at:], job.newText)
		for _, p := range job.pointers {
			binary.LittleEndian.PutUint32(copyData[p:], block.Base+uint32(at))
		}
		result.Placements = append(result.Placements, Placement{job.line.Offset, at, !job.movable, append([]int(nil), job.pointers...)})
	}
	result.Lines = len(jobs)
	seen := map[int]bool{}
	for _, at := range placed {
		seen[at] = true
	}
	result.Copies = len(seen)
	copy(data, copyData)
	return result, nil
}
