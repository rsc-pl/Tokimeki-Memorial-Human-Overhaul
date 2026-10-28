package fullenglish

// The original short-name dialogue pool provides 124 bytes, while translated
// names may require more space even when each original slot individually fits.
// Verified name records use the relocated pool, without relaxing size checks
// for unrelated dialogues or modifying the translation sources.
import (
	"bytes"
	"fmt"

	nametables "tokimemo/internal/namepatch"
	"tokimemo/internal/patchplan"
	"tokimemo/internal/script"
)

func npcDialogueNamesSeparateNPCNameDialogue(retail []byte, batch patchplan.Batch) (patchplan.Batch, []longNameDeferredName, error) {
	cleaned := batch
	cleaned.Dialogue = make([]script.DialogueBlock, 0, len(batch.Dialogue))
	var deferred []longNameDeferredName
	seen := map[string]bool{}
	for _, block := range batch.Dialogue {
		if block.Source != "character_names.json" || block.File != "SLPM_86.053" || block.Base != nametables.Base || len(block.Lines) == 0 {
			cleaned.Dialogue = append(cleaned.Dialogue, block)
			continue
		}
		group := ""
		candidates := make([]longNameDeferredName, 0, len(block.Lines))
		eligible := true
		indexes := map[int]bool{}
		for _, line := range block.Lines {
			p := script.InPlaceString{Source: block.Source, File: block.File, Offset: line.Offset, Original: line.Original, Text: line.Text}
			kind, idx, known := longNameClassifyName(retail, p)
			if !known || (kind != "short" && kind != "full") || line.Text == "" {
				eligible = false
				break
			}
			if group != "" && group != kind {
				eligible = false
				break
			}
			group = kind
			if indexes[idx] {
				return cleaned, nil, fmt.Errorf("dialogue name pool duplicate original NPC %s index %d", kind, idx)
			}
			indexes[idx] = true
			jp, err := script.EncodeOriginal(line.Original)
			if err != nil {
				return cleaned, nil, fmt.Errorf("dialogue name pool original name encoding: %w", err)
			}
			end := line.Offset + len(jp)
			if line.Offset < 0 || end >= len(retail) || !bytes.Equal(retail[line.Offset:end], jp) || retail[end] != 0 {
				return cleaned, nil, fmt.Errorf("dialogue name pool authenticated NPC name mismatch at %#x", line.Offset)
			}
			cap := len(jp) + 1
			for (line.Offset+cap)%4 != 0 && line.Offset+cap < len(retail) && retail[line.Offset+cap] == 0 {
				cap++
			}
			placeholder, err := longNamePlaceholder(line.Text, cap)
			if err != nil {
				return cleaned, nil, fmt.Errorf("dialogue name pool name index %d: %w", idx, err)
			}
			candidates = append(candidates, longNameDeferredName{entry: p, kind: kind, index: idx, placeholder: placeholder})
		}
		// No exemption for mixed/unknown dialogue or other NPC-related text.
		if !eligible {
			cleaned.Dialogue = append(cleaned.Dialogue, block)
			continue
		}
		for _, d := range candidates {
			key := fmt.Sprintf("%s:%d", d.kind, d.index)
			if seen[key] {
				return cleaned, nil, fmt.Errorf("dialogue name pool duplicate source name %s across blocks", key)
			}
			seen[key] = true
			deferred = append(deferred, d)
		}
		// Do not run the short, legacy 124-byte dialogue packer for this
		// authenticated N10 pool. Its exact JSON values go to N10 instead.
	}
	return cleaned, deferred, nil
}
