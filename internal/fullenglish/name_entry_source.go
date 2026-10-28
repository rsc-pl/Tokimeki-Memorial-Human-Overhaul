package fullenglish

// Name-entry graphics are supplied only through the normal, explicit
// translation corpus. An optional private research directory must never
// influence a public build.
import (
	"fmt"
	"os"
	"path/filepath"

	"tokimemo/internal/patchplan"
)

func nameEntryLabelsAddNameLabels(root string, batch patchplan.Batch) (patchplan.Batch, string, error) {
	path := filepath.Join(root, "translation", "name_entry_labels.json")
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return batch, "NAME_ENTRY_LABELS_NOT_PROVIDED", nil
	}
	if err != nil {
		return batch, "NAME_ENTRY_LABELS_SOURCE_ERROR", err
	}
	if !info.Mode().IsRegular() {
		return batch, "NAME_ENTRY_LABELS_SOURCE_ERROR", fmt.Errorf("nonregular name-entry label source %s", path)
	}
	// patchplan.Load has already read the source-authored JSON into batch.
	return batch, "NAME_ENTRY_LABELS_FROM_TRANSLATION", nil
}
