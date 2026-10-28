package fullenglish

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tokimemo/internal/patchplan"
)

func TestExplicitNameEntryLabelsOnly(t *testing.T) {
	root := t.TempDir()
	private := filepath.Join(root, ".local", "go_toolchain", "upstream_candidates", "test", "translation")
	if err := os.MkdirAll(private, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(private, "name_entry_labels.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	batch := patchplan.Batch{}
	got, label, err := nameEntryLabelsAddNameLabels(root, batch)
	if err != nil || label != "NAME_ENTRY_LABELS_NOT_PROVIDED" || got.Files != batch.Files {
		t.Fatalf("private path affected production: %q %v", label, err)
	}
	if err := os.MkdirAll(filepath.Join(root, "translation"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "translation", "name_entry_labels.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	got, label, err = nameEntryLabelsAddNameLabels(root, batch)
	if err != nil || label != "NAME_ENTRY_LABELS_FROM_TRANSLATION" || got.Files != batch.Files {
		t.Fatalf("public translation not selected: %q %v", label, err)
	}
}

func TestProductionImageSourcesHaveNoPrivateBuildSelectors(t *testing.T) {
	for _, name := range []string{"full_english.go", "english_name_composition.go", "name_entry_source.go"} {
		data, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"N20_QA_", "upstream_candidates/", "PlanC10DistributedOffline(", "PlanTELFullnameOffline("} {
			if strings.Contains(string(data), forbidden) {
				t.Fatalf("%s embeds a private production input: %s", name, forbidden)
			}
		}
	}
}
