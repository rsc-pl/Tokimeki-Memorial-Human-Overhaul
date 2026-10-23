package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestPublicPythonBuilderCollectsAllErrors(t *testing.T) {
	for _, tt := range []struct {
		name      string
		preflight bool
		expected  []string
	}{
		{"build", false, []string{"-m", "tokipatch", "/tmp/original.cue", "--all-errors"}},
		{"preflight", true, []string{"-m", "tokipatch.preflight", "/tmp/original.cue", "--all-errors"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got := productionPlannerArgs("/tmp/original.cue", tt.preflight)
			if !reflect.DeepEqual(got, tt.expected) {
				t.Fatalf("Python args = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestPublicValidationCollectsMalformedEntriesAcrossFiles(t *testing.T) {
	root := t.TempDir()
	folder := filepath.Join(root, "translation")
	if err := os.MkdirAll(folder, 0755); err != nil {
		t.Fatal(err)
	}
	inputs := map[string]string{
		"one.json": `{"strings":[{"file":"SLPM_86.053","offset":"0x10","text":"ok"},{"file":"SLPM_86.053","offset":"bad","original":"a","text":"b"}]}`,
		"two.json": `{"strings":[{"file":"","offset":"0x20","original":"a","text":"b"}]}`,
	}
	for name, value := range inputs {
		if err := os.WriteFile(filepath.Join(folder, name), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	_, err := validate(root)
	if err == nil {
		t.Fatal("bad corpus unexpectedly passed")
	}
	for _, want := range []string{"one.json:strings[0]", "one.json:strings[1]", "two.json:strings[0]"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing diagnostic for %q: %v", want, err)
		}
	}
}
