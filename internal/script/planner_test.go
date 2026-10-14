package script

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

type plannerVector struct {
	Name  string        `json:"name"`
	Data  string        `json:"data"`
	Block DialogueBlock `json:"block"`
}
type plannerExpected struct {
	OK         bool     `json:"ok"`
	SHA256     string   `json:"sha256"`
	Placements [][2]int `json:"placements"`
	Error      string   `json:"error"`
}

func TestPlannerPythonGolden(t *testing.T) {
	raw, e := os.ReadFile("testdata/planner_vectors.json")
	if e != nil {
		t.Fatal(e)
	}
	expected, e := os.ReadFile("testdata/planner_expected.json")
	if e != nil {
		t.Fatal(e)
	}
	var cases []plannerVector
	var answers []plannerExpected
	if e = json.Unmarshal(raw, &cases); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(expected, &answers); e != nil {
		t.Fatal(e)
	}
	if len(cases) != len(answers) || len(cases) < 15 {
		t.Fatal("missing planner fixtures")
	}
	for i, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			data, e := base64.StdEncoding.DecodeString(c.Data)
			if e != nil {
				t.Fatal(e)
			}
			original := append([]byte(nil), data...)
			stats, e := ApplyDialogue(original, data, c.Block, &PairEncoder{})
			want := answers[i]
			if (e == nil) != want.OK {
				t.Fatalf("result mismatch, got error=%v; Python=%+v", e, want)
			}
			if !want.OK {
				if e == nil {
					t.Fatal("missing error")
				}
				// Python's human-readable messages differ; check the semantic failure class.
				class := map[string]string{"unreferenced_oversize": "pinned", "code_pinned_oversize": "pinned", "pointer_into_text": "pointer", "struct_invalid": "structure", "thought_invalid": "bracket", "width_invalid": "width", "nonfit": "pool"}
				if wantMessage, ok := class[c.Name]; ok {
					match := map[string][]string{"pinned": {"has no pointer", "referenced from code"}, "pointer": {"points inside text"}, "structure": {"line breaks"}, "bracket": {"bracket"}, "width": {"exceeds"}, "pool": {"doesn't fit"}}[wantMessage]
					found := false
					for _, substring := range match {
						if strings.Contains(e.Error(), substring) {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("unexpected class: %v", e)
					}
				}
				if fmt.Sprintf("%x", sha256.Sum256(data)) != fmt.Sprintf("%x", sha256.Sum256(original)) {
					t.Error("failed planner mutated input")
				}
				return
			}
			actual := fmt.Sprintf("%x", sha256.Sum256(data))
			if actual != want.SHA256 {
				t.Errorf("different final bytes Go=%s Python=%s", actual, want.SHA256)
			}
			if len(stats.Placements) != len(want.Placements) {
				t.Fatalf("different placement count Go %d Python %d", len(stats.Placements), len(want.Placements))
			}
			for n, p := range stats.Placements {
				q := want.Placements[n]
				if p.Offset != q[0] || p.At != q[1] {
					t.Errorf("placement[%d] Go=%#v Python=%#v", n, p, q)
				}
			}
		})
	}
}
