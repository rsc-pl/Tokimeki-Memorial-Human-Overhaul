package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestBuildProgressStageCounting(t *testing.T) {
	var b bytes.Buffer
	w := &stageWriter{destination: &b}
	for _, v := range []string{"Step 1/3: checking", "\nStep 2/3: copying", "\nStep 3/3: writing"} {
		for _, segment := range []string{v[:len(v)/2], v[len(v)/2:]} {
			if _, e := w.Write([]byte(segment)); e != nil {
				t.Fatal(e)
			}
		}
	}
	if w.stage != 3 || strings.Count(b.String(), "STEP 1/3") != 1 || strings.Count(b.String(), "STEP 2/3") != 1 || strings.Count(b.String(), "STEP 3/3") != 1 {
		t.Fatalf("incorrect progress: %s", b.String())
	}
}
