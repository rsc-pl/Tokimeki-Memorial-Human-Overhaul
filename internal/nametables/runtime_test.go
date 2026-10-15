package nametables

import "testing"

func TestObservedRuntimeCopyFootprints(t *testing.T) {
	for _, c := range []struct {
		dest  uint32
		name  string
		cross bool
	}{
		{BufferA, "Shiori", false}, // actual R07 source names
		{BufferA, "Yuko", false},
		{BufferB, "Shiori", false},
		{BufferA, "Fujisaki", true},
		{BufferA, "Tatebayashi", true},
		{BufferB, "Tatebayashi", true},
		{BufferB, "Koshiki", false}, // 9 bytes, fits before next observed START (12)
	} {
		span, e := AnalyzeNameCopy(c.dest, c.name, "")
		if e != nil {
			t.Fatal(e)
		}
		if span.IntersectsLaterStart != c.cross {
			t.Fatalf("%#x %s: %+v", c.dest, c.name, span)
		}
	}
	appendCase, e := AnalyzeNameCopy(BufferB, "Mikihara", "-san")
	if e != nil || !appendCase.IntersectsLaterStart {
		t.Fatalf("unbounded strcat risk not flagged: %+v %v", appendCase, e)
	}
}
