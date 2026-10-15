package nametables

import (
	"testing"
	"tokimemo/internal/graphics"
)

func TestRAMSnapshotRendererGuardsAndZeroTail(t *testing.T) {
	site, _, font, _, err := graphics.RendererBuild()
	if err != nil {
		t.Fatal(err)
	}
	mem := make([]byte, NarrowRAMBytes)
	copy(mem, font)
	s, err := AssessRAMSnapshot(site, mem)
	if err != nil {
		t.Fatal(err)
	}
	if !s.RendererSiteMatches || !s.RendererFontMatches || !s.PoolIsZero || !s.BufferAIsZero || !s.BufferBIsZero || s.NamePoolOccupied || s.RuntimeSafe {
		t.Fatalf("bad safe-negative snapshot %+v", s)
	}
	mem[768+N10CompactExpectedBytes] = 0x7b
	s, err = AssessRAMSnapshot(site, mem)
	if err != nil {
		t.Fatal(err)
	}
	if s.BufferAIsZero || !s.BufferBIsZero || s.RuntimeSafe {
		t.Fatalf("missed A contamination %+v", s)
	}
	mem[768+N10CompactExpectedBytes+N10BufferACapacity] = 0x02
	s, _ = AssessRAMSnapshot(site, mem)
	if s.BufferBIsZero || s.RuntimeSafe {
		t.Fatalf("missed B contamination %+v", s)
	}
	mem[0] ^= 1
	s, _ = AssessRAMSnapshot(site, mem)
	if s.RendererFontMatches || s.RuntimeSafe {
		t.Fatal("font contamination missed")
	}
	site[0] ^= 1
	s, _ = AssessRAMSnapshot(site, mem)
	if s.RendererSiteMatches || s.RuntimeSafe {
		t.Fatal("hook mismatch missed")
	}
}
func TestRAMSnapshotRejectsPartialReads(t *testing.T) {
	for _, c := range []struct{ site, narrow int }{{7, 948}, {8, 947}, {8, 949}, {9, 948}} {
		if _, err := AssessRAMSnapshot(make([]byte, c.site), make([]byte, c.narrow)); err == nil {
			t.Fatalf("accepted truncated snapshot %+v", c)
		}
	}
}
