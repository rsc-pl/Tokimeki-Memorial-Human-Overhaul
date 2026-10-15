package nametables

import (
	"bytes"
	"encoding/binary"
	"testing"
	"tokimemo/internal/graphics"
	"tokimemo/internal/script"
)

func n10SyntheticABFixture(t *testing.T) ([]byte, []byte) {
	t.Helper()
	exe := make([]byte, 667648)
	geko := make([]byte, 196608)
	// Install exact Go-generated English renderer code/font to a synthetic EXE.
	site, hook, font, scratch, e := graphics.RendererBuild()
	if e != nil {
		t.Fatal(e)
	}
	if scratch != 0x8004451c {
		t.Fatal("renderer scratch moved")
	}
	put := func(addr uint32, b []byte) { copy(exe[int(addr-Base):], b) }
	put(0x8004f2cc, site)
	put(0x8004443c, hook)
	put(0x8004b778, font)
	names := []string{"Fujisaki", "Kisaragi", "Himoo", "Katagiri", "Nijino", "Koshiki", "Kiyokawa", "Kagami", "Asahina", "Mikihara", "Saotome", "Tatebayashi", "Ijuin", "Yoshio", "Sotoi", "Yumi"}
	at := int(0x8004b778-Base) + len(font)
	for i, n := range names {
		binary.LittleEndian.PutUint32(exe[PointerTable+i*4:], Base+uint32(at))
		b, e := (&script.PairEncoder{}).Encode(n)
		if e != nil {
			t.Fatal(e)
		}
		copy(exe[at:], b)
		at += len(b) + 1
	}
	if at != int(0x8004b778-Base)+len(font)+132 {
		t.Fatalf("unexpected synthetic table end %#x", at)
	}
	// All 21+51 direct references are explicit synthetic signatures, including
	// five independently reviewed addresses (but no game executable bytes).
	refsEXE := KnownN10Copies(EXE)
	for i := 0; i < 10; i++ {
		refsEXE = append(refsEXE, AddressPair{UpperOffset: 0x20000 + i*0x40, LowerOffset: 0x20008 + i*0x40, UpperWord: 0x3c04800d, LowerWord: 0x2484a188, OldAddress: BufferA})
	}
	for i := 0; i < 8; i++ {
		refsEXE = append(refsEXE, AddressPair{UpperOffset: 0x22000 + i*0x40, LowerOffset: 0x22008 + i*0x40, UpperWord: 0x3c04800d, LowerWord: 0x2484a190, OldAddress: BufferB})
	}
	refsEXE = append(refsEXE, AddressPair{UpperOffset: 0x23000, LowerOffset: 0x23008, UpperWord: 0x3c04800d, LowerWord: 0x2484a19c, OldAddress: BufferC})
	refsGEKO := KnownN10Copies(Geko)
	for i := 0; i < 4; i++ {
		refsGEKO = append(refsGEKO, AddressPair{UpperOffset: 0x2000 + i*0x40, LowerOffset: 0x2008 + i*0x40, UpperWord: 0x3c04800d, LowerWord: 0x2484a188, OldAddress: BufferA})
	}
	for i := 0; i < 44; i++ {
		refsGEKO = append(refsGEKO, AddressPair{UpperOffset: 0x3000 + i*0x40, LowerOffset: 0x3008 + i*0x40, UpperWord: 0x3c04800d, LowerWord: 0x2484a19c, OldAddress: BufferC})
	}
	for _, group := range []struct {
		buf   []byte
		pairs []AddressPair
	}{{exe, refsEXE}, {geko, refsGEKO}} {
		for _, p := range group.pairs {
			binary.LittleEndian.PutUint32(group.buf[p.UpperOffset:], p.UpperWord)
			binary.LittleEndian.PutUint32(group.buf[p.LowerOffset:], p.LowerWord)
			binary.LittleEndian.PutUint32(group.buf[p.LowerOffset-4:], 0x0c02b83c)
		}
	}
	// Reproduce the two EXE conditional branch-delay-slot source patterns.
	binary.LittleEndian.PutUint32(exe[0x20004:], 0x17000564)
	binary.LittleEndian.PutUint32(exe[0x20044:], 0x1720041d)
	return exe, geko
}

func TestN10ABResearchCandidateSyntheticExactFootprint(t *testing.T) {
	exe, geko := n10SyntheticABFixture(t)
	originalEXE, originalGEKO := bytes.Clone(exe), bytes.Clone(geko)
	exAudit, exErr := AuditXrefs(EXE, exe)
	if exErr != nil {
		t.Fatal(exErr)
	}
	t.Log("synthetic EXE ref counts", len(exAudit.References), exAudit.CountsByAddress)
	gAudit, gErr := AuditXrefs(Geko, geko)
	if gErr != nil {
		t.Fatal(gErr)
	}
	t.Log("synthetic GEKO ref counts", len(gAudit.References), gAudit.CountsByAddress)
	changedEXE, changedGEKO, r, e := stageABAfterIdentityProof(exe, geko)
	if e != nil {
		t.Fatal(e)
	}
	if !r.UnsafeToBoot || r.RuntimeVerified || r.CompleteCallerCoverage || r.EXESites != 20 || r.GEKOSites != 6 || r.ACapacity != 16 || r.BCapacity != 32 || r.CandidateA != 0x8004bafc || r.CandidateB != 0x8004bb0c || r.OriginalC != BufferC {
		t.Fatalf("unsafe summary %+v", r)
	}
	if !bytes.Equal(exe, originalEXE) || !bytes.Equal(geko, originalGEKO) {
		t.Fatal("source modified")
	}
	// Only the two 32-bit address words in each of 26 selected sites may differ.
	for _, tc := range []struct {
		name     string
		src, dst []byte
		want     int
	}{{EXE, exe, changedEXE, 20}, {Geko, geko, changedGEKO, 6}} {
		orig, e := AuditXrefs(tc.name, tc.src)
		if e != nil {
			t.Fatal(e)
		}
		permitted := map[int]bool{}
		for _, rr := range orig.References {
			if rr.Address == BufferC {
				continue
			}
			for j := 0; j < 4; j++ {
				permitted[rr.UpperOffset+j] = true
				permitted[rr.UseOffset+j] = true
			}
		}
		diff := 0
		for i := range tc.src {
			if tc.src[i] != tc.dst[i] {
				diff++
				if !permitted[i] {
					t.Fatalf("unrelated byte %s %#x", tc.name, i)
				}
			}
		}
		if diff < tc.want {
			t.Fatalf("too few differences in %s: %d", tc.name, diff)
		}
		// A/B direct references disappear while all original C refs remain.
		after, e := FindRAMReferences(tc.dst, 0x800ca180, 0x800ca1c0)
		if e != nil {
			t.Fatal(e)
		}
		for _, rr := range after {
			if rr.Address != BufferC {
				t.Fatalf("old A/B remains in %s %#x", tc.name, rr.UseOffset)
			}
		}
	}
	// Wrong GEKO identity must fail, even if synthetic patching otherwise works.
	if _, _, _, e := StageABResearchCandidates(exe, geko); e == nil {
		t.Fatal("accepted unverified GEKO")
	}
}

func TestN10ABCandidateFailClosed(t *testing.T) {
	exe, geko := n10SyntheticABFixture(t)
	beforeE, beforeG := bytes.Clone(exe), bytes.Clone(geko)
	for _, tc := range []struct {
		name   string
		mutate func()
	}{
		{"pool occupied", func() { exe[0xb278+150] = 0x25 }},
		{"pointer changed", func() { exe[PointerTable+7*4]++ }},
		{"missing caller", func() { geko[0x3000] = 0 }},
	} {
		copy(exe, beforeE)
		copy(geko, beforeG)
		tc.mutate()
		outE, outG, _, e := stageABAfterIdentityProof(exe, geko)
		if e == nil || outE != nil || outG != nil {
			t.Fatalf("%s accepted", tc.name)
		}
	}
}
