package nametables

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func createKnownFixture(t *testing.T, file string) ([]byte, []AddressPair) {
	t.Helper()
	sites := KnownN10Copies(file)
	var max int
	for _, s := range sites {
		if s.LowerOffset > max {
			max = s.LowerOffset
		}
	}
	buf := make([]byte, max+8)
	for _, s := range sites {
		binary.LittleEndian.PutUint32(buf[s.UpperOffset:], s.UpperWord)
		binary.LittleEndian.PutUint32(buf[s.LowerOffset:], s.LowerWord)
		// EXE and GEKO have an intervening JAL before the delay-slot ADDIU.
		if s.LowerOffset-s.UpperOffset >= 8 {
			binary.LittleEndian.PutUint32(buf[s.LowerOffset-4:], 0x0c02b83c)
		}
	}
	return buf, sites
}

func TestKnownN10MIPSPairsRoundTrip(t *testing.T) {
	for _, f := range []string{"SLPM_86.053", "CDROM/EXEDIR/GEKO.EXN"} {
		t.Run(f, func(t *testing.T) {
			buf, sites := createKnownFixture(t, f)
			orig := append([]byte(nil), buf...)
			plan, e := ApplyCandidateAddresses(sites, map[uint32]uint32{BufferA: 0x8004bb00, BufferB: 0x8004bb10, BufferC: 0x8004bb28})
			if e != nil {
				t.Fatal(e)
			}
			out, res, e := RewriteGuardedAddressPairs(buf, plan)
			if e != nil {
				t.Fatal(e)
			}
			if res.RuntimeValidated || res.Sites != len(sites) || res.Words != len(sites)*2 {
				t.Fatalf("bad report %+v", res)
			}
			if !bytes.Equal(buf, orig) {
				t.Fatal("source mutated")
			}
			for _, p := range plan {
				for i := 0; i < len(out); i++ {
					if i >= p.UpperOffset && i < p.UpperOffset+4 || i >= p.LowerOffset && i < p.LowerOffset+4 {
						continue
					}
				}
			}
			// Each of the exactly 2*len(sites) words may differ, never others.
			protected := map[int]bool{}
			for _, p := range plan {
				for i := 0; i < 4; i++ {
					protected[p.UpperOffset+i] = true
					protected[p.LowerOffset+i] = true
				}
			}
			for i := range out {
				if out[i] != orig[i] && !protected[i] {
					t.Fatalf("out-of-scope byte at %#x", i)
				}
			}
		})
	}
}

func TestN10MIPSRewriteFailClosed(t *testing.T) {
	f, sites := createKnownFixture(t, "SLPM_86.053")
	p := sites[0]
	p.NewAddress = 0x8004bb00
	for _, tc := range []struct {
		name   string
		mutate func([]byte, *AddressPair)
	}{
		{"wrong original", func(b []byte, p *AddressPair) { b[p.LowerOffset] ^= 1 }},
		{"claimed address", func(b []byte, p *AddressPair) { p.OldAddress = 0x800ca190 }},
		{"wrong LUI", func(b []byte, p *AddressPair) { p.UpperWord = 0x3c05800d }},
		{"intermediate clobber", func(b []byte, p *AddressPair) { binary.LittleEndian.PutUint32(b[p.UpperOffset+4:], 0x24840001) }},
		{"control flow", func(b []byte, p *AddressPair) { binary.LittleEndian.PutUint32(b[p.UpperOffset+4:], 0x08000010) }},
		{"overlap", func(b []byte, p *AddressPair) { p.LowerOffset = p.UpperOffset }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clone := append([]byte(nil), f...)
			site := p
			tc.mutate(clone, &site)
			before := append([]byte(nil), clone...)
			if out, _, e := RewriteGuardedAddressPairs(clone, []AddressPair{site}); e == nil {
				t.Fatalf("accepted unsafe pair %d", len(out))
			}
			if !bytes.Equal(clone, before) {
				t.Fatal("changed input on failure")
			}
		})
	}
}

func TestN10MIPSNegativeSignedLow(t *testing.T) {
	b := make([]byte, 12)
	binary.LittleEndian.PutUint32(b[0:], 0x3c04800d)
	binary.LittleEndian.PutUint32(b[4:], 0x2484a188)
	p := AddressPair{0, 4, 0x3c04800d, 0x2484a188, BufferA, 0x8004bb20}
	out, _, e := RewriteGuardedAddressPairs(b, []AddressPair{p})
	if e != nil {
		t.Fatal(e)
	}
	if binary.LittleEndian.Uint32(out[0:4]) != 0x3c048005 || binary.LittleEndian.Uint32(out[4:8]) != 0x2484bb20 {
		t.Fatal("signed-low MIPS relocation wrong")
	}
}

func TestReviewedCallerPreflight(t *testing.T) {
	for _, path := range []string{"SLPM_86.053", "CDROM/EXEDIR/GEKO.EXN"} {
		original, sites := createKnownFixture(t, path)
		n, e := VerifyKnownCopySites(path, original)
		if e != nil || n != len(sites) {
			t.Fatalf("%s: count=%d err=%v", path, n, e)
		}
		original[sites[0].LowerOffset] ^= 0x20
		if _, e := VerifyKnownCopySites(path, original); e == nil {
			t.Fatal("accepted unexpected code")
		}
	}
	if _, e := VerifyKnownCopySites("unknown", []byte{}); e == nil {
		t.Fatal("missing source accepted")
	}
}

// Real original-disc N10 EXE has two A references whose low-half ADDIU is in
// a conditional BNE delay slot. MIPS I executes the slot on both paths.
func TestN10ConditionalBranchDelaySlotAddressRewrite(t *testing.T) {
	for _, branch := range []uint32{0x17000564, 0x1720041d} {
		data := make([]byte, 16)
		binary.LittleEndian.PutUint32(data[0:], 0x3c04800d)
		binary.LittleEndian.PutUint32(data[4:], branch)
		binary.LittleEndian.PutUint32(data[8:], 0x2484a188)
		p := AddressPair{UpperOffset: 0, LowerOffset: 8, UpperWord: 0x3c04800d, LowerWord: 0x2484a188, OldAddress: BufferA, NewAddress: 0x8004bafc}
		out, summary, e := RewriteGuardedAddressPairs(data, []AddressPair{p})
		if e != nil {
			t.Fatal(e)
		}
		if summary.RuntimeValidated || !bytes.Equal(data[4:8], out[4:8]) || binary.LittleEndian.Uint32(out[0:]) != 0x3c048005 || binary.LittleEndian.Uint32(out[8:]) != 0x2484bafc {
			t.Fatalf("invalid delay-slot rewrite %#x", branch)
		}
	}
	// Crossing a branch into a *later* block remains prohibited.
	data := make([]byte, 20)
	binary.LittleEndian.PutUint32(data[0:], 0x3c04800d)
	binary.LittleEndian.PutUint32(data[4:], 0x17000564)
	binary.LittleEndian.PutUint32(data[12:], 0x2484a188)
	p := AddressPair{UpperOffset: 0, LowerOffset: 12, UpperWord: 0x3c04800d, LowerWord: 0x2484a188, OldAddress: BufferA, NewAddress: 0x8004bafc}
	if _, _, e := RewriteGuardedAddressPairs(data, []AddressPair{p}); e == nil {
		t.Fatal("accepted transfer across branch")
	}
}
