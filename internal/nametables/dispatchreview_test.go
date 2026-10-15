package nametables

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func ownerG38Fixture(t *testing.T) N10LoaderFollowupReport {
	t.Helper()
	path := filepath.Join("..", "..", ".local", "go_toolchain", "reports", "G39_OWNER_G38_FOLLOWUP.json")
	b, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var r N10LoaderFollowupReport
	if e = json.Unmarshal(b, &r); e != nil {
		t.Fatal(e)
	}
	return r
}

func TestG39AuthenticOriginalContextDispatch(t *testing.T) {
	r := ownerG38Fixture(t)
	out, e := ReviewN10OverlayDispatch(r, "9ba733be9781712606e3a6d6bcfb23aa713c668160ee9c67073d6529d748c4da")
	if e != nil {
		t.Fatal(e)
	}
	if len(out.DispatchArms) != 45 || len(out.SeparateAnchorOffsets) != 3 || out.DispatchJoinFileOffset != 232604 || out.DispatchSlot != "0x80123110" || !out.FollowupPointerReadObserved {
		t.Fatalf("wrong results: %+v", out)
	}
	for i, a := range out.DispatchArms {
		if a.StoredAt != "0x80123110" || (i == 44) == a.UnconditionalBranch || a.JoinFileOffset != 232604 {
			t.Fatalf("bad arm %d %+v", i, a)
		}
	}
	if out.SafeToPatch || out.RuntimeLoaderVerified || out.WritableRAMVerified {
		t.Fatal("static bytes incorrectly authorized as patch safe")
	}
}

func TestG39TampersRejected(t *testing.T) {
	sha := "9ba733be9781712606e3a6d6bcfb23aa713c668160ee9c67073d6529d748c4da"
	cases := []struct {
		name   string
		modify func(*N10LoaderFollowupReport)
	}{
		{"missing site", func(r *N10LoaderFollowupReport) { r.MainOverlayAddressPairs = r.MainOverlayAddressPairs[:47] }},
		{"changed delay-store", func(r *N10LoaderFollowupReport) {
			for i, w := range r.MainOverlayAddressPairs[2].Words {
				if w.Offset == 231676 {
					r.MainOverlayAddressPairs[2].Words[i].Hex = "00000000"
				}
			}
		}},
		{"branch different join", func(r *N10LoaderFollowupReport) {
			for i, w := range r.MainOverlayAddressPairs[2].Words {
				if w.Offset == 231672 {
					r.MainOverlayAddressPairs[2].Words[i].Hex = "10000000"
				}
			}
		}},
		{"unsafe", func(r *N10LoaderFollowupReport) { r.SafeToPatch = true }},
		{"wrong odd", func(r *N10LoaderFollowupReport) { r.OddBINABCUniqueSites = 1 }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := ownerG38Fixture(t)
			tc.modify(&r)
			if _, e := ReviewN10OverlayDispatch(r, sha); e == nil {
				t.Fatal("altered or unsafe evidence accepted")
			}
		})
	}
}
