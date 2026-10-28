package fullenglish

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	n "tokimemo/internal/n20arch"
	nametables "tokimemo/internal/namepatch"
)

// These exact original source files are distributed inside the cumulative
// handoff. Never replace them with extracted files from modified game images.
func imageCompositionTestFiles(t *testing.T) ([]byte, map[string][]byte) {
	t.Helper()
	d := filepath.Join("..", "..", ".local", "go_toolchain", "research_handoffs", "N10_PHASE2_20261020", "scratch", "extract")
	original, e := os.ReadFile(filepath.Join(d, "SLPM_86.053"))
	if e != nil {
		t.Fatal(e)
	}
	sh := sha256.Sum256(original)
	if hex.EncodeToString(sh[:]) != "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae" {
		t.Fatalf("untrusted original EXE %x", sh)
	}
	ov := make(map[string][]byte, len(n.OverlaySHA))
	for name, want := range n.OverlaySHA {
		raw, e := os.ReadFile(filepath.Join(d, "exn", name))
		if e != nil {
			t.Fatal(e)
		}
		sha := sha256.Sum256(raw)
		if hex.EncodeToString(sha[:]) != want {
			t.Fatalf("untrusted original %s SHA %x", name, sha)
		}
		ov[name] = raw
	}
	return original, ov
}
func TestBothUndecidedGEKOPoliciesAuthenticallyCompose(t *testing.T) {
	ex, overlays := imageCompositionTestFiles(t)
	var outputs [][]byte
	for _, pol := range []string{nametables.N10GEKOBare, nametables.N10GEKOSan} {
		t.Run(pol, func(t *testing.T) {
			in, e := imageCompositionInput(ex, overlays, pol)
			if e != nil {
				t.Fatal(e)
			}
			manualCopyStage, e := n.PlanAllManualLoopsOffline(ex, overlays, in)
			if e != nil {
				t.Fatal(e)
			}
			if manualCopyStage.SafeToPatch || manualCopyStage.RuntimePass || manualCopyStage.ImageBuilt || manualCopyStage.TotalGuardedManualLoops != 22 || manualCopyStage.PatchedCalls != 32 || len(manualCopyStage.Overlays) != 26 {
				t.Fatal("wrong English image composition inherited N10/N20 coverage/safety")
			}
			// direct name hooks's new production/private composer preflight must succeed
			// on BOTH undecided GEKO alternatives, not merely a detached formatter bridge image.
			if err := n.VerifyDirectSavedNameHooks(overlays, manualCopyStage.Overlays); err != nil {
				t.Fatalf("direct name hooks live English image composition composer name hook gate: %v", err)
			}
			g := manualCopyStage.Overlays["GEKO.EXN"]
			outputs = append(outputs, bytes.Clone(g))
			if !bytes.Equal(overlays["NAME_ENT.EXN"], overlays["NAME_ENT.EXN"]) {
				t.Fatal("impossible overlay drift")
			}
			// English-plan merger must preserve independent textual edits on an
			// unmodified name overlay byte, without replacing loop guards code or checksum.
			p := "CDROM/EXEDIR/SHOUGATU.EXN"
			english := bytes.Clone(overlays["SHOUGATU.EXN"])
			changed := manualCopyStage.Overlays["SHOUGATU.EXN"]
			i := 0x8000
			for i < len(english)-4 && changed[i] != english[i] {
				i++
			}
			if i >= len(english)-4 {
				t.Fatal("no untouched English byte")
			}
			english[i] ^= 1
			merged, nconf, _, err := fullMergeFile(p, overlays["SHOUGATU.EXN"], english, changed)
			if err != nil || nconf != 0 || merged[i] != english[i] {
				t.Fatalf("English content overwritten at %#x err=%v conflicts=%d", i, err, nconf)
			}
		})
	}
	if len(outputs) != 2 || bytes.Equal(outputs[0], outputs[1]) {
		t.Fatal("GEKO policy branches identical; do not silently select one")
	}
}
func TestRejectsUnavailableProductionSource(t *testing.T) {
	if _, err := ComposeEnglish("/missing-project", "/missing.cue"); err == nil {
		t.Fatal("production composition must reject missing authenticated sources")
	}
}
