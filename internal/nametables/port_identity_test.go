package nametables

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sort"
	"testing"
	"tokimemo/internal/graphics"
	"tokimemo/internal/script"
)

func TestNameCompositionByteIdentity(t *testing.T) {
	zipPath := os.Getenv("TOKIMEMO_AUTHENTIC_NAMETABLES_ZIP")
	if zipPath == "" {
		t.Skip("optional authenticated reference fixture not set")
	}
	zr, err := zip.OpenReader(zipPath)
	if err != nil {
		t.Fatal(err)
	}
	defer zr.Close()
	paths := map[string]string{EXE: "original/SLPM_86.053", "GEKO.EXN": "original/overlays/CDROM/EXEDIR/GEKO.EXN", "SHUGAKU.EXN": "original/overlays/CDROM/EXEDIR/SHUGAKU.EXN", "SHOUGATU.EXN": "original/overlays/CDROM/EXEDIR/SHOUGATU.EXN"}
	original := map[string][]byte{}
	for _, f := range zr.File {
		for target, p := range paths {
			if f.Name == p {
				r, e := f.Open()
				if e != nil {
					t.Fatal(e)
				}
				b, e := io.ReadAll(r)
				r.Close()
				if e != nil {
					t.Fatal(e)
				}
				original[target] = b
			}
		}
	}
	if len(original) != 4 {
		t.Fatal("missing originals")
	}
	staged, err := graphics.InstallRenderer(original[EXE])
	if err != nil {
		t.Fatal(err)
	}
	current := []string{"Shiori", "Mio", "Himoo", "Ayako", "Nijino", "Yukari", "Nozomi", "Mira", "Yuko", "Megumi", "Yumi", "Miharu", "Ijuin", "Yoshio", "Sotoi", "Yumi"}
	targetShort := []string{"Fujisaki", "Kisaragi", "Himoo", "Katagiri", "Nijino", "Koshiki", "Kiyokawa", "Kagami", "Asahina", "Mikihara", "Saotome", "Tatebayashi", "Ijuin", "Yoshio", "Sotoi", "Yumi"}
	targetFull := []string{"Fujisaki Shiori", "Kisaragi Mio", "Himoo Yuina", "Katagiri Ayako", "Nijino Saki", "Koshiki Yukari", "Kiyokawa Nozomi", "Kagami Mira", "Asahina Yuko", "Mikihara Megumi", "Saotome Yumi", "Tatebayashi Miharu", "Ijuin Rei", "Saotome Yoshio", "Sotoi Yukinojou", "Player"}
	cursor := ShortStart
	clear(staged[ShortStart:ShortEnd])
	for i, s := range current {
		raw, e := (&script.PairEncoder{}).Encode(s)
		if e != nil {
			t.Fatal(e)
		}
		if cursor+len(raw)+1 > ShortEnd {
			t.Fatal("source pool overflow")
		}
		copy(staged[cursor:], raw)
		staged[cursor+len(raw)] = 0
		binary.LittleEndian.PutUint32(staged[PointerTable+i*4:], Base+uint32(cursor))
		cursor += len(raw) + 1
	}
	knownOutputs := map[string]map[string]string{
		NameGEKOBare: {
			"GEKO.EXN":     "720139ff906bfea17de0e43ba24df218040bd35d1a840950e36796f91204a11a",
			"SHOUGATU.EXN": "52f880a86bd448f49b4c861c49c732469ff9746fda7b13dadc95a5f2492a0278",
			"SHUGAKU.EXN":  "46c3987cafecf64ee5ff7e683cbfe4d5a86d541952f93b81d24e75e78e1f23d3",
			"SLPM_86.053":  "5ff56b13567852851d1bc2e636d912fea5078435fc27f4f2dce5e31ece85fdcb",
		},
		NameGEKOSan: {
			"GEKO.EXN":     "151d328fcb8dce01febcdf68ea08405e1d2fa244bf51f37efb444d5716e477cc",
			"SHOUGATU.EXN": "52f880a86bd448f49b4c861c49c732469ff9746fda7b13dadc95a5f2492a0278",
			"SHUGAKU.EXN":  "46c3987cafecf64ee5ff7e683cbfe4d5a86d541952f93b81d24e75e78e1f23d3",
			"SLPM_86.053":  "2d3c4bdec91e4e199a87c2255350a025883f427b5d877ac2306388c2880b91a7",
		},
	}
	for _, pol := range []string{NameGEKOBare, NameGEKOSan} {
		input := NameOfflineTransaction{Originals: original, StagedEXE: staged, StagedEXESHA: sha256.Sum256(staged), CurrentShort: current, TargetShort: targetShort, TargetFull: targetFull, GEKOG2Policy: pol}
		b, r, e := ComposeNamePhase2Offline(input)
		if e != nil {
			t.Fatal(e)
		}
		keys := make([]string, 0, len(b))
		for k := range b {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			want, exists := knownOutputs[pol][k]
			if !exists || fmt.Sprintf("%x", sha256.Sum256(b[k])) != want {
				t.Fatalf("policy %s image %s drifted from verified result", pol, k)
			}
		}
		if r.ShortBytes != 132 || r.FullFirstBytes != 184 || r.FullSecondBytes != 44 || r.RewrittenA != 16 || r.RewrittenB != 12 || r.AliasSources != 5 || r.ParserCalls != 32 || r.SafeToPatch || r.RuntimeVerified {
			t.Fatalf("composition invariant failed: %+v", r)
		}
		if bytes.Equal(b[EXE], staged) {
			t.Fatal("no changes")
		}
		if !bytes.Equal(input.StagedEXE, staged) {
			t.Fatal("input changed")
		}
		missing := input
		missing.GEKOG2Policy = ""
		if out, _, e := ComposeNamePhase2Offline(missing); e == nil || out != nil {
			t.Fatal("missing alias policy accepted")
		}
		tampered := input
		tampered.StagedEXE = bytes.Clone(staged)
		tampered.StagedEXE[0x70000] ^= 1
		if out, _, e := ComposeNamePhase2Offline(tampered); e == nil || out != nil {
			t.Fatal("revision mismatch accepted")
		}

	}
}
