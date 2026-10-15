package main

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"testing"
	"tokimemo/internal/nametables"
	"tokimemo/internal/ps1"
)

func TestG46SourceSelection(t *testing.T) {
	iso := &ps1.ISO{Entries: map[string]ps1.ISOEntry{}}
	iso.Entries[nametables.EXE] = ps1.ISOEntry{Path: nametables.EXE, Size: 32}
	iso.Entries["CDROM/EXEDIR/O.BIN"] = ps1.ISOEntry{Path: "CDROM/EXEDIR/O.BIN", Size: 32}
	for i := 0; i < 26; i++ {
		p := "CDROM/EXEDIR/" + string(rune('A'+i)) + ".EXN"
		iso.Entries[p] = ps1.ISOEntry{Path: p, Size: 32}
	}
	iso.Entries["CDROM/DADIR/TR02.DA"] = ps1.ISOEntry{Path: "CDROM/DADIR/TR02.DA", Size: 100000}
	list, err := selectN10SourceFiles(iso)
	if err != nil || len(list) != 28 {
		t.Fatalf("selection: %v %d", err, len(list))
	}
	delete(iso.Entries, "CDROM/EXEDIR/O.BIN")
	if _, err = selectN10SourceFiles(iso); err == nil {
		t.Fatal("missing O.BIN should fail")
	}
}

func TestG46ZipRejectsNonOriginalEXE(t *testing.T) {
	selected := make([]ps1.ISOEntry, 28)
	selected[0] = ps1.ISOEntry{Path: nametables.EXE, Size: 4}
	for i := 1; i < 28; i++ {
		selected[i] = ps1.ISOEntry{Path: "CDROM/EXEDIR/Z" + string(rune('A'+i)) + ".EXN", Size: 4}
	}
	var b bytes.Buffer
	_, e := writeN10SourceZIP(&b, selected, nametables.N10OriginalEXESHA, func(_ ps1.ISOEntry, w io.Writer) error { _, e := w.Write([]byte{1, 2, 3, 4}); return e })
	if e == nil || !strings.Contains(e.Error(), "SHA-256 mismatch") {
		t.Fatalf("must reject wrong EXE SHA: %v", e)
	}
}

func TestG46ZipRejectsBadLengthsAndPaths(t *testing.T) {
	entries := make([]ps1.ISOEntry, 28)
	for i := range entries {
		entries[i] = ps1.ISOEntry{Path: "x", Size: 4}
	}
	entries[0].Path = "../escape"
	_, err := writeN10SourceZIP(io.Discard, entries, nametables.N10OriginalEXESHA, func(_ ps1.ISOEntry, w io.Writer) error { return nil })
	if err == nil {
		t.Fatal("unsafe ZIP name accepted")
	}
	entries[0].Path = "valid"
	_, err = writeN10SourceZIP(io.Discard, entries, nametables.N10OriginalEXESHA, func(_ ps1.ISOEntry, w io.Writer) error { _, e := w.Write([]byte("one")); return e })
	if err == nil {
		t.Fatal("incorrect entry size accepted")
	}
}

func TestG46ZipEntryAndManifestValidation(t *testing.T) {
	// This test cannot create retail EXE: ensure the fail-closed check happens
	// only after a well-formed ZIP source member is actually written.
	entries := make([]ps1.ISOEntry, 28)
	entries[0] = ps1.ISOEntry{Path: nametables.EXE, Size: 4}
	for i := 1; i < 28; i++ {
		entries[i] = ps1.ISOEntry{Path: "CDROM/EXEDIR/X" + string(rune('A'+i)) + ".EXN", Size: 4}
	}
	var buf bytes.Buffer
	_, err := writeN10SourceZIP(&buf, entries, nametables.N10OriginalEXESHA, func(_ ps1.ISOEntry, w io.Writer) error { _, e := w.Write([]byte("test")); return e })
	if err == nil {
		t.Fatal("false retail verification")
	}
	// Prefix is valid ZIP data even though the writer rightfully never committed.
	if _, err = zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len())); err == nil {
		t.Fatal("rejected source should not produce valid archive")
	}
}

func TestG46ZipSuccessfulSyntheticRoundtrip(t *testing.T) {
	source := map[string][]byte{}
	entries := make([]ps1.ISOEntry, 0, 28)
	for i := 0; i < 26; i++ {
		path := fmt.Sprintf("CDROM/EXEDIR/TEST%02d.EXN", i)
		data := []byte(fmt.Sprintf("overlay-%02d-contents", i))
		source[path] = data
		entries = append(entries, ps1.ISOEntry{Path: path, LBA: int64(i + 100), Size: int64(len(data))})
	}
	source[nametables.EXE] = []byte("SYNTHETIC_EXE_ONLY")
	source["CDROM/EXEDIR/O.BIN"] = []byte("SYNTHETIC_ODD_BIN")
	for _, path := range []string{nametables.EXE, "CDROM/EXEDIR/O.BIN"} {
		entries = append(entries, ps1.ISOEntry{Path: path, Size: int64(len(source[path]))})
	}
	sum := sha256.Sum256(source[nametables.EXE])
	sha := fmt.Sprintf("%x", sum)
	var b bytes.Buffer
	_, err := writeN10SourceZIP(&b, entries, sha, func(ent ps1.ISOEntry, w io.Writer) error {
		_, e := w.Write(source[ent.Path])
		return e
	})
	if err != nil {
		t.Fatal(err)
	}
	z, err := zip.NewReader(bytes.NewReader(b.Bytes()), int64(b.Len()))
	if err != nil {
		t.Fatal(err)
	}
	if len(z.File) != 29 {
		t.Fatalf("want 28 sources + manifest, got %d", len(z.File))
	}
	var m n10ExportManifest
	for _, f := range z.File {
		r, e := f.Open()
		if e != nil {
			t.Fatal(e)
		}
		data, e := io.ReadAll(r)
		r.Close()
		if e != nil {
			t.Fatal(e)
		}
		if f.Name == "SOURCE_MANIFEST.json" {
			if e = json.Unmarshal(data, &m); e != nil {
				t.Fatal(e)
			}
			continue
		}
		path := strings.TrimPrefix(f.Name, "sources/")
		if !bytes.Equal(data, source[path]) {
			t.Fatalf("bad archived member %s", path)
		}
	}
	if m.OriginalEXESHA256 != sha || len(m.Files) != 28 {
		t.Fatalf("bad manifest %+v", m)
	}
}
