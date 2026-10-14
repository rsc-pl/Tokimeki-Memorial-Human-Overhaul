package ps1

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func sectorFixture(data []byte) []byte {
	s := make([]byte, SectorSize)
	s[0] = 0
	for i := 1; i < 11; i++ {
		s[i] = 255
	}
	s[0x0f] = 2
	copy(s[0x10:0x18], []byte{0, 0, 8, 0, 0, 0, 8, 0})
	copy(s[DataOffset:], data)
	if err := RegenerateForm1(s); err != nil {
		panic(err)
	}
	return s
}
func dirRecord(name []byte, lba, size uint32, dir bool) []byte {
	length := 33 + len(name)
	if len(name)%2 == 0 {
		length++
	}
	rec := make([]byte, length)
	rec[0] = byte(length)
	binary.LittleEndian.PutUint32(rec[2:6], lba)
	binary.BigEndian.PutUint32(rec[6:10], lba)
	binary.LittleEndian.PutUint32(rec[10:14], size)
	binary.BigEndian.PutUint32(rec[14:18], size)
	if dir {
		rec[25] = 2
	}
	rec[28] = 1
	rec[31] = 1
	rec[32] = byte(len(name))
	copy(rec[33:], name)
	return rec
}
func syntheticTrack(t *testing.T) []byte {
	t.Helper()
	data := make([]byte, 90*SectorSize)
	for lba := 0; lba < 90; lba++ {
		copy(data[lba*SectorSize:], sectorFixture(nil))
	}
	install := func(lba int, payload []byte) {
		s := sectorFixture(payload)
		copy(data[lba*SectorSize:(lba+1)*SectorSize], s)
	}
	root := dirRecord([]byte{0}, 20, DataSize, true)
	pvd := make([]byte, DataSize)
	pvd[0] = 1
	copy(pvd[1:6], "CD001")
	pvd[6] = 1
	copy(pvd[40:72], "TOKIMEMO_TEST_VOL")
	copy(pvd[156:], root)
	install(16, pvd)
	top := make([]byte, DataSize)
	pos := 0
	for _, r := range [][]byte{
		dirRecord([]byte{0}, 20, DataSize, true),
		dirRecord([]byte{1}, 20, DataSize, true),
		dirRecord([]byte("CDROM"), 21, DataSize, true),
		dirRecord([]byte("SYSTEM.CNF;1"), 23, 2300, false),
		dirRecord([]byte("VIDEO.STR;1"), 26, 1700, false),
	} {
		copy(top[pos:], r)
		pos += len(r)
	}
	install(20, top)
	sub := make([]byte, DataSize)
	copy(sub, dirRecord([]byte{0}, 21, DataSize, true))
	copy(sub[34:], dirRecord([]byte{1}, 20, DataSize, true))
	copy(sub[68:], dirRecord([]byte("TEST.BIN;1"), 24, 7, false))
	// Disc-specific directory exception: data begins at 0x10, not 0x18.
	quirky := sectorFixture(nil)
	copy(quirky[0x10:], sub)
	copy(data[21*SectorSize:22*SectorSize], quirky)
	contents := make([]byte, 2300)
	for i := range contents {
		contents[i] = byte(i*7 + 3)
	}
	install(23, contents[:2048])
	install(24, contents[2048:])
	// An ordinary file shares sector 24 for this *read-only* synthetic test.
	install(26, []byte("VIDEO"))
	return data
}
func TestISO9660Synthetic(t *testing.T) {
	track := syntheticTrack(t)
	iso, err := OpenISO(bytes.NewReader(track), int64(len(track)/SectorSize))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]ISOEntry{
		"CDROM":          {"CDROM", 21, DataSize, true},
		"SYSTEM.CNF":     {"SYSTEM.CNF", 23, 2300, false},
		"VIDEO.STR":      {"VIDEO.STR", 26, 1700, false},
		"CDROM/TEST.BIN": {"CDROM/TEST.BIN", 24, 7, false},
	}
	if !reflect.DeepEqual(iso.Entries, want) {
		t.Fatalf("ISO entries = %+v", iso.Entries)
	}
	if iso.Volume != "TOKIMEMO_TEST_VOL" {
		t.Fatal(iso.Volume)
	}
	var out bytes.Buffer
	e := iso.Entries["SYSTEM.CNF"]
	if err := ReadFileTo(iso.Reader, iso.Sectors, e.LBA, e.Size, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Bytes()) != 2300 {
		t.Fatal(out.Len())
	}
	if !bytes.Equal(out.Bytes()[:2048], track[23*SectorSize+24:24*SectorSize-280]) {
		t.Fatal("bad main data")
	}
	if !bytes.Equal(out.Bytes()[2048:], track[24*SectorSize+24:24*SectorSize+24+252]) {
		t.Fatal("bad tail data")
	}
	e = iso.Entries["CDROM/TEST.BIN"]
	out.Reset()
	if err := ReadFileTo(iso.Reader, iso.Sectors, e.LBA, e.Size, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Bytes()) != 7 {
		t.Fatal("bad smaller file")
	}
	if !reflect.DeepEqual([]string{iso.Sorted()[0].Path, iso.Sorted()[1].Path}, []string{"CDROM", "SYSTEM.CNF"}) {
		t.Fatal("sort order")
	}
}
func TestISOSafety(t *testing.T) {
	orig := syntheticTrack(t)
	broken := append([]byte(nil), orig...)
	// Path traversal is prohibited even if the original Python reader accepts it.
	root := broken[20*SectorSize+DataOffset:]
	index := bytes.Index(root[:DataSize], []byte("SYSTEM.CNF;1"))
	if index < 0 {
		t.Fatal("fixture missing")
	}
	copy(root[index:index+12], []byte("../BAD.EXE;1"))
	if _, err := OpenISO(bytes.NewReader(broken), 90); err == nil {
		t.Fatal("accepted unsafe name")
	}
	if err := ReadFileTo(bytes.NewReader(orig), 90, 89, 4096, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted out-of-bounds read")
	}
	if _, err := OpenISO(bytes.NewReader(orig[:16*SectorSize]), 16); err == nil {
		t.Fatal("accepted short disc")
	}
}
func TestPythonDirectoryAndSectorWriteParity(t *testing.T) {
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python parity fixture requires python3")
	}
	repo, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(repo, "legacy_scripts/tokipatch/iso9660.py")); err != nil {
		t.Skip("legacy Python files unavailable")
	}
	tmp := t.TempDir()
	a := filepath.Join(tmp, "go.bin")
	b := filepath.Join(tmp, "python.bin")
	data := syntheticTrack(t)
	for _, p := range []string{a, b} {
		if err := os.WriteFile(p, data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	goFile, err := os.OpenFile(a, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	iso, err := OpenISO(goFile, 90)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, e := range iso.Sorted() {
		got = append(got, fmt.Sprintf("%d\t%d\t%s\t%v", e.LBA, e.Size, e.Path, map[bool]string{true: "True", false: "False"}[e.IsDir]))
	}
	payload := make([]byte, 2900)
	for i := range payload {
		payload[i] = byte(i*13 + 77)
	}
	count, err := WriteFileBytes(goFile, 90, 28, 100, payload)
	if err != nil || count != 2 {
		t.Fatalf("wrote %d, err %v", count, err)
	}
	if err := goFile.Close(); err != nil {
		t.Fatal(err)
	}
	py := `import json,sys
from pathlib import Path
from tokipatch.cd import Track
from tokipatch.iso9660 import list_files
with Track(Path(sys.argv[1]), True) as track:
    entries=list_files(track)
    sorted_entries=sorted(entries.values(), key=lambda e:(e.lba,e.path))
    print(json.dumps([f"{e.lba}\\t{e.size}\\t{e.path}\\t{e.is_dir}" for e in sorted_entries]))
    payload=bytes((i*13+77)&255 for i in range(2900))
    print(track.write_file_bytes(28,100,payload))
`
	command := exec.Command(python, "-c", py, b)
	command.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join(repo, "legacy_scripts"), "PYTHONDONTWRITEBYTECODE=1")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("python parity error: %v\n%s", err, output)
	}
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	if len(lines) != 2 {
		t.Fatalf("unexpected Python output %q", output)
	}
	// Python JSON escapes tab controls; these are unescaped by json.Unmarshal.
	var pythonEntries []string
	if err := json.Unmarshal([]byte(lines[0]), &pythonEntries); err != nil {
		t.Fatal(err)
	}
	// The embedded Python uses literal \\t for stable JSON display: normalize.
	for i := range pythonEntries {
		pythonEntries[i] = strings.ReplaceAll(pythonEntries[i], `\t`, "\t")
	}
	if !reflect.DeepEqual(got, pythonEntries) {
		t.Fatalf("Go directory list %q != Python %q", got, pythonEntries)
	}
	if lines[1] != "2" {
		t.Fatalf("Python wrote %q sectors, expected 2", lines[1])
	}
	goBytes, err := os.ReadFile(a)
	if err != nil {
		t.Fatal(err)
	}
	pyBytes, err := os.ReadFile(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(goBytes, pyBytes) {
		t.Fatalf("Go/Python patched BIN differ: go SHA256=%x python SHA256=%x", sha256.Sum256(goBytes), sha256.Sum256(pyBytes))
	}
}
func TestWriteSectorPreflight(t *testing.T) {
	tmp := filepath.Join(t.TempDir(), "test.bin")
	data := syntheticTrack(t)
	data[29*SectorSize+0xf] = 1 // second sector is not Form1
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(tmp, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, err = WriteFileBytes(f, 90, 28, 100, make([]byte, 3000))
	f.Close()
	if err == nil {
		t.Fatal("invalid second sector accepted")
	}
	after, err := os.ReadFile(tmp)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, after) {
		t.Fatal("partial modification despite preflight failure")
	}
}
