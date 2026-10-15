package patchplan

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tokimemo/internal/graphics"
	"tokimemo/internal/ps1"
)

type memorySource map[string][]byte

func (s memorySource) ReadFile(f string) ([]byte, error) { return append([]byte(nil), s[f]...), nil }
func createFixture(t *testing.T) (string, memorySource, Batch) {
	t.Helper()
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "translation"), 0700); err != nil {
		t.Fatal(err)
	}
	img := graphics.Indexed{Width: 2, Height: 2, Pixels: []byte{9, 8, 7, 6}, Palette: make([][3]uint8, 16)}
	var png bytes.Buffer
	if err := graphics.WriteIndexed(&png, img); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "translation", "test.png"), png.Bytes(), 0600); err != nil {
		t.Fatal(err)
	}
	first := make([]byte, 240)
	copy(first[8:], []byte{'A', 'B', 0, 0})
	copy(first[70:], []byte{0x13, 0x24})
	copy(first[128:], []byte{3, 2, 4, 1})
	copy(first[len(first)-2:], []byte{0x12, 0x10})
	if err := ps1.FixTailChecksum(first); err != nil {
		t.Fatal(err)
	}
	second := make([]byte, 80)
	copy(second[20:], []byte{0x55, 0x66})
	source := memorySource{"FIRST.BIN": first, "SECOND.BIN": second}
	spec := map[string]any{
		"strings": []any{map[string]any{"file": "FIRST.BIN", "offset": "0x8", "original": "AB", "text": "  "}},
		"bytes":   []any{map[string]any{"file": "FIRST.BIN", "offset": "0x46", "original": "1324", "replacement": "3579"}, map[string]any{"file": "SECOND.BIN", "offset": "0x14", "original": "5566", "replacement": "aabb"}},
		"images":  []any{map[string]any{"file": "FIRST.BIN", "png": "test.png", "pixels": "0x80", "stride": 2, "x": 0, "y": 0, "rects": [][4]int{{0, 0, 2, 2}}, "original_crc32": "0x" + strings.ToUpper(strings.TrimPrefix(strings.TrimPrefix(fmtHex(crc32.ChecksumIEEE([]byte{3, 2, 4, 1})), "0x"), "0X"))}},
	}
	b, e := json.Marshal(spec)
	if e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile(filepath.Join(root, "translation", "sample.json"), b, 0600); e != nil {
		t.Fatal(e)
	}
	batch, e := Load(root, nil)
	if e != nil {
		t.Fatal(e)
	}
	return root, source, batch
}
func fmtHex(n uint32) string {
	const chars = "0123456789abcdef"
	b := make([]byte, 8)
	for i := 7; i >= 0; i-- {
		b[i] = chars[n&15]
		n >>= 4
	}
	return "0x" + string(b)
}
func TestFullFilePlanPythonParity(t *testing.T) {
	root, source, batch := createFixture(t)
	pristine := append([]byte(nil), source["FIRST.BIN"]...)
	goResult, err := Plan(source, batch)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(pristine, source["FIRST.BIN"]) {
		t.Fatal("planner modified source")
	}
	if len(goResult.Files) != 2 || !goResult.Files[0].ChecksumUpdated || goResult.RendererInstalled {
		t.Fatalf("unexpected report %+v", goResult)
	}
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("Python reference unavailable")
	}
	fixture := map[string]string{}
	for k, v := range source {
		fixture[k] = base64.StdEncoding.EncodeToString(v)
	}
	raw, _ := json.Marshal(fixture)
	f := filepath.Join(root, "input.json")
	if err = os.WriteFile(f, raw, 0600); err != nil {
		t.Fatal(err)
	}
	scriptPath := filepath.Join("..", "..", "legacy_scripts", "tools", "fullplan_reference.py")
	command := exec.Command(python, scriptPath, "--fixture", f, "--translation", filepath.Join(root, "translation", "sample.json"))
	command.Env = append(os.Environ(), "PYTHONPATH="+filepath.Join("..", "..", "legacy_scripts"), "PYTHONDONTWRITEBYTECODE=1")
	stdout, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("Python planner: %s (%v)", stdout, err)
	}
	var want Result
	if err = json.Unmarshal(stdout, &want); err != nil {
		t.Fatalf("Python oracle JSON: %s %v", stdout, err)
	}
	if !reflect.DeepEqual(goResult, want) {
		t.Fatalf("whole-file parity differs\nGo: %+v\nPython: %+v", goResult, want)
	}
}
func TestFullFilePlanTransactionalOnError(t *testing.T) {
	_, source, batch := createFixture(t)
	before := append([]byte(nil), source["FIRST.BIN"]...)
	batch.Bytes[1].Original = []byte{0xff, 0xff}
	if _, err := Plan(source, batch); err == nil {
		t.Fatal("expected invalid original bytes error")
	}
	if !bytes.Equal(source["FIRST.BIN"], before) {
		t.Fatal("source mutated after later failure")
	}
}
func TestTranslationPNGTraversalRejected(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "translation"), 0700); err != nil {
		t.Fatal(err)
	}
	doc := `{"images":[{"file":"A.BIN","png":"../../outside.png","pixels":"0x0","original_crc32":"0x00000000","stride":1,"rects":[[0,0,1,1]]}]}`
	if err := os.WriteFile(filepath.Join(root, "translation", "test.json"), []byte(doc), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(root, nil); err == nil {
		t.Fatal("expected traversal rejection")
	}
}

func TestPlanBytesIsolatedAndSameReport(t *testing.T) {
	_, source, batch := createFixture(t)
	old := append([]byte(nil), source["FIRST.BIN"]...)
	expected, err := Plan(source, batch)
	if err != nil {
		t.Fatal(err)
	}
	result, buffers, err := PlanBytes(source, batch)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result, expected) {
		t.Fatal("PlanBytes metadata differs from read-only Plan")
	}
	if result.Files[0].PatchedSHA256 != sha256String(buffers["FIRST.BIN"]) {
		t.Fatal("planned bytes SHA mismatch")
	}
	buffers["FIRST.BIN"][0] ^= 0xff
	if !bytes.Equal(source["FIRST.BIN"], old) {
		t.Fatal("exposed source was changed")
	}
}
func sha256String(b []byte) string { s := sha256.Sum256(b); return fmt.Sprintf("%x", s[:]) }
