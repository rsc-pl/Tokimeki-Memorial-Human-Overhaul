package n20arch

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

// OriginalEXESHA is the SHA-256 of the authenticated Japanese retail PS-X EXE.
const OriginalEXESHA = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"

// OverlaySHA pins all 26 authenticated original overlays (packed transliteration table/previous version).
var OverlaySHA = map[string]string{
	"BUNKAKEN.EXN": "950de4f402232a1a36242935ad18094b1a4327d7d8fc187a8ecdb7e090313952",
	"BUNKASAI.EXN": "381a936f10c244b21bd274eab74bda0f0388f33570947e473afbf46c31204b42",
	"BUNKA_SD.EXN": "a6929b157190c8e016da76e43f96a1389f67b04afc543c9d6de6252aa9ea4a2b",
	"DATE.EXN":     "35035e4e3ebdd9b3aebf8affd049554ad6745f76dc27cd697a7b646ce3438ebc",
	"DATE2.EXN":    "650795ceb419b8261e049dd9a84d4938417a78e7b1e0b4f3e48976a5000a50c8",
	"ENDING.EXN":   "44e18b1a7766886c12cd6a165c63a16d69b1953cc0063ee06b75848111d2cd47",
	"EN_NICHI.EXN": "a5ae62a050e390a72448fd398eb52d8ead0ba0c275a153cee119889c02a5defc",
	"ETC.EXN":      "60e75aeb8956a626c5af40347c73b0fd13b1f85df434b86b7f5aee318d3de87c",
	"EVENT.EXN":    "891730ab9ab7e17b110c6fe4cba4c34f95dfc057c824be1f273075ae3e5dcfe0",
	"GEKO.EXN":     "f7295203dc38417b8ff3c274833c06554dd072f5a6efcc74674cdaf38f06e5ad",
	"GYOZI.EXN":    "f186f48fe7669a4f9abf468a0d2f34451b453d458f459ba3487ae7e3e92f3d4e",
	"KANGEI.EXN":   "63bd7fb18df21bb6f1be64b8bff162b2755b3037a434bca80d2a209fc1d14ca0",
	"MASTER.EXN":   "20be135688f5614cea1e4dd15f2136c7185d58f82cb433257efd66d0f40fe712",
	"NAME_ENT.EXN": "f7384ad3617361282638ffd9bc1800bb6655d43ddee37ffe257de2ab485cd4a2",
	"OLH.EXN":      "be3524e75f2d3dee771d34aeac061bdd18999cb019264549979c7ace74fe9558",
	"OMIMAI.EXN":   "563cd44d97e7a3cdac7bae7467084a11ef221968ee7ba34bdeef123398267893",
	"OPTION.EXN":   "f36c2ea3166818f6aae3d044eb659c060d81e42d6e020b2f965038a0f16e68c3",
	"RENSYU.EXN":   "15dbab58f5b52cfe07ae48b46591cf804d530f00b93c24c494111aa486c1c385",
	"RPG_BAT.EXN":  "59a6d1687e59132017eb7212fd6560b2e96bddad0a19ecac0929517b9ec4944c",
	"SHOUGATU.EXN": "84842bc3e8540ef9853d38ca04bb453eddb60a5a9b14786896ac618b3b84bb13",
	"SHUGAKU.EXN":  "06f885c6038811fbbf2f4081d81a18b74cfec08c244e12004e4fa91a8e54cc14",
	"TACO.EXN":     "1eb8bad166897063bbb9c4bb94dafa426d34b56db5aa55e1b4f9b8d998e29b80",
	"TAIIKU.EXN":   "84087a69106671ebcc710091bf359bd457aac5cb10bea70ac2247a35efe37c17",
	"TEL.EXN":      "25a0379724a5e364e83e5196af5e59bd3c40eccb139c0bb0e80557138fd7e0e7",
	"TT.EXN":       "a1c39d54045f5c82d1de542442a705fb65adae22c05781dee6fc69dad3da208c",
	"VALEN.EXN":    "8ac1c5db86b31d1b9e22b10fa661138d35923686442abc310e47ed4c99b312b8",
}

type AnchorReport struct {
	EXESHA         string
	ChangedWords   int
	HookSites      int
	PreloadSites   int
	BootWords      int
	PreservedBoot  int
	DelaySlotsKept int
	ChangedPCs     []uint32
	AllDelayWords  []uint32
}

func packedTableChecksum(d []byte) uint16 {
	var total uint32
	for _, b := range d[:len(d)-4] {
		total += uint32(b)
	}
	return uint16(total)
}

func wordAt(exe []byte, pc uint32) uint32 {
	return binary.LittleEndian.Uint32(exe[pc-0x80040800:])
}

// VerifyRetailEXE checks every original word, every preserved boot word and
// every hook delay slot against the private authenticated EXE bytes. It
// changes nothing and refuses any non-minimal changed-word set.
func VerifyRetailEXE(exe []byte) (AnchorReport, error) {
	var r AnchorReport
	if len(exe) != 667648 || sha(exe) != OriginalEXESHA {
		return r, fmt.Errorf("unrecognised original EXE")
	}
	r.EXESHA = OriginalEXESHA
	// Boot words must remain byte-identical to pristine retail.
	for _, b := range PreservedBootWords {
		if wordAt(exe, b.PC) != b.Word {
			return r, fmt.Errorf("preserved boot word mismatch at %08x: %08x", b.PC, wordAt(exe, b.PC))
		}
	}
	r.PreservedBoot = len(PreservedBootWords)
	// The InitHeap wrapper and the boot BSS-clear wrapper must also be
	// original; no heap-disable argument is permitted.
	for pc, want := range map[uint32]uint32{
		0x800420F4: 0x0C02BBF0, // jal 0x800AEFC0 InitHeap wrapper
		0x800AEFC0: 0x240A00A0, // addiu t2,zero,0xA0
		0x800AEFC4: 0x01400008, // jr t2
		0x800AEFC8: 0x24090039, // addiu t1,zero,0x39
		0x80042100: 0x3C050004, // lui a1,0x0004
		0x80042104: 0x34A55498, // ori a1,a1,0x5498
		0x80042108: 0x0C02B820, // jal 0x800AE080 BSS clear
		0x8004210C: 0x348460A0, // delay: ori a0,a0,0x60A0
	} {
		if wordAt(exe, pc) != want {
			return r, fmt.Errorf("boot/heap anchor mismatch at %08x", pc)
		}
	}
	// Hook sites and their original delay slots.
	for _, h := range RetailHooks {
		if wordAt(exe, h.PC) != 0x0C0139E2 {
			return r, fmt.Errorf("%s original JAL mismatch at %08x", h.Name, h.PC)
		}
		r.AllDelayWords = append(r.AllDelayWords, wordAt(exe, h.DelayPC))
		r.HookSites++
	}
	wantDelay := []uint32{0xAFA00010, 0xAFA00010, 0xAFA00010, 0xAFA00010, 0xAFA00010}
	for i := range wantDelay {
		if r.AllDelayWords[i] != wantDelay[i] {
			return r, fmt.Errorf("delay slot %d = %08x", i, r.AllDelayWords[i])
		}
	}
	r.DelaySlotsKept = len(wantDelay)
	// The san/full-name retail JALs must remain untouched: those routes are
	// deliberately left on retail kana in this corrected build.
	for _, pc := range []uint32{0x80081DC8, 0x80082700, 0x80082724} {
		if wordAt(exe, pc) != 0x0C0139E2 {
			return r, fmt.Errorf("retail-only route word changed at %08x", pc)
		}
	}
	r.BootWords = 0 // no boot patch
	// Apply the five hook JALs to an in-memory copy and count exact deltas.
	patched := append([]byte(nil), exe...)
	for _, h := range RetailHooks {
		binary.LittleEndian.PutUint32(patched[h.PC-0x80040800:], jalWord(h.Target))
	}
	changed := map[uint32]bool{}
	for i := 0; i < len(exe); i++ {
		if exe[i] != patched[i] {
			changed[uint32(i/4)*4+0x80040800] = true
		}
	}
	r.ChangedWords = len(changed)
	for pc := range changed {
		r.ChangedPCs = append(r.ChangedPCs, pc)
	}
	sort.Slice(r.ChangedPCs, func(i, j int) bool { return r.ChangedPCs[i] < r.ChangedPCs[j] })
	if r.ChangedWords != len(RetailHooks) {
		return r, fmt.Errorf("changed words %d want %d", r.ChangedWords, len(RetailHooks))
	}
	for _, h := range RetailHooks {
		if !changed[h.PC] {
			return r, fmt.Errorf("missing hook delta at %08x", h.PC)
		}
	}
	for pc := range changed {
		if pc >= 0x800420D0 && pc < 0x80042120 {
			return r, fmt.Errorf("boot word unexpectedly changed at %08x", pc)
		}
	}
	return r, nil
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

type HeapCensus struct {
	InitHeapCalls        []uint32
	BSSZeroCalls         int
	A0AllocatorWrappers  map[string]int
	B0AllocatorWrappers  map[string]int
	B0AllocatorCalls     map[string]int
	TopRAMConstantPairs  int
	StoreOpcodes         int
	UnresolvedStoreBases int
	Inconclusive         bool
	Verdict              string
	Note                 string
}

// CensusHeap is a negative-only static census. It does not prove the BIOS heap
// unused; it records what can be resolved and explicitly keeps overlay status
// inconclusive. The architecture rejects the top-of-RAM claim regardless.
func CensusHeap(exe []byte, overlays map[string][]byte) HeapCensus {
	h := HeapCensus{A0AllocatorWrappers: map[string]int{}, B0AllocatorWrappers: map[string]int{},
		B0AllocatorCalls: map[string]int{}, Inconclusive: true}
	scan := func(d []byte, base uint32) {
		for i := 0; i+12 <= len(d); i += 4 {
			pc := base + uint32(i)
			w := binary.LittleEndian.Uint32(d[i:])
			op := w >> 26
			if op == 0x03 { // jal
				t := ((w & 0x03FFFFFF) << 2) | 0x80000000
				switch t {
				case 0x800AEFC0:
					h.InitHeapCalls = append(h.InitHeapCalls, pc)
				case 0x800AE080:
					h.BSSZeroCalls++
				case 0x800AF210:
					h.B0AllocatorCalls["b0_0x32"]++
				case 0x800AF230:
					h.B0AllocatorCalls["b0_0x34"]++
				case 0x800AF240:
					h.B0AllocatorCalls["b0_0x35"]++
				}
			}
			if op == 0x09 && (w>>16)&31 == 10 && (w&0xffff) == 0xA0 {
				w1 := binary.LittleEndian.Uint32(d[i+4:])
				w2 := binary.LittleEndian.Uint32(d[i+8:])
				if w1>>26 == 0 && w1&63 == 8 {
					fn := w2 & 0xffff
					if fn >= 0x33 && fn <= 0x36 {
						h.A0AllocatorWrappers[fmt.Sprintf("a0_0x%02x", fn)]++
					}
				}
			}
			if op == 0x09 && (w>>16)&31 == 10 && (w&0xffff) == 0xB0 {
				w1 := binary.LittleEndian.Uint32(d[i+4:])
				w2 := binary.LittleEndian.Uint32(d[i+8:])
				if w1>>26 == 0 && w1&63 == 8 {
					fn := w2 & 0xffff
					if fn == 0x32 || fn == 0x34 || fn == 0x35 {
						h.B0AllocatorWrappers[fmt.Sprintf("b0_0x%02x", fn)]++
					}
				}
			}
			if op == 0x0F { // lui, followed by ori same reg
				hi := w & 0xffff
				rt := (w >> 16) & 31
				for j := 1; j <= 3 && i+4*j+4 <= len(d); j++ {
					y := binary.LittleEndian.Uint32(d[i+4*j:])
					if y>>26 == 0x0D && (y>>21)&31 == rt && (y>>16)&31 == rt {
						v := hi<<16 | (y & 0xffff)
						if v >= 0x801FF800 && v < 0x80200000 {
							h.TopRAMConstantPairs++
						}
						break
					}
				}
			}
			if op == 0x2B || op == 0x29 || op == 0x28 || op == 0x2A || op == 0x2E {
				h.StoreOpcodes++
			}
		}
	}
	scan(exe, 0x80040800)
	for _, d := range overlays {
		scan(d, 0x80132000)
	}
	h.UnresolvedStoreBases = 55657 // previous version authenticated census; not recomputed here.
	h.Verdict = "REJECTED: InitHeap heap use is not disproved; previous version/overlay status are inconclusive"
	h.Note = "Negative-only static census. No A0 malloc wrapper is resolved, but B0 kernel-heap allocation calls exist and 55,657 store bases remain unresolved. Absence of a resolved malloc is not proof."
	return h
}

type OverlayReport struct {
	Count        int
	Carriers     int
	CoreCarrier  string
	StubOnly     int
	WindowBytes  int
	PayloadBytes int
	PlanSHA      map[string]string
}

// PlanDelivery applies the overlay-local payload and identical window to
// in-memory overlay copies. No file is written. Every one of the 24 non-EVENT/
// TACO carriers installs the same module; EVENT and TACO keep their original
// payload and therefore fail closed to retail on every hooked route.
func PlanDelivery(c Core, overlays map[string][]byte) (OverlayReport, error) {
	var r OverlayReport
	if len(overlays) != len(OverlaySHA) {
		return r, fmt.Errorf("need all 26 original overlays, got %d", len(overlays))
	}
	r.WindowBytes = WindowBytes
	r.PayloadBytes = PayloadCapacity
	r.PlanSHA = map[string]string{}
	names := make([]string, 0, len(overlays))
	for n := range overlays {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, name := range names {
		original := overlays[name]
		if len(original) != 196608 || sha(original) != OverlaySHA[name] {
			return r, fmt.Errorf("unrecognised overlay %s", name)
		}
		if original[0x2FFFE] != 0x12 || original[0x2FFFF] != 0x10 {
			return r, fmt.Errorf("trailer mismatch %s", name)
		}
		if packedTableChecksum(original) != binary.BigEndian.Uint16(original[0x2FFFC:]) {
			return r, fmt.Errorf("checksum mismatch %s", name)
		}
		if !allZero(original[WindowFileOff : WindowFileOff+WindowBytes]) {
			return r, fmt.Errorf("stub window not zero in %s", name)
		}
		if name != "EVENT.EXN" && name != "TACO.EXN" {
			if !allZero(original[PayloadFileOff : PayloadFileOff+PayloadCapacity]) {
				return r, fmt.Errorf("payload window not zero in %s", name)
			}
		} else if binary.LittleEndian.Uint32(original[PayloadFileOff:]) == PayloadMagicWord {
			return r, fmt.Errorf("magic collision in stub-only %s", name)
		}
		d := bytes.Clone(original)
		switch name {
		case "EVENT.EXN", "TACO.EXN":
			r.StubOnly++
			// Payload deliberately untouched.
		default:
			copy(d[PayloadFileOff:], c.PayloadBytes())
			r.Carriers++
		}
		copy(d[WindowFileOff:], c.Window)
		ck := packedTableChecksum(d)
		d[0x2FFFC] = byte(ck >> 8)
		d[0x2FFFD] = byte(ck)
		if len(d) != len(original) || d[0x2FFFE] != 0x12 || d[0x2FFFF] != 0x10 {
			return r, fmt.Errorf("geometry/trailer damaged %s", name)
		}
		if binary.BigEndian.Uint16(d[0x2FFFC:]) != packedTableChecksum(d) {
			return r, fmt.Errorf("checksum failed %s", name)
		}
		for i := range d {
			if d[i] == original[i] {
				continue
			}
			allowed := i >= WindowFileOff && i < 0x2FFFE
			allowed = allowed || (name != "EVENT.EXN" && name != "TACO.EXN" &&
				i >= PayloadFileOff && i < PayloadFileOff+PayloadCapacity)
			if !allowed {
				return r, fmt.Errorf("delta outside plan %s+0x%x", name, i)
			}
		}
		r.Count++
		r.PlanSHA[name] = sha(d)
	}
	if r.Count != 26 || r.Carriers != 24 || r.StubOnly != 2 || r.CoreCarrier != "" {
		return r, fmt.Errorf("unexpected delivery counts %+v", r)
	}
	return r, nil
}

// CheckRetailAnchors is a convenience for tests.
func CheckRetailAnchors(exe []byte) error {
	_, err := VerifyRetailEXE(exe)
	return err
}
