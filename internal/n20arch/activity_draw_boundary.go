package n20arch

// activity screen audits the authenticated activity-scene queue consumers, not merely
// saved-name references. No name display is declared fixed by this audit.
// OPTION's six direct queues are already handled by nickname; OLH lacks an
// equivalent immediately materialised saved-name a3. Indirect sources remain
// UNKNOWN, never a permission to install an additional hook.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
)

type ActivityDrawAudit struct {
	OptionQueueCalls        int
	OLHQueueCalls           int
	OptionDirectNameCalls   []uint32
	OLHDirectNameCalls      []uint32
	OptionOtherQueueCalls   int
	OLHUnresolvedQueueCalls int
	ActivityNameResolved    bool
	SafeToPatch             bool
	RuntimePass             bool
}

// A strict *positive* witness: instructions exactly 20 and 16 bytes before
// the queue JAL must materialise a saved kana field directly into a3, and
// the 5th argument must remain the original O32 stack store. Anything else
// is unresolved, not automatically classified as a static literal.
func nameEntryQueueDirectField(d []byte, off int) uint32 {
	if off < 20 || off+8 > len(d) {
		return 0
	}
	if binary.LittleEndian.Uint32(d[off+4:]) != olSW(0, 29, 0x10) {
		return 0
	}
	for _, address := range []uint32{SurnameField, GivenField, 0x800E6364} {
		if binary.LittleEndian.Uint32(d[off-20:]) == olLUI(7, address) &&
			binary.LittleEndian.Uint32(d[off-16:]) == olADDIU(7, 7, int16(address&0xffff)) {
			return address
		}
	}
	return 0
}

func nameEntryQueueAuthenticatedQueues(name string, d []byte) (int, []uint32, error) {
	if len(d) != OverlayLoadSectors*2048 || sha(d) != OverlaySHA[name] {
		return 0, nil, fmt.Errorf("activity screen unauthenticated %s", name)
	}
	if packedTableChecksum(d) != binary.BigEndian.Uint16(d[len(d)-4:]) {
		return 0, nil, fmt.Errorf("activity screen invalid checksum %s", name)
	}
	// These two exact authenticated retail images have known executable ends.
	// A 512-byte blank witness is verified instead of rescanning 512 bytes
	// at every instruction; the previous generic search was costly inside
	// large integration-test matrices. Unknown overlays are never accepted.
	codeEnd := map[string]int{"OPTION.EXN": 0xC884, "OLH.EXN": 0xB6E0}[name]
	if codeEnd == 0 || codeEnd+512 > len(d) || !bytes.Equal(d[codeEnd:codeEnd+512], make([]byte, 512)) || binary.LittleEndian.Uint32(d[codeEnd-4:]) == 0 {
		return 0, nil, fmt.Errorf("activity screen code-end witness refused: %s", name)
	}
	var direct []uint32
	count := 0
	for off := 0; off+8 <= codeEnd; off += 4 {
		if binary.LittleEndian.Uint32(d[off:]) != jalWord(optionQueueRetail) {
			continue
		}
		count++
		if nameEntryQueueDirectField(d, off) != 0 {
			direct = append(direct, OverlaySlotBase+uint32(off))
		}
	}
	sort.Slice(direct, func(i, j int) bool { return direct[i] < direct[j] })
	return count, direct, nil
}

// AuditActivityDrawBoundary refuses to infer an OLH UI route from the
// presence of activity scenes alone. It is intentionally read-only and does
// not create any modified overlay, runtime image or new MIPS hook.
func AuditActivityDrawBoundary(option, olh []byte) (ActivityDrawAudit, error) {
	var a ActivityDrawAudit
	var err error
	a.OptionQueueCalls, a.OptionDirectNameCalls, err = nameEntryQueueAuthenticatedQueues("OPTION.EXN", option)
	if err != nil {
		return a, err
	}
	a.OLHQueueCalls, a.OLHDirectNameCalls, err = nameEntryQueueAuthenticatedQueues("OLH.EXN", olh)
	if err != nil {
		return a, err
	}
	expected := []uint32{0x8013A78C, 0x8013A7A8, 0x8013A7C4, 0x8013AEB0, 0x8013AECC, 0x8013AEE8}
	if a.OptionQueueCalls != 47 || a.OLHQueueCalls != 286 || len(a.OptionDirectNameCalls) != len(expected) || len(a.OLHDirectNameCalls) != 0 {
		return ActivityDrawAudit{}, fmt.Errorf("activity screen unexpected source-backed route census: OPTION=%d (%d direct), OLH=%d (%d direct)", a.OptionQueueCalls, len(a.OptionDirectNameCalls), a.OLHQueueCalls, len(a.OLHDirectNameCalls))
	}
	for i, v := range expected {
		if a.OptionDirectNameCalls[i] != v {
			return ActivityDrawAudit{}, fmt.Errorf("activity screen OPTION direct name call changed at index %d", i)
		}
	}
	a.OptionOtherQueueCalls = a.OptionQueueCalls - len(expected)
	a.OLHUnresolvedQueueCalls = a.OLHQueueCalls
	return a, nil
}
