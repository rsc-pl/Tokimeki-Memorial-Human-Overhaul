package nametables

// This is the previously authenticated overlay-local speaker composition,
// moved into ordinary Go source as a self-contained code layer. Its verified
// MIPS body is copied verbatim from the working generator, and only original
// retail caller words are changed. This is a source-to-bytes planner: it does
// not alter a game image or assert that CPU/DMA/IRQ ownership is proven.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sort"
)

type speakerCarrier struct {
	hash  string
	calls []int
}

const (
	speakerOverlaySize           = 196608
	speakerGuardOffset           = 0x2ee00
	speakerGuardEnd              = 0x2ef00
	speakerBodyOffset            = 0x2ef00
	speakerPayloadEnd            = 0x2fed8
	speakerOriginalTarget uint32 = 0x80050dfc
	speakerStubTarget     uint32 = 0x80160e10
	speakerArgumentLUI    uint32 = 0x3c04800e
	speakerArgumentDelay  uint32 = 0x24846354
	speakerGuardDigest           = "621d8da96ba4351f48b73dc19e6574a283f138b302d6585972e3e148cc750786"
	speakerBodyDigest            = "2622213d739344b20ac2cb16b03d2d4088cc51c527976ca88a56e0172cad8f1d"
)

func speakerHash(b []byte) string     { return fmt.Sprintf("%x", sha256.Sum256(b)) }
func speakerJAL(target uint32) uint32 { return 0x0c000000 | (target>>2)&0x03ffffff }
func speakerChecksum(b []byte) uint16 {
	var value uint32
	for _, v := range b[:len(b)-4] {
		value += uint32(v)
	}
	return uint16(value)
}
func speakerZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// ComposeSpeakerCarriers emits the exact original-overlay local surname route
// modifications for authenticated, source-proven carriers. The return map
// holds independent in-memory copies. It is a building block, NOT a complete
// English/long-name image composer. Callers must pass all three original
// overlay images; unknown/changed sources, incomplete sets, or destination
// overlap abort before any output is returned.
func ComposeSpeakerCarriers(readOriginal func(string) ([]byte, error)) (map[string][]byte, error) {
	if readOriginal == nil {
		return nil, fmt.Errorf("missing authenticated retail reader")
	}
	if len(speakerGuardImage) != 256 || len(speakerBodyImage) != 3328 ||
		speakerHash(speakerGuardImage[:]) != speakerGuardDigest ||
		speakerHash(speakerBodyImage[:]) != speakerBodyDigest {
		return nil, fmt.Errorf("embedded speaker module changed")
	}
	if binary.LittleEndian.Uint32(speakerGuardImage[:]) != 0x364e ||
		binary.LittleEndian.Uint32(speakerGuardImage[4:]) != uint32(len(speakerBodyImage)) ||
		binary.LittleEndian.Uint32(speakerGuardImage[8:]) != 0x05e4f550 || // checked against original module sum below
		binary.LittleEndian.Uint32(speakerGuardImage[12:]) != 0x01ec7abc {
		// All guard metadata is covered by the digest; the MIPS body sum/XOR
		// are also recomputed below to catch binary/metadata disagreement.
		return nil, fmt.Errorf("embedded guard metadata changed")
	}
	var sum, xor uint32
	for i := 0; i < len(speakerBodyImage); i += 4 {
		w := binary.LittleEndian.Uint32(speakerBodyImage[i:])
		sum += w
		xor ^= w
	}
	if sum != binary.LittleEndian.Uint32(speakerGuardImage[8:]) ||
		xor != binary.LittleEndian.Uint32(speakerGuardImage[12:]) {
		return nil, fmt.Errorf("embedded guard/body integrity mismatch")
	}
	ids := make([]string, 0, len(speakerCarriers))
	for id := range speakerCarriers {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	if len(ids) != 3 {
		return nil, fmt.Errorf("authenticated carrier set changed")
	}
	out := make(map[string][]byte, len(ids))
	for _, id := range ids {
		carrier := speakerCarriers[id]
		retail, err := readOriginal("CDROM/EXEDIR/" + id)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", id, err)
		}
		if len(retail) != speakerOverlaySize || speakerHash(retail) != carrier.hash {
			return nil, fmt.Errorf("%s: unknown retail overlay image", id)
		}
		if retail[len(retail)-2] != 0x12 || retail[len(retail)-1] != 0x10 ||
			speakerChecksum(retail) != binary.BigEndian.Uint16(retail[len(retail)-4:]) {
			return nil, fmt.Errorf("%s: original checksum or trailer mismatch", id)
		}
		if !speakerZero(retail[speakerGuardOffset:speakerPayloadEnd]) {
			return nil, fmt.Errorf("%s: original module region is occupied", id)
		}
		candidate := bytes.Clone(retail)
		copy(candidate[speakerGuardOffset:speakerGuardEnd], speakerGuardImage[:])
		copy(candidate[speakerBodyOffset:speakerBodyOffset+len(speakerBodyImage)], speakerBodyImage[:])
		if len(carrier.calls) == 0 {
			return nil, fmt.Errorf("%s: no source-owned callers", id)
		}
		visited := make(map[int]bool, len(carrier.calls))
		for _, off := range carrier.calls {
			if off < 4 || off+8 > speakerGuardOffset || off%4 != 0 || visited[off] {
				return nil, fmt.Errorf("%s: invalid caller offset %#x", id, off)
			}
			visited[off] = true
			if binary.LittleEndian.Uint32(retail[off-4:]) != speakerArgumentLUI ||
				binary.LittleEndian.Uint32(retail[off:]) != speakerJAL(speakerOriginalTarget) ||
				binary.LittleEndian.Uint32(retail[off+4:]) != speakerArgumentDelay {
				return nil, fmt.Errorf("%s: retail caller preimage mismatch %#x", id, off)
			}
			binary.LittleEndian.PutUint32(candidate[off:], speakerJAL(speakerStubTarget))
		}
		binary.BigEndian.PutUint16(candidate[len(candidate)-4:], speakerChecksum(candidate))
		if len(candidate) != len(retail) || candidate[len(candidate)-2] != 0x12 || candidate[len(candidate)-1] != 0x10 ||
			speakerChecksum(candidate) != binary.BigEndian.Uint16(candidate[len(candidate)-4:]) {
			return nil, fmt.Errorf("%s: final overlay integrity failure", id)
		}
		// In particular, no unlisted text bytes, saved-name fields, other
		// original JALs or overlay-header bytes may be altered.
		for i := range candidate {
			if candidate[i] == retail[i] {
				continue
			}
			allowed := (i >= speakerGuardOffset && i < speakerPayloadEnd) ||
				(i >= len(candidate)-4 && i < len(candidate)-2) || visited[(i/4)*4]
			if !allowed {
				return nil, fmt.Errorf("%s: unowned byte %#x", id, i)
			}
		}
		out["CDROM/EXEDIR/"+id] = candidate
	}
	return out, nil
}
