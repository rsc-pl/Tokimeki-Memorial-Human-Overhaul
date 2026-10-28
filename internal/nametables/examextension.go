package nametables

// Exam table and caption name hooks, applied after the overlay-local speaker
// module. This stage returns a verified overlay buffer without writing a disc.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
)

const (
	examRetailExeDigest     = "bae1514fcc4bd8843c69803bf469632b004377b67f3e4408f0641c545fd843ae"
	examBaseETCDigest       = "f3319426d1936b639d9bb0d2410f56f89731face62ff6b4a1310d90b2f86d7b7"
	examCombinedETCDigest   = "5f7c6af55136aa0cee92fd23b3c30217c837c8fa0bcc2b76c8404e7218a5839c"
	examFrozenPayloadDigest = "9619dcf15044552ba00f9ea5b6e7b110ed4ff97e30ac0896d1bf8850696fa384"
	examGuardDigest         = "0712fae5cba4a6335b047f60b002fd7c544dadebc73fcb2ddc4659fcf7ac0d6e"
	examBodyDigest          = "4547765f8fabf22c951ae3e8067859a1fd73607b30227f0546982390de797a77"
	examTableJalOffset      = 0x15bd0
	examCaptionJalOffset    = 0x15db0
	examTableStub           = 0x80160ee0
)

// ComposeFrozenExamETC installs the verified exam-label module and redirects
// two authenticated ETC callsites. It requires the overlay-local speaker base;
// unknown source bytes, unexpected module geometry and unrelated edits fail.
// Runtime ownership must be verified by the enclosing image composer.
func ComposeFrozenExamETC(originalExe, originalETC, speakerBaseETC []byte) ([]byte, error) {
	if len(originalExe) != 667648 || speakerHash(originalExe) != examRetailExeDigest {
		return nil, fmt.Errorf("original EXE not authenticated")
	}
	if len(originalETC) != speakerOverlaySize || speakerHash(originalETC) != speakerCarriers["ETC.EXN"].hash {
		return nil, fmt.Errorf("original ETC overlay not authenticated")
	}
	if len(speakerBaseETC) != speakerOverlaySize || speakerHash(speakerBaseETC) != examBaseETCDigest {
		return nil, fmt.Errorf("exam hook requires the verified ETC speaker layer")
	}
	if speakerHash(examETCGuardImage[:]) != examGuardDigest || speakerHash(examETCBodyImage[:]) != examBodyDigest {
		return nil, fmt.Errorf("exam-label module integrity failure")
	}
	if binary.LittleEndian.Uint32(examETCGuardImage[:]) != 0x364e ||
		binary.LittleEndian.Uint32(examETCGuardImage[4:]) != uint32(len(examETCBodyImage)) {
		return nil, fmt.Errorf("exam-label verifier header mismatch")
	}
	var sum, xor uint32
	for i := 0; i < len(examETCBodyImage); i += 4 {
		w := binary.LittleEndian.Uint32(examETCBodyImage[i:])
		sum += w
		xor ^= w
	}
	if binary.LittleEndian.Uint32(examETCGuardImage[8:]) != sum || binary.LittleEndian.Uint32(examETCGuardImage[12:]) != xor {
		return nil, fmt.Errorf("exam-label guard checksum mismatch")
	}
	// Both sites are exact original retail calls, including the MIPS delay slot.
	for _, s := range []struct {
		off    int
		target uint32
		delay  uint32
	}{
		{examTableJalOffset, 0x800ae110, 0x24060008},
		{examCaptionJalOffset, speakerOriginalTarget, speakerArgumentDelay},
	} {
		expected := speakerJAL(s.target)
		if binary.LittleEndian.Uint32(originalETC[s.off:]) != expected ||
			binary.LittleEndian.Uint32(originalETC[s.off+4:]) != s.delay ||
			binary.LittleEndian.Uint32(speakerBaseETC[s.off:]) != expected ||
			binary.LittleEndian.Uint32(speakerBaseETC[s.off+4:]) != s.delay {
			return nil, fmt.Errorf("exam-label callsite preimage mismatch at %#x", s.off)
		}
	}
	if !bytes.Equal(speakerBaseETC[speakerGuardOffset:speakerGuardEnd], speakerGuardImage[:]) ||
		!bytes.Equal(speakerBaseETC[speakerBodyOffset:speakerBodyOffset+len(speakerBodyImage)], speakerBodyImage[:]) {
		return nil, fmt.Errorf("verified speaker module is missing")
	}
	if !speakerZero(originalETC[speakerGuardOffset:speakerPayloadEnd]) {
		return nil, fmt.Errorf("original ETC payload region is not empty")
	}
	result := bytes.Clone(speakerBaseETC)
	copy(result[speakerGuardOffset:speakerGuardEnd], examETCGuardImage[:])
	copy(result[speakerBodyOffset:speakerBodyOffset+len(examETCBodyImage)], examETCBodyImage[:])
	binary.LittleEndian.PutUint32(result[examTableJalOffset:], speakerJAL(examTableStub))
	binary.LittleEndian.PutUint32(result[examCaptionJalOffset:], speakerJAL(speakerStubTarget))
	binary.BigEndian.PutUint16(result[len(result)-4:], speakerChecksum(result))
	payloadSum := sha256.Sum256(result[speakerGuardOffset:speakerPayloadEnd])
	if fmt.Sprintf("%x", payloadSum) != examFrozenPayloadDigest || speakerHash(result) != examCombinedETCDigest {
		return nil, fmt.Errorf("exam-label code layer digest mismatch")
	}
	// The only authorized differences from the speaker base are the two
	// original calls, local module area and checksum. All 38 speaker hooks
	// remain untouched. No writes to input buffers or saved-name fields.
	for i := range result {
		if result[i] == speakerBaseETC[i] {
			continue
		}
		allowed := (i >= speakerGuardOffset && i < speakerPayloadEnd) ||
			(i >= len(result)-4 && i < len(result)-2) ||
			(i >= examTableJalOffset && i < examTableJalOffset+4) ||
			(i >= examCaptionJalOffset && i < examCaptionJalOffset+4)
		if !allowed {
			return nil, fmt.Errorf("unexpected exam overlay byte change at %#x", i)
		}
	}
	return result, nil
}
