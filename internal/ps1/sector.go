// Package ps1 supplies native, testable MODE2/Form1 sector primitives.
// Patcher writing remains Python-owned until complete disc/renderer parity is verified.
package ps1

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const SectorSize = 2352
const DataOffset = 0x18
const DataSize = 2048

var forward, backward [256]byte
var edcTable [256]uint32

func init() {
	for i := 0; i < 256; i++ {
		j := byte((i << 1) ^ map[bool]int{true: 0x11d, false: 0}[i&0x80 != 0])
		forward[i] = j
		backward[byte(i)^j] = byte(i)
		crc := uint32(i)
		for k := 0; k < 8; k++ {
			if crc&1 != 0 {
				crc = (crc >> 1) ^ 0xd8018001
			} else {
				crc >>= 1
			}
		}
		edcTable[i] = crc
	}
}
func EDC(data []byte) uint32 {
	var c uint32
	for _, b := range data {
		c = (c >> 8) ^ edcTable[byte(c)^b]
	}
	return c
}
func ecc(src []byte, majorCount, minorCount, majorMult, minorInc int) []byte {
	size := majorCount * minorCount
	out := make([]byte, majorCount*2)
	for major := 0; major < majorCount; major++ {
		idx := (major>>1)*majorMult + (major & 1)
		var a, b byte
		for minor := 0; minor < minorCount; minor++ {
			v := src[idx]
			idx += minorInc
			if idx >= size {
				idx -= size
			}
			a ^= v
			b ^= v
			a = forward[a]
		}
		a = backward[forward[a]^b]
		out[major] = a
		out[major+majorCount] = a ^ b
	}
	return out
}
func IsForm1(s []byte) bool { return len(s) == SectorSize && s[0xf] == 2 && s[0x12]&0x20 == 0 }
func RegenerateForm1(s []byte) error {
	if !IsForm1(s) {
		return errors.New("sector is not a Mode 2 Form 1 sector")
	}
	binary.LittleEndian.PutUint32(s[0x818:0x81c], EDC(s[0x10:0x818]))
	var head [4]byte
	copy(head[:], s[0x0c:0x10])
	clear(s[0x0c:0x10])
	copy(s[0x81c:0x8c8], ecc(s[0x0c:0x81c], 86, 24, 2, 86))
	copy(s[0x8c8:0x930], ecc(s[0x0c:0x8c8], 52, 43, 86, 88))
	copy(s[0x0c:0x10], head[:])
	return nil
}
func VerifyForm1(s []byte) error {
	if !IsForm1(s) {
		return errors.New("not Mode 2 Form 1")
	}
	cp := append([]byte(nil), s...)
	if e := RegenerateForm1(cp); e != nil {
		return e
	}
	for i := 0x818; i < 0x930; i++ {
		if cp[i] != s[i] {
			return fmt.Errorf("EDC/ECC mismatch at sector byte 0x%x", i)
		}
	}
	return nil
}
func ReadSectorAt(reader io.ReaderAt, lba int64) ([]byte, error) {
	if lba < 0 {
		return nil, errors.New("negative LBA")
	}
	out := make([]byte, SectorSize)
	_, e := reader.ReadAt(out, lba*SectorSize)
	return out, e
}
func Data(s []byte) ([]byte, error) {
	if len(s) != SectorSize {
		return nil, errors.New("invalid sector length")
	}
	// Historical disc quirk: the first /CDROM directory sector can have mismatched subheaders.
	if string(s[0x10:0x14]) != string(s[0x14:0x18]) {
		return s[0x10 : 0x10+DataSize], nil
	}
	return s[DataOffset : DataOffset+DataSize], nil
}
func TailChecksumValid(data []byte) bool {
	return len(data) >= 4 && data[len(data)-2] == 0x12 && data[len(data)-1] == 0x10 && uint16(sum(data[:len(data)-4])) == binary.BigEndian.Uint16(data[len(data)-4:len(data)-2])
}
func sum(data []byte) int {
	n := 0
	for _, v := range data {
		n += int(v)
	}
	return n
}
func FixTailChecksum(data []byte) error {
	if len(data) < 4 || data[len(data)-2] != 0x12 || data[len(data)-1] != 0x10 {
		return errors.New("file has no recognized checksum marker")
	}
	binary.BigEndian.PutUint16(data[len(data)-4:len(data)-2], uint16(sum(data[:len(data)-4])))
	return nil
}
