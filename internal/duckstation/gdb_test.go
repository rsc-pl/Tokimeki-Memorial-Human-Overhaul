package duckstation

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type stub struct {
	addr string
	cmds []string
	mu   sync.Mutex
	done chan struct{}
}

func startStub(t *testing.T, malformed bool) *stub {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := &stub{addr: listener.Addr().String(), done: make(chan struct{})}
	go func() {
		defer close(s.done)
		defer listener.Close()
		c, e := listener.Accept()
		if e != nil {
			return
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(4 * time.Second))
		var one [1]byte
		for {
			// Skip acknowledgment of our previous packet.
			for {
				if _, e = io.ReadFull(c, one[:]); e != nil {
					return
				}
				if one[0] == '$' {
					break
				}
			}
			var cmd bytes.Buffer
			for {
				if _, e = io.ReadFull(c, one[:]); e != nil {
					return
				}
				if one[0] == '#' {
					break
				}
				cmd.WriteByte(one[0])
			}
			if _, e = io.ReadFull(c, make([]byte, 2)); e != nil {
				return
			}
			command := cmd.String()
			s.mu.Lock()
			s.cmds = append(s.cmds, command)
			s.mu.Unlock()
			var response string
			switch {
			case command == "?":
				response = "S05"
			case strings.HasPrefix(command, "m"):
				vals := strings.Split(command[1:], ",")
				if len(vals) != 2 {
					response = "E02"
					break
				}
				addr, _ := strconv.ParseUint(vals[0], 16, 64)
				length, _ := strconv.ParseUint(vals[1], 16, 32)
				raw := make([]byte, length)
				for i := range raw {
					raw[i] = byte((int(addr) + i) & 255)
				}
				response = hex.EncodeToString(raw)
				if malformed {
					response = "zz"
				}
			case command == "D":
				response = "OK"
			default:
				response = "E01"
			}
			var sum byte
			for _, v := range []byte(response) {
				sum += v
			}
			_, _ = fmt.Fprintf(c, "+$%s#%02x", response, sum)
			if command == "D" {
				return
			}
		}
	}()
	return s
}
func (s *stub) checkDone(t *testing.T) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(3 * time.Second):
		t.Fatal("connection not detached")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cmds) < 2 || s.cmds[0] != "?" || s.cmds[len(s.cmds)-1] != "D" {
		t.Fatalf("unexpected GDB commands %v", s.cmds)
	}
	for _, c := range s.cmds {
		if c != "?" && c != "D" && !strings.HasPrefix(c, "m") {
			t.Fatalf("write/control GDB command: %s", c)
		}
	}
}
func TestReadOnlyMemoryChunksAndDetach(t *testing.T) {
	s := startStub(t, false)
	_, portString, _ := net.SplitHostPort(s.addr)
	port, _ := strconv.Atoi(portString)
	c, err := Dial(port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	data, err := c.ReadMemory(0x800000ff, 2050)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) != 2050 || data[0] != 0xff || data[1] != 0 || data[1024] != 0xff {
		t.Fatal("wrong data or chunking")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	if err = c.Close(); err != nil {
		t.Fatal("close is not idempotent", err)
	}
	s.checkDone(t)
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.cmds) != 5 {
		t.Fatalf("expected handshake, three reads, detach; got %v", s.cmds)
	}
}
func TestRejectMalformedReadAndStillDetach(t *testing.T) {
	s := startStub(t, true)
	_, portString, _ := net.SplitHostPort(s.addr)
	port, _ := strconv.Atoi(portString)
	c, err := Dial(port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.ReadMemory(0x80000000, 4); err == nil {
		t.Fatal("accepted malformed memory reply")
	}
	if err = c.Close(); err != nil {
		t.Fatal(err)
	}
	s.checkDone(t)
}
func TestRejectUnsafeReadSizesAndPort(t *testing.T) {
	if _, err := Dial(-1, time.Second); err == nil {
		t.Fatal("accepted invalid port")
	}
	if _, err := Dial(2, 31*time.Second); err == nil {
		t.Fatal("accepted unbounded timeout")
	}
	c := &Client{}
	for _, size := range []int{0, MaxRead + 1} {
		if _, err := c.ReadMemory(0, size); err == nil {
			t.Fatal("accepted invalid size")
		}
	}
	if _, err := c.ReadMemory(0xfffffffe, 4); err == nil {
		t.Fatal("accepted wrapping address")
	}
}
