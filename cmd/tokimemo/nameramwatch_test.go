package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"tokimemo/internal/graphics"
	"tokimemo/internal/nametables"
)

func TestNameRAMWatchOnlyReadsAndDetaches(t *testing.T) {
	site, _, font, _, err := graphics.RendererBuild()
	if err != nil {
		t.Fatal(err)
	}
	region := make([]byte, nametables.NarrowRAMBytes)
	copy(region, font)
	memory := map[string][]byte{
		"8004f2cc": site,
		"8004b778": region,
		"800b6d40": {0x6a, 0x94, 0, 0},
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var mu sync.Mutex
	commands := []string{}
	done := make(chan error, 1)
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		send := func(s string) error {
			var checksum byte
			for i := 0; i < len(s); i++ {
				checksum += s[i]
			}
			_, e := fmt.Fprintf(conn, "$%s#%02x", s, checksum)
			return e
		}
		var one [1]byte
		for {
			if _, e = io.ReadFull(conn, one[:]); e != nil {
				done <- e
				return
			}
			if one[0] != '$' {
				continue
			}
			command := []byte{}
			for {
				if _, e = io.ReadFull(conn, one[:]); e != nil {
					done <- e
					return
				}
				if one[0] == '#' {
					break
				}
				command = append(command, one[0])
			}
			sum := make([]byte, 2)
			if _, e = io.ReadFull(conn, sum); e != nil {
				done <- e
				return
			}
			cmd := string(command)
			mu.Lock()
			commands = append(commands, cmd)
			mu.Unlock()
			switch {
			case cmd == "?":
				e = send("T05")
			case cmd == "D":
				e = send("OK")
				done <- e
				return
			case strings.HasPrefix(cmd, "m"):
				args := strings.Split(strings.TrimPrefix(cmd, "m"), ",")
				if len(args) != 2 {
					done <- fmt.Errorf("bad read %q", cmd)
					return
				}
				n, e2 := strconv.ParseInt(args[1], 16, 32)
				if e2 != nil {
					done <- e2
					return
				}
				value, ok := memory[args[0]]
				if !ok || len(value) != int(n) {
					done <- fmt.Errorf("bad address/size %q", cmd)
					return
				}
				e = send(fmt.Sprintf("%x", value))
			default:
				done <- fmt.Errorf("unsafe GDB command: %q", cmd)
				return
			}
			if e != nil {
				done <- e
				return
			}
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	sample, err := captureN10RAM(port, 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !sample.Assessment.RendererSiteMatches || !sample.Assessment.RendererFontMatches || !sample.Assessment.BufferAIsZero || !sample.Assessment.BufferBIsZero || sample.Assessment.RuntimeSafe || sample.OverlayLBA != 37994 {
		t.Fatalf("unexpected sample %+v", sample)
	}
	select {
	case e := <-done:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("missing GDB detach")
	}
	mu.Lock()
	joined := strings.Join(commands, ";")
	mu.Unlock()
	if !strings.HasSuffix(joined, ";D") || !bytes.Equal([]byte(joined), []byte("?;m8004f2cc,8;m8004b778,3b4;m800b6d40,4;D")) {
		t.Errorf("unexpected GDB commands: %s", joined)
	}
}
