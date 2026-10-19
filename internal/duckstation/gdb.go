// Package duckstation implements a read-only remote debugger inspector.
package duckstation

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

const MaxRead = 4096

// Client only connects to the emulator's loopback debug stub. A connection
// briefly halts emulation; Close sends D and waits for its acknowledgment.
type Client struct {
	conn     net.Conn
	detached bool
}

func Dial(port int, timeout time.Duration) (*Client, error) {
	if port < 1 || port > 65535 {
		return nil, errors.New("invalid GDB stub port")
	}
	if timeout <= 0 || timeout > 30*time.Second {
		return nil, errors.New("timeout must be between 1ms and 30s")
	}
	conn, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), timeout)
	if err != nil {
		return nil, fmt.Errorf("DuckStation GDB stub not reachable on localhost:%d: %w", port, err)
	}
	if err = conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		conn.Close()
		return nil, err
	}
	c := &Client{conn: conn}
	if _, err = c.request("?"); err != nil {
		conn.Close()
		return nil, fmt.Errorf("DuckStation GDB handshake: %w", err)
	}
	return c, nil
}

func (c *Client) receive() (string, error) {
	// RSP responses are bounded: no infinitely growing buffer on a broken stub.
	var payload []byte
	var one [1]byte
	for {
		if _, err := io.ReadFull(c.conn, one[:]); err != nil {
			return "", err
		}
		if one[0] == '$' {
			break
		}
		if one[0] == '-' {
			return "", errors.New("GDB stub rejected request")
		}
	}
	for len(payload) <= 2*MaxRead+1024 {
		if _, err := io.ReadFull(c.conn, one[:]); err != nil {
			return "", err
		}
		if one[0] == '#' {
			break
		}
		payload = append(payload, one[0])
	}
	if len(payload) > 2*MaxRead+1024 {
		return "", errors.New("oversized GDB packet")
	}
	var sum [2]byte
	if _, err := io.ReadFull(c.conn, sum[:]); err != nil {
		return "", err
	}
	check, err := strconv.ParseUint(string(sum[:]), 16, 8)
	if err != nil {
		return "", fmt.Errorf("invalid GDB checksum: %w", err)
	}
	var checksum byte
	for _, v := range payload {
		checksum += v
	}
	if byte(check) != checksum {
		_, _ = c.conn.Write([]byte("-"))
		return "", errors.New("GDB packet checksum mismatch")
	}
	if _, err := c.conn.Write([]byte("+")); err != nil {
		return "", err
	}
	if bytes.ContainsAny(payload, "}") {
		return "", errors.New("escaped GDB packet not supported by read-only inspector")
	}
	reply := string(payload)
	if strings.HasPrefix(reply, "E") && len(reply) <= 3 {
		return "", fmt.Errorf("GDB remote error %q", reply)
	}
	return reply, nil
}
func (c *Client) request(command string) (string, error) {
	if c.conn == nil || c.detached {
		return "", errors.New("GDB connection closed")
	}
	var checksum byte
	for i := 0; i < len(command); i++ {
		checksum += command[i]
	}
	if _, err := fmt.Fprintf(c.conn, "$%s#%02x", command, checksum); err != nil {
		return "", err
	}
	return c.receive()
}

// ReadMemory is a non-mutating memory read. It does not accept arbitrary GDB
// commands and bounds each transaction to 1024 bytes as the legacy client did.
func (c *Client) ReadMemory(addr uint32, length int) ([]byte, error) {
	if length < 1 || length > MaxRead {
		return nil, fmt.Errorf("read size must be 1..%d", MaxRead)
	}
	if uint64(addr)+uint64(length) > 1<<32 {
		return nil, errors.New("memory read wraps address space")
	}
	output := make([]byte, 0, length)
	for len(output) < length {
		n := length - len(output)
		if n > 1024 {
			n = 1024
		}
		raw, err := c.request(fmt.Sprintf("m%x,%x", uint64(addr)+uint64(len(output)), n))
		if err != nil {
			return nil, err
		}
		if len(raw) != n*2 {
			return nil, fmt.Errorf("short GDB read: got %d hex characters, want %d", len(raw), n*2)
		}
		data, err := hex.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("invalid GDB memory response: %w", err)
		}
		output = append(output, data...)
	}
	return output, nil
}

// Close sends detach on all normal and failure paths, allowing a paused
// emulator to continue; callers should defer Close immediately after Dial.
func (c *Client) Close() error {
	if c == nil || c.conn == nil || c.detached {
		return nil
	}
	c.detached = true
	// Renew deadline after any read timeout so detach is still attempted.
	_ = c.conn.SetDeadline(time.Now().Add(2 * time.Second))
	var checksum byte
	checksum += 'D'
	_, err := fmt.Fprintf(c.conn, "$D#%02x", checksum)
	if err == nil {
		_, err = c.receive()
	}
	closeErr := c.conn.Close()
	if err != nil {
		return fmt.Errorf("could not confirm emulator detach: %w", err)
	}
	return closeErr
}
