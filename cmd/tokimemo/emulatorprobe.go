package main

// Read-only scene/state inspector for DuckStation on Linux and other
// platforms. No breakpoints, register writes, cheat patches, or memory writes.

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strconv"
	"strings"
	"time"

	"tokimemo/internal/duckstation"
)

type sceneSnapshot struct {
	Schema    int    `json:"schema"`
	State     byte   `json:"state"`
	Stage     byte   `json:"stage"`
	Step      byte   `json:"step"`
	Girl      byte   `json:"girl"`
	Scene     uint32 `json:"scene"`
	SceneGirl uint32 `json:"scene_girl"`
}

func readScene(c *duckstation.Client) (sceneSnapshot, error) {
	a, err := c.ReadMemory(0x800e7388, 3)
	if err != nil {
		return sceneSnapshot{}, err
	}
	b, err := c.ReadMemory(0x800e71df, 1)
	if err != nil {
		return sceneSnapshot{}, err
	}
	d, err := c.ReadMemory(0x80122cd0, 8)
	if err != nil {
		return sceneSnapshot{}, err
	}
	return sceneSnapshot{1, a[0], a[1], a[2], b[0], binary.LittleEndian.Uint32(d[:4]), binary.LittleEndian.Uint32(d[4:])}, nil
}
func cmdEmulatorProbe(args []string) (retErr error) {
	fs := flag.NewFlagSet("emulator-probe", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	port := fs.Int("port", 2345, "local DuckStation GDB stub port")
	timeout := fs.Duration("timeout", 5*time.Second, "GDB connection/read deadline (maximum 30s)")
	state := fs.Bool("state", false, "read state/stage/step/scene/girl values from known game RAM")
	address := fs.String("address", "", "read-only RAM address, e.g. 0x800e7388")
	size := fs.Int("size", 16, "read length (1..4096 bytes)")
	jsonFormat := fs.Bool("json", false, "emit structured machine-readable JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: emulator-probe [--state] [--address 0xADDR --size N] [--port 2345] [--json]")
	}
	if !*state && *address == "" {
		return errors.New("specify --state or --address for read-only diagnostics")
	}
	if *size < 1 || *size > duckstation.MaxRead {
		return fmt.Errorf("size must be 1..%d", duckstation.MaxRead)
	}
	if *timeout <= 0 || *timeout > 30*time.Second {
		return errors.New("invalid timeout")
	}
	var at uint64
	if *address != "" {
		v, err := strconv.ParseUint(*address, 0, 32)
		if err != nil {
			return fmt.Errorf("invalid memory address: %w", err)
		}
		at = v
		// Restrict to PS1 RAM segments for stable, safe read-only scene checks.
		physical := uint32(at) & 0x1fffffff
		if (((uint32(at) & 0xe0000000) != 0x80000000) && ((uint32(at) & 0xe0000000) != 0xa0000000)) || physical >= 0x200000 || uint64(physical)+uint64(*size) > 0x200000 {
			return errors.New("address must be inside KSEG0/KSEG1 2 MiB PS1 RAM")
		}
	}
	c, err := duckstation.Dial(*port, *timeout)
	if err != nil {
		return err
	}
	defer func() {
		if e := c.Close(); e != nil {
			if retErr == nil {
				retErr = e
			} else {
				retErr = fmt.Errorf("%w; detach: %v", retErr, e)
			}
		}
	}()
	result := map[string]any{"schema": 1, "mode": "read_only", "emulator": "DuckStation"}
	if *state {
		snap, err := readScene(c)
		if err != nil {
			return fmt.Errorf("reading scene: %w", err)
		}
		result["scene_state"] = snap
	}
	if *address != "" {
		raw, err := c.ReadMemory(uint32(at), *size)
		if err != nil {
			return fmt.Errorf("reading memory: %w", err)
		}
		h := sha256.Sum256(raw)
		result["address"] = fmt.Sprintf("0x%08x", at)
		result["size"] = len(raw)
		result["sha256"] = hex.EncodeToString(h[:])
		if len(raw) <= 64 {
			result["hex"] = hex.EncodeToString(raw)
		}
	}
	// Confirm detach before claiming that a captured state is complete.
	if err = c.Close(); err != nil {
		return err
	}
	if *jsonFormat {
		out, err := json.MarshalIndent(result, "", "  ")
		if err != nil {
			return err
		}
		fmt.Fprintln(commandOutput, string(out))
		return nil
	}
	fmt.Fprintln(commandOutput, "DuckStation GDB diagnostics: READ ONLY (emulator resumes after detach)")
	if s, ok := result["scene_state"].(sceneSnapshot); ok {
		fmt.Fprintf(commandOutput, "State=%#02x  Stage=%d  Step=%d  Girl=%d  Scene=%#x  SceneGirl=%d\n", s.State, s.Stage, s.Step, s.Girl, s.Scene, s.SceneGirl)
	}
	if *address != "" {
		fmt.Fprintf(commandOutput, "RAM %s: %d bytes; SHA-256 %s\n", strings.ToLower(result["address"].(string)), result["size"], result["sha256"])
	}
	return nil
}
