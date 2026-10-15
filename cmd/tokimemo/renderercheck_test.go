package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRendererCheckNativeAndCPUOracle(t *testing.T) {
	root, err := rootDir()
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	previous := commandOutput
	commandOutput = &buf
	defer func() { commandOutput = previous }()
	if err := cmdRendererCheck(root, nil); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "native Go MIPS I/R3000: PASS") {
		t.Fatal(buf.String())
	}
	if err := cmdRendererCheck(root, []string{"--compare-python"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "pairs") {
		t.Fatal("CPU interpreter did not report glyph-pair coverage")
	}
	if err := cmdRendererCheck(root, []string{"--bogus"}); err == nil {
		t.Fatal("unknown flag accepted")
	}
}
