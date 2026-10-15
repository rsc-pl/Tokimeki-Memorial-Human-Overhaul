package main

import (
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"tokimemo/internal/graphics"
)

// These values come from the Python source assembler, not from a Go-generated
// binary. The independent fixture lives in internal/graphics/testdata.
const rendererCodeSHA = "f330b360d68df9067d3e4ddc5973154e66703f72a95fb5f064dff40be2b52916"
const rendererFontSHA = "04ba1cac4684341dfa4a74d1af902f5e183e7d8cccbf9110d1c361fcb3636f80"
const rendererSiteHex = "0f110108ffff6830"

func cmdRendererCheck(root string, argv []string) error {
	fs := flag.NewFlagSet("renderer-check", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	compare := fs.Bool("compare-python", false, "run the legacy CPU-interpreter test for all supported English pairs")
	if err := fs.Parse(argv); err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return errors.New("usage: tokimemo renderer-check [--compare-python]")
	}
	site, code, font, scratch, err := graphics.RendererBuild()
	if err != nil {
		return err
	}
	if hex.EncodeToString(site) != rendererSiteHex || hexSHA(code) != rendererCodeSHA || hexSHA(font) != rendererFontSHA || len(code) != 216 || scratch != 0x8004451c {
		return errors.New("native renderer assembler does not match Python reference; refusing to certify")
	}
	say("Assembler", "native Go MIPS I/R3000: PASS")
	say("Hook bytes", fmt.Sprintf("%d bytes; SHA-256 %s", len(code), rendererCodeSHA))
	say("Scratch glyph", fmt.Sprintf("0x%08x", scratch))
	say("Font table", "768 bytes; Python SHA-256 reference: PASS")
	if *compare {
		python := os.Getenv("TOKIMEMO_PYTHON")
		if python == "" {
			python = "python3"
		}
		command := exec.Command(python, filepath.Join(root, "legacy_scripts", "tools", "check_renderer.py"))
		command.Dir = root
		command.Env = pythonEnv(root)
		data, err := command.CombinedOutput()
		if err != nil {
			return fmt.Errorf("Python CPU-interpreter oracle: %w: %s", err, strings.TrimSpace(string(data)))
		}
		say("MIPS emulator", strings.TrimSpace(string(data)))
	}
	return nil
}
