package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"tokimemo/internal/duckstation"
)

func cmdScreenCheck(args []string) error {
	fs := flag.NewFlagSet("screen-check", flag.ContinueOnError)
	fs.SetOutput(commandOutput)
	name := fs.String("name", "title", "known screen detector (currently title)")
	screenshot := fs.String("png", "", "path to a DuckStation screenshot PNG")
	jsonFormat := fs.Bool("json", false, "print JSON summary")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *screenshot == "" {
		return errors.New("usage: screen-check --name title --png SCREENSHOT.png [--json]")
	}
	if *name != "title" {
		return fmt.Errorf("unknown detector %q (supported: title)", *name)
	}
	stats, err := duckstation.AnalyzeScreen(*screenshot)
	if err != nil {
		return err
	}
	matched := stats.IsTitle()
	if *jsonFormat {
		output := struct {
			Name  string `json:"name"`
			Match bool   `json:"match"`
			duckstation.ScreenStats
		}{*name, matched, stats}
		b, _ := json.MarshalIndent(output, "", "  ")
		fmt.Fprintln(commandOutput, string(b))
	} else {
		fmt.Fprintf(commandOutput, "Screen %q: match=%t; white=%.4f pink=%.4f (%dx%d)\n", *name, matched, stats.WhiteFraction, stats.PinkFraction, stats.Width, stats.Height)
	}
	if !matched {
		return errors.New("screenshot did not match the requested screen")
	}
	return nil
}
