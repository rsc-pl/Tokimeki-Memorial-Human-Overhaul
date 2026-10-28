// Source-preserving extraction of name-table composition primitives.
package nametables

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"sort"
)

type NameOfflineTransaction struct {
	Originals    map[string][]byte
	StagedEXE    []byte
	StagedEXESHA [32]byte
	CurrentShort []string
	TargetShort  []string
	TargetFull   []string
	GEKOG2Policy string
}
type NameDiffRange struct {
	Start        int `json:"start"`
	EndExclusive int `json:"end_exclusive"`
}
type NameImageDiff struct {
	Name          string          `json:"name"`
	InputSHA256   string          `json:"input_sha256"`
	OutputSHA256  string          `json:"output_sha256"`
	ChangedBytes  int             `json:"changed_bytes"`
	AllowedRanges []NameDiffRange `json:"allowed_ranges"`
}
type NameOfflineTransactionReport struct {
	ShortBytes      int                    `json:"short_bytes"`
	FullFirstBytes  int                    `json:"full_first_bytes"`
	FullSecondBytes int                    `json:"full_second_bytes"`
	RewrittenA      int                    `json:"rewritten_a"`
	RewrittenB      int                    `json:"rewritten_b"`
	AliasSources    int                    `json:"alias_sources"`
	GEKOG2Policy    string                 `json:"geko_g2_policy"`
	ParserCalls     int                    `json:"parser_calls"`
	ParserGuarded   bool                   `json:"parser_guarded"`
	Presentation    NamePresentationReport `json:"presentation"`
	Diffs           []NameImageDiff        `json:"diffs"`
	RuntimeVerified bool                   `json:"runtime_verified"`
	SafeToPatch     bool                   `json:"safe_to_patch"`
}

func nameAllowRange(m map[string][]NameDiffRange, name string, a, b int) {
	m[name] = append(m[name], NameDiffRange{Start: a, EndExclusive: b})
}

func namePhase2AllowedDiffs() map[string][]NameDiffRange {
	m := make(map[string][]NameDiffRange)
	nameAllowRange(m, EXE, 0xb278, 0xb278+132)
	nameAllowRange(m, EXE, NameFullPoolStart, NamePhase2SpareEnd)
	nameAllowRange(m, EXE, PointerTable, PointerTable+Entries*4)
	for _, p := range verifiedFixedDirectEXE {
		nameAllowRange(m, EXE, p.UpperOffset, p.UpperOffset+4)
		nameAllowRange(m, EXE, p.LowerOffset, p.LowerOffset+4)
	}
	for _, a := range []int{0x3ff94, 0x40068} {
		nameAllowRange(m, EXE, a, a+4)
	}
	for name, pairs := range namePhase2ASites {
		for _, p := range pairs {
			base := namePhase2Base[name]
			nameAllowRange(m, name, int(p[0]-base), int(p[0]-base)+4)
			nameAllowRange(m, name, int(p[1]-base), int(p[1]-base)+4)
		}
	}
	for name, pairs := range namePhase2BSites {
		for _, p := range pairs {
			base := namePhase2Base[name]
			nameAllowRange(m, name, int(p[0]-base), int(p[0]-base)+4)
			nameAllowRange(m, name, int(p[1]-base), int(p[1]-base)+4)
		}
	}
	for _, p := range verifiedFixedDirectGEKO {
		nameAllowRange(m, "GEKO.EXN", p.UpperOffset, p.UpperOffset+4)
		nameAllowRange(m, "GEKO.EXN", p.LowerOffset, p.LowerOffset+4)
	}
	for _, a := range []int{0xf47c, 0xf480} {
		nameAllowRange(m, "GEKO.EXN", a, a+4)
	}
	for k, v := range m {
		sort.Slice(v, func(i, j int) bool { return v[i].Start < v[j].Start })
		merged := make([]NameDiffRange, 0, len(v))
		for _, r := range v {
			if len(merged) > 0 && r.Start <= merged[len(merged)-1].EndExclusive {
				if r.EndExclusive > merged[len(merged)-1].EndExclusive {
					merged[len(merged)-1].EndExclusive = r.EndExclusive
				}
			} else {
				merged = append(merged, r)
			}
		}
		m[k] = merged
	}
	return m
}

func nameCheckDiff(name string, before, after []byte, ranges []NameDiffRange) (NameImageDiff, error) {
	if len(before) != len(after) {
		return NameImageDiff{}, fmt.Errorf("%s image length changed", name)
	}
	out := NameImageDiff{Name: name, InputSHA256: fmt.Sprintf("%x", sha256.Sum256(before)), OutputSHA256: fmt.Sprintf("%x", sha256.Sum256(after)), AllowedRanges: ranges}
	j := 0
	for i := range before {
		if before[i] == after[i] {
			continue
		}
		out.ChangedBytes++
		for j < len(ranges) && ranges[j].EndExclusive <= i {
			j++
		}
		if j >= len(ranges) || i < ranges[j].Start || i >= ranges[j].EndExclusive {
			return NameImageDiff{}, fmt.Errorf("%s out-of-scope mutation at file offset %#x", name, i)
		}
	}
	return out, nil
}

func ComposeNamePhase2Offline(input NameOfflineTransaction) (map[string][]byte, NameOfflineTransactionReport, error) {
	fail := func(stage string, e error) (map[string][]byte, NameOfflineTransactionReport, error) {
		return nil, NameOfflineTransactionReport{}, fmt.Errorf("Name offline transaction %s: %w", stage, e)
	}
	if sha256.Sum256(input.StagedEXE) != input.StagedEXESHA {
		return fail("revision", fmt.Errorf("staged EXE digest changed"))
	}
	if input.GEKOG2Policy != NameGEKOBare && input.GEKOG2Policy != NameGEKOSan {
		return fail("policy", fmt.Errorf("GEKO G2 requires explicit bare or san"))
	}
	if len(input.CurrentShort) != Entries || len(input.TargetShort) != Entries || len(input.TargetFull) != Entries {
		return fail("names", fmt.Errorf("expected exactly 16 current short, target short, and full names"))
	}
	if len(input.Originals) != 4 {
		return fail("originals", fmt.Errorf("requires four authenticated originals"))
	}
	for name, hash := range namePhase2ImageSHA {
		b, exists := input.Originals[name]
		if !exists || fmt.Sprintf("%x", sha256.Sum256(b)) != hash {
			return fail("originals", fmt.Errorf("%s original digest mismatch", name))
		}
	}

	parserContract, err := InspectNameParserContract(input.Originals[EXE])
	if err != nil {
		return fail("parser contract", err)
	}
	if parserContract.SafeToPatch || parserContract.RuntimeGuardImplemented {
		return fail("parser contract", fmt.Errorf("unexpected parser boot authorization"))
	}
	if err := CheckStagedNameParserPreimage(input.Originals[EXE], input.StagedEXE, parserContract); err != nil {
		return fail("parser staged preimage", err)
	}
	staged, short, err := StageInRendererPool(input.StagedEXE, input.CurrentShort, input.TargetShort)
	if err != nil {
		return fail("short", err)
	}
	if short.NewBytes <= 0 || short.NewBytes > 132 || short.PointerCount != Entries {
		return fail("short", fmt.Errorf("unexpected short layout"))
	}
	staged, full, err := StageFullNameSplit(staged, sha256.Sum256(staged), input.TargetFull)
	if err != nil {
		return fail("full", err)
	}
	if full.FirstBytes <= 0 || full.FirstBytes > 184 || full.SecondBytes <= 0 || full.SecondBytes > 44 || full.PointerWords != Entries {
		return fail("full", fmt.Errorf("unexpected full layout"))
	}
	aliasedEXE, aliasedGEKO, aliases, err := StageDirectFixedAliases(staged, input.Originals["GEKO.EXN"], input.TargetShort)
	if err != nil {
		return fail("aliases", err)
	}
	if aliases.EXEDirectRewrites != 3 || aliases.EXEInheritedRewrites != 1 || aliases.GEKODirectRewrites != 1 {
		return fail("aliases", fmt.Errorf("incomplete alias sites"))
	}
	stagedImages := map[string][]byte{EXE: aliasedEXE, "GEKO.EXN": aliasedGEKO, "SHUGAKU.EXN": input.Originals["SHUGAKU.EXN"], "SHOUGATU.EXN": input.Originals["SHOUGATU.EXN"]}
	stagedImages, ab, err := StagePhase2AB(input.Originals, stagedImages)
	if err != nil {
		return fail("buffers", err)
	}
	if ab.RewrittenA != 16 || ab.RewrittenB != 12 {
		return fail("buffers", fmt.Errorf("incomplete 16+12 address pairs"))
	}
	finalEXE, finalGEKO, g2, err := StageGEKOG2(stagedImages[EXE], stagedImages["GEKO.EXN"], input.Originals["GEKO.EXN"], input.GEKOG2Policy, input.TargetShort[11])
	if err != nil {
		return fail("GEKO G2", err)
	}
	stagedImages[EXE], stagedImages["GEKO.EXN"] = finalEXE, finalGEKO
	if g2.Policy != input.GEKOG2Policy || !g2.UnsafeToBoot {
		return fail("GEKO G2", fmt.Errorf("unexpected policy or safety status"))
	}

	presentation, err := AuditNamePresentation(stagedImages, input.TargetShort, input.TargetFull, input.GEKOG2Policy)
	if err != nil {
		return fail("presentation", err)
	}
	allowed := namePhase2AllowedDiffs()
	report := NameOfflineTransactionReport{ShortBytes: short.NewBytes, FullFirstBytes: full.FirstBytes, FullSecondBytes: full.SecondBytes, RewrittenA: ab.RewrittenA, RewrittenB: ab.RewrittenB, AliasSources: aliases.EXEDirectRewrites + aliases.EXEInheritedRewrites + aliases.GEKODirectRewrites, GEKOG2Policy: input.GEKOG2Policy, ParserCalls: len(parserContract.Sites), Presentation: presentation}
	for _, name := range []string{EXE, "GEKO.EXN", "SHUGAKU.EXN", "SHOUGATU.EXN"} {
		before := input.Originals[name]
		if name == EXE {
			before = input.StagedEXE
		}
		diff, err := nameCheckDiff(name, before, stagedImages[name], allowed[name])
		if err != nil {
			return fail("byte scope", err)
		}
		report.Diffs = append(report.Diffs, diff)
	}

	if bytes.Equal(stagedImages[EXE], input.StagedEXE) {
		return fail("diff", fmt.Errorf("EXE unexpectedly unchanged"))
	}
	return stagedImages, report, nil
}
