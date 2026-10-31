package fullenglish

// Builds the complete English and name-rendering edit plan in memory.
// Translation and executable changes are checked against the same pristine
// game bytes, with conflicts rejected before any output is published.
// The original disc, translation sources and save files are not modified.

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"tokimemo/internal/graphics"
	n "tokimemo/internal/n20arch"
	"tokimemo/internal/ps1"
)

type fullISOReader struct {
	track   io.ReaderAt
	sectors int64
	iso     *ps1.ISO
}

func (r fullISOReader) ReadFile(path string) ([]byte, error) {
	e, ok := r.iso.Entries[path]
	if !ok || e.IsDir {
		return nil, fmt.Errorf("ISO entry missing: %s", path)
	}
	if e.Size < 0 || e.Size > 128<<20 {
		return nil, fmt.Errorf("ISO file size out of bounds: %s", path)
	}
	var b bytes.Buffer
	if err := ps1.ReadFileTo(r.track, r.sectors, e.LBA, e.Size, &b); err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	return b.Bytes(), nil
}

type fullConflict struct {
	File    string `json:"file"`
	Offset  int    `json:"offset"`
	Retail  string `json:"retail"`
	English string `json:"english"`
	N20     string `json:"n20"`
}

func fullHash(data []byte) string { h := sha256.Sum256(data); return hex.EncodeToString(h[:]) }
func fullCorpusFiles(root string) ([]string, string, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return nil, "", err
	}
	files, err := filepath.Glob(filepath.Join(root, "translation", "*.json"))
	if err != nil {
		return nil, "", err
	}
	sort.Strings(files)
	if len(files) < 70 {
		return nil, "", fmt.Errorf("incomplete translation corpus: %d JSON files", len(files))
	}
	h := sha256.New()
	assetPaths, err := filepath.Glob(filepath.Join(root, "translation", "graphics", "*.png"))
	if err != nil {
		return nil, "", err
	}
	sort.Strings(assetPaths)
	all := append(append([]string{}, files...), assetPaths...)
	for _, p := range all {
		b, e := os.ReadFile(p)
		if e != nil {
			return nil, "", e
		}
		rel, err := filepath.Rel(root, p)
		if err != nil {
			return nil, "", err
		}
		fmt.Fprintf(h, "%s %s\n", filepath.ToSlash(rel), fullHash(b))
	}
	return files, hex.EncodeToString(h.Sum(nil)), nil
}

// fullReadN20 composes the authenticated integrated baseline and direct
// saved-name queue hooks against the same retail bytes. The base 414-word
// manifest is checked separately from the 13 additional hook records.
func fullReadN20(source fullISOReader) (n.N20IntegratedPlan, []n.N20ManifestWord, error) {
	var empty n.N20IntegratedPlan
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return empty, nil, err
	}
	originals := map[string][]byte{}
	for p, e := range source.iso.Entries {
		if !strings.HasPrefix(p, "CDROM/EXEDIR/") || !strings.HasSuffix(p, ".EXN") || e.IsDir {
			continue
		}
		name := strings.TrimPrefix(p, "CDROM/EXEDIR/")
		if strings.Contains(name, "/") {
			continue
		}
		data, e := source.ReadFile(p)
		if e != nil {
			return empty, nil, e
		}
		originals[name] = data
	}
	base, err := n.PlanIntegratedN20Build(exe, originals)
	if err != nil {
		return empty, nil, err
	}
	if _, err = verify(base, exe, originals); err != nil {
		return empty, nil, err
	}
	h4, err := n.N20DirectQueueCoResident(exe, originals)
	if err != nil {
		return empty, nil, fmt.Errorf("direct-name queue composition refused: %w", err)
	}
	if len(h4.Words) != 13 || len(h4.ChangedCarrierSHA) != 4 || h4.SafeToPatch || h4.RuntimePass || !bytes.Equal(h4.PatchedEXE, base.PatchedEXE) {
		return empty, nil, errors.New("direct-name queue accounting/safety drift")
	}
	if err = checkDirectNameLayer(base.PatchedOverlays, h4.PatchedOverlays, originals, h4.Words, h4.ChangedCarrierSHA); err != nil {
		return empty, nil, fmt.Errorf("direct-name queue readback: %w", err)
	}
	base.PatchedOverlays = h4.PatchedOverlays
	// The public compositor uses only the authenticated integrated layer.
	// Experimental resident/queue variants are deliberately not selectable.
	return base, h4.Words, nil
}

// The authenticated combined romanization candidate is verified for exact
// source ownership. Its runtime-safety status is not inferred from this check.
func fullReadCombinedRomanizer(source fullISOReader) (n.CombinedQACandidate, error) {
	var empty n.CombinedQACandidate
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return empty, err
	}
	originals := make(map[string][]byte, len(n.OverlaySHA))
	for name := range n.OverlaySHA {
		b, err := source.ReadFile("CDROM/EXEDIR/" + name)
		if err != nil {
			return empty, fmt.Errorf("combined romanization source %s: %w", name, err)
		}
		originals[name] = b
	}
	out, err := n.PlanCombinedQAOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	if !out.Blocked || out.SafeToPatch || out.RuntimePass || out.ResidentUsed != 3792 ||
		out.ExactSurnameCallsites != 16 || out.KeyboardQueueCallsites != 42 ||
		out.OptionNicknameCallsites != 2 || len(out.Overlays) != len(n.OverlaySHA) ||
		!out.MergeChecksumValid {
		return empty, errors.New("combined romanization safety/coverage/accounting drift")
	}
	return out, nil
}

// overlay allocation read-only alternate plan: same complete English corpus as combined romanization, but the
// C10 executable is relinked to eligible overlay-local RAM, with all persistent
// promotion hooks removed. Four occupied source windows remain fallback-only.
// This is NEVER an executable-image authorization.
func fullReadOverlay(source fullISOReader) (n.OverlayLocalCandidate, error) {
	var empty n.OverlayLocalCandidate
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return empty, err
	}
	originals := make(map[string][]byte, len(n.OverlaySHA))
	for name := range n.OverlaySHA {
		b, e := source.ReadFile("CDROM/EXEDIR/" + name)
		if e != nil {
			return empty, fmt.Errorf("overlay allocation original %s: %w", name, e)
		}
		originals[name] = b
	}
	out, err := n.PlanOverlayLocalOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	if !out.Blocked || out.SafeToPatch || out.RuntimePass || !out.PersistentPromotionRemoved || len(out.Carriers) != 22 || len(out.FallbackOverlays) != 4 {
		return empty, errors.New("overlay allocation overlay-local scope/safety drift")
	}
	return out, nil
}

// overlay dispatch uses the *same complete English corpus* with fail-closed overlay-local
// C10 integrity checking. It is plan-only, never an image creator.
func fullReadOverlayDispatch(source fullISOReader) (n.OverlayDispatchIntegrityCandidate, error) {
	var empty n.OverlayDispatchIntegrityCandidate
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return empty, err
	}
	originals := make(map[string][]byte, len(n.OverlaySHA))
	for name := range n.OverlaySHA {
		b, e := source.ReadFile("CDROM/EXEDIR/" + name)
		if e != nil {
			return empty, fmt.Errorf("overlay dispatch original %s: %w", name, e)
		}
		originals[name] = b
	}
	out, err := n.PlanOverlayLocalIntegrityOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	if !out.Blocked || out.SafeToPatch || out.RuntimePass || !out.BodyIntegrityGuarded || !out.PersistentPromotionRemoved || len(out.Carriers) != 22 || len(out.FallbackOverlays) != 4 {
		return empty, errors.New("overlay dispatch scope/safety drift")
	}
	return out, nil
}

// overlay formatter replaces overlay dispatch's order-insensitive XOR sentinel with a reversible,
// order-dependent 32-bit rolling guard in the same 64-byte EXE space. It
// remains an offline full-English plan with 22 carriers and 4 fallbacks.
func fullReadOverlayFormatter(source fullISOReader) (n.OverlayFormatterIntegrityCandidate, error) {
	var empty n.OverlayFormatterIntegrityCandidate
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return empty, err
	}
	originals := make(map[string][]byte, len(n.OverlaySHA))
	for name := range n.OverlaySHA {
		b, e := source.ReadFile("CDROM/EXEDIR/" + name)
		if e != nil {
			return empty, fmt.Errorf("overlay formatter original %s: %w", name, e)
		}
		originals[name] = b
	}
	out, err := n.PlanOverlayLocalOrderIntegrityOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	if !out.Blocked || out.SafeToPatch || out.RuntimePass || !out.OrderSensitiveSentinel || !out.PersistentPromotionRemoved || len(out.Carriers) != 22 || len(out.FallbackOverlays) != 4 {
		return empty, errors.New("overlay formatter scope/safety drift")
	}
	return out, nil
}

// formatter interposition keeps the COMPLETE English corpus and adds only the three authenticated
// interposed surname callsite JAL words to the overlay formatter offline source candidate.
func fullReadRomanizerInterposer(source fullISOReader) (n.InterposedCandidate, error) {
	var empty n.InterposedCandidate
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return empty, err
	}
	originals := make(map[string][]byte, len(n.OverlaySHA))
	for name := range n.OverlaySHA {
		b, e := source.ReadFile("CDROM/EXEDIR/" + name)
		if e != nil {
			return empty, fmt.Errorf("formatter interposition original %s: %w", name, e)
		}
		originals[name] = b
	}
	out, err := n.PlanInterposedSurnameOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	if !out.Blocked || out.SafeToPatch || out.RuntimePass || out.SpeakerSurnameCalls != 19 ||
		len(out.NewlyRoutedSurnamePCs) != 3 || len(out.Carriers) != 22 || len(out.FallbackOverlays) != 4 {
		return empty, errors.New("formatter interposition scope/safety drift")
	}
	return out, nil
}

// tail guard adds full executable guard coverage and source-bound OLH help-menu
// correction to the formatter interposition candidate. Never builds or patches a disc.
func fullReadTailGuard(source fullISOReader) (n.GuardTailCandidate, error) {
	var empty n.GuardTailCandidate
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return empty, err
	}
	originals := make(map[string][]byte, len(n.OverlaySHA))
	for name := range n.OverlaySHA {
		b, e := source.ReadFile("CDROM/EXEDIR/" + name)
		if e != nil {
			return empty, fmt.Errorf("tail guard original %s: %w", name, e)
		}
		originals[name] = b
	}
	out, err := n.PlanGuardTailIntegrityOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	if !out.Blocked || out.SafeToPatch || out.RuntimePass || !out.GuardTailCovered || out.VerifiedExecutableBytes != 4040 || out.SpeakerSurnameCalls != 19 || len(out.Carriers) != 22 || len(out.FallbackOverlays) != 4 || out.OriginalOLHHelpTables.StaticPointers != 47 {
		return empty, errors.New("tail guard safety/coverage drift")
	}
	return out, nil
}

// memory ownership enforces the authenticated original-overlay C10 source-ownership
// boundary before attempting a FULL English in-memory merge. The scan
// excludes only bounded direct accesses, never certifies indirect CPU/DMA
// writes. No output image can be built from this candidate.
func fullReadOwnership(source fullISOReader) (n.BoundedCandidate, error) {
	var empty n.BoundedCandidate
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return empty, err
	}
	originals := make(map[string][]byte, len(n.OverlaySHA))
	for name := range n.OverlaySHA {
		data, e := source.ReadFile("CDROM/EXEDIR/" + name)
		if e != nil {
			return empty, fmt.Errorf("memory ownership original %s: %w", name, e)
		}
		originals[name] = data
	}
	out, err := n.PlanBoundedOwnershipOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	if !out.Blocked || out.SafeToPatch || out.RuntimePass || out.Boundary.ProvenExclusiveOwnership ||
		out.Boundary.Carriers != 22 || out.Boundary.FallbackOverlays != 4 ||
		out.SpeakerSurnameCalls != 19 || !out.GuardTailCovered {
		return empty, errors.New("memory ownership original-memory boundary safety/accounting drift")
	}
	return out, nil
}

// formatter bridge: authentic complete-English, READ-ONLY variant containing four newly
// integrated surname+space formatter JALs through the existing terminal gate.
// Not a runtime-authorized image and never writes the English corpus.
func fullReadFormatter(source fullISOReader) (n.FormatterIntegratedCandidate, error) {
	var empty n.FormatterIntegratedCandidate
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return empty, err
	}
	originals := make(map[string][]byte, len(n.OverlaySHA))
	for name := range n.OverlaySHA {
		data, e := source.ReadFile("CDROM/EXEDIR/" + name)
		if e != nil {
			return empty, fmt.Errorf("formatter bridge original %s: %w", name, e)
		}
		originals[name] = data
	}
	out, err := n.PlanFormatterIntegratedOffline(exe, originals)
	if err != nil {
		return empty, err
	}
	if !out.Blocked || out.SafeToPatch || out.RuntimePass || out.Boundary.ProvenExclusiveOwnership || len(out.FormatterPCs) != 4 || len(out.Carriers) != 22 || len(out.FallbackOverlays) != 4 || out.SpeakerSurnameCalls != 19 || out.GuardedBytes != 4564 {
		return empty, errors.New("formatter bridge scope/safety drift")
	}
	return out, nil
}

// The direct-name layer may alter exactly four owner overlays, with only the 13 authenticated
// queue JAL words, their module regions and derived trailer checksums changing.
// All other original N6-FP relocations and callsite words remain unchanged.
func checkDirectNameLayer(base, extended, retail map[string][]byte, extra []n.N20ManifestWord, shaByOwner map[string]string) error {
	allowedWords := map[string]map[int]bool{}
	for _, w := range extra {
		if w.Owner == "EXE" || w.Kind != "direct_saved_name_queue_jal" {
			return errors.New("invalid direct-name word classification")
		}
		if _, ok := allowedWords[w.Owner]; !ok {
			allowedWords[w.Owner] = map[int]bool{}
		}
		off := int(w.PC - n.OverlaySlotBase)
		original := retail[w.Owner]
		next := extended[w.Owner]
		if off < 0 || off+8 > len(original) || off+8 > len(next) ||
			binary.LittleEndian.Uint32(original[off:]) != w.Old ||
			binary.LittleEndian.Uint32(base[w.Owner][off:]) != w.Old ||
			binary.LittleEndian.Uint32(next[off:]) != w.New ||
			!bytes.Equal(next[off+4:off+8], original[off+4:off+8]) || allowedWords[w.Owner][off] {
			return fmt.Errorf("direct-name callsite readback %s+%x", w.Owner, off)
		}
		allowedWords[w.Owner][off] = true
	}
	if len(extended) != len(base) || len(shaByOwner) != 4 {
		return errors.New("direct-name carrier count mismatch")
	}
	for name, prev := range base {
		next, ok := extended[name]
		if !ok || len(prev) != len(next) {
			return fmt.Errorf("missing carrier %s", name)
		}
		_, changed := shaByOwner[name]
		if !changed {
			if !bytes.Equal(prev, next) {
				return fmt.Errorf("direct-name changed unexpected carrier %s", name)
			}
			continue
		}
		if fullHash(next) != shaByOwner[name] || !ps1.TailChecksumValid(next) {
			return fmt.Errorf("direct-name checksum mismatch %s", name)
		}
		for i := range prev {
			if prev[i] == next[i] {
				continue
			}
			module := i >= n.OLPayloadFileOff && i < n.OLPayloadEndOff
			checksum := i >= len(prev)-4 && i < len(prev)-2
			word := allowedWords[name][i&^3]
			if !module && !checksum && !word {
				return fmt.Errorf("direct-name unmanifested byte %s+%x", name, i)
			}
		}
	}
	return nil
}

// Merge in memory. Every genuine shared-byte edit is refused, even when both
// replacements are equal: the two planners may expect different semantics.
// The derived two-byte overlay checksum is excluded from overlap detection,
// then recalculated exactly once on the merged result.
func fullMergeFile(path string, retail, english, n20 []byte) ([]byte, int, []fullConflict, error) {
	if len(retail) != len(english) || len(retail) != len(n20) {
		return nil, 0, nil, fmt.Errorf("ISO file length changed %s", path)
	}
	result := bytes.Clone(retail)
	clashes := 0
	samples := []fullConflict{}
	checksum := strings.HasSuffix(path, ".EXN") && ps1.TailChecksumValid(retail)
	for i := range retail {
		ed := english[i] != retail[i]
		nd := n20[i] != retail[i]
		if checksum && i >= len(retail)-4 && i < len(retail)-2 {
			continue
		}
		if ed && nd {
			clashes++
			if len(samples) < 30 {
				samples = append(samples, fullConflict{path, i, fmt.Sprintf("%02x", retail[i]), fmt.Sprintf("%02x", english[i]), fmt.Sprintf("%02x", n20[i])})
			}
			continue
		}
		if nd {
			result[i] = n20[i]
		} else if ed {
			result[i] = english[i]
		}
	}
	if clashes > 0 {
		return nil, clashes, samples, nil
	}
	if checksum {
		if err := ps1.FixTailChecksum(result); err != nil {
			return nil, 0, nil, err
		}
	}
	return result, 0, nil, nil
}

// The English renderer deliberately clears its reserved 180-byte tail. resident module
// installs guarded MIPS code into exactly that tail. The ordinary merger must
// still refuse ALL other overlaps. The only explicit common ownership is
// waived here after byte-for-byte authentication of the English reservation.
func c10ExactRendererTailConflict(retail, translated, n20EXE []byte) ([]byte, error) {
	if len(retail) != len(translated) || len(retail) != len(n20EXE) {
		return nil, errors.New("resident module EXE lengths differ")
	}
	start := int(n.C10EXEGuardF1 - 0x80040800)
	end := start + n.C10EXEGuardTailBytes
	if end > len(retail) {
		return nil, errors.New("resident module renderer reservation outside EXE")
	}
	for i := start; i < end; i++ {
		if translated[i] != 0 {
			return nil, fmt.Errorf("resident module English tail nonzero at %x", i)
		}
	}
	if bytes.Equal(retail[start:end], n20EXE[start:end]) {
		return nil, errors.New("resident module EXE guard tail missing")
	}
	// Release only this precisely pre-authorized renderer reservation back to
	// retail for the conflict detector. N20 owns the complete 180-byte result;
	// dialogue/text and all other renderer glyphs retain the normal rules.
	corrected := bytes.Clone(translated)
	copy(corrected[start:end], retail[start:end])
	return corrected, nil
}

func fullCompose(source fullISOReader, english map[string][]byte, n20 n.N20IntegratedPlan) (map[string][]byte, int, []fullConflict, error) {
	files := map[string][]byte{}
	for p, b := range english {
		files[p] = b
	}
	files["SLPM_86.053"] = files["SLPM_86.053"]
	for name := range n20.PatchedOverlays {
		p := "CDROM/EXEDIR/" + name
		files[p] = files[p]
	}
	collisions := 0
	examples := []fullConflict{}
	out := map[string][]byte{}
	names := make([]string, 0, len(files))
	for p := range files {
		names = append(names, p)
	}
	sort.Strings(names)
	for _, p := range names {
		retail, err := source.ReadFile(p)
		if err != nil {
			return nil, 0, nil, err
		}
		translated, ok := english[p]
		if !ok {
			translated = retail
		}
		changed := retail
		if p == "SLPM_86.053" {
			changed = n20.PatchedEXE
		} else if strings.HasPrefix(p, "CDROM/EXEDIR/") {
			if v, ok := n20.PatchedOverlays[strings.TrimPrefix(p, "CDROM/EXEDIR/")]; ok {
				changed = v
			}
		}
		merged, num, bad, err := fullMergeFile(p, retail, translated, changed)
		if err != nil {
			return nil, 0, nil, err
		}
		collisions += num
		for _, c := range bad {
			if len(examples) < 40 {
				examples = append(examples, c)
			}
		}
		if num == 0 && !bytes.Equal(merged, retail) {
			out[p] = merged
		}
	}
	if collisions > 0 {
		return nil, collisions, examples, nil
	}
	return out, 0, nil, nil
}

// disc validation: combined romanization is already built on the same authenticated English renderer.
// Waive ONLY byte-identical renderer changes that reproduce the current
// production graphics.InstallRenderer on the exact retail EXE. All other
// overlap still fails, including identical values in unrelated code/text.
func fullMergeEXE(retail, english, combinedRomanizerImage []byte) ([]byte, int, []fullConflict, error) {
	return fullMergeEXEOwned(retail, english, combinedRomanizerImage, nil, 0, 0)
}

// pool ownership: combined romanization normally owns the English renderer verbatim. loop guards additionally
// owns the exact N10 string pool and bounded parser guard inside its otherwise
// unused HOOK reservation. The authorized image is produced separately by the
// authenticated N10/N20 planner; the generic combined romanization path cannot waive this area.
// An exclusive, explicitly sized ownership exception keeps all other renderer
// bytes under combined romanization's byte-perfect preimage check.
func fullMergeEXEOwned(retail, english, combinedRomanizerImage, authorized []byte, ownerStart, ownerEnd int) ([]byte, int, []fullConflict, error) {
	renderer, err := graphics.InstallRenderer(retail)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("combined romanization retail renderer auth: %w", err)
	}
	adjusted, err := c10ExactRendererTailConflict(retail, english, combinedRomanizerImage)
	if err != nil {
		return nil, 0, nil, fmt.Errorf("combined romanization renderer tail: %w", err)
	}
	if len(retail) != len(combinedRomanizerImage) || len(renderer) != len(combinedRomanizerImage) {
		return nil, 0, nil, errors.New("combined romanization EXE size drift")
	}
	lo := int(n.C10EXEGuardF1 - 0x80040800)
	hi := lo + n.C10EXEGuardTailBytes
	const expectedStart = int(n.ShortHookSpareRAM - n.Base)
	const expectedEnd = expectedStart + n.ShortHookSpareBytes + 308
	if authorized != nil && (len(authorized) != len(retail) || ownerStart != expectedStart || ownerEnd != expectedEnd || ownerEnd > len(retail) || (ownerStart < hi && ownerEnd > lo)) {
		return nil, 0, nil, errors.New("pool ownership invalid N10 ownership reservation")
	}
	for i := range retail {
		owned := authorized != nil && i >= ownerStart && i < ownerEnd
		if owned {
			// Both the retail image and installed renderer are pinned by the
			// authenticated planner. Its exclusive reserved bytes must be zero
			// in the current English renderer. Never waive EN changes here.
			if renderer[i] != 0 || english[i] != renderer[i] || combinedRomanizerImage[i] != authorized[i] {
				return nil, 0, nil, fmt.Errorf("pool ownership N10 exclusive renderer reservation drift EXE+%#x", i)
			}
			// English renderer's zero-filled allocation is relinquished only
			// inside this exact region, so N10 is treated as its sole writer.
			adjusted[i] = retail[i]
		} else if (i < lo || i >= hi) && renderer[i] != retail[i] && combinedRomanizerImage[i] != renderer[i] {
			return nil, 0, nil, fmt.Errorf("combined romanization modified required English renderer EXE+%#x", i)
		}
		if adjusted[i] != retail[i] && combinedRomanizerImage[i] != retail[i] &&
			renderer[i] != retail[i] && adjusted[i] == renderer[i] && combinedRomanizerImage[i] == renderer[i] {
			adjusted[i] = retail[i]
		}
	}
	return fullMergeFile("SLPM_86.053", retail, adjusted, combinedRomanizerImage)
}

// The complete English patchplan output and combined romanization share exactly the same retail
// reader and sector planner. This is a PLAN ONLY: it cannot write an image.
func fullComposeCombined(source fullISOReader, english map[string][]byte, combinedRomanizerImage n.CombinedQACandidate) (map[string][]byte, int, []fullConflict, error) {
	return fullComposeCombinedWithEXEMerge(source, english, combinedRomanizerImage, fullMergeEXE)
}

func fullComposeCombinedWithEXEMerge(source fullISOReader, english map[string][]byte, combinedRomanizerImage n.CombinedQACandidate, mergeEXE func([]byte, []byte, []byte) ([]byte, int, []fullConflict, error)) (map[string][]byte, int, []fullConflict, error) {
	if !combinedRomanizerImage.Blocked || combinedRomanizerImage.SafeToPatch || combinedRomanizerImage.RuntimePass ||
		len(combinedRomanizerImage.Overlays) != len(n.OverlaySHA) || len(combinedRomanizerImage.EnglishEXE) == 0 {
		return nil, 0, nil, errors.New("combined romanization candidate not safely blocked")
	}
	files := make(map[string]bool, len(english)+len(combinedRomanizerImage.Overlays)+1)
	for path := range english {
		files[path] = true
	}
	files["SLPM_86.053"] = true
	for name := range combinedRomanizerImage.Overlays {
		files["CDROM/EXEDIR/"+name] = true
	}
	names := make([]string, 0, len(files))
	for path := range files {
		names = append(names, path)
	}
	sort.Strings(names)
	out := make(map[string][]byte)
	collisions := 0
	examples := []fullConflict{}
	for _, path := range names {
		retail, err := source.ReadFile(path)
		if err != nil {
			return nil, 0, nil, err
		}
		translated, ok := english[path]
		if !ok {
			translated = retail
		}
		candidate := retail
		if path == "SLPM_86.053" {
			candidate = combinedRomanizerImage.EnglishEXE
		} else if strings.HasPrefix(path, "CDROM/EXEDIR/") {
			if v, ok := combinedRomanizerImage.Overlays[strings.TrimPrefix(path, "CDROM/EXEDIR/")]; ok {
				candidate = v
			}
		}
		var merged []byte
		var count int
		var bad []fullConflict
		if path == "SLPM_86.053" {
			merged, count, bad, err = mergeEXE(retail, translated, candidate)
		} else {
			merged, count, bad, err = fullMergeFile(path, retail, translated, candidate)
		}
		if err != nil {
			return nil, 0, nil, err
		}
		collisions += count
		for _, c := range bad {
			if len(examples) < 40 {
				examples = append(examples, c)
			}
		}
		if count == 0 && !bytes.Equal(merged, retail) {
			out[path] = merged
		}
	}
	if collisions != 0 {
		return nil, collisions, examples, nil
	}
	if _, ok := out["SLPM_86.053"]; !ok {
		return nil, 0, nil, errors.New("combined romanization lost English executable")
	}
	if _, ok := out["CDROM/EXEDIR/NAME_ENT.EXN"]; !ok {
		return nil, 0, nil, errors.New("combined romanization lost NAME_ENT")
	}
	return out, 0, nil, nil
}

// disc validation: prove that independently authored JP->EN content survives the
// combined romanization merger. A correct renderer alone is NOT evidence of a translated game.
// The proof is byte-for-byte relative to the authenticated retail source,
// excluding only derived EXN checksum bytes; combined romanization has no right to replace
// independently translated story/UI bytes. The source reader remains read-only.
func fullEnglishContentProof(source fullISOReader, english, combined map[string][]byte) (int, int, error) {
	preservedFiles, preservedBytes := 0, 0
	for path, translated := range english {
		// Renderer changes and C10 code are not translated dialogue.
		if path == "SLPM_86.053" {
			continue
		}
		original, err := source.ReadFile(path)
		if err != nil {
			return 0, 0, fmt.Errorf("disc validation original content %s: %w", path, err)
		}
		got, ok := combined[path]
		if !ok || len(original) != len(translated) || len(got) != len(original) {
			return 0, 0, fmt.Errorf("disc validation English content missing or size drift: %s", path)
		}
		count := 0
		checksum := strings.HasSuffix(path, ".EXN") && ps1.TailChecksumValid(original)
		for i := range original {
			if checksum && i >= len(original)-4 && i < len(original)-2 {
				continue
			}
			if original[i] != translated[i] {
				if got[i] != translated[i] {
					return 0, 0, fmt.Errorf("disc validation English edit overwritten by combined romanization: %s +%#x", path, i)
				}
				count++
			}
		}
		if count > 0 {
			preservedFiles++
			preservedBytes += count
		}
	}
	if preservedFiles == 0 || preservedBytes == 0 {
		return 0, 0, errors.New("disc validation REFUSED: merged candidate has no proven JP->EN content outside the executable renderer")
	}
	return preservedFiles, preservedBytes, nil
}

func fullSectorDeltas(source fullISOReader, modified map[string][]byte) ([]sectorDelta, error) {
	used := map[int64]string{}
	out := []sectorDelta{}
	paths := make([]string, 0, len(modified))
	for p := range modified {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		e, ok := source.iso.Entries[p]
		if !ok || e.IsDir || e.Size != int64(len(modified[p])) {
			return nil, fmt.Errorf("unexpected ISO extent %s", p)
		}
		count := (e.Size + ps1.DataSize - 1) / ps1.DataSize
		for _, other := range source.iso.Entries {
			if other.Path == p || ps1.IsExternalTrackAudio(other) || other.IsDir {
				continue
			}
			length := (other.Size + ps1.DataSize - 1) / ps1.DataSize
			if e.LBA < other.LBA+length && other.LBA < e.LBA+count {
				return nil, fmt.Errorf("overlapping ISO files: %s and %s", p, other.Path)
			}
		}
		original, err := source.ReadFile(p)
		if err != nil {
			return nil, err
		}
		for j := int64(0); j < count; j++ {
			lba := e.LBA + j
			if lba < 0 || lba >= source.sectors {
				return nil, fmt.Errorf("ISO sector outside Track1: %s %d", p, lba)
			}
			if who, ok := used[lba]; ok {
				return nil, fmt.Errorf("shared ISO sector %d: %s and %s", lba, p, who)
			}
			used[lba] = p
			start := int(j * ps1.DataSize)
			end := start + ps1.DataSize
			if end > len(original) {
				end = len(original)
			}
			if bytes.Equal(original[start:end], modified[p][start:end]) {
				continue
			}
			raw, err := ps1.ReadSectorAt(source.track, lba)
			if err != nil {
				return nil, err
			}
			if err = ps1.VerifyForm1(raw); err != nil {
				return nil, fmt.Errorf("invalid source sector %d: %w", lba, err)
			}
			if !bytes.Equal(raw[ps1.DataOffset:ps1.DataOffset+end-start], original[start:end]) {
				return nil, fmt.Errorf("sector source mismatch %s LBA %d", p, lba)
			}
			next := bytes.Clone(raw)
			copy(next[ps1.DataOffset:ps1.DataOffset+end-start], modified[p][start:end])
			if err = ps1.RegenerateForm1(next); err != nil {
				return nil, err
			}
			if err = ps1.VerifyForm1(next); err != nil {
				return nil, err
			}
			out = append(out, sectorDelta{LBA: lba, Before: raw, After: next, Files: []string{p}})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].LBA < out[j].LBA })
	return out, nil
}
