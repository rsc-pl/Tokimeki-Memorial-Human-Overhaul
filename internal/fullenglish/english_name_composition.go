package fullenglish

// Composes the source-authored English name tables with saved-name rendering.
// Candidate names used by regression tests do not replace live translated
// names. All supported GEKO layouts must validate independently; layout
// selection does not authorize a translation or establish runtime RAM safety.
import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"tokimemo/internal/graphics"
	n "tokimemo/internal/n20arch"
	nametables "tokimemo/internal/namepatch"
	"tokimemo/internal/patchplan"
	"tokimemo/internal/ps1"
	"tokimemo/internal/script"
)

// These lists are a byte-for-byte reification of the already tested name fixture
// engineering fixture. They are not silently promoted to reviewed translation.
var imageCompositionCurrent = []string{"Shiori", "Mio", "Himoo", "Ayako", "Nijino", "Yukari", "Nozomi", "Mira", "Yuko", "Megumi", "Yumi", "Miharu", "Ijuin", "Yoshio", "Sotoi", "Yumi"}
var imageCompositionShort = []string{"Fujisaki", "Kisaragi", "Himoo", "Katagiri", "Nijino", "Koshiki", "Kiyokawa", "Kagami", "Asahina", "Mikihara", "Saotome", "Tatebayashi", "Ijuin", "Yoshio", "Sotoi", "Yumi"}
var imageCompositionFull = []string{"Fujisaki Shiori", "Kisaragi Mio", "Himoo Yuina", "Katagiri Ayako", "Nijino Saki", "Koshiki Yukari", "Kiyokawa Nozomi", "Kagami Mira", "Asahina Yuko", "Mikihara Megumi", "Saotome Yumi", "Tatebayashi Miharu", "Ijuin Rei", "Saotome Yoshio", "Sotoi Yukinojou", "Player"}

func imageCompositionInput(retail []byte, overlays map[string][]byte, policy string) (nametables.N10OfflineTransaction, error) {
	if policy != nametables.N10GEKOBare && policy != nametables.N10GEKOSan {
		return nametables.N10OfflineTransaction{}, errors.New("English image composition requires named GEKO policy")
	}
	stage, err := graphics.InstallRenderer(retail)
	if err != nil {
		return nametables.N10OfflineTransaction{}, err
	}
	if len(imageCompositionCurrent) != nametables.Entries || len(imageCompositionShort) != nametables.Entries || len(imageCompositionFull) != nametables.Entries {
		return nametables.N10OfflineTransaction{}, errors.New("invalid research fixture names")
	}
	clear(stage[nametables.ShortStart:nametables.ShortEnd])
	pos := nametables.ShortStart
	for i, v := range imageCompositionCurrent {
		raw, e := (&script.PairEncoder{}).Encode(v)
		if e != nil {
			return nametables.N10OfflineTransaction{}, e
		}
		if pos+len(raw)+1 > nametables.ShortEnd {
			return nametables.N10OfflineTransaction{}, errors.New("English image composition fixture name pool overflow")
		}
		copy(stage[pos:], raw)
		stage[pos+len(raw)] = 0
		binary.LittleEndian.PutUint32(stage[nametables.PointerTable+4*i:], nametables.Base+uint32(pos))
		pos += len(raw) + 1
	}
	originals := map[string][]byte{"SLPM_86.053": retail}
	for _, name := range []string{"GEKO.EXN", "SHUGAKU.EXN", "SHOUGATU.EXN"} {
		b, ok := overlays[name]
		if !ok {
			return nametables.N10OfflineTransaction{}, fmt.Errorf("missing N10 original %s", name)
		}
		originals[name] = b
	}
	return nametables.N10OfflineTransaction{Originals: originals, StagedEXE: stage, StagedEXESHA: sha256.Sum256(stage), CurrentShort: append([]string(nil), imageCompositionCurrent...), TargetShort: append([]string(nil), imageCompositionShort...), TargetFull: append([]string(nil), imageCompositionFull...), GEKOG2Policy: policy}, nil
}

// authoritativeSourceNames obtains the authoritative CURRENT game names from the
// translated English executable, not the name fixture/English image composition engineering target fixture.
// The owner will later edit surname strings in translation source; this layer
// must never decide to promote an unintroduced Girl to Asahina by fiat.
func ownerEnglishSourceNames(retail []byte, english []byte) ([]string, []string, error) {
	short, err := namePoolLayoutReadNameSlots(english, retail, namePoolLayoutShortPointer, namePoolLayoutShortPoolStart, namePoolLayoutShortPointer)
	if err != nil {
		return nil, nil, fmt.Errorf("source name composition live short names: %w", err)
	}
	full, err := namePoolLayoutReadNameSlots(english, retail, namePoolLayoutFullPointer, namePoolLayoutFullPoolStart, namePoolLayoutFullPointer)
	if err != nil {
		return nil, nil, fmt.Errorf("source name composition live full names: %w", err)
	}
	sh, fu := make([]string, nametables.Entries), make([]string, nametables.Entries)
	for i := range sh {
		sh[i], fu[i] = short[i].value, full[i].value
	}
	if err := namePoolLayoutConfirmNameOwnership(retail, english, sh, fu); err != nil {
		return nil, nil, err
	}
	return sh, fu, nil
}

// sourceNameInput stages verbatim live EN names, never a surname fixture. Its
// authenticated retail original is used only for physical instruction checks;
// all game-visible label decisions come from the translated EXE.
func ownerEnglishInput(retail []byte, overlays map[string][]byte, policy string, currentShort, currentFull []string) (nametables.N10OfflineTransaction, error) {
	if policy != nametables.N10GEKOBare && policy != nametables.N10GEKOSan {
		return nametables.N10OfflineTransaction{}, errors.New("source name composition requires named GEKO policy")
	}
	if len(currentShort) != nametables.Entries || len(currentFull) != nametables.Entries {
		return nametables.N10OfflineTransaction{}, errors.New("source name composition requires 16 source-authored names of both kinds")
	}
	stage, err := graphics.InstallRenderer(retail)
	if err != nil {
		return nametables.N10OfflineTransaction{}, err
	}
	clear(stage[nametables.ShortStart:nametables.ShortEnd])
	pos := nametables.ShortStart
	for i, value := range currentShort {
		raw, e := (&script.PairEncoder{}).Encode(value)
		if e != nil {
			return nametables.N10OfflineTransaction{}, fmt.Errorf("source name composition source short %d: %w", i, e)
		}
		if len(raw) == 0 || pos+len(raw)+1 > nametables.ShortEnd {
			return nametables.N10OfflineTransaction{}, fmt.Errorf("source name composition current English names exceed short staging capacity at index %d", i)
		}
		copy(stage[pos:], raw)
		stage[pos+len(raw)] = 0
		binary.LittleEndian.PutUint32(stage[nametables.PointerTable+4*i:], nametables.Base+uint32(pos))
		pos += len(raw) + 1
	}
	originals := map[string][]byte{"SLPM_86.053": retail}
	for _, name := range []string{"GEKO.EXN", "SHUGAKU.EXN", "SHOUGATU.EXN"} {
		v, ok := overlays[name]
		if !ok {
			return nametables.N10OfflineTransaction{}, fmt.Errorf("source name composition missing original %s", name)
		}
		originals[name] = v
	}
	return nametables.N10OfflineTransaction{Originals: originals, StagedEXE: stage, StagedEXESHA: sha256.Sum256(stage),
		CurrentShort: append([]string(nil), currentShort...), TargetShort: append([]string(nil), currentShort...),
		TargetFull: append([]string(nil), currentFull...), GEKOG2Policy: policy}, nil
}

// long-name source: N10 source-authored surnames may be longer than the old 8-byte slots.
// Keep the original short-stage labels to authenticate the legacy tables, but
// transfer the actual selected final labels separately (without global rename).
func longNameInput(retail []byte, overlays map[string][]byte, policy string, stageShort, desiredShort, desiredFull []string) (nametables.N10OfflineTransaction, error) {
	tx, err := ownerEnglishInput(retail, overlays, policy, stageShort, desiredFull)
	if err != nil {
		return tx, err
	}
	if len(desiredShort) != nametables.Entries {
		return tx, errors.New("long-name source requires 16 source-owned NPC surnames")
	}
	tx.TargetShort = append([]string(nil), desiredShort...)
	return tx, nil
}

type imageCompositionPolicyResult struct {
	PrivateCUE          string         `json:"private_cue,omitempty"`
	ImageBuilt          bool           `json:"image_built"`
	Policy              string         `json:"geko_policy"`
	Status              string         `json:"status"`
	Blocker             string         `json:"blocker,omitempty"`
	ConflictBytes       int            `json:"conflict_bytes"`
	ConflictExamples    []fullConflict `json:"conflict_examples,omitempty"`
	EnglishContentFiles int            `json:"english_content_files"`
	EnglishContentBytes int            `json:"english_content_bytes"`
	MergedFiles         int            `json:"merged_files"`
	PlannedSectors      int            `json:"planned_sectors"`
	GuardedLoops        int            `json:"n10_manual_loops"`
	N10BIOSCalls        int            `json:"n10_bios_calls"`
	N20Overlays         int            `json:"n20_overlay_count"`
	NPCLabelGeometry    string         `json:"npc_label_geometry,omitempty"`
	NPCFormatterScratch string         `json:"npc_formatter_scratch,omitempty"`
}

type imageCompositionReport struct {
	Schema              int                            `json:"schema"`
	Status              string                         `json:"status"`
	SafeToPatch         bool                           `json:"safe_to_patch"`
	RuntimePass         bool                           `json:"runtime_pass"`
	ImageBuilt          bool                           `json:"image_built"`
	SourceCUE           string                         `json:"source_cue"`
	CorpusJSONs         int                            `json:"corpus_jsons"`
	CorpusSHA256        string                         `json:"corpus_sha256"`
	CorpusStrings       int                            `json:"corpus_strings"`
	CorpusDialogue      int                            `json:"corpus_dialogue"`
	DeferredLongNames   int                            `json:"n10_deferred_long_names"`
	NameEntryLabels     string                         `json:"name_entry_labels"`
	RendererInstalled   bool                           `json:"renderer_installed"`
	ResearchFixtureOnly bool                           `json:"n10_research_fixture_only"`
	EditorialWarning    string                         `json:"editorial_warning"`
	GekoDecision        string                         `json:"geko_owner_decision"`
	RuntimeBlocker      string                         `json:"runtime_blocker"`
	Policies            []imageCompositionPolicyResult `json:"policies"`
}

// composeFullEnglishPlan validates both name-layout policies and provides the
// complete, checked production edit plan. No diagnostic image-write mode is
// reachable through this API.
func composeFullEnglishPlan(root, cuePath string, w io.Writer, selected *map[string][]byte) error {
	report := imageCompositionReport{Schema: 1, Status: "NOT_CHECKED", SafeToPatch: false, RuntimePass: false, ImageBuilt: false, SourceCUE: cuePath, ResearchFixtureOnly: false,
		EditorialWarning: "long-name source conversion: labels are taken from the live English EXE or exact oversized character_names.json source records, never from historic surname fixtures. GEKO branches remain diagnostic; no owner choice inferred.", GekoDecision: "PENDING",
		RuntimeBlocker: "No exclusive overlay-local C10 code RAM/CPU/DMA/IRQ ownership proof, complete parser NUL/alias proof or in-game GPU/layout QA. Offline validation does not establish runtime safety; image generation is permitted by the builder but gameplay safety remains unverified."}
	out := func() error { return json.NewEncoder(w).Encode(report) }
	paths, digest, err := fullCorpusFiles(root)
	if err != nil {
		report.Status = "CORPUS_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	report.CorpusJSONs = len(paths)
	report.CorpusSHA256 = digest
	cue, err := parseRetailCue(cuePath)
	if err != nil {
		report.Status = "DISC_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	file, err := os.Open(cue.Track1)
	if err != nil {
		return err
	}
	defer file.Close()
	st, err := file.Stat()
	if err != nil {
		return err
	}
	if !st.Mode().IsRegular() || st.Size() != 298500*ps1.SectorSize {
		report.Status = "DISC_BLOCKED"
		report.RuntimeBlocker = "wrong source Track1 geometry"
		return out()
	}
	sectors := st.Size() / ps1.SectorSize
	iso, err := ps1.OpenISO(file, sectors)
	if err != nil {
		report.Status = "DISC_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	source := fullISOReader{file, sectors, iso}
	marker, err := source.ReadFile("SYSTEM.CNF")
	if err != nil || !bytes.Contains(marker, []byte("cdrom:SLPM_86.053")) {
		report.Status = "DISC_BLOCKED"
		report.RuntimeBlocker = "unknown original boot marker"
		return out()
	}
	batch, err := patchplan.Load(root, paths)
	if err != nil {
		report.Status = "CORPUS_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	report.CorpusStrings = len(batch.Strings)
	report.CorpusDialogue = len(batch.Dialogue)
	// Name-entry labels are loaded from translation/ only, with no hidden
	// filesystem inputs or auto-import from private research directories.
	batch, report.NameEntryLabels, err = nameEntryLabelsAddNameLabels(root, batch)
	if err != nil {
		report.Status = "GRAPHICS_SOURCE_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	// long-name source allows ONLY authenticated N10-owned long name slots to be
	// deferred. The public fixed-slot planner remains unmodified.
	originalEXE, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		report.Status = "DISC_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	originalGEKO, err := source.ReadFile("CDROM/EXEDIR/GEKO.EXN")
	if err != nil {
		report.Status = "DISC_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	nameBatch, deferredNames, err := longNameSeparateLongNames(originalEXE, originalGEKO, batch)
	if err != nil {
		report.Status = "CORPUS_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	// dialogue name pool: a name dialogue pool may exceed its TOTAL 124-byte budget even
	// when long-name source already deferred individual fixed-slot overruns (132/124).
	// Defer only wholly authenticated N10 short/full pools, not other text.
	nameBatch, dialogueNames, err := npcDialogueNamesSeparateNPCNameDialogue(originalEXE, nameBatch)
	if err != nil {
		report.Status = "CORPUS_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	deferredNames = append(deferredNames, dialogueNames...)
	report.DeferredLongNames = len(deferredNames)
	engReport, english, err := patchplan.PlanBytes(source, nameBatch)
	if err != nil {
		report.Status = "CORPUS_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	report.RendererInstalled = engReport.RendererInstalled
	if !report.RendererInstalled {
		report.Status = "CORPUS_BLOCKED"
		report.RuntimeBlocker = "production English renderer missing"
		return out()
	}
	exe, err := source.ReadFile("SLPM_86.053")
	if err != nil {
		return err
	}
	overlays := map[string][]byte{}
	for name := range n.OverlaySHA {
		v, e := source.ReadFile("CDROM/EXEDIR/" + name)
		if e != nil {
			return e
		}
		overlays[name] = v
	}
	// Fail closed if the English build has a missing, ambiguous, unrecognized,
	// or malformed 16-entry name table. There is NO fallback to English image composition names.
	liveEXE, ok := english["SLPM_86.053"]
	if !ok {
		report.Status = "CORPUS_BLOCKED"
		report.RuntimeBlocker = "source name composition translated EXE missing; refusing fallback fixture"
		return out()
	}
	if err := longNameApplyNameStage(liveEXE, deferredNames); err != nil {
		report.Status = "CORPUS_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	liveShort, _, targetShort, targetFull, err := longNameSourceNames(exe, liveEXE, deferredNames)
	if err != nil {
		report.Status = "INTEGRATION_BLOCKED"
		report.RuntimeBlocker = err.Error()
		return out()
	}
	// layout restoration: speaker geometry's six-site NPC speaker-X experiment was REJECTED by the
	// In-game testing found additional overlap for long surnames.
	// The source-owned N10 long names remain, but no speaker geometry-only length gate
	// or unverified label movement is allowed in the composed image.
	formatterBridgeStage, err := n.PlanFormatterIntegratedOffline(exe, overlays)
	if err != nil {
		report.Status = "INTEGRATION_BLOCKED"
		report.RuntimeBlocker = "formatter bridge: " + err.Error()
		return out()
	}
	results := make([]imageCompositionPolicyResult, 0, 2)

	for _, policy := range []string{nametables.N10GEKOBare, nametables.N10GEKOSan} {
		item := imageCompositionPolicyResult{Policy: policy, Status: "INTEGRATION_BLOCKED"}
		tx, e := longNameInput(exe, overlays, policy, liveShort, targetShort, targetFull)
		if e != nil {
			item.Blocker = e.Error()
			results = append(results, item)
			continue
		}
		manualCopyStage, e := n.PlanAllManualLoopsOffline(exe, overlays, tx)
		if e != nil {
			item.Blocker = e.Error()
			results = append(results, item)
			continue
		}
		if manualCopyStage.SafeToPatch || manualCopyStage.RuntimePass || manualCopyStage.ImageBuilt || manualCopyStage.TotalGuardedManualLoops != 22 || manualCopyStage.PatchedCalls != 32 || !bytes.Equal(formatterBridgeStage.EnglishEXE[int(n.C10EXEGuardF1-0x80040800):int(n.C10EXEGuardF1-0x80040800)+n.C10EXEGuardTailBytes], manualCopyStage.EnglishRendererEXE[int(n.C10EXEGuardF1-0x80040800):int(n.C10EXEGuardF1-0x80040800)+n.C10EXEGuardTailBytes]) {
			item.Blocker = "loop guards safety or N20 guard preservation drift"
			results = append(results, item)
			continue
		}
		mergedCandidate := formatterBridgeStage.CombinedQACandidate
		mergedCandidate.EnglishEXE = manualCopyStage.EnglishRendererEXE
		mergedCandidate.Overlays = manualCopyStage.Overlays
		// direct name hooks: the owner already relies on 15 dynamic surname/given/nickname
		// sites in four existing overlay carriers. A future source/merge drift
		// must abort before any private ISO write, rather than silently show kana.
		if hookErr := n.VerifyDirectSavedNameHooks(overlays, mergedCandidate.Overlays); hookErr != nil {
			item.Blocker = "direct name hooks existing player-name route integrity: " + hookErr.Error()
			results = append(results, item)
			continue
		}
		mergedCandidate.ExactSurnameCallsites = 19
		// The combined romanization merger predates N10's authenticated relocation into the
		// English renderer's previously zero-filled HOOK spare. Its strict
		// validator is kept for every other caller: pool ownership authorizes only
		// 132 pool bytes and the 308-byte guarded parser proven by loop guards.
		const namePoolGuardPoolAndGuardStart = int(n.ShortHookSpareRAM - n.Base)
		const namePoolGuardPoolAndGuardBytes = n.ShortHookSpareBytes + 308
		if manualCopyStage.GuardCodeBytes != 308 || namePoolGuardPoolAndGuardStart+namePoolGuardPoolAndGuardBytes > len(manualCopyStage.EnglishRendererEXE) {
			item.Blocker = "pool ownership authenticated N10 renderer reservation footprint changed"
			results = append(results, item)
			continue
		}
		mergeN10 := func(retail, translated, physical []byte) ([]byte, int, []fullConflict, error) {
			return fullMergeN10Names(retail, translated, physical, manualCopyStage.EnglishRendererEXE,
				namePoolGuardPoolAndGuardStart, namePoolGuardPoolAndGuardStart+namePoolGuardPoolAndGuardBytes,
				liveShort, targetFull)
		}
		physical, clashes, examples, e := fullComposeCombinedWithEXEMerge(source, english, mergedCandidate, mergeN10)
		item.ConflictBytes = clashes
		item.ConflictExamples = examples
		if e != nil {
			item.Blocker = e.Error()
			results = append(results, item)
			continue
		}
		if clashes > 0 {
			item.Status = "BYTE_CONFLICTS"
			item.Blocker = "current English bytes and N10/N20 code modify the same locations differently"
			results = append(results, item)
			continue
		}
		// layout restoration: preserve the pre-speaker geometry NPC X instructions byte-for-byte.
		// This verification refuses accidental reapplication of the rejected
		// experiment, including partial writes. It does not assert that the
		// original long-surname label geometry is visually correct.
		labelStage, ok := physical["SLPM_86.053"]
		if !ok {
			item.Blocker = "layout restoration: no composed English EXE"
			results = append(results, item)
			continue
		}
		if e = n.VerifyNPCLabelGeometryBaseline(exe, labelStage); e != nil {
			item.Blocker = "layout restoration rejected speaker geometry geometry still active: " + e.Error()
			results = append(results, item)
			continue
		}
		item.NPCLabelGeometry = "rejected_npc_geometry_restored_layout_still_fails"
		// NPC scratch buffer candidate: isolate six NPC-A sprintf temporary strings
		// from the adjacent sp+0x74 scratch. This does not alter layout restoration label X,
		// parser-body layout, the source names, or the public image builder.
		// The destination and synchronous queue pointer must move together.
		scratchEXE, scratchErr := n.PlanPrivateNPCScratch(exe, labelStage, targetShort)
		if scratchErr != nil {
			item.Blocker = "NPC scratch buffer NPC temporary scratch ownership: " + scratchErr.Error()
			results = append(results, item)
			continue
		}
		// formatted length: read label length from the same formatted N10-A source used
		// by the queue, not a possibly stale pre-relocation strlen buffer.
		// No speaker-X/body relocation and no additional runtime storage.
		coherentEXE, lengthErr := n.PlanNPCFormattedLengthPrivate(exe, scratchEXE)
		if lengthErr != nil {
			item.Blocker = "formatted length NPC formatted-name count ownership: " + lengthErr.Error()
			results = append(results, item)
			continue
		}
		// NPC coordinates unverified first-line alternative: keeps retail NPC speaker X;
		// moves quotation prefix and parser together to a conservative
		// max-16-pixel pair-font edge derived from formatted length's actual formatted
		// byte length. No code cave, no public builder changes. This cannot
		// certify right-edge wrapping or in-game VRAM placement.
		coordinatedEXE, layoutErr := n.PlanCoordinatedNPCAFirstLinePrivate(exe, coherentEXE, targetShort)
		if layoutErr != nil {
			item.Blocker = "NPC coordinates private coordinated NPC first-line gate: " + layoutErr.Error()
			results = append(results, item)
			continue
		}
		// NPC spacing owner-directed pragmatic visual compromise: speaker +3,
		// quotation AND parser -1, six NPC-A routes only. Phone and other
		// speaker consumers remain separate. Runtime remains unverified.
		balancedEXE, balanceErr := n.PlanNPCModerateBalancePrivate(exe, coordinatedEXE, targetShort)
		if balanceErr != nil {
			item.Blocker = "NPC spacing private label/quote two-sided compromise: " + balanceErr.Error()
			results = append(results, item)
			continue
		}
		// NPC frame recorded screenshot QA: the left-border frame lip still touches the
		// surname. Translate BOTH label and prefix/body RIGHT by +3 relative
		// to tested NPC spacing, keeping their mutual ink clearance unchanged.
		// NOTE: right-edge text/wrap is NOT certified; user will test once.
		insetEXE, insetErr := n.PlanNPCFrameInsetPrivate(exe, balancedEXE, targetShort)
		if insetErr != nil {
			item.Blocker = "NPC frame private one-time frame inset: " + insetErr.Error()
			results = append(results, item)
			continue
		}
		physical["SLPM_86.053"] = insetEXE
		// exam labels UNVERIFIED: the source-authenticated ETC exam table previously
		// bypassed N20 by calling retail strncat on saved CP932 name fields.
		// Extend the ALREADY-COMPOSED suffix punctuation/N6 ETC carrier (same overlay/guard
		// lifetime), not a second stand-alone module. The lower caption uses
		// the existing N6 surname stub. No save, translation, or public code
		// is mutated; a code/translation conflict is a hard refusal.
		etcPath := "CDROM/EXEDIR/ETC.EXN"
		mergedETC, present := physical[etcPath]
		if !present {
			item.Blocker = "exam labels private ETC integration: merged English ETC.EXN absent"
			results = append(results, item)
			continue
		}
		etcIntegration, etcErr := n.PlanETCExamPrivateOverlay(exe, overlays["ETC.EXN"], mergedETC)
		if etcErr != nil || etcIntegration.SafeToPatch || etcIntegration.RuntimePass {
			item.Blocker = fmt.Sprintf("exam labels private ETC actual join/caption hooks: %v", etcErr)
			results = append(results, item)
			continue
		}
		physical[etcPath] = etcIntegration.Overlay
		// exam integrity: fail closed if either visually accepted exam labels exam fix, the
		// complete local module or an unrelated owner-translated byte drifts.
		// Compare the actual assembled image against the authenticated
		// pre-exam labels English source, never a hardcoded player name.
		if gateErr := n.VerifyFrozenETC(exe, overlays["ETC.EXN"], mergedETC, physical[etcPath]); gateErr != nil {
			item.Blocker = "exam integrity owner-approved ETC image integrity: " + gateErr.Error()
			results = append(results, item)
			continue
		}
		// battle surname PRIVATE: RPG_BAT has an independently authenticated saved-surname
		// strcpy outside the 15 already frozen direct name hooks direct name sites. Install
		// a separate verifier-covered N6 adapter only in the previously unused
		// RPG_BAT local window; formatter bridge C10 and both exam labels ETC hooks remain intact.
		rpgPath := "CDROM/EXEDIR/RPG_BAT.EXN"
		mergedRPG, rpgPresent := physical[rpgPath]
		if !rpgPresent {
			item.Blocker = "battle surname private RPG surname adapter: English RPG_BAT.EXN absent"
			results = append(results, item)
			continue
		}
		rpgIntegration, rpgErr := n.PlanRPGPrivateSurname(overlays["RPG_BAT.EXN"], mergedRPG)
		if rpgErr != nil || rpgIntegration.SafeToPatch || rpgIntegration.RuntimePass {
			item.Blocker = fmt.Sprintf("battle surname private RPG saved-surname hook: %v", rpgErr)
			results = append(results, item)
			continue
		}
		physical[rpgPath] = rpgIntegration.Overlay
		item.NPCLabelGeometry = "npc_frame_inset_runtime_not_proven"
		item.NPCFormatterScratch = "npc_scratch_formatted_length_load_delay_runtime_not_proven"
		files, edited, e := fullEnglishContentProof(source, english, physical)
		if e != nil {
			item.Status = "ENGLISH_CONTENT_BLOCKED"
			item.Blocker = e.Error()
			results = append(results, item)
			continue
		}
		deltas, e := fullSectorDeltas(source, physical)
		if e != nil {
			item.Status = "DISC_BLOCKED"
			item.Blocker = e.Error()
			results = append(results, item)
			continue
		}
		item.EnglishContentFiles = files
		item.EnglishContentBytes = edited
		item.MergedFiles = len(physical)
		item.PlannedSectors = len(deltas)
		item.GuardedLoops = manualCopyStage.TotalGuardedManualLoops
		item.N10BIOSCalls = manualCopyStage.PatchedCalls
		item.N20Overlays = len(manualCopyStage.Overlays)
		item.Status = "COMPLETE_EN_N10_N20_PLAN_PASS_OFFLINE_ONLY"
		if selected != nil && policy == nametables.N10GEKOBare {
			// The validated test image uses the bare diagnostic branch;
			// no new GEKO editorial decision is inferred by this transfer.
			copyMap := make(map[string][]byte, len(physical))
			for file, b := range physical {
				copyMap[file] = bytes.Clone(b)
			}
			*selected = copyMap
		}

		results = append(results, item)
	}
	report.Policies = results
	report.Status = "COMPLETE_EN_N10_N20_INTEGRATION_BLOCKED"
	if len(results) == 2 && results[0].Status == "COMPLETE_EN_N10_N20_PLAN_PASS_OFFLINE_ONLY" && results[1].Status == "COMPLETE_EN_N10_N20_PLAN_PASS_OFFLINE_ONLY" {
		report.Status = "TWO_GEKO_POLICIES_PASS_OFFLINE_NOT_RUNTIME"
	}
	check, digestAfter, e := fullCorpusFiles(root)
	if e != nil || len(check) != len(paths) || digestAfter != digest {
		return errors.New("translation corpus changed while processing English image composition")
	}
	return out()
}

// Production image paths remain unchanged and blocked. Experimental
// staging uses the existing isolated backend with two explicit approval gates.
