package n20arch

import (
	"fmt"
)

// ColdBootVerdict is the explicit verdict for the cold-boot activation
// invariant: no N20 EXE hook may target the overlay window unless the
// authentic dispatcher is already installed.
//
// This corrected prototype DOES NOT satisfy the invariant. Five unconditional
// EXE JALs target 0x80161EDC / 0x80161EE4 before any overlay load. Those bytes
// are zero/absent at cold boot, so the CPU executes NOPs and falls through
// 0x80162000 instead of reaching the retail fallback 0x8004E788.
//
// The verdict is deliberately BLOCKED, not PASS and not FAIL: the defect is
// reproduced and understood, but no source-proven mechanism can fix it under
// the standing constraints (no boot/preload EXE hook, no resident RAM, no
// proven EXE code cave, no authenticated overlay scene-entry/LBA mapping).
type ColdBootVerdict string

const (
	ColdBootPass    ColdBootVerdict = "PASS"
	ColdBootFail    ColdBootVerdict = "FAIL"
	ColdBootBlocked ColdBootVerdict = "BLOCKED"
)

const (
	// ColdBootActivationVerdict is BLOCKED. Do not change this to PASS until
	// one of the dependencies below is met and independently tested.
	ColdBootActivationVerdict = ColdBootBlocked

	// ColdBootGuardBytes is the exact size of the two encoded fail-closed
	// guards below: 40 B for the formatter class and 40 B for the speaker
	// class. Each guard checks its window stub word, tail-Jumps to the window
	// on success and tail-Jumps to 0x8004E788 on failure. This is a lower-bound
	// placement dependency, not a claim that a cave exists.
	ColdBootGuardBytes = 80

	// ColdBootDependency is the precise unresolved dependency. Any future fix
	// must satisfy at least one branch and prove it from source.
	ColdBootDependency = "BLOCKED: five unconditional EXE JALs target 0x80161EDC/0x80161EE4 before any overlay payload/window exists; with a zero/absent window the CPU executes NOPs and falls through 0x80162000, not retail 0x8004E788. No boot/preload EXE hook, no resident RAM, no source-proven executable EXE cave, and no authenticated per-overlay runtime writer/scene-entry mapping are available offline. A PASS requires (a) >=80 B of source-proven executable EXE cave for fail-closed per-class guards (40 B each; 96 B with alignment), or (b) a source-proven deferred writer that installs the hooks only after a verified carrier load (with a verified scene-entry address and LBA->overlay mapping), or (c) a complete indirect-CFG proof that no hooked formatter/speaker site is reachable before the first carrier load plus FlushCache."
)

// HookAudit records one authenticated retail hook and the cold-boot problem.
type HookAudit struct {
	Name           string
	PC             uint32
	OriginalWord   uint32
	OriginalTarget uint32
	AppliedWord    uint32
	DelayPC        uint32
	DelayWord      uint32
	TargetInWindow bool
}

// ColdBootAudit is a read-only, offline audit of the activation ordering.
// It does not execute hardware and does not claim a runtime result.
type ColdBootAudit struct {
	EXESHA string
	Hooks  []HookAudit

	// Direct JAL callers inside the pristine EXE. Their existence means a
	// simple "only overlays call the formatter/speaker" reachability argument
	// cannot be made. Indirect call closure remains UNKNOWN.
	FormatterCallers []uint32
	SpeakerCallers   []uint32

	// SceneEntryTable lists the distinct overlay entry addresses written to
	// 0x80123110 by the EXE scene table. They are not one uniform entry.
	SceneEntryTable []uint32

	// PreFirstOverlaySafe is false: before the first carrier load the hook
	// target is zero/absent. ZeroWindow is the best-case synthetic state.
	ZeroWindow          bool
	PreFirstOverlaySafe bool
	Verdict             ColdBootVerdict
	Reason              string
}

// AuditColdBootActivation re-decodes the five changed EXE words from pristine
// bytes and records the unresolved cold-boot dependency. It never writes.
func AuditColdBootActivation(exe []byte) (ColdBootAudit, error) {
	var a ColdBootAudit
	if _, err := VerifyRetailEXE(exe); err != nil {
		return a, err
	}
	a.EXESHA = OriginalEXESHA
	a.ZeroWindow = true
	a.PreFirstOverlaySafe = false
	a.Verdict = ColdBootActivationVerdict
	a.Reason = ColdBootDependency
	for _, h := range RetailHooks {
		orig := wordAt(exe, h.PC)
		applied := jalWord(h.Target)
		a.Hooks = append(a.Hooks, HookAudit{
			Name:           h.Name,
			PC:             h.PC,
			OriginalWord:   orig,
			OriginalTarget: jumpTarget(orig),
			AppliedWord:    applied,
			DelayPC:        h.DelayPC,
			DelayWord:      wordAt(exe, h.DelayPC),
			TargetInWindow: h.Target >= WindowStart && h.Target < WindowStart+WindowBytes,
		})
	}
	a.FormatterCallers = DirectCallers(exe, 0x8007EF48)
	a.SpeakerCallers = DirectCallers(exe, 0x80050DFC)
	a.SceneEntryTable = SceneEntryTable(exe)
	return a, nil
}

// jumpTarget decodes a MIPS J/JAL absolute target using the PC region. The
// hook sites are all in 0x80000000..0x8FFFFFFF, so the region is 0x80000000.
func jumpTarget(w uint32) uint32 {
	return 0x80000000 | ((w & 0x03FFFFFF) << 2)
}

// DirectCallers returns every direct JAL site in the pristine EXE text that
// targets addr. It intentionally ignores indirect calls.
func DirectCallers(exe []byte, addr uint32) []uint32 {
	var out []uint32
	for pc := uint32(0x80041000); pc+4 <= 0x800E3800; pc += 4 {
		w := wordAt(exe, pc)
		if w>>26 != 0x03 { // jal
			continue
		}
		t := ((pc + 4) & 0xF0000000) | ((w & 0x03FFFFFF) << 2)
		if t == addr {
			out = append(out, pc)
		}
	}
	return out
}

// SceneEntryTable extracts the distinct overlay entry addresses assigned to
// 0x80123110 from the authenticated 129-entry scene jump table at 0x800B1BEC.
// The earlier scan of 0x800790EC..0x80079300 stopped inside the dispatch body
// and therefore undercounted (24); the full table yields 40 distinct entries.
// The table uses multiple entries (not only 0x80132000), so a runtime writer
// cannot be validated by patching one uniform overlay offset.
func SceneEntryTable(exe []byte) []uint32 {
	return FullSceneEntryTable(exe)
}

// FormatColdBootVerdict is a stable one-line evidence string.
func FormatColdBootVerdict(a ColdBootAudit) string {
	return fmt.Sprintf("cold-boot activation: %s (pre_first_overlay_safe=%t, hooks=%d, formatter_callers=%d, speaker_callers=%d, scene_entries=%d)",
		a.Verdict, a.PreFirstOverlaySafe, len(a.Hooks), len(a.FormatterCallers), len(a.SpeakerCallers), len(a.SceneEntryTable))
}

// buildColdBootGuard encodes one 40 B fail-closed guard. checkAddr is the
// window stub word that must be present; classTarget is the stub entered on
// success; failure tail-Jumps to the retail queue, preserving $ra.
//
// This is dependency/size evidence only. No EXE cave is proven and the guard
// is NOT installed in the prototype.
func buildColdBootGuard(checkAddr, classTarget uint32) []byte {
	a := &miniAsm{labels: map[string]int{}}
	expected := jWord(VerifierRAM)
	a.w(0x3C088016)                        // lui t0,0x8016
	a.w(0x8D090000 | (checkAddr & 0xFFFF)) // lw t1,checkAddr(t0)
	a.w(0x3C0A0000 | (expected >> 16))     // lui t2,expected_hi
	a.w(0x354A0000 | (expected & 0xFFFF))  // ori t2,t2,expected_lo
	a.b(5, 9, 10, "fail")                  // bne t1,t2,fail
	a.w(0)                                 // nop
	a.w(jWord(classTarget))                // j class stub
	a.w(0)                                 // nop
	a.label("fail")
	a.w(jWord(OriginalQueue)) // j retail queue
	a.w(0)                    // nop
	a.resolve()
	return words(a.words...)
}

// ColdBootGuardPair returns the formatter and speaker guard prototypes. Both
// are 40 B and together require ColdBootGuardBytes of executable space.
func ColdBootGuardPair() (formatter, speaker []byte) {
	return buildColdBootGuard(WindowStart, FormatterStubRAM),
		buildColdBootGuard(SpeakerStubRAM, SpeakerStubRAM)
}
