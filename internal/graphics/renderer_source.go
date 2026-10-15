// The original hook source, retained verbatim as MIPS I assembly.
// Source of truth: legacy_scripts/tokipatch/renderer.py HOOK_SOURCE.
package graphics

const hookAssembly = `
hook:                           ; t0 = character code (from the delay slot at HOOK_SITE)
    srl   t2, t0, 8
    sltiu at, t2, 0xA0
    beqz  at, pair
    nop
    lui   t1, 0x800b            ; not a pair: the two instructions we replaced,
    lhu   t1, 0x402c(t1)        ; then back into the game's range lookup
    j     HOOK_RESUME
    nop                         ; (load delay for t1)
pair:
    addiu a1, t2, -0xA0         ; left character index
    andi  a2, t0, 0xFF
    addiu a2, a2, -0xA0         ; right character index
    lui   t9, %hi(NARROW)
    addiu t9, t9, %lo(NARROW)
    sll   a1, a1, 3
    addu  a1, a1, t9
    sll   a2, a2, 3
    addu  a2, a2, t9
    lui   t8, %hi(SCRATCH)
    addiu t8, t8, %lo(SCRATCH)
    addiu t7, zero, 2           ; two words per character
half:
    lw    t3, 0(a1)
    lw    t4, 0(a2)
    addiu t6, zero, 3           ; three row pairs per word
rows:
    andi  t1, t3, 31            ; row A = left << 7 | right
    sll   t1, t1, 7
    andi  t2, t4, 31
    or    t1, t1, t2
    srl   t3, t3, 5
    srl   t4, t4, 5
    andi  t2, t3, 31            ; row B
    sll   t2, t2, 7
    andi  t5, t4, 31
    or    t2, t2, t5
    srl   t3, t3, 5
    srl   t4, t4, 5
    sll   t1, t1, 12            ; two 12-bit rows -> 3 bytes, MSB first
    or    t1, t1, t2
    srl   t2, t1, 16
    sb    t2, 0(t8)
    srl   t2, t1, 8
    sb    t2, 1(t8)
    sb    t1, 2(t8)
    addiu t6, t6, -1
    bnez  t6, rows
    addiu t8, t8, 3
    addiu a1, a1, 4
    addiu t7, t7, -1
    bnez  t7, half
    addiu a2, a2, 4
    lui   a0, %hi(SCRATCH_INDEX)
    jal   RENDER_GLYPH
    addiu a0, a0, %lo(SCRATCH_INDEX)
    j     LAYOUT_LOOP           ; same exit as the game's own glyph path
    move  v0, s1
`
