/* Synthetic prologue shapes, assembled by the real assembler so the
 * encodings are authoritative. Each shape_X takes a long in x0 and
 * returns a long in x0. The driver displaces the first N instructions
 * into a trampoline and checks the result is unchanged. */
    .arch armv8.3-a
    .text
    .balign 8

    .global g_shape_val
    .data
    .balign 8
g_shape_val:
    .quad 0x1122334455667788
    .text

/* ---- 1. B as the first instruction (displace 1) ---------------- */
    .global shape_b
    .type shape_b,%function
shape_b:
    b       .Lb_t
    mov     x0, #0xBAD
    ret
.Lb_t:
    add     x0, x0, #11
    ret

/* ---- 2. B.cond (displace 2: cmp + b.eq) ------------------------ */
    .global shape_bcond
    .type shape_bcond,%function
shape_bcond:
    cmp     x0, #7
    b.eq    .Lbc_eq
    mov     x0, #100
    ret
.Lbc_eq:
    mov     x0, #200
    ret

/* ---- 3. CBZ (displace 1) --------------------------------------- */
    .global shape_cbz
    .type shape_cbz,%function
shape_cbz:
    cbz     x0, .Lcbz_z
    mov     x0, #5
    ret
.Lcbz_z:
    mov     x0, #6
    ret

/* ---- 4. CBNZ (displace 1) -------------------------------------- */
    .global shape_cbnz
    .type shape_cbnz,%function
shape_cbnz:
    cbnz    x0, .Lcbnz_n
    mov     x0, #7
    ret
.Lcbnz_n:
    mov     x0, #8
    ret

/* ---- 5. TBZ (displace 1) --------------------------------------- */
    .global shape_tbz
    .type shape_tbz,%function
shape_tbz:
    tbz     x0, #3, .Ltbz_z
    mov     x0, #9
    ret
.Ltbz_z:
    mov     x0, #10
    ret

/* ---- 6. TBNZ, high bit index (displace 1) ---------------------- */
    .global shape_tbnz
    .type shape_tbnz,%function
shape_tbnz:
    tbnz    x0, #40, .Ltbnz_n
    mov     x0, #12
    ret
.Ltbnz_n:
    mov     x0, #13
    ret

/* ---- 7. BL (displace 2: stp then bl) --------------------------- */
    .global shape_bl
    .type shape_bl,%function
shape_bl:
    stp     x29, x30, [sp, #-16]!
    bl      shape_bl_helper
    add     x0, x0, #1
    ldp     x29, x30, [sp], #16
    ret
shape_bl_helper:
    add     x0, x0, #21
    ret

/* ---- 8. ADR (displace 1) --------------------------------------- */
    .global shape_adr
    .type shape_adr,%function
shape_adr:
    adr     x1, .Ldata_adr
    ldr     x1, [x1]
    add     x0, x0, x1
    ret
    .balign 8
.Ldata_adr:
    .quad   0x0000000000000101

/* ---- 9. ADR with a negative displacement (displace 1) ---------- */
    .balign 8
.Ldata_adr_back:
    .quad   0x0000000000000202
    .global shape_adr_neg
    .type shape_adr_neg,%function
shape_adr_neg:
    adr     x1, .Ldata_adr_back
    ldr     x1, [x1]
    add     x0, x0, x1
    ret

/* ---- 10. ADRP only, leaving the paired ADD in place (displace 1) */
    .global shape_adrp
    .type shape_adrp,%function
shape_adrp:
    adrp    x1, g_shape_val
    add     x1, x1, #:lo12:g_shape_val
    ldr     x1, [x1]
    add     x0, x0, x1
    ret

/* ---- 11. ADRP + ADD both displaced (displace 2) ---------------- */
    .global shape_adrp2
    .type shape_adrp2,%function
shape_adrp2:
    adrp    x1, g_shape_val
    add     x1, x1, #:lo12:g_shape_val
    ldr     x1, [x1]
    add     x0, x0, x1
    ret

/* ---- 12. LDR x, literal (displace 1) --------------------------- */
    .global shape_ldr_x
    .type shape_ldr_x,%function
shape_ldr_x:
    ldr     x1, .Llit_x
    add     x0, x0, x1
    ret
    .balign 8
.Llit_x:
    .quad   0x0123456789ABCDEF

/* ---- 13. LDR w, literal (displace 1) --------------------------- */
    .global shape_ldr_w
    .type shape_ldr_w,%function
shape_ldr_w:
    ldr     w1, .Llit_w
    add     x0, x0, x1
    ret
    .balign 4
.Llit_w:
    .word   0xDEADBEEF

/* ---- 14. LDRSW literal, negative value (displace 1) ------------ */
    .global shape_ldrsw
    .type shape_ldrsw,%function
shape_ldrsw:
    ldrsw   x1, .Llit_sw
    add     x0, x0, x1
    ret
    .balign 4
.Llit_sw:
    .word   -12345

/* ---- 15. PRFM literal (displace 1) ----------------------------- */
    .global shape_prfm
    .type shape_prfm,%function
shape_prfm:
    prfm    pldl1keep, .Llit_pf
    add     x0, x0, #77
    ret
    .balign 8
.Llit_pf:
    .quad   0

/* ---- 16. LDR s, literal (displace 1) --------------------------- */
    .global shape_ldr_s
    .type shape_ldr_s,%function
shape_ldr_s:
    ldr     s0, .Llit_s
    fmov    w1, s0
    add     x0, x0, x1
    ret
    .balign 4
.Llit_s:
    .word   0x40490FDB

/* ---- 17. LDR d, literal (displace 1) --------------------------- */
    .global shape_ldr_d
    .type shape_ldr_d,%function
shape_ldr_d:
    ldr     d0, .Llit_d
    fmov    x1, d0
    add     x0, x0, x1
    ret
    .balign 8
.Llit_d:
    .quad   0x3FF0000000000000

/* ---- 18. LDR q, literal; check the HIGH half (displace 1) ------ */
    .global shape_ldr_q
    .type shape_ldr_q,%function
shape_ldr_q:
    ldr     q0, .Llit_q
    umov    x1, v0.d[1]
    add     x0, x0, x1
    ret
    .balign 16
.Llit_q:
    .quad   0xAAAAAAAAAAAAAAAA
    .quad   0x0000000000000303

/* ---- 19. LDR x literal with a live X17 (displace 1) ------------ */
/* the GPR path must not clobber x17; caller checks x17 survives     */
    .global shape_ldr_x_livex17
    .type shape_ldr_x_livex17,%function
shape_ldr_x_livex17:
    ldr     x1, .Llit_x2
    add     x0, x0, x1
    add     x0, x0, x17
    ret
    .balign 8
.Llit_x2:
    .quad   0x0000000000001000

/* ---- 20. LDR d literal with a live X17 (displace 1) ------------ */
/* the vector path spills x17; caller checks x17 survives            */
    .global shape_ldr_d_livex17
    .type shape_ldr_d_livex17,%function
shape_ldr_d_livex17:
    ldr     d0, .Llit_d2
    fmov    x1, d0
    add     x0, x0, x1
    add     x0, x0, x17
    ret
    .balign 8
.Llit_d2:
    .quad   0x0000000000002000

/* ---- 21. PAC prologue (displace 1: paciasp) -------------------- */
    .global shape_pac
    .type shape_pac,%function
shape_pac:
    paciasp
    stp     x29, x30, [sp, #-16]!
    add     x0, x0, #33
    ldp     x29, x30, [sp], #16
    autiasp
    ret

/* ---- 22. BTI landing pad prologue (displace 1) ----------------- */
    .global shape_bti
    .type shape_bti,%function
shape_bti:
    bti     c
    add     x0, x0, #44
    ret

/* ---- 23. self-branch: must be REFUSED (displace 2) ------------- */
    .global shape_selfbr
    .type shape_selfbr,%function
shape_selfbr:
    nop
    b       shape_selfbr
    ret

/* ---- 24. multi-form prologue, 4 displaced instructions --------- */
    .global shape_multi
    .type shape_multi,%function
shape_multi:
    adrp    x1, g_shape_val
    ldr     x2, .Llit_m
    adr     x3, .Ldata_m
    nop
    add     x1, x1, #:lo12:g_shape_val
    ldr     x1, [x1]
    ldr     x3, [x3]
    eor     x1, x1, x2
    add     x0, x0, x1
    add     x0, x0, x3
    ret
    .balign 8
.Llit_m:
    .quad   0x00000000000F0F0F
.Ldata_m:
    .quad   0x0000000000000404

/* ---- 25. conditional branch to a FAR target (displace 2) ------- */
/* b.ne over 1MB away, so even the near trampoline needs an island  */
    .global shape_bcond_farsrc
    .type shape_bcond_farsrc,%function
shape_bcond_farsrc:
    cmp     x0, #1
    b.ne    .Lfar_away
    mov     x0, #500
    ret
    .section .text.far,"ax",%progbits
    .balign 4
.Lfar_away:
    mov     x0, #600
    ret
    .text

    .section .note.GNU-stack,"",%progbits

/* ---- 26. purely position-independent prologue, body reads X17 ----
 * Nothing needs relocating here, so any X17 damage can only come from
 * the engine's own tail jump. */
    .text
    .global shape_x17_nop
    .type shape_x17_nop,%function
shape_x17_nop:
    nop
    add     x0, x0, x17
    ret

/* ---- 27. same, but body reads X16 -------------------------------- */
    .global shape_x16_nop
    .type shape_x16_nop,%function
shape_x16_nop:
    nop
    add     x0, x0, x16
    ret

/* ================= targets for the direct-patch API ================= */
    .text
    .balign 16
/* a call site we can NOP out: original returns 778, patched returns 11 */
    .global pt_caller
    .type pt_caller,%function
pt_caller:
    stp     x29, x30, [sp, #-16]!
    mov     w0, #10
    .global pt_call_site
    .type pt_call_site,%function
pt_call_site:
    bl      pt_helper
    add     w0, w0, #1
    ldp     x29, x30, [sp], #16
    ret
    .global pt_helper
    .type pt_helper,%function
pt_helper:
    mov     w0, #777
    ret

/* a conditional branch we can flip in place */
    .balign 16
    .global pt_cond
    .type pt_cond,%function
pt_cond:
    cmp     w0, #0
    .global pt_cond_br
    .type pt_cond_br,%function
pt_cond_br:
    b.eq    .Lpt_z
    mov     w0, #1
    ret
.Lpt_z:
    mov     w0, #2
    ret

/* long enough to hold a 20-byte movz/movk/ret stub */
    .balign 16
    .global pt_long
    .type pt_long,%function
pt_long:
    nop
    nop
    nop
    nop
    nop
    mov     w0, #5
    ret

/* jump source and destination */
    .balign 16
    .global pt_jsrc
    .type pt_jsrc,%function
pt_jsrc:
    mov     w0, #100
    ret
    .balign 16
    .global pt_jdst
    .type pt_jdst,%function
pt_jdst:
    mov     w0, #200
    ret

/* float / double returning targets, padded so a put_float/put_double stub fits */
    .balign 16
    .global pt_fret
    .type pt_fret,%function
pt_fret:
    nop
    nop
    nop
    nop
    fmov    s0, #2.0
    ret

    .balign 16
    .global pt_dret
    .type pt_dret,%function
pt_dret:
    nop
    nop
    nop
    nop
    nop
    fmov    d0, #2.0
    ret

/* spare scratch functions for branch / brk tests */
    .balign 16
    .global pt_s1
    .type pt_s1,%function
pt_s1:
    mov     w0, #11
    ret
    .balign 16
    .global pt_s2
    .type pt_s2,%function
pt_s2:
    mov     w0, #22
    ret
