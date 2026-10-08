/*
 * Relocation of AArch64 instructions out of a function prologue and into a
 * trampoline at a different address.
 *
 * A64 has exactly nine PC-relative instruction forms:
 *     B, BL, B.cond (and BC.cond), CBZ/CBNZ, TBZ/TBNZ,
 *     ADR, ADRP, LDR(literal) (which covers LDRSW and PRFM literal)
 * Everything else in A64 is position independent and can be copied verbatim.
 * That closed set is what makes a relocator of this size tractable.
 */
#include "arm64_relocate.h"
#include "arm64_insn.h"

/* ------------------------------------------------------------------ emit */
typedef struct {
    uint32_t *w;
    size_t    cap_w;
    size_t    n;
    uint64_t  pc0;
    int       ovf;
} emitter;

static void em(emitter *e, uint32_t insn) {
    if (e->n >= e->cap_w) { e->ovf = 1; return; }
    e->w[e->n++] = insn;
}
static void em64(emitter *e, uint64_t v) {
    em(e, (uint32_t)(v & 0xFFFFFFFFu));
    em(e, (uint32_t)(v >> 32));
}
static uint64_t em_pc(const emitter *e) { return e->pc0 + (uint64_t)e->n * 4; }

/*
 * Long branch via X17. Legitimate because AAPCS64 lets a linker-inserted
 * branch veneer clobber X16/X17 at any branch site, so no caller may assume
 * X17 survives a branch.
 *
 *   ldr  x17, #8      ; +0
 *   br   x17          ; +4
 *   .quad target      ; +8
 */
static void emit_abs_jump(emitter *e, uint64_t target) {
    em(e, enc_ldr_lit_x(REG_IP1, 8));
    em(e, INSN_BR_X17);
    em64(e, target);
}

/*
 *   ldr  x17, #12     ; +0
 *   blr  x17          ; +4   (returns to +8)
 *   b    #12          ; +8   jump over the literal
 *   .quad target      ; +12
 */
static void emit_abs_call(emitter *e, uint64_t target) {
    em(e, enc_ldr_lit_x(REG_IP1, 12));
    em(e, INSN_BLR_X17);
    em(e, enc_b(12));
    em64(e, target);
}

/*
 * Materialise a 64-bit constant into Xd using only Xd - no scratch register
 * is disturbed, which is what makes ADR/ADRP/LDR-literal relocation safe in
 * the middle of a function.
 *
 *   ldr  xd, #8       ; +0
 *   b    #12          ; +4
 *   .quad value       ; +8
 */
static void emit_load_abs(emitter *e, unsigned rd, uint64_t val) {
    em(e, enc_ldr_lit_x(rd, 8));
    em(e, enc_b(12));
    em64(e, val);
}

/*
 * A short-range conditional branch whose target no longer fits. Keep the
 * condition, redirect it over a long-branch island:
 *
 *   <cond> #8         ; +0   taken -> island
 *   b      #20        ; +4   not taken -> past island
 *   ldr    x17, #8    ; +8
 *   br     x17        ; +12
 *   .quad  target     ; +16
 *                     ; +24  next relocated instruction
 */
static void emit_cond_island(emitter *e, uint32_t cond_to_plus8, uint64_t target) {
    em(e, cond_to_plus8);
    em(e, enc_b(20));
    emit_abs_jump(e, target);
}

/* ------------------------------------------------------------- relocate */
sh_status sh_relocate(const uint32_t *src, uint64_t src_pc, size_t min_bytes,
                      uint32_t *dst, uint64_t dst_pc, size_t dst_cap_bytes,
                      size_t *out_src_bytes, size_t *out_dst_bytes)
{
    if (!src || !dst || (src_pc & 3) || (dst_pc & 3) || min_bytes == 0)
        return SH_ERR_INVAL;

    emitter e = { dst, dst_cap_bytes / 4, 0, dst_pc, 0 };

    uint64_t targets[32];
    unsigned ntargets = 0;
    size_t   i = 0;                       /* source instruction index */

    while (i * 4 < min_bytes) {
        const uint32_t in     = src[i];
        const uint64_t pc_in  = src_pc + (uint64_t)i * 4;
        const uint64_t pc_out = em_pc(&e);

        if (IS_B(in) || IS_BL(in)) {
            uint64_t t = pc_in + (uint64_t)(sext(FLD_IMM26(in), 26) * 4);
            if (ntargets < 32) targets[ntargets++] = t;
            int64_t d = (int64_t)(t - pc_out);
            if (fits_branch(d, 26))
                em(&e, IS_B(in) ? enc_b(d) : enc_bl(d));
            else if (IS_B(in))
                emit_abs_jump(&e, t);
            else
                emit_abs_call(&e, t);

        } else if (IS_BCOND(in) || IS_BCCOND(in) || IS_CBZ(in)) {
            uint64_t t = pc_in + (uint64_t)(sext(FLD_IMM19(in), 19) * 4);
            if (ntargets < 32) targets[ntargets++] = t;
            int64_t d = (int64_t)(t - pc_out);
            if (fits_branch(d, 19))
                em(&e, reenc_imm19(in, d));
            else
                emit_cond_island(&e, reenc_imm19(in, 8), t);

        } else if (IS_TBZ(in)) {
            uint64_t t = pc_in + (uint64_t)(sext(FLD_IMM14(in), 14) * 4);
            if (ntargets < 32) targets[ntargets++] = t;
            int64_t d = (int64_t)(t - pc_out);
            if (fits_branch(d, 14))
                em(&e, reenc_imm14(in, d));
            else
                emit_cond_island(&e, reenc_imm14(in, 8), t);

        } else if (IS_ADR(in)) {
            emit_load_abs(&e, FLD_RD(in), pc_in + (uint64_t)adr_imm(in));

        } else if (IS_ADRP(in)) {
            uint64_t page = (pc_in & ~0xFFFULL) + (uint64_t)(adr_imm(in) << 12);
            emit_load_abs(&e, FLD_RD(in), page);

        } else if (IS_LDR_LIT(in)) {
            const uint64_t addr = pc_in + (uint64_t)(sext(FLD_IMM19(in), 19) * 4);
            const unsigned opc = FLD_LDRLIT_OPC(in);
            const unsigned v   = FLD_LDRLIT_V(in);
            const unsigned rt  = FLD_RT(in);

            if (!v) {
                if (opc == 3) {
                    /* PRFM (literal) is a hint with no architectural effect
                     * we must preserve; dropping it is always correct. */
                    em(&e, INSN_NOP);
                } else {
                    emit_load_abs(&e, rt, addr);      /* address -> Xrt */
                    em(&e, opc == 0 ? enc_ldr_w_base(rt, rt)
                         : opc == 1 ? enc_ldr_x_base(rt, rt)
                                    : enc_ldrsw_base(rt, rt));
                }
            } else {
                /* Vector destination: we need a GPR to hold the address.
                 * Unlike a branch, this sits mid-function where X17 may be
                 * live, so spill and restore it around the load. */
                if (opc == 3) return SH_ERR_RELOC;    /* unallocated */
                em(&e, INSN_STR_X17_PRE);
                em(&e, enc_ldr_lit_x(REG_IP1, 8));
                em(&e, enc_b(12));
                em64(&e, addr);
                em(&e, opc == 0 ? enc_ldr_s_base(rt, REG_IP1)
                     : opc == 1 ? enc_ldr_d_base(rt, REG_IP1)
                                : enc_ldr_q_base(rt, REG_IP1));
                em(&e, INSN_LDR_X17_POST);
            }

        } else {
            /* Position independent - copy as is. */
            em(&e, in);
        }

        if (e.ovf) return SH_ERR_NOMEM;
        i++;
    }

    const size_t consumed = i * 4;

    /* A branch back into the bytes we are about to overwrite cannot work:
     * its destination will be the middle of our patch. Refuse rather than
     * silently produce a function that jumps into a half-instruction. */
    for (unsigned k = 0; k < ntargets; k++)
        if (targets[k] >= src_pc && targets[k] < src_pc + consumed)
            return SH_ERR_SELF_BRANCH;

    if (out_src_bytes) *out_src_bytes = consumed;
    if (out_dst_bytes) *out_dst_bytes = e.n * 4;
    return SH_OK;
}

/*
 * True when the displaced region contains an instruction that always
 * transfers control, so the tail jump appended after it is unreachable and
 * can be omitted entirely.
 *
 * Soundness: anything following that transfer is reachable only by a branch,
 * and sh_relocate already refuses the whole relocation if any branch it moved
 * targets an address inside the displaced region (SH_ERR_SELF_BRANCH). A
 * branch from elsewhere in the function into the displaced region is the
 * general inline-hooking hazard and is not specific to the tail jump.
 *
 * This keeps the far-placement fallback usable for the very common case of a
 * short function that fits entirely inside the displaced region.
 */
int sh_region_ends_unconditionally(const uint32_t *src, size_t bytes) {
    if (!src || bytes < 4) return 0;
    for (size_t i = 0; i < bytes / 4; i++) {
        const uint32_t in = src[i];
        if (IS_B(in)) return 1;                              /* b    */
        if ((in & 0xFFFFFC1Fu) == 0xD65F0000u) return 1;     /* ret  */
        if ((in & 0xFFFFFC1Fu) == 0xD61F0000u) return 1;     /* br   */
    }
    return 0;
}

/* Append the jump that returns control to the untouched remainder of the
 * original function. */
sh_status sh_emit_tail_jump(uint32_t *dst, uint64_t dst_pc, size_t dst_cap_bytes,
                            uint64_t resume_pc, size_t *out_bytes)
{
    emitter e = { dst, dst_cap_bytes / 4, 0, dst_pc, 0 };
    int64_t d = (int64_t)(resume_pc - dst_pc);
    /*
     * This jump resumes STRAIGHT-LINE code in the middle of the original
     * function, so unlike a relocated branch it may not clobber X17: the
     * original code contained no branch here, and the AAPCS64 veneer
     * argument therefore does not apply. A `BR X17` here would also fault
     * on a BTI-guarded page, since mid-function has no landing pad.
     * If a direct B cannot reach, refuse instead of corrupting X17.
     */
    if (!fits_branch(d, 26)) return SH_ERR_RANGE;
    em(&e, enc_b(d));
    if (e.ovf) return SH_ERR_NOMEM;
    if (out_bytes) *out_bytes = e.n * 4;
    return SH_OK;
}

/* Build the patch written over the target itself. */
sh_status sh_emit_detour(uint32_t *dst, uint64_t at_pc, size_t dst_cap_bytes,
                         uint64_t dest_pc, size_t *out_bytes)
{
    emitter e = { dst, dst_cap_bytes / 4, 0, at_pc, 0 };
    int64_t d = (int64_t)(dest_pc - at_pc);
    if (fits_branch(d, 26)) em(&e, enc_b(d));
    else                    emit_abs_jump(&e, dest_pc);
    if (e.ovf) return SH_ERR_NOMEM;
    if (out_bytes) *out_bytes = e.n * 4;
    return SH_OK;
}
