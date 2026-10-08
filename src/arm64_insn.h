/*
 * AArch64 instruction encode/decode helpers.
 *
 * Every constant here was cross-checked against llvm-mc; see test/ for the
 * round-trip disassembly test that keeps them honest.
 */
#ifndef ARM64_INSN_H
#define ARM64_INSN_H

#include <stdint.h>

/* ---- register numbers we use as scratch ------------------------------- */
/*
 * X17 is IP1. AAPCS64 permits a linker-inserted branch veneer to clobber
 * X16/X17 at *any* branch, so using X17 to synthesise a long branch is
 * architecturally sanctioned. We do NOT rely on that for non-branch
 * relocations - those save and restore X17 around their use.
 */
#define REG_IP0 16
#define REG_IP1 17

/* ---- fixed encodings --------------------------------------------------- */
#define INSN_NOP            0xD503201Fu
#define INSN_BR_X17         0xD61F0220u   /* br   x17                       */
#define INSN_BLR_X17        0xD63F0220u   /* blr  x17                       */
#define INSN_STR_X17_PRE    0xF81F0FF1u   /* str  x17, [sp, #-16]!          */
#define INSN_LDR_X17_POST   0xF84107F1u   /* ldr  x17, [sp], #16            */

/* ---- sign extension ---------------------------------------------------- */
static inline int64_t sext(uint64_t v, unsigned bits) {
    const uint64_t m = 1ULL << (bits - 1);
    return (int64_t)((v ^ m) - m);
}

/* ---- range checks ------------------------------------------------------ */
/* An offset encodable in `bits` of imm, scaled by 4 (i.e. imm<<2). */
static inline int fits_branch(int64_t off, unsigned bits) {
    if (off & 3) return 0;
    const int64_t lim = 1LL << (bits + 1);   /* +-(2^bits * 4) / 2 */
    return off >= -lim && off < lim;
}

/* ---- encoders ---------------------------------------------------------- */
static inline uint32_t enc_b(int64_t off) {
    return 0x14000000u | (uint32_t)((off >> 2) & 0x03FFFFFF);
}
static inline uint32_t enc_bl(int64_t off) {
    return 0x94000000u | (uint32_t)((off >> 2) & 0x03FFFFFF);
}
/* ldr x<rt>, <pc-relative literal> */
static inline uint32_t enc_ldr_lit_x(unsigned rt, int64_t off) {
    return 0x58000000u | (uint32_t)(((off >> 2) & 0x7FFFF) << 5) | (rt & 31);
}
static inline uint32_t enc_br(unsigned rn)  { return 0xD61F0000u | ((rn & 31) << 5); }
static inline uint32_t enc_blr(unsigned rn) { return 0xD63F0000u | ((rn & 31) << 5); }

/* ldr x<rt>, [x<rn>] / ldr w<rt>, [x<rn>] / ldrsw x<rt>, [x<rn>] */
static inline uint32_t enc_ldr_x_base(unsigned rt, unsigned rn) {
    return 0xF9400000u | ((rn & 31) << 5) | (rt & 31);
}
static inline uint32_t enc_ldr_w_base(unsigned rt, unsigned rn) {
    return 0xB9400000u | ((rn & 31) << 5) | (rt & 31);
}
static inline uint32_t enc_ldrsw_base(unsigned rt, unsigned rn) {
    return 0xB9800000u | ((rn & 31) << 5) | (rt & 31);
}
/* ldr s/d/q <rt>, [x<rn>] */
static inline uint32_t enc_ldr_s_base(unsigned rt, unsigned rn) {
    return 0xBD400000u | ((rn & 31) << 5) | (rt & 31);
}
static inline uint32_t enc_ldr_d_base(unsigned rt, unsigned rn) {
    return 0xFD400000u | ((rn & 31) << 5) | (rt & 31);
}
static inline uint32_t enc_ldr_q_base(unsigned rt, unsigned rn) {
    return 0x3DC00000u | ((rn & 31) << 5) | (rt & 31);
}

/* Re-encode an imm19 branch (b.cond / cbz / cbnz) keeping opcode + Rt/cond. */
static inline uint32_t reenc_imm19(uint32_t in, int64_t off) {
    return (in & 0xFF00001Fu) | (uint32_t)(((off >> 2) & 0x7FFFF) << 5);
}
/* Re-encode an imm14 branch (tbz / tbnz) keeping opcode + bit index + Rt. */
static inline uint32_t reenc_imm14(uint32_t in, int64_t off) {
    return (in & 0xFFF8001Fu) | (uint32_t)(((off >> 2) & 0x3FFF) << 5);
}

/* ---- classifiers ------------------------------------------------------- */
#define IS_B(i)        (((i) & 0xFC000000u) == 0x14000000u)
#define IS_BL(i)       (((i) & 0xFC000000u) == 0x94000000u)
/* b.cond (…0x54000000) and bc.cond / FEAT_HBC (…0x54000010) share imm19 */
#define IS_BCOND(i)    (((i) & 0xFF000010u) == 0x54000000u)
#define IS_BCCOND(i)   (((i) & 0xFF000010u) == 0x54000010u)
#define IS_CBZ(i)      (((i) & 0x7E000000u) == 0x34000000u)  /* CBZ + CBNZ  */
#define IS_TBZ(i)      (((i) & 0x7E000000u) == 0x36000000u)  /* TBZ + TBNZ  */
#define IS_ADR(i)      (((i) & 0x9F000000u) == 0x10000000u)
#define IS_ADRP(i)     (((i) & 0x9F000000u) == 0x90000000u)
#define IS_LDR_LIT(i)  (((i) & 0x3B000000u) == 0x18000000u)

/* ---- field extraction -------------------------------------------------- */
#define FLD_RT(i)      ((i) & 31u)
#define FLD_RD(i)      ((i) & 31u)
#define FLD_IMM26(i)   ((i) & 0x03FFFFFFu)
#define FLD_IMM19(i)   (((i) >> 5) & 0x7FFFFu)
#define FLD_IMM14(i)   (((i) >> 5) & 0x3FFFu)
#define FLD_LDRLIT_OPC(i) (((i) >> 30) & 3u)
#define FLD_LDRLIT_V(i)   (((i) >> 26) & 1u)

/* ADR/ADRP immediate: immhi[23:5] : immlo[30:29] */
static inline int64_t adr_imm(uint32_t i) {
    uint64_t immlo = ((uint64_t)i >> 29) & 3u;
    uint64_t immhi = ((uint64_t)i >> 5) & 0x7FFFFu;
    return sext((immhi << 2) | immlo, 21);
}

#endif /* ARM64_INSN_H */
