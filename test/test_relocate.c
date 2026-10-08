/*
 * Host-runnable test harness for the relocator.
 *
 * The relocator is pure bit manipulation, so it runs correctly on any host.
 * This prints a machine readable trace that test/verify.py checks against
 * llvm-mc's disassembler.
 */
#include <stdio.h>
#include <string.h>
#include "../src/arm64_relocate.h"

typedef struct {
    const char *name;
    uint64_t    src_pc;
    uint64_t    dst_pc;
    uint32_t    insns[8];
    unsigned    n;
    int         expect_err;
} testcase;

static const testcase cases[] = {
 /* --- branches that still reach after the move ----------------------- */
 { "b_near",        0x1000000, 0x1000400, { 0x14000020 }, 1, 0 }, /* b  +0x80  */
 { "bl_near",       0x1000000, 0x1000400, { 0x94000020 }, 1, 0 }, /* bl +0x80  */
 /* --- branches that no longer reach: must become long-branch islands -- */
 { "b_far",         0x1000000, 0x41000000,{ 0x14000020 }, 1, 0 },
 { "bl_far",        0x1000000, 0x41000000,{ 0x94000020 }, 1, 0 },
 { "bcond_far",     0x1000000, 0x41000000,{ 0x54000100 }, 1, 0 }, /* b.eq +32  */
 { "cbz_far",       0x1000000, 0x41000000,{ 0x34000102 }, 1, 0 }, /* cbz w2    */
 { "tbz_far",       0x1000000, 0x1100000, { 0x36080103 }, 1, 0 }, /* tbz w3,#1 */
 /* --- pc-relative address formation ---------------------------------- */
 { "adr",           0x1000000, 0x41000000,{ 0x10000100 }, 1, 0 }, /* adr x0    */
 { "adrp",          0x1000000, 0x41000000,{ 0x90000101 }, 1, 0 }, /* adrp x1   */
 { "adrp_neg",      0x8000000, 0x41000000,{ 0x90FFFFE2 }, 1, 0 }, /* adrp x2,- */
 /* --- literal loads ---------------------------------------------------- */
 { "ldr_x_lit",     0x1000000, 0x41000000,{ 0x58000104 }, 1, 0 }, /* ldr x4    */
 { "ldr_w_lit",     0x1000000, 0x41000000,{ 0x18000105 }, 1, 0 }, /* ldr w5    */
 { "ldrsw_lit",     0x1000000, 0x41000000,{ 0x98000106 }, 1, 0 }, /* ldrsw x6  */
 { "prfm_lit",      0x1000000, 0x41000000,{ 0xD8000100 }, 1, 0 }, /* prfm      */
 { "ldr_d_lit",     0x1000000, 0x41000000,{ 0x5C000107 }, 1, 0 }, /* ldr d7    */
 { "ldr_q_lit",     0x1000000, 0x41000000,{ 0x9C000108 }, 1, 0 }, /* ldr q8    */
 /* --- position independent prologue, must be copied verbatim ---------- */
 { "pi_prologue",   0x1000000, 0x41000000,
   { 0xA9BF7BFD, 0x910003FD, 0xD10043FF, 0xD65F03C0 }, 4, 0 },
 /* --- a branch back into the bytes we overwrite must be refused ------- */
 { "self_branch",   0x1000000, 0x41000000,
   { 0x14000002, 0xD503201F, 0xD503201F }, 3, SH_ERR_SELF_BRANCH },
};

int main(void) {
    uint32_t out[256];
    for (unsigned c = 0; c < sizeof(cases)/sizeof(cases[0]); c++) {
        const testcase *t = &cases[c];
        size_t src_used = 0, dst_used = 0;
        memset(out, 0, sizeof(out));
        sh_status st = sh_relocate(t->insns, t->src_pc, t->n * 4,
                                   out, t->dst_pc, sizeof(out),
                                   &src_used, &dst_used);
        if (st != SH_OK) {
            printf("#case %s %llu status=%d\n", t->name,
                   (unsigned long long)t->dst_pc, (int)st);
            continue;
        }
        printf("#case %s %llu status=0 src_in=%llu\n", t->name,
               (unsigned long long)t->dst_pc, (unsigned long long)t->src_pc);
        for (size_t i = 0; i < dst_used / 4; i++)
            printf("%08x\n", out[i]);
    }
    return 0;
}
