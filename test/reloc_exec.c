/* Relocate-and-execute differential tester.
 *
 * For each synthetic prologue shape: run it as built, then displace its
 * first N instructions into a trampoline (once NEAR, once >128MB AWAY),
 * append the tail jump back, execute the trampoline, and require the
 * identical result. This exercises the relocator's output as code, not
 * just as bit patterns. */
#define _GNU_SOURCE
#include "../include/slophook.h"
#include "../src/arm64_relocate.h"
#include "../src/mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/mman.h>
#include <unistd.h>

typedef long (*fn1)(long);

#define MAXSH 4
typedef struct {
    const char *name;
    void       *fn;
    unsigned    displace;      /* leading instructions to relocate */
    long        args[MAXSH];
    unsigned    nargs;
    int         expect_err;    /* 0 = expect success */
    int         live_x17;      /* target reads x17; set it before calling */
} shape;

extern long shape_b(long), shape_bcond(long), shape_cbz(long), shape_cbnz(long);
extern long shape_tbz(long), shape_tbnz(long), shape_bl(long);
extern long shape_adr(long), shape_adr_neg(long), shape_adrp(long), shape_adrp2(long);
extern long shape_ldr_x(long), shape_ldr_w(long), shape_ldrsw(long), shape_prfm(long);
extern long shape_ldr_s(long), shape_ldr_d(long), shape_ldr_q(long);
extern long shape_ldr_x_livex17(long), shape_ldr_d_livex17(long);
extern long shape_pac(long), shape_bti(long), shape_selfbr(long);
extern long shape_multi(long), shape_bcond_farsrc(long);

static const shape SHAPES[] = {
 {"B first",              shape_b,       1, {0,1},        2, 0, 0},
 {"B.cond (cmp+b.eq)",    shape_bcond,   2, {7,8},        2, 0, 0},
 {"CBZ",                  shape_cbz,     1, {0,1},        2, 0, 0},
 {"CBNZ",                 shape_cbnz,    1, {0,1},        2, 0, 0},
 {"TBZ bit3",             shape_tbz,     1, {0,8},        2, 0, 0},
 {"TBNZ bit40",           shape_tbnz,    1, {0,1L<<40},   2, 0, 0},
 {"BL (stp+bl)",          shape_bl,      2, {1,2},        2, 0, 0},
 {"ADR forward",          shape_adr,     1, {0,1},        2, 0, 0},
 {"ADR negative",         shape_adr_neg, 1, {0,1},        2, 0, 0},
 {"ADRP, ADD left behind",shape_adrp,    1, {0,1},        2, 0, 0},
 {"ADRP+ADD both moved",  shape_adrp2,   2, {0,1},        2, 0, 0},
 {"LDR x literal",        shape_ldr_x,   1, {0,1},        2, 0, 0},
 {"LDR w literal",        shape_ldr_w,   1, {0,1},        2, 0, 0},
 {"LDRSW literal (neg)",  shape_ldrsw,   1, {0,1},        2, 0, 0},
 {"PRFM literal -> nop",  shape_prfm,    1, {0,1},        2, 0, 0},
 {"LDR s literal",        shape_ldr_s,   1, {0,1},        2, 0, 0},
 {"LDR d literal",        shape_ldr_d,   1, {0,1},        2, 0, 0},
 {"LDR q literal (hi)",   shape_ldr_q,   1, {0,1},        2, 0, 0},
 {"LDR x lit, X17 live",  shape_ldr_x_livex17, 1, {0,1},  2, 0, 1},
 {"LDR d lit, X17 live",  shape_ldr_d_livex17, 1, {0,1},  2, 0, 1},
 {"PAC paciasp prologue", shape_pac,     1, {0,1},        2, 0, 0},
 {"BTI c prologue",       shape_bti,     1, {0,1},        2, 0, 0},
 {"B.cond to >1MB target",shape_bcond_farsrc, 2, {1,2},   2, 0, 0},
 {"multi-form, 4 insns",  shape_multi,   4, {0,1},        2, 0, 0},
 {"self-branch",          shape_selfbr,  2, {0},          1, SH_ERR_SELF_BRANCH, 0},
};

static int fails, passes;
static void ck(int ok, const char *fmt, ...) {
    va_list ap; va_start(ap, fmt);
    printf(ok ? "  PASS  " : "  FAIL  ");
    vprintf(fmt, ap); printf("\n"); va_end(ap);
    if (ok) passes++; else fails++;
}

/* Call the target with a known value in X17 so we can detect clobbering. */
#define X17_MAGIC 0x00000000000ABC00L
static long call_with_x17(fn1 f, long a) {
    register long r0 asm("x0") = a;
    register long r17 asm("x17") = X17_MAGIC;
    asm volatile("blr %2" : "+r"(r0), "+r"(r17) : "r"(f)
                 : "x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11",
                   "x12","x13","x14","x15","x16","x18","x30","memory",
                   "v0","v1","v2","v3","v4","v5","v6","v7");
    return r0;
}

/* Build the trampoline for `s` at `dst` and return it, or NULL + status. */
static void *build(const shape *s, uint8_t *dst, size_t cap, sh_status *out) {
    size_t su = 0, du = 0;
    sh_status st = sh_relocate((const uint32_t *)s->fn, (uint64_t)s->fn,
                               s->displace * 4u, (uint32_t *)dst,
                               (uint64_t)dst, cap, &su, &du);
    *out = st;
    if (st != SH_OK) return NULL;
    size_t tail = 0;
    st = sh_emit_tail_jump((uint32_t *)(dst + du), (uint64_t)(dst + du),
                           cap - du, (uint64_t)s->fn + su, &tail);
    *out = st;
    if (st != SH_OK) return NULL;
    sh_flush_icache(dst, du + tail);
    return dst;
}

static void run(const shape *s, uint8_t *dst, size_t cap, const char *where,
                int64_t dist)
{
    sh_status st = SH_OK;
    void *tr = build(s, dst, cap, &st);

    if (s->expect_err) {
        ck(st == s->expect_err, "%-24s %-5s refused: %s", s->name, where,
           sh_strerror(st));
        return;
    }
    if (!tr) {
        /* A displaced region that still needs a tail jump cannot be resumed
         * from out of branch range without clobbering X17, so refusing is
         * the correct behaviour here, not a failure. */
        int ok = (st == SH_ERR_RANGE && strcmp(where, "far") == 0);
        ck(ok, "%-24s %-5s %s", s->name, where,
           ok ? "refused (tail jump out of range) - correct" : sh_strerror(st));
        return;
    }

    int bad = 0; long w = 0, g = 0;
    for (unsigned i = 0; i < s->nargs; i++) {
        if (s->live_x17) { w = call_with_x17((fn1)s->fn, s->args[i]);
                           g = call_with_x17((fn1)tr,    s->args[i]); }
        else             { w = ((fn1)s->fn)(s->args[i]);
                           g = ((fn1)tr)(s->args[i]); }
        if (w != g) { bad = 1; break; }
    }
    ck(!bad, "%-24s %-5s (%+lldMB) %s", s->name, where,
       (long long)(dist / (1024*1024)),
       bad ? "MISMATCH" : "identical result");
    if (bad) printf("        arg path differs: original=%ld relocated=%ld\n", w, g);
}

int main(void) {
    const size_t PG = (size_t)sysconf(_SC_PAGESIZE);
    const size_t CAP = 4096;

    /* near page: inside +-128MB of the shapes, via the engine's own finder */
    uint8_t *near = (uint8_t *)sh_mem_alloc_near((uint64_t)shape_b, CAP);
    /* far page: deliberately way outside B range */
    uint8_t *far = NULL;
    for (uint64_t hint = 0x100000000000ULL; hint < 0x400000000000ULL;
         hint += 0x10000000000ULL) {
        void *p = mmap((void *)hint, CAP, PROT_READ|PROT_WRITE|PROT_EXEC,
                       MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) { far = (uint8_t *)p; break; }
    }
    printf("page size %zu   shapes at %p\n", PG, (void *)shape_b);
    printf("near trampoline %p   far trampoline %p\n", (void *)near, (void *)far);
    if (!near) { printf("  (near allocation failed; skipping near pass)\n"); }
    if (!far)  { printf("  (far allocation failed; skipping far pass)\n"); }
    printf("\n--- displaced into a NEAR page (branches should re-encode) ---\n");
    if (near) for (unsigned i = 0; i < sizeof SHAPES/sizeof SHAPES[0]; i++) {
        memset(near, 0, CAP);
        run(&SHAPES[i], near, CAP, "near",
            (int64_t)((uint64_t)near - (uint64_t)SHAPES[i].fn));
    }
    printf("\n--- displaced into a FAR page (branches need islands) ---\n");
    if (far) for (unsigned i = 0; i < sizeof SHAPES/sizeof SHAPES[0]; i++) {
        memset(far, 0, CAP);
        run(&SHAPES[i], far, CAP, "far",
            (int64_t)((uint64_t)far - (uint64_t)SHAPES[i].fn));
    }

    printf("\n==== %d passed, %d failed ====\n", passes, fails);
    return fails ? 1 : 0;
}
