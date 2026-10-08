/*
 * slophook - the sh_put_* utility layer.
 *
 * Short, named operations for the things you actually do to a function when
 * you are modifying a binary: delete a call, make it return true, make it
 * return 3.5, trap on it, redirect it. Every one of these is a thin shim
 * over sh_patch_code(), so they all inherit its page handling, cache
 * maintenance, overlap refusal and sh_revert() support, and the 4-byte ones
 * inherit its single-store atomicity.
 *
 * What none of them inherit is knowledge of how long your function is. See
 * the sh_size_* queries and the warning in slophook.h.
 */
#include "../include/slophook.h"
#include "arm64_relocate.h"
#include "arm64_insn.h"
#include "mem.h"
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------- mov immediate */
/*
 * Materialise `v` into register `rd` using the smallest MOVZ/MOVN/MOVK
 * sequence. MOVN catches the common negative cases (-1 becomes one
 * instruction instead of four).
 *
 *   MOVN  sf 00 100101 hw imm16 Rd      MOVZ  sf 10 100101 ...
 *   MOVK  sf 11 100101 hw imm16 Rd
 */
static size_t emit_mov_imm(uint32_t *w, unsigned rd, uint64_t v, int is64) {
    const uint32_t MOVN = is64 ? 0x92800000u : 0x12800000u;
    const uint32_t MOVZ = is64 ? 0xD2800000u : 0x52800000u;
    const uint32_t MOVK = is64 ? 0xF2800000u : 0x72800000u;
    const unsigned nhw  = is64 ? 4u : 2u;
    if (!is64) v &= 0xFFFFFFFFu;

    for (unsigned hw = 0; hw < nhw; hw++) {               /* single MOVZ? */
        const uint64_t c = (uint64_t)(uint16_t)(v >> (16u * hw));
        if ((c << (16u * hw)) == v) {
            w[0] = MOVZ | (hw << 21) | ((uint32_t)c << 5) | rd;
            return 1;
        }
    }
    const uint64_t nv = is64 ? ~v : ((~v) & 0xFFFFFFFFu);
    for (unsigned hw = 0; hw < nhw; hw++) {               /* single MOVN? */
        const uint64_t c = (uint64_t)(uint16_t)(nv >> (16u * hw));
        if ((c << (16u * hw)) == nv) {
            w[0] = MOVN | (hw << 21) | ((uint32_t)c << 5) | rd;
            return 1;
        }
    }
    size_t n = 0;                                    /* MOVZ + MOVK chain */
    int first = 1;
    for (unsigned hw = 0; hw < nhw; hw++) {
        const uint16_t c = (uint16_t)(v >> (16u * hw));
        if (c == 0) continue;
        w[n++] = (first ? MOVZ : MOVK) | (hw << 21) | ((uint32_t)c << 5) | rd;
        first = 0;
    }
    if (first) w[n++] = MOVZ | rd;                          /* v == 0 */
    return n;
}

/* ------------------------------------------------- fixed single words */
typedef struct { uint32_t word; } one;
static void cb_fill(void *code, void *addr, size_t size, void *user) {
    (void)addr;
    const uint32_t w = ((const one *)user)->word;
    uint32_t *p = (uint32_t *)code;
    for (size_t i = 0; i < size / 4; i++) p[i] = w;
}
static sh_status fill(void *addr, size_t bytes, uint32_t word) {
    one u = { word };
    return sh_patch_code(addr, bytes, cb_fill, &u);
}

sh_status sh_put_nop (void *addr)               { return fill(addr, 4, SH_INSN_NOP); }
sh_status sh_put_ret (void *addr)               { return fill(addr, 4, SH_INSN_RET); }
sh_status sh_put_brk (void *addr)               { return fill(addr, 4, SH_INSN_BRK); }
sh_status sh_nop_call(void *call_site)          { return fill(call_site, 4, SH_INSN_NOP); }
sh_status sh_put_nops(void *addr, size_t count) {
    if (count == 0) return SH_ERR_INVAL;
    return fill(addr, count * 4, SH_INSN_NOP);
}

/* ------------------------------------------------- return a constant */
/* integer: mov into x0/w0, then ret */
typedef struct { uint64_t v; int is64; } imm_req;

static size_t build_imm_ret(uint32_t *w, uint64_t v, int is64) {
    size_t n = emit_mov_imm(w, 0, v, is64);
    w[n++] = SH_INSN_RET;
    return n * 4;
}
static void cb_imm_ret(void *code, void *addr, size_t size, void *user) {
    (void)addr; (void)size;
    const imm_req *r = (const imm_req *)user;
    build_imm_ret((uint32_t *)code, r->v, r->is64);
}
static sh_status put_imm(void *addr, uint64_t v, int is64) {
    uint32_t tmp[8];
    imm_req r = { v, is64 };
    return sh_patch_code(addr, build_imm_ret(tmp, v, is64), cb_imm_ret, &r);
}

sh_status sh_put_int  (void *addr, int32_t v) { return put_imm(addr, (uint32_t)v, 0); }
sh_status sh_put_long (void *addr, int64_t v) { return put_imm(addr, (uint64_t)v, 1); }
sh_status sh_put_true (void *addr)            { return put_imm(addr, 1, 0); }
sh_status sh_put_false(void *addr)            { return put_imm(addr, 0, 0); }

size_t sh_size_int (int32_t v) { uint32_t t[8]; return build_imm_ret(t, (uint32_t)v, 0); }
size_t sh_size_long(int64_t v) { uint32_t t[8]; return build_imm_ret(t, (uint64_t)v, 1); }

/*
 * float/double: the value has to reach s0/d0, and there is no "move
 * immediate to vector register" for an arbitrary bit pattern. So stage it
 * in X16 - IP0, which AAPCS64 makes dead at a function entry - and FMOV it
 * across. A zero result is just FMOV from the zero register.
 *
 *   FMOV Sd, Wn   0 0011110 00 1 00 111 000000 Rn Rd   -> 0x1E270000
 *   FMOV Dd, Xn   1 0011110 01 1 00 111 000000 Rn Rd   -> 0x9E670000
 */
#define FMOV_S_W(rd, rn) (0x1E270000u | ((uint32_t)(rn) << 5) | (uint32_t)(rd))
#define FMOV_D_X(rd, rn) (0x9E670000u | ((uint32_t)(rn) << 5) | (uint32_t)(rd))

static size_t build_float_ret(uint32_t *w, float f) {
    uint32_t bits;
    memcpy(&bits, &f, sizeof bits);
    size_t n = 0;
    if (bits == 0) {
        w[n++] = FMOV_S_W(0, 31);                  /* fmov s0, wzr */
    } else {
        n  = emit_mov_imm(w, REG_IP0, bits, 0);    /* mov w16, #bits */
        w[n++] = FMOV_S_W(0, REG_IP0);             /* fmov s0, w16  */
    }
    w[n++] = SH_INSN_RET;
    return n * 4;
}
static size_t build_double_ret(uint32_t *w, double d) {
    uint64_t bits;
    memcpy(&bits, &d, sizeof bits);
    size_t n = 0;
    if (bits == 0) {
        w[n++] = FMOV_D_X(0, 31);                  /* fmov d0, xzr */
    } else {
        n  = emit_mov_imm(w, REG_IP0, bits, 1);    /* mov x16, #bits */
        w[n++] = FMOV_D_X(0, REG_IP0);             /* fmov d0, x16  */
    }
    w[n++] = SH_INSN_RET;
    return n * 4;
}
static void cb_float (void *code, void *a, size_t s, void *u) {
    (void)a; (void)s; build_float_ret((uint32_t *)code, *(const float *)u);
}
static void cb_double(void *code, void *a, size_t s, void *u) {
    (void)a; (void)s; build_double_ret((uint32_t *)code, *(const double *)u);
}
sh_status sh_put_float(void *addr, float v) {
    uint32_t t[8];
    return sh_patch_code(addr, build_float_ret(t, v), cb_float, &v);
}
sh_status sh_put_double(void *addr, double v) {
    uint32_t t[8];
    return sh_patch_code(addr, build_double_ret(t, v), cb_double, &v);
}
size_t sh_size_float (float  v) { uint32_t t[8]; return build_float_ret(t, v); }
size_t sh_size_double(double v) { uint32_t t[8]; return build_double_ret(t, v); }

/* ------------------------------------------------------ raw instructions */
static void cb_bytes(void *code, void *addr, size_t size, void *user) {
    (void)addr;
    memcpy(code, user, size);
}
sh_status sh_put_bytes(void *addr, const void *src, size_t n) {
    if (!src) return SH_ERR_INVAL;
    return sh_patch_code(addr, n, cb_bytes, (void *)src);
}

/* hex string -> bytes, in memory order. Returns byte count, 0 on error. */
static size_t parse_hex(const char *s, uint8_t *out, size_t cap) {
    if (!s) return 0;
    size_t n = 0;
    int hi = -1;
    for (; *s; s++) {
        const char c = *s;
        if (c == ' ' || c == '\t' || c == ',' || c == ':' || c == '-'
            || c == '\n' || c == '\r') continue;
        if ((c == 'x' || c == 'X') && hi == 0) { hi = -1; continue; } /* 0x */
        int d;
        if      (c >= '0' && c <= '9') d = c - '0';
        else if (c >= 'a' && c <= 'f') d = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') d = c - 'A' + 10;
        else return 0;                                   /* junk */
        if (hi < 0) { hi = d; }
        else {
            if (out) { if (n >= cap) return 0; out[n] = (uint8_t)((hi << 4) | d); }
            n++; hi = -1;
        }
    }
    if (hi >= 0) return 0;                               /* odd digit count */
    return n;
}

size_t sh_size_hex(const char *hex) {
    const size_t n = parse_hex(hex, NULL, 0);
    return (n && (n % 4) == 0) ? n : 0;
}

sh_status sh_put_hex(void *addr, const char *hex) {
    const size_t n = sh_size_hex(hex);
    if (n == 0) return SH_ERR_INVAL;
    uint8_t buf[256];
    if (n > sizeof buf) return SH_ERR_INVAL;
    if (parse_hex(hex, buf, sizeof buf) != n) return SH_ERR_INVAL;
    return sh_put_bytes(addr, buf, n);
}

/* ------------------------------------------------------------- branches */
uint32_t sh_enc_branch(const void *from, const void *to, int with_link) {
    const int64_t d = (int64_t)((uint64_t)(uintptr_t)to - (uint64_t)(uintptr_t)from);
    if (!fits_branch(d, 26)) return 0;
    return with_link ? enc_bl(d) : enc_b(d);
}

static sh_status put_branch(void *addr, void *dest, int link) {
    if (!dest) return SH_ERR_INVAL;
    const uint32_t w = sh_enc_branch(addr, dest, link);
    if (!w) return SH_ERR_RANGE;
    return fill(addr, 4, w);
}
sh_status sh_put_b (void *addr, void *dest) { return put_branch(addr, dest, 0); }
sh_status sh_put_bl(void *addr, void *dest) { return put_branch(addr, dest, 1); }

size_t sh_size_jump(const void *addr, const void *dest) {
    return sh_enc_branch(addr, dest, 0) ? 4 : 16;
}
static void cb_jump(void *code, void *addr, size_t size, void *user) {
    size_t n = 0;
    sh_emit_detour((uint32_t *)code, (uint64_t)(uintptr_t)addr, size,
                   (uint64_t)(uintptr_t)*(void **)user, &n);
}
sh_status sh_put_jump(void *addr, void *dest) {
    if (!dest) return SH_ERR_INVAL;
    return sh_patch_code(addr, sh_size_jump(addr, dest), cb_jump, &dest);
}

/* ------------------------------------------------------ finding targets */
void *sh_module_base(const char *name_substring, size_t *out_span) {
    if (!name_substring) return NULL;
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return NULL;

    char line[1024];
    uint64_t base = 0, last_end = 0;
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        /* "<start>-<end> perms offset dev inode   pathname" */
        const char *path = strchr(line, '/');
        if (!path) continue;           /* anonymous (e.g. .bss): not a break */
        if (!strstr(path, name_substring)) {
            if (found) break;          /* a different file: this module ended */
            continue;
        }
        uint64_t s, e;
        if (sscanf(line, "%llx-%llx", (unsigned long long *)&s,
                                      (unsigned long long *)&e) != 2) continue;
        if (!found) { base = s; found = 1; }
        last_end = e;
    }
    fclose(f);
    if (!found) return NULL;
    if (out_span) *out_span = (size_t)(last_end - base);
    return (void *)(uintptr_t)base;
}

void *sh_resolve(const char *name_substring, size_t offset) {
    uint8_t *b = (uint8_t *)sh_module_base(name_substring, NULL);
    return b ? (void *)(b + offset) : NULL;
}

void *sh_sym(const char *soname, const char *symbol) {
    if (!symbol) return NULL;
    void *h = dlopen(soname, RTLD_NOW | RTLD_NOLOAD);
    if (!h) h = dlopen(soname, RTLD_NOW);
    if (!h) return NULL;
    return dlsym(h, symbol);
}
