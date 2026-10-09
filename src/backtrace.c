/*
 * slophook - backtracing.
 *
 * Two walkers over the same validator:
 *
 *   FP     the AAPCS64 frame-record chain. At [X29] sits the caller's
 *          frame pointer and at [X29+8] the return address into it, so
 *          the chain is just a linked list up the stack.
 *
 *   FUZZY  every 8-byte-aligned word on the stack, kept if it looks like
 *          a return address.
 *
 * "Looks like a return address" is the part that does the work: the value
 * must be 4-byte aligned, land inside an executable mapping, and the four
 * bytes immediately before it must decode as a call. That last test is
 * what keeps a stack scan from being useless - arbitrary stack garbage
 * almost never has a BL sitting in front of it.
 */
#define _GNU_SOURCE
#include "../include/slophook.h"
#include "mem.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

/* ------------------------------------------------- call-site encodings */
/*
 * Verified against the assembler, not from memory:
 *   bl      .           94000000
 *   blr     x16         d63f0200      -> & FFFFFC1F == D63F0000
 *   blraaz  x16         d63f0a1f      -> & FFFFFC1F == D63F081F
 *   blrabz  x16         d63f0e1f      -> & FFFFFC1F == D63F0C1F
 *   blraa   x16, x17    d73f0a11      -> & FFFFFC00 == D73F0800
 *   blrab   x16, x17    d73f0e11      -> & FFFFFC00 == D73F0C00
 * BR and RET deliberately do not match: a tail call leaves no return
 * address, so a word in front of one is not a frame.
 */
static int is_call(uint32_t i) {
    if ((i & 0xFC000000u) == 0x94000000u) return 1;   /* bl        */
    if ((i & 0xFFFFFC1Fu) == 0xD63F0000u) return 1;   /* blr   Xn  */
    if ((i & 0xFFFFFC1Fu) == 0xD63F081Fu) return 1;   /* blraaz Xn */
    if ((i & 0xFFFFFC1Fu) == 0xD63F0C1Fu) return 1;   /* blrabz Xn */
    if ((i & 0xFFFFFC00u) == 0xD73F0800u) return 1;   /* blraa Xn,Xm */
    if ((i & 0xFFFFFC00u) == 0xD73F0C00u) return 1;   /* blrab Xn,Xm */
    return 0;
}

/* --------------------------------------------- cached mapping snapshot */
#define SH_MAX_MODULES 256
#define SH_MAX_EXEC    512
#define SH_NAME_POOL   (24 * 1024)

typedef struct { uint64_t lo, hi; uint32_t name; } module_rec;
typedef struct { uint64_t lo, hi; int32_t  mod;  } exec_rec;

static module_rec g_mods[SH_MAX_MODULES];
static size_t     g_nmods;
static exec_rec   g_exec[SH_MAX_EXEC];
static size_t     g_nexec;
static char       g_names[SH_NAME_POOL];
static size_t     g_names_used;
static int        g_have_snapshot;

static uint64_t hex64(const char **pp) {
    const char *p = *pp;
    uint64_t v = 0;
    for (;; p++) {
        unsigned d;
        if      (*p >= '0' && *p <= '9') d = (unsigned)(*p - '0');
        else if (*p >= 'a' && *p <= 'f') d = (unsigned)(*p - 'a' + 10);
        else if (*p >= 'A' && *p <= 'F') d = (unsigned)(*p - 'A' + 10);
        else break;
        v = (v << 4) | d;
    }
    *pp = p;
    return v;
}

static uint32_t intern(const char *s, size_t n) {
    for (size_t i = 0; i < g_nmods; i++) {
        const char *e = g_names + g_mods[i].name;
        if (strlen(e) == n && memcmp(e, s, n) == 0) return g_mods[i].name;
    }
    if (g_names_used + n + 1 > SH_NAME_POOL) return 0;
    const uint32_t off = (uint32_t)g_names_used;
    memcpy(g_names + off, s, n);
    g_names[off + n] = '\0';
    g_names_used += n + 1;
    return off;
}

/* Find or create the module record for `path`, widening its bounds. */
static int32_t note_module(const char *path, size_t plen, uint64_t lo, uint64_t hi) {
    if (!plen) return -1;
    const uint32_t name = intern(path, plen);
    for (size_t i = 0; i < g_nmods; i++) {
        if (g_mods[i].name != name) continue;
        if (lo < g_mods[i].lo) g_mods[i].lo = lo;
        if (hi > g_mods[i].hi) g_mods[i].hi = hi;
        return (int32_t)i;
    }
    if (g_nmods >= SH_MAX_MODULES) return -1;
    g_mods[g_nmods].lo = lo;
    g_mods[g_nmods].hi = hi;
    g_mods[g_nmods].name = name;
    return (int32_t)g_nmods++;
}

static void parse_line(const char *line, size_t len) {
    const char *p = line;
    const uint64_t lo = hex64(&p);
    if (*p != '-') return;
    p++;
    const uint64_t hi = hex64(&p);
    if (hi <= lo || *p != ' ') return;
    p++;
    if (len < (size_t)(p - line) + 4) return;
    /*
     * Require readable AND executable. looks_like_ra() reads the four bytes
     * before a candidate to check for a call, so an execute-only mapping
     * would fault; leaving it out of the snapshot simply means candidates
     * there are not accepted.
     */
    const int usable = (p[0] == 'r' && p[2] == 'x');

    /* the pathname is the last field; absolute, or a [bracketed] pseudo-name */
    const char *path = NULL;
    size_t plen = 0;
    for (const char *q = p; q < line + len; q++) {
        if (*q == '/' || *q == '[') {
            path = q;
            plen = (size_t)(line + len - q);
            while (plen && (path[plen-1] == '\n' || path[plen-1] == ' ')) plen--;
            break;
        }
    }
    const int32_t mod = path ? note_module(path, plen, lo, hi) : -1;
    if (!usable) return;

    /* merge with the previous range when it is contiguous and same module */
    if (g_nexec && g_exec[g_nexec-1].hi == lo && g_exec[g_nexec-1].mod == mod) {
        g_exec[g_nexec-1].hi = hi;
        return;
    }
    if (g_nexec >= SH_MAX_EXEC) return;
    g_exec[g_nexec].lo = lo;
    g_exec[g_nexec].hi = hi;
    g_exec[g_nexec].mod = mod;
    g_nexec++;
}

/* Deliberately no stdio: this can run inside a hook, and fopen allocates. */
size_t sh_refresh_modules(void) {
    g_nmods = g_nexec = 0;
    g_names_used = 1;              /* offset 0 is the empty string */
    g_names[0] = '\0';

    const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) { g_have_snapshot = 1; return 0; }

    char buf[8192];
    size_t held = 0;
    for (;;) {
        const ssize_t got = read(fd, buf + held, sizeof buf - held);
        if (got <= 0) break;
        size_t avail = held + (size_t)got, start = 0;
        for (size_t i = 0; i < avail; i++) {
            if (buf[i] != '\n') continue;
            parse_line(buf + start, i - start);
            start = i + 1;
        }
        held = avail - start;
        if (held >= sizeof buf) held = 0;             /* absurd line: drop it */
        else memmove(buf, buf + start, held);
    }
    if (held) parse_line(buf, held);
    close(fd);
    g_have_snapshot = 1;
    return g_nexec;
}

static const exec_rec *exec_of(uint64_t a) {
    if (!g_have_snapshot) sh_refresh_modules();
    size_t lo = 0, hi = g_nexec;
    while (lo < hi) {                                  /* ranges are sorted */
        const size_t mid = lo + (hi - lo) / 2;
        if (a < g_exec[mid].lo)      hi = mid;
        else if (a >= g_exec[mid].hi) lo = mid + 1;
        else return &g_exec[mid];
    }
    return NULL;
}

/*
 * Which mapping contains `addr`? Allocation-free on purpose: this runs on
 * the first capture from a given thread, and that capture may be happening
 * inside a hook on malloc. open/read/close are syscalls and allocate
 * nothing, where fopen() and pthread_getattr_np() both can.
 */
static int find_mapping(uint64_t addr, uint64_t *lo, uint64_t *hi) {
    addr = SH_UNTAG(addr);
    const int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return 0;

    char buf[8192];
    size_t held = 0;
    int found = 0;
    while (!found) {
        const ssize_t got = read(fd, buf + held, sizeof buf - held);
        if (got <= 0) break;
        size_t avail = held + (size_t)got, start = 0;
        for (size_t i = 0; i < avail && !found; i++) {
            if (buf[i] != '\n') continue;
            const char *p = buf + start;
            const uint64_t s = hex64(&p);
            if (*p == '-') {
                p++;
                const uint64_t e = hex64(&p);
                if (e > s && addr >= s && addr < e) {
                    *lo = s; *hi = e; found = 1;
                }
            }
            start = i + 1;
        }
        held = avail - start;
        if (held >= sizeof buf) held = 0;
        else memmove(buf, buf + start, held);
    }
    close(fd);
    return found;
}

/* ------------------------------------------------ return-address filter */
static int looks_like_ra(uint64_t ra) {
    if (ra == 0 || (ra & 3)) return 0;                  /* A64 is 4-aligned */
    const exec_rec *r = exec_of(SH_UNTAG(ra));
    if (!r) return 0;
    const uint64_t a = SH_UNTAG(ra);
    if (a - 4 < r->lo) return 0;          /* no room for the call in front */
    uint32_t insn;
    memcpy(&insn, (const void *)(uintptr_t)(a - 4), 4);
    return is_call(insn);
}

/* ------------------------------------------------------- stack bounds */
static __thread uint64_t t_stack_lo, t_stack_hi;

static int stack_bounds(uint64_t sp, uint64_t *lo, uint64_t *hi) {
    sp = SH_UNTAG(sp);
    if (t_stack_hi && sp >= t_stack_lo && sp < t_stack_hi) {
        *lo = t_stack_lo; *hi = t_stack_hi; return 1;        /* cached */
    }
    uint64_t a = 0, b = 0;
    if (!find_mapping(sp, &a, &b)) return 0;
    t_stack_lo = a; t_stack_hi = b;
    *lo = a; *hi = b;
    return 1;
}

/*
 * How far above SP a fuzzy scan will look. The scan also stops as soon as
 * it has `max` candidates, so this only bounds the worst case - a request
 * for 16 frames almost never walks the whole window.
 */
#define SH_FUZZY_WINDOW (32 * 1024)

/* ----------------------------------------------------------- the walks */
static int in_stack(uint64_t a, uint64_t lo, uint64_t hi) {
    return a >= lo && a + 16 <= hi && (a & 15) == 0;
}

static size_t walk_fp(uint64_t fp, uint64_t sp, void **out, size_t max) {
    uint64_t lo, hi;
    if (!stack_bounds(sp, &lo, &hi)) return 0;

    size_t n = 0;
    uint64_t prev = 0;
    for (uint64_t f = SH_UNTAG(fp); n < max; ) {
        if (!in_stack(f, lo, hi)) break;
        if (f <= prev) break;              /* must climb: no loops, no games */
        prev = f;

        uint64_t next, ra;
        memcpy(&next, (const void *)(uintptr_t)f, 8);
        memcpy(&ra,   (const void *)(uintptr_t)(f + 8), 8);

        if (!looks_like_ra(ra)) break;
        out[n++] = (void *)(uintptr_t)SH_UNTAG(ra);
        f = SH_UNTAG(next);
    }
    return n;
}

static size_t walk_fuzzy(uint64_t sp, void **out, size_t max) {
    uint64_t lo, hi;
    if (!stack_bounds(sp, &lo, &hi)) return 0;

    uint64_t end = SH_UNTAG(sp) + SH_FUZZY_WINDOW;
    if (end > hi) end = hi;

    size_t n = 0;
    uint64_t last = 0;
    for (uint64_t p = (SH_UNTAG(sp) + 7) & ~7ULL; p + 8 <= end && n < max; p += 8) {
        uint64_t v;
        memcpy(&v, (const void *)(uintptr_t)p, 8);
        if (!looks_like_ra(v)) continue;
        v = SH_UNTAG(v);
        if (v == last) continue;           /* the same slot saved twice */
        out[n++] = (void *)(uintptr_t)v;
        last = v;
    }
    return n;
}

static size_t dedupe_push(void **out, size_t n, size_t max, uint64_t v) {
    if (n >= max) return n;
    if (n && (uint64_t)(uintptr_t)out[n-1] == v) return n;
    out[n] = (void *)(uintptr_t)v;
    return n + 1;
}

/*
 * Re-entrancy guard. Capturing a backtrace reads /proc/self/maps the first
 * time a thread does it, and a hook installed on something that path
 * touches would otherwise recurse into us forever. Nothing here allocates,
 * so this is belt and braces - but it is cheap and it turns a hang into a
 * missing trace.
 */
static __thread int t_busy;

static size_t run(uint64_t pc, uint64_t lr, uint64_t fp, uint64_t sp,
                  void **out, size_t max, sh_backtrace_mode mode, int with_pc)
{
    if (!out || max == 0) return 0;
    if (t_busy) return 0;
    t_busy = 1;

    size_t head = 0;
    if (with_pc && pc) head = dedupe_push(out, head, max, pc);
    if (lr && looks_like_ra(lr)) head = dedupe_push(out, head, max, lr);

    size_t n = head;
    if (mode == SH_BT_FP || mode == SH_BT_AUTO) {
        n = head + walk_fp(fp, sp, out + head, max - head);
        /* drop a frame 1 that the chain repeats */
        if (head && n > head && out[head] == out[head-1]) {
            memmove(out + head, out + head + 1, (n - head - 1) * sizeof *out);
            n--;
        }
        if (mode == SH_BT_FP || n >= 2) { t_busy = 0; return n; }
    }
    /* FUZZY, or AUTO where the frame chain gave us almost nothing */
    n = head + walk_fuzzy(sp, out + head, max - head);
    t_busy = 0;
    return n;
}

__attribute__((noinline))
size_t sh_backtrace(void **out, size_t max, sh_backtrace_mode mode) {
    uint64_t fp, sp;
    __asm__ volatile("mov %0, x29" : "=r"(fp));
    __asm__ volatile("mov %0, sp"  : "=r"(sp));
    /*
     * Our own frame record is the starting point, so [fp+8] is our return
     * address - the caller's PC - and the walk proceeds from there. That
     * keeps sh_backtrace itself out of the result without any skipping.
     */
    return run(0, 0, fp, sp, out, max, mode, 0);
}

size_t sh_backtrace_from(const sh_context *ctx, void **out, size_t max,
                         sh_backtrace_mode mode)
{
    if (!ctx) return 0;
    return run(ctx->pc, ctx->x[30], ctx->x[29], ctx->sp, out, max, mode, 1);
}

/* ------------------------------------------------------- symbolication */
static const char *basename_of(const char *p) {
    const char *s = strrchr(p, '/');
    return s ? s + 1 : p;
}

int sh_addr_info(const void *addr, sh_frame_info *out) {
    if (!out) return 0;
    memset(out, 0, sizeof *out);
    out->address = addr;
    const uint64_t a = SH_UNTAG(addr);
    int resolved = 0;

    Dl_info di;
    memset(&di, 0, sizeof di);
    if (dladdr((void *)(uintptr_t)a, &di) && di.dli_fbase) {
        out->module_base   = di.dli_fbase;
        out->module_offset = (size_t)(a - (uint64_t)(uintptr_t)di.dli_fbase);
        if (di.dli_fname)
            snprintf(out->module, sizeof out->module, "%s", basename_of(di.dli_fname));
        if (di.dli_sname && di.dli_saddr) {
            snprintf(out->symbol, sizeof out->symbol, "%s", di.dli_sname);
            out->symbol_offset = (size_t)(a - (uint64_t)(uintptr_t)di.dli_saddr);
        }
        resolved = 1;
    }

    if (!resolved) {                       /* fall back to our own snapshot */
        if (!g_have_snapshot) sh_refresh_modules();
        const exec_rec *r = exec_of(a);
        if (r && r->mod >= 0) {
            const module_rec *m = &g_mods[r->mod];
            out->module_base   = (const void *)(uintptr_t)m->lo;
            out->module_offset = (size_t)(a - m->lo);
            snprintf(out->module, sizeof out->module, "%s",
                     basename_of(g_names + m->name));
            resolved = 1;
        }
    }
    return resolved;
}

size_t sh_format_frame(const void *addr, char *buf, size_t cap) {
    if (!buf || cap == 0) return 0;
    sh_frame_info fi;
    int n;
    if (!sh_addr_info(addr, &fi) || fi.module[0] == '\0') {
        n = snprintf(buf, cap, "0x%llx",
                     (unsigned long long)SH_UNTAG(addr));
    } else if (fi.symbol[0]) {
        n = snprintf(buf, cap, "%s!0x%llx (%s+0x%llx)", fi.module,
                     (unsigned long long)fi.module_offset, fi.symbol,
                     (unsigned long long)fi.symbol_offset);
    } else {
        n = snprintf(buf, cap, "%s!0x%llx", fi.module,
                     (unsigned long long)fi.module_offset);
    }
    if (n < 0) { buf[0] = '\0'; return 0; }
    return (size_t)n >= cap ? cap - 1 : (size_t)n;
}

size_t sh_format_backtrace(void *const *frames, size_t n, char *buf, size_t cap) {
    if (!buf || cap == 0) return 0;
    buf[0] = '\0';
    if (!frames) return 0;

    size_t used = 0;
    for (size_t i = 0; i < n; i++) {
        char line[384];
        const size_t fl = sh_format_frame(frames[i], line, sizeof line);
        (void)fl;
        const int w = snprintf(buf + used, cap - used, "#%02zu 0x%llx %s\n", i,
                               (unsigned long long)SH_UNTAG(frames[i]), line);
        if (w < 0) break;
        if ((size_t)w >= cap - used) { used = cap - 1; break; }
        used += (size_t)w;
    }
    return used;
}
