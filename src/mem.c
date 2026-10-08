#define _GNU_SOURCE
#include "mem.h"
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#ifndef MAP_FIXED_NOREPLACE
#define MAP_FIXED_NOREPLACE 0x100000
#endif

/* B imm26 reaches +-128MB. Keep a margin so an entire trampoline, not just
 * its first byte, stays inside the window. */
#define NEAR_WINDOW (120ULL << 20)

/*
 * Test-only knobs for exercising the fallback paths that are hard to reach
 * on purpose. Compiled in ONLY with -DSH_TEST_HOOKS, which the Android build
 * never defines - see Makefile.hosttests.
 */
#ifdef SH_TEST_HOOKS
#define SH_TEST_ON(name) (getenv(name) != NULL)
#else
#define SH_TEST_ON(name) 0
#endif

static size_t page_size(void) {
    static size_t ps;
    if (!ps) ps = (size_t)sysconf(_SC_PAGESIZE);
    return ps;
}
/* Both strip a top-byte pointer tag first: see SH_UNTAG in mem.h. */
static uint64_t page_down(uint64_t a) {
    return SH_UNTAG(a) & ~(uint64_t)(page_size() - 1);
}
static uint64_t page_up(uint64_t a) {
    const uint64_t m = page_size() - 1;
    return (SH_UNTAG(a) + m) & ~m;
}

/* ------------------------------------------------------ mapping lookups */
/*
 * One pass over /proc/self/maps looking for the mapping that contains
 * `addr`. Returns its PROT_* bits and bounds.
 */
static int map_of(uint64_t addr, int *prot, uint64_t *start, uint64_t *end) {
    addr = SH_UNTAG(addr);
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;

    char line[512];
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        unsigned long long s, e;
        char perm[8];
        if (sscanf(line, "%llx-%llx %4s", &s, &e, perm) != 3) continue;
        if (addr < (uint64_t)s || addr >= (uint64_t)e) continue;
        if (prot)  *prot  = (perm[0] == 'r' ? PROT_READ  : 0)
                          | (perm[1] == 'w' ? PROT_WRITE : 0)
                          | (perm[2] == 'x' ? PROT_EXEC  : 0);
        if (start) *start = (uint64_t)s;
        if (end)   *end   = (uint64_t)e;
        found = 1;
        break;
    }
    fclose(f);
    return found;
}

int sh_mem_prot_of(uint64_t addr, int *out_prot) {
    return map_of(addr, out_prot, NULL, NULL);
}

int sh_mem_patchable(uint64_t addr, size_t len) {
    addr = SH_UNTAG(addr);
    if (len == 0) return 0;

    int prot = 0;
    uint64_t start = 0, end = 0;
    if (!map_of(addr, &prot, &start, &end)) {
        /* Distinguish "no maps file" from "address is not mapped": if we can
         * read maps at all, an address we did not find really is unmapped. */
        FILE *f = fopen("/proc/self/maps", "re");
        if (!f) return -1;
        fclose(f);
        return 0;
    }
    if (!(prot & PROT_EXEC))  return 0;   /* not code */
    if (!(prot & PROT_READ))  return 0;   /* cannot copy the original bytes */
    if (addr + len > end)     return 0;   /* straddles a mapping boundary */
    return 1;
}

/* ------------------------------------------------------- arena bookkeeping */
typedef struct arena {
    uint64_t      base;
    size_t        size;
    size_t        used;
    int           rwx;       /* mapped read-write-execute, no flipping needed */
    struct arena *next;
} arena;

static arena *g_arenas;

/* --------------------------------------------------- /proc/self/maps scan */
typedef struct { uint64_t start, end; } range;

static size_t read_maps(range *out, size_t cap) {
    FILE *f = fopen("/proc/self/maps", "re");
    if (!f) return 0;
    char line[512];
    size_t n = 0;
    while (n < cap && fgets(line, sizeof line, f)) {
        uint64_t s, e;
        if (sscanf(line, "%lx-%lx", (unsigned long *)&s, (unsigned long *)&e) == 2)
            out[n].start = s, out[n].end = e, n++;
    }
    fclose(f);
    return n;
}

/*
 * Try to map exactly one page at `hint`.
 *
 * MAP_FIXED_NOREPLACE (Linux 4.17+) makes this safe: the kernel refuses
 * rather than silently unmapping something that is already there. On older
 * kernels we fall back to a plain hint, which the kernel treats as advisory
 * and will never use to clobber an existing mapping - we just have to check
 * where we actually landed.
 */
static void *try_map(uint64_t hint, size_t size, int *got_rwx) {
    /*
     * RWX first. A trampoline arena is shared by many hooks, and flipping a
     * live arena page to non-executable to install the next hook would fault
     * any thread currently running a trampoline in it. Where policy forbids
     * RWX we fall back to RW and the caller flips to RX, accepting that
     * narrow race; see README for the memfd dual-mapping that removes it.
     */
    const int prots[2] = { PROT_READ | PROT_WRITE | PROT_EXEC,
                           PROT_READ | PROT_WRITE };
    for (int i = SH_TEST_ON("SH_TEST_NO_RWX") ? 1 : 0; i < 2; i++) {
        *got_rwx = (i == 0);
        void *p = mmap((void *)hint, size, prots[i],
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);
        if (p != MAP_FAILED) return p;
        p = mmap((void *)hint, size, prots[i],
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p != MAP_FAILED) return p;
    }
    return NULL;
}

static int in_window(uint64_t addr, size_t size, uint64_t anchor) {
    uint64_t lo = anchor > NEAR_WINDOW ? anchor - NEAR_WINDOW : 0;
    uint64_t hi = anchor + NEAR_WINDOW;
    return addr >= lo && addr + size <= hi;
}

void *sh_mem_alloc_near(uint64_t anchor, size_t size) {
    if (SH_TEST_ON("SH_TEST_NO_NEAR")) return NULL;
    size = (size + 15) & ~(size_t)15;      /* sub-allocate inside a page */

    /*
     * An arena we already own may still have room in range - but only share
     * a page when it is RWX. A non-RWX arena has to be flipped to RW to write
     * the next trampoline into it, which would de-execute every trampoline
     * already live in that page and fault any thread running in one. Giving
     * each hook its own page costs a page instead of 256 bytes and removes
     * the race entirely.
     */
    for (arena *a = g_arenas; a; a = a->next) {
        if (!a->rwx) continue;
        size_t avail = a->size - a->used;
        uint64_t cand = a->base + a->used;
        if (avail >= size && in_window(cand, size, anchor)) {
            a->used += size;
            return (void *)cand;
        }
    }

    static range maps[4096];
    size_t nm = read_maps(maps, 4096);

    uint64_t lo = anchor > NEAR_WINDOW ? anchor - NEAR_WINDOW : page_size();
    uint64_t hi = anchor + NEAR_WINDOW;
    lo = page_up(lo);
    hi = page_down(hi);

    /* Collect gap candidates, nearest to the anchor first. */
    uint64_t cand[128];
    size_t nc = 0;
    for (size_t i = 0; i + 1 <= nm && nc < 128; i++) {
        uint64_t gs = maps[i].end;
        uint64_t ge = (i + 1 < nm) ? maps[i + 1].start : hi;
        if (ge <= gs) continue;
        if (gs < lo) gs = lo;
        if (ge > hi) ge = hi;
        if (ge < gs || ge - gs < size) continue;
        /* bias toward the end of the gap nearest the anchor */
        uint64_t pick = (anchor > gs) ? (ge - size) : gs;
        if (pick < gs) pick = gs;
        cand[nc++] = page_down(pick);
    }

    /* selection sort by distance from the anchor */
    for (size_t i = 0; i < nc; i++) {
        size_t best = i;
        for (size_t j = i + 1; j < nc; j++) {
            uint64_t dj = cand[j] > anchor ? cand[j] - anchor : anchor - cand[j];
            uint64_t db = cand[best] > anchor ? cand[best] - anchor : anchor - cand[best];
            if (dj < db) best = j;
        }
        uint64_t t = cand[i]; cand[i] = cand[best]; cand[best] = t;
    }

    const size_t asize = page_up(size);
    for (size_t i = 0; i < nc; i++) {
        int rwx = 0;
        void *p = try_map(cand[i], asize, &rwx);
        if (!p) continue;
        if (!in_window((uint64_t)p, asize, anchor)) { munmap(p, asize); continue; }
        arena *a = (arena *)calloc(1, sizeof *a);
        if (!a) { munmap(p, asize); return NULL; }
        a->base = (uint64_t)p; a->size = asize; a->used = size; a->rwx = rwx;
        a->next = g_arenas; g_arenas = a;
        return p;
    }
    return NULL;   /* caller must fall back to a 16-byte absolute detour */
}

/* ------------------------------------------------------------ protection */
static arena *arena_of(void *p) {
    uint64_t a = (uint64_t)p;
    for (arena *x = g_arenas; x; x = x->next)
        if (a >= x->base && a < x->base + x->size) return x;
    return NULL;
}

sh_status sh_mem_begin_write(void *p, size_t n) {
    arena *a = arena_of(p);
    if (a && a->rwx) return SH_OK;        /* already writable and executable */
    uint64_t s = page_down((uint64_t)p), e = page_up((uint64_t)p + n);
    return mprotect((void *)s, e - s, PROT_READ | PROT_WRITE) == 0
         ? SH_OK : SH_ERR_PROTECT;
}

sh_status sh_mem_end_write(void *p, size_t n) {
    arena *a = arena_of(p);
    if (!a || !a->rwx) {
        uint64_t s = page_down((uint64_t)p), e = page_up((uint64_t)p + n);
        if (mprotect((void *)s, e - s, PROT_READ | PROT_EXEC) != 0)
            return SH_ERR_PROTECT;
    }
    sh_flush_icache(p, n);
    return SH_OK;
}

/* ----------------------------------------------------------- code writes */
/*
 * Writing through /proc/self/mem goes via the kernel's access_process_vm(),
 * which ignores the VMA's write protection. It is the reliable fallback when
 * SELinux denies making a file-backed executable page writable (execmod).
 */
static sh_status write_via_procmem(void *dst, const void *src, size_t n) {
    int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
    if (fd < 0) return SH_ERR_PROTECT;
    /* The offset is an address, so it must be untagged. */
    ssize_t w = pwrite(fd, src, n, (off_t)SH_UNTAG(dst));
    close(fd);
    return (w == (ssize_t)n) ? SH_OK : SH_ERR_PROTECT;
}

/*
 * Protection to put back after a write, and the one to ask for in order to
 * perform it.
 *
 * Restoring a hardcoded PROT_READ|PROT_EXEC is wrong and actively dangerous:
 * on any page that was not r-x to begin with it silently strips PROT_WRITE,
 * and the next ordinary write to that page faults with SEGV_ACCERR somewhere
 * entirely unrelated to the patch. So read the real protection first and put
 * exactly that back. We also ask for `orig | PROT_WRITE` rather than RWX, so
 * a non-executable page does not briefly become executable.
 */
typedef struct { int have, orig, want; } prot_plan;

static prot_plan plan_write(uint64_t addr) {
    prot_plan p = { 0, PROT_READ | PROT_EXEC, PROT_READ | PROT_WRITE | PROT_EXEC };
    int cur = 0;
    if (sh_mem_prot_of(addr, &cur)) {
        p.have = 1;
        p.orig = cur;
        p.want = cur | PROT_WRITE;
    }
    return p;
}

sh_status sh_code_write(void *dst, const void *src, size_t n) {
    const uint64_t s = page_down((uint64_t)dst), e = page_up((uint64_t)dst + n);
    const prot_plan p = plan_write((uint64_t)dst);

    if (mprotect((void *)s, e - s, p.want) == 0) {
        memcpy(dst, src, n);
        /* Best effort restore. Leaving a page writable is a hardening
         * regression, so we care if this fails, but the patch is already in. */
        mprotect((void *)s, e - s, p.orig);
    } else if (write_via_procmem(dst, src, n) != SH_OK) {
        return SH_ERR_PROTECT;
    }
    sh_flush_icache(dst, n);
    return SH_OK;
}

sh_status sh_code_patch_word(void *dst, uint32_t insn) {
    if (SH_UNTAG(dst) & 3) return SH_ERR_ALIGN;
    const uint64_t s = page_down((uint64_t)dst), e = page_up((uint64_t)dst + 4);
    const prot_plan p = plan_write((uint64_t)dst);

    if (mprotect((void *)s, e - s, p.want) == 0) {
        /* A single naturally aligned 32-bit store is single-copy atomic on
         * AArch64: another core sees either the old or the new instruction,
         * never a tear. */
        __atomic_store_n((uint32_t *)dst, insn, __ATOMIC_RELEASE);
        mprotect((void *)s, e - s, p.orig);
    } else if (write_via_procmem(dst, &insn, 4) != SH_OK) {
        return SH_ERR_PROTECT;
    }
    sh_flush_icache(dst, 4);
    return SH_OK;
}

void sh_flush_icache(void *start, size_t n) {
    /*
     * AArch64 has split, non-coherent I and D caches. The compiler builtin
     * expands to the architecturally required sequence, reading CTR_EL0 for
     * the correct line sizes:
     *     dc cvau, <line> ; dsb ish ; ic ivau, <line> ; dsb ish ; isb
     */
    __builtin___clear_cache((char *)start, (char *)start + n);
}

void *sh_mem_alloc_any(size_t size) {
    size = (size + 15) & ~(size_t)15;
    for (arena *a = g_arenas; a; a = a->next)
        if (a->rwx && a->size - a->used >= size) {   /* see sh_mem_alloc_near */
            uint64_t p = a->base + a->used;
            a->used += size;
            return (void *)p;
        }
    size_t asize = page_up(size);
    int rwx = 1;
    void *p = mmap(NULL, asize, PROT_READ | PROT_WRITE | PROT_EXEC,
                   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) {
        rwx = 0;
        p = mmap(NULL, asize, PROT_READ | PROT_WRITE,
                 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) return NULL;
    }
    arena *a = (arena *)calloc(1, sizeof *a);
    if (!a) { munmap(p, asize); return NULL; }
    a->base = (uint64_t)p; a->size = asize; a->used = size; a->rwx = rwx;
    a->next = g_arenas; g_arenas = a;
    return p;
}
