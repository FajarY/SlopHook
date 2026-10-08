/*
 * slophook - direct code patching.
 *
 * This is the "edit the instructions in place" half of the engine, the
 * equivalent of Frida's Memory.patchCode(). No trampoline, no relocation,
 * no registry of displaced prologues: just a correctly published write to a
 * code page, plus enough bookkeeping to undo it.
 *
 * Everything here funnels through sh_patch_code() so that there is exactly
 * one place that gets the three hard parts right:
 *
 *   1. getting write access to a read-only, file-backed text page
 *      (mprotect, falling back to /proc/self/mem when SELinux says no),
 *   2. the I-cache/D-cache maintenance that must follow any instruction
 *      write on AArch64,
 *   3. using a single naturally aligned store when - and only when - the
 *      patch is exactly one word, so it is atomic against other threads.
 */
#include "../include/slophook.h"
#include "arm64_relocate.h"
#include "arm64_insn.h"
#include "internal.h"
#include "mem.h"
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------- registry */
typedef struct patch_entry {
    void               *addr;
    size_t              size;
    uint8_t            *orig;     /* bytes as they were before the first patch */
    struct patch_entry *next;
} patch_entry;

static patch_entry *g_patches;

static patch_entry *find_exact(const void *addr, size_t size) {
    addr = (const void *)(uintptr_t)SH_UNTAG(addr);
    for (patch_entry *p = g_patches; p; p = p->next)
        if (p->addr == addr && p->size == size) return p;
    return NULL;
}

int sh_patch_region_overlaps(const void *addr, size_t len) {
    const uint64_t a0 = SH_UNTAG(addr), a1 = a0 + len;
    for (patch_entry *p = g_patches; p; p = p->next) {
        const uint64_t b0 = (uint64_t)(uintptr_t)p->addr, b1 = b0 + p->size;
        if (a0 < b1 && b0 < a1) return 1;
    }
    return 0;
}

/* ------------------------------------------------------------ primitive */
sh_status sh_patch_code(void *addr, size_t size, sh_patch_cb cb, void *user) {
    if (!addr || !cb || size == 0)   return SH_ERR_INVAL;
    if (SH_UNTAG(addr) & 3)          return SH_ERR_ALIGN;
    if (size & 3)                    return SH_ERR_INVAL;

    /*
     * Refuse anything that is not readable, executable code. Without this a
     * mis-resolved target - a data symbol, a GOT slot, a heap buffer passed
     * where the address belonged - gets its page mprotected here and has
     * PROT_WRITE stripped on the way out. The fault then lands in whatever
     * touches that page next, typically the allocator, arbitrarily far from
     * the real mistake.
     */
    if (sh_mem_patchable((uint64_t)addr, size) == 0) return SH_ERR_NOTCODE;

    /* From here on work with the untagged address, so a caller that passes a
     * tagged pointer once and an untagged one later still matches the same
     * registry entry. */
    addr = (void *)(uintptr_t)SH_UNTAG(addr);

    /*
     * Re-patching the same region is a normal workflow, so only a *different*
     * overlapping region is a conflict. Refusing those is what stops two
     * patches (or a patch and a hook) each saving the other's bytes as
     * "original" and leaving the target permanently corrupted on revert.
     */
    patch_entry *existing = find_exact(addr, size);
    if (!existing) {
        if (sh_patch_region_overlaps(addr, size)) return SH_ERR_ALREADY;
        if (sh_hook_region_overlaps(addr, size))  return SH_ERR_ALREADY;
    }

    uint8_t *scratch = (uint8_t *)malloc(size);
    if (!scratch) return SH_ERR_NOMEM;
    memcpy(scratch, addr, size);          /* start from what is there now */

    patch_entry *pe = existing;
    if (!pe) {
        pe = (patch_entry *)calloc(1, sizeof *pe);
        if (!pe) { free(scratch); return SH_ERR_NOMEM; }
        pe->orig = (uint8_t *)malloc(size);
        if (!pe->orig) { free(pe); free(scratch); return SH_ERR_NOMEM; }
        memcpy(pe->orig, addr, size);
        pe->addr = addr;
        pe->size = size;
    }

    cb(scratch, addr, size, user);

    sh_status st;
    if (size == 4) {
        uint32_t w;
        memcpy(&w, scratch, 4);
        st = sh_code_patch_word(addr, w);   /* single-copy atomic */
    } else {
        st = sh_code_write(addr, scratch, size);
    }
    free(scratch);

    if (st != SH_OK) {
        if (!existing) { free(pe->orig); free(pe); }
        return st;
    }
    if (!existing) { pe->next = g_patches; g_patches = pe; }
    return SH_OK;
}

int sh_is_patched(const void *addr) {
    addr = (const void *)(uintptr_t)SH_UNTAG(addr);
    for (patch_entry *p = g_patches; p; p = p->next)
        if (p->addr == addr) return 1;
    return 0;
}

size_t sh_revert_all(void) {
    size_t n = 0;
    while (g_patches) {
        void *a = g_patches->addr;
        if (sh_revert(a) != SH_OK) break;    /* cannot make progress */
        n++;
    }
    return n;
}

sh_status sh_revert(void *addr) {
    addr = (void *)(uintptr_t)SH_UNTAG(addr);
    patch_entry **pp = &g_patches;
    while (*pp && (*pp)->addr != addr) pp = &(*pp)->next;
    if (!*pp) return SH_ERR_NOTFOUND;
    patch_entry *pe = *pp;

    sh_status st;
    if (pe->size == 4) {
        uint32_t w;
        memcpy(&w, pe->orig, 4);
        st = sh_code_patch_word(addr, w);
    } else {
        st = sh_code_write(addr, pe->orig, pe->size);
    }
    if (st != SH_OK) return st;

    *pp = pe->next;
    free(pe->orig);
    free(pe);
    return SH_OK;
}

sh_status sh_read_code(const void *addr, void *dst, size_t n) {
    if (!addr || !dst) return SH_ERR_INVAL;
    memcpy(dst, addr, n);
    return SH_OK;
}
