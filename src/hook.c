/*
 * slophook - inline hook engine for AArch64.
 */
#include "../include/slophook.h"
#include "arm64_relocate.h"
#include "arm64_insn.h"
#include "mem.h"
#include "internal.h"
#include <stdlib.h>
#include <string.h>

/* Must match the offsets used by src/bridge_arm64.S */
typedef struct {
    uint64_t cb;
    uint64_t user;
    uint64_t resume;
    uint64_t pc;
} sh_closure_info;

extern void sh_bridge_entry(void);

/* ---- closure: 48 bytes, clobbers only X17 (which it saves) -------------
 *  +0   sub  sp, sp, #16
 *  +4   str  x17, [sp, #8]      ; preserve the caller's X17
 *  +8   ldr  x17, #24           ; -> +32
 *  +12  str  x17, [sp, #0]      ; &closure_info for the bridge
 *  +16  ldr  x17, #24           ; -> +40
 *  +20  br   x17                ; -> sh_bridge_entry
 *  +24  nop  / +28 nop
 *  +32  .quad &closure_info
 *  +40  .quad sh_bridge_entry
 */
#define CLOSURE_SIZE 48
static void build_closure(uint32_t *w, uint64_t info, uint64_t bridge) {
    w[0]  = 0xD10043FFu;                 /* sub sp, sp, #16    */
    w[1]  = 0xF90007F1u;                 /* str x17, [sp, #8]  */
    w[2]  = enc_ldr_lit_x(REG_IP1, 24);
    w[3]  = 0xF90003F1u;                 /* str x17, [sp]      */
    w[4]  = enc_ldr_lit_x(REG_IP1, 24);
    w[5]  = INSN_BR_X17;
    w[6]  = INSN_NOP;
    w[7]  = INSN_NOP;
    w[8]  = (uint32_t)(info & 0xFFFFFFFFu);
    w[9]  = (uint32_t)(info >> 32);
    w[10] = (uint32_t)(bridge & 0xFFFFFFFFu);
    w[11] = (uint32_t)(bridge >> 32);
}

/* ---- resume stub: undoes the closure's stack block --------------------- */
#define RESUME_STUB_SIZE 8
static void build_resume_stub(uint32_t *w) {
    w[0] = 0xF94007F1u;                  /* ldr x17, [sp, #8]  */
    w[1] = 0x910043FFu;                  /* add sp, sp, #16    */
}

/* ------------------------------------------------------------- registry */
typedef struct hook_entry {
    void              *target;
    size_t             patch_size;
    uint32_t           orig[4];
    void              *origin;
    sh_closure_info   *info;
    struct hook_entry *next;
} hook_entry;

static hook_entry *g_hooks;

static hook_entry *find_hook(void *target) {
    target = (void *)(uintptr_t)SH_UNTAG(target);
    for (hook_entry *h = g_hooks; h; h = h->next)
        if (h->target == target) return h;
    return NULL;
}

/*
 * A detour is 4 or 16 bytes wide. Two hooks whose patched regions overlap
 * would each save the other's bytes as "original", so unhooking leaves the
 * target permanently corrupted - and a 16-byte detour over a function
 * shorter than 16 bytes silently destroys whatever follows it.
 */
int sh_hook_region_overlaps(const void *addr, size_t len) {
    const uint64_t a0 = SH_UNTAG(addr), a1 = a0 + len;
    for (hook_entry *h = g_hooks; h; h = h->next) {
        const uint64_t b0 = (uint64_t)(uintptr_t)h->target, b1 = b0 + h->patch_size;
        if (a0 < b1 && b0 < a1) return 1;
    }
    return 0;
}

static hook_entry *find_overlap(void *target, size_t len) {
    const uint64_t a0 = SH_UNTAG(target), a1 = a0 + len;
    for (hook_entry *h = g_hooks; h; h = h->next) {
        const uint64_t b0 = (uint64_t)h->target, b1 = b0 + h->patch_size;
        if (a0 < b1 && b0 < a1) return h;
    }
    return NULL;
}

#define BLOCK_SIZE 256

/*
 * Decide how we reach `dest` from `target`.
 *
 * Preferred: a page within branch range holds a stub, so the patch at the
 * target is a single 4-byte B. That matters for two reasons - only one
 * instruction has to be relocated, and a single aligned store is atomic.
 *
 * Fallback: no free page in range, so we write a 16-byte absolute detour
 * directly over the target and relocate four instructions.
 */
typedef struct {
    uint8_t *block;      /* arena block for this hook      */
    size_t   patch_size; /* bytes overwritten at target    */
    int      near;
} placement;

static sh_status place(void *target, placement *out) {
    uint8_t *b = (uint8_t *)sh_mem_alloc_near((uint64_t)target, BLOCK_SIZE);
    if (b) { out->block = b; out->patch_size = 4;  out->near = 1; return SH_OK; }
    b = (uint8_t *)sh_mem_alloc_any(BLOCK_SIZE);
    if (!b) return SH_ERR_NOMEM;
    out->block = b; out->patch_size = 16; out->near = 0;
    return SH_OK;
}

/* Build the trampoline that runs the displaced prologue then rejoins the
 * original function. `prefix` is prepended verbatim (the resume stub, for
 * instrument hooks). */
static sh_status build_origin(void *target, size_t patch_size,
                              uint8_t *dst, size_t cap, const uint32_t *prefix,
                              size_t prefix_bytes, size_t *used)
{
    if (cap <= prefix_bytes) return SH_ERR_NOMEM;
    size_t n = 0;
    if (prefix_bytes) { memcpy(dst, prefix, prefix_bytes); n = prefix_bytes; }

    size_t src_used = 0, dst_used = 0;
    sh_status st = sh_relocate((const uint32_t *)target, (uint64_t)target,
                               patch_size, (uint32_t *)(dst + n),
                               (uint64_t)(dst + n), cap - n,
                               &src_used, &dst_used);
    if (st != SH_OK) return st;
    n += dst_used;

    /* If the displaced region always transfers control, the tail jump would
     * be dead code - and skipping it avoids needing a reachable direct B. */
    if (sh_region_ends_unconditionally((const uint32_t *)target, src_used)) {
        *used = n;
        return SH_OK;
    }

    size_t tail = 0;
    st = sh_emit_tail_jump((uint32_t *)(dst + n), (uint64_t)(dst + n),
                           cap - n,
                           (uint64_t)target + src_used, &tail);
    if (st != SH_OK) return st;
    *used = n + tail;
    return SH_OK;
}

/* Write the detour over the target, saving what was there. */
static sh_status install(hook_entry *h, void *target, uint64_t dest,
                         size_t patch_size)
{
    uint32_t patch[4];
    size_t   plen = 0;
    sh_status st = sh_emit_detour(patch, (uint64_t)target, sizeof patch,
                                  dest, &plen);
    if (st != SH_OK) return st;
    if (plen > patch_size) return SH_ERR_RANGE;

    memcpy(h->orig, target, patch_size);
    h->patch_size = patch_size;

    if (plen == 4 && patch_size == 4)
        return sh_code_patch_word(target, patch[0]);

    /* Pad a short detour out to the full displaced region so the leftover
     * bytes are never executed as a partial instruction. */
    for (size_t i = plen / 4; i < patch_size / 4; i++) patch[i] = INSN_NOP;
    return sh_code_write(target, patch, patch_size);
}

/* -------------------------------------------------------------- public */
sh_status sh_hook(void *target, void *replacement, void **origin) {
    if (!target || !replacement) return SH_ERR_INVAL;
    if (SH_UNTAG(target) & 3)    return SH_ERR_ALIGN;
    if (find_hook(target))       return SH_ERR_ALREADY;
    /* Cheap pre-check before we commit any arena memory. */
    if (sh_mem_patchable((uint64_t)target, 4) == 0) return SH_ERR_NOTCODE;

    placement pl;
    sh_status st = place(target, &pl);
    if (st != SH_OK) return st;
    if (sh_mem_patchable((uint64_t)target, pl.patch_size) == 0)
        return SH_ERR_NOTCODE;
    target = (void *)(uintptr_t)SH_UNTAG(target);
    if (find_overlap(target, pl.patch_size))                return SH_ERR_ALREADY;
    if (sh_patch_region_overlaps(target, pl.patch_size))    return SH_ERR_ALREADY;

    st = sh_mem_begin_write(pl.block, BLOCK_SIZE);
    if (st != SH_OK) return st;

    uint8_t *cursor = pl.block;
    uint64_t dest   = (uint64_t)replacement;

    if (pl.near) {
        /* The 4-byte B at the target can only reach +-128MB, and the
         * replacement usually lives in a different mapping. Bounce through
         * an absolute jump placed in the near page. */
        size_t n = 0;
        st = sh_emit_detour((uint32_t *)cursor, (uint64_t)cursor, 32,
                            (uint64_t)replacement, &n);
        if (st != SH_OK) { sh_mem_end_write(pl.block, BLOCK_SIZE); return st; }
        dest = (uint64_t)cursor;
        cursor += (n + 15) & ~(size_t)15;
    }

    size_t used = 0;
    st = build_origin(target, pl.patch_size, cursor,
                      BLOCK_SIZE - (size_t)(cursor - pl.block), NULL, 0, &used);
    if (st != SH_OK) { sh_mem_end_write(pl.block, BLOCK_SIZE); return st; }

    hook_entry *h = (hook_entry *)calloc(1, sizeof *h);
    if (!h) { sh_mem_end_write(pl.block, BLOCK_SIZE); return SH_ERR_NOMEM; }
    h->target = target;
    h->origin = cursor;

    /* Publish the trampoline - and make it visible to the instruction fetch
     * path - strictly before the target starts branching into it. */
    sh_mem_end_write(pl.block, BLOCK_SIZE);

    /* Publish *origin BEFORE the detour goes live: another thread may already
     * be calling `target`, and it will reach `replacement` - which typically
     * dereferences *origin - the instant install() lands. */
    if (origin) *origin = cursor;
    __atomic_thread_fence(__ATOMIC_RELEASE);

    st = install(h, target, dest, pl.patch_size);
    if (st != SH_OK) { if (origin) *origin = NULL; free(h); return st; }

    h->next = g_hooks; g_hooks = h;
    return SH_OK;
}

sh_status sh_instrument(void *addr, sh_instrument_cb cb, void *user) {
    if (!addr || !cb)        return SH_ERR_INVAL;
    if (SH_UNTAG(addr) & 3)  return SH_ERR_ALIGN;
    if (find_hook(addr))     return SH_ERR_ALREADY;
    if (sh_mem_patchable((uint64_t)addr, 4) == 0) return SH_ERR_NOTCODE;

    placement pl;
    sh_status st = place(addr, &pl);
    if (st != SH_OK) return st;
    if (sh_mem_patchable((uint64_t)addr, pl.patch_size) == 0)
        return SH_ERR_NOTCODE;
    addr = (void *)(uintptr_t)SH_UNTAG(addr);
    if (find_overlap(addr, pl.patch_size))                return SH_ERR_ALREADY;
    if (sh_patch_region_overlaps(addr, pl.patch_size))    return SH_ERR_ALREADY;

    sh_closure_info *info = (sh_closure_info *)calloc(1, sizeof *info);
    if (!info) return SH_ERR_NOMEM;

    st = sh_mem_begin_write(pl.block, BLOCK_SIZE);
    if (st != SH_OK) { free(info); return st; }

    uint8_t *closure = pl.block;
    uint8_t *resume  = pl.block + CLOSURE_SIZE;

    uint32_t stub[RESUME_STUB_SIZE / 4];
    build_resume_stub(stub);

    size_t used = 0;
    st = build_origin(addr, pl.patch_size, resume, BLOCK_SIZE - CLOSURE_SIZE,
                      stub, sizeof stub, &used);
    if (st != SH_OK) { sh_mem_end_write(pl.block, BLOCK_SIZE); free(info); return st; }

    info->cb     = (uint64_t)(uintptr_t)cb;
    info->user   = (uint64_t)(uintptr_t)user;
    info->resume = (uint64_t)resume;
    info->pc     = (uint64_t)addr;

    build_closure((uint32_t *)closure, (uint64_t)(uintptr_t)info,
                  (uint64_t)(uintptr_t)&sh_bridge_entry);

    hook_entry *h = (hook_entry *)calloc(1, sizeof *h);
    if (!h) { sh_mem_end_write(pl.block, BLOCK_SIZE); free(info); return SH_ERR_NOMEM; }
    h->target = addr;
    h->info   = info;

    sh_mem_end_write(pl.block, BLOCK_SIZE);

    st = install(h, addr, (uint64_t)closure, pl.patch_size);
    if (st != SH_OK) { free(h); free(info); return st; }

    h->next = g_hooks; g_hooks = h;
    return SH_OK;
}

sh_status sh_unhook(void *target) {
    target = (void *)(uintptr_t)SH_UNTAG(target);
    hook_entry **pp = &g_hooks;
    while (*pp && (*pp)->target != target) pp = &(*pp)->next;
    if (!*pp) return SH_ERR_NOTFOUND;
    hook_entry *h = *pp;

    sh_status st = (h->patch_size == 4)
        ? sh_code_patch_word(target, h->orig[0])
        : sh_code_write(target, h->orig, h->patch_size);
    if (st != SH_OK) return st;

    *pp = h->next;
    free(h->info);
    free(h);
    return SH_OK;
}

int sh_is_hooked(const void *addr) {
    addr = (const void *)(uintptr_t)SH_UNTAG(addr);
    for (hook_entry *h = g_hooks; h; h = h->next)
        if (h->target == addr) return 1;
    return 0;
}

size_t sh_unhook_all(void) {
    size_t n = 0;
    while (g_hooks) {
        void *t = g_hooks->target;
        if (sh_unhook(t) != SH_OK) break;    /* cannot make progress */
        n++;
    }
    return n;
}

const char *sh_strerror(sh_status st) {
    switch (st) {
    case SH_OK:               return "ok";
    case SH_ERR_ALIGN:        return "address is not 4-byte aligned";
    case SH_ERR_NOMEM:        return "out of trampoline memory";
    case SH_ERR_PROTECT:      return "could not make target page writable";
    case SH_ERR_RELOC:        return "prologue contains a non-relocatable instruction";
    case SH_ERR_SELF_BRANCH:  return "prologue branches into the patched region";
    case SH_ERR_ALREADY:      return "already hooked";
    case SH_ERR_NOTFOUND:     return "not hooked";
    case SH_ERR_RANGE:        return "target out of branch range";
    case SH_ERR_INVAL:        return "invalid argument";
    case SH_ERR_NOTCODE:      return "target is not in a readable, executable mapping";
    }
    return "unknown";
}
