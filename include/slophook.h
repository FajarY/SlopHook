/*
 * slophook - a minimal inline hooking engine for AArch64 (Android / Linux)
 *
 * Public API. See README.md for the design rationale.
 */
#ifndef SLOPHOOK_H
#define SLOPHOOK_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SH_OK = 0,
    SH_ERR_ALIGN        = -1,  /* target address not 4-byte aligned          */
    SH_ERR_NOMEM        = -2,  /* could not allocate trampoline memory       */
    SH_ERR_PROTECT      = -3,  /* could not make target page writable        */
    SH_ERR_RELOC        = -4,  /* an instruction in the prologue is not
                                  safely relocatable                         */
    SH_ERR_SELF_BRANCH  = -5,  /* prologue branches into the patched region  */
    SH_ERR_ALREADY      = -6,  /* address is already hooked                  */
    SH_ERR_NOTFOUND     = -7,  /* no hook registered at this address         */
    SH_ERR_RANGE        = -8,  /* unreachable target / immediate overflow    */
    SH_ERR_INVAL        = -9,  /* bad argument                               */
    SH_ERR_NOTCODE      = -10, /* target is not in a readable, executable
                                  mapping - almost always a mis-resolved
                                  address pointing at data or the heap      */
} sh_status;

/*
 * Full register context presented to an instrument callback.
 * Layout is mirrored exactly by src/bridge_arm64.S - keep them in sync.
 */
typedef struct {
    uint64_t x[31];     /* x0..x30 (x30 == LR)                              */
    uint64_t sp;        /* SP as it was at the hooked instruction           */
    uint64_t pc;        /* address of the hooked instruction                */
    uint64_t nzcv;      /* condition flags, as read by MRS                  */
    __uint128_t q[8];   /* v0..v7 - the AAPCS64 argument/result vectors     */
} sh_context;

typedef void (*sh_instrument_cb)(sh_context *ctx, void *user);

/*
 * Replace `target` with `replacement`.
 *
 * On success *origin receives a callable pointer that executes the original
 * prologue and then resumes the target function. Call it to "call through".
 * Pass origin == NULL if you never need the original behaviour.
 */
sh_status sh_hook(void *target, void *replacement, void **origin);

/*
 * Run `cb` every time execution reaches `addr`, then continue normally.
 * The callback may freely modify ctx->x[], ctx->nzcv and ctx->q[]; the
 * modified values are written back before execution resumes.
 */
sh_status sh_instrument(void *addr, sh_instrument_cb cb, void *user);

/* Restore the original bytes at `target` and release its trampoline. */
sh_status sh_unhook(void *target);

/* ======================================================================
 * Direct code patching
 *
 * The other half of the engine: edit instructions in place, with no
 * trampoline and no relocation. sh_patch_code() is the primitive (the
 * equivalent of Frida's Memory.patchCode); the sh_put_* family below is the
 * ergonomic layer built on it.
 *
 * Everything funnels through sh_patch_code() so there is exactly one place
 * that handles page write access (mprotect, falling back to /proc/self/mem
 * when SELinux denies execmod), the dc/ic/isb maintenance that must follow
 * any instruction write, remembering the original bytes for sh_revert(),
 * and using a single naturally aligned store when - and only when - the
 * patch is exactly 4 bytes, which makes it atomic against other threads.
 * ====================================================================== */

#define SH_INSN_NOP 0xD503201Fu
#define SH_INSN_RET 0xD65F03C0u
#define SH_INSN_BRK 0xD4200000u   /* brk #0 */

/*
 * Called with a scratch copy of the region in `code`, pre-loaded with the
 * bytes currently at `addr`. Write your new instructions into `code`; they
 * are committed when you return.
 *
 * `code` is NOT `addr` - it is a writable copy. Use `addr` (also passed in)
 * for any PC-relative arithmetic. `size` is always a multiple of 4.
 */
typedef void (*sh_patch_cb)(void *code, void *addr, size_t size, void *user);

/*
 * Apply `cb` to the `size` bytes at `addr`. `addr` must be 4-byte aligned
 * and `size` a non-zero multiple of 4.
 *
 * Patching a region that overlaps an existing hook, or a *different*
 * existing patch, is refused with SH_ERR_ALREADY. Re-patching exactly the
 * same [addr, size) is allowed and keeps the first original, so one
 * sh_revert() still restores untouched code.
 */
sh_status sh_patch_code(void *addr, size_t size, sh_patch_cb cb, void *user);

/* Restore the bytes at `addr` as they were before the first patch there. */
sh_status sh_revert(void *addr);

/* Revert every outstanding patch. Returns how many were reverted. */
size_t sh_revert_all(void);

/* Is there a patch registered exactly at `addr`? */
int sh_is_patched(const void *addr);

/* Read a region of code, e.g. to save it yourself before patching. */
sh_status sh_read_code(const void *addr, void *dst, size_t n);

/* ======================================================================
 * sh_put_* - the utility layer
 *
 * These overwrite the start of a function (or any instruction) with a
 * short sequence. The 4-byte ones are atomic; the longer ones are not.
 *
 * NOTHING HERE KNOWS HOW LONG YOUR FUNCTION IS. Writing a 20-byte stub
 * over a 12-byte function overwrites whatever follows it, and overlap
 * detection only protects a neighbour that is itself hooked or patched.
 * Use the sh_size_* queries against a symbol size from .symtab when it
 * matters.
 * ====================================================================== */

/* ---- 4 bytes, single atomic store ------------------------------------ */
sh_status sh_put_nop  (void *addr);              /* nop                   */
sh_status sh_put_nops (void *addr, size_t count);/* `count` nops          */
sh_status sh_put_ret  (void *addr);              /* ret - function no-ops */
sh_status sh_put_brk  (void *addr);              /* brk #0 - trap here    */

/* Delete a call: 4 atomic bytes over a BL. Same as sh_put_nop, named for
 * what you are actually doing. */
sh_status sh_nop_call (void *call_site);

/* ---- return a constant: mov into the result register, then ret -------- */
sh_status sh_put_true  (void *addr);                 /* return 1   (8 B)  */
sh_status sh_put_false (void *addr);                 /* return 0   (8 B)  */
sh_status sh_put_int   (void *addr, int32_t  value); /* w0, 8-12 B        */
sh_status sh_put_long  (void *addr, int64_t  value); /* x0, 8-20 B        */
sh_status sh_put_float (void *addr, float    value); /* s0, 8-16 B        */
sh_status sh_put_double(void *addr, double   value); /* d0, 8-24 B        */

/* ---- raw instructions ------------------------------------------------- */
sh_status sh_put_bytes(void *addr, const void *src, size_t n);

/*
 * Bytes written as a hex string, in MEMORY order - exactly what you copy
 * out of a hex editor or IDA. Separators (space, comma, ':', '-') and
 * "0x" prefixes are ignored.
 *
 *     sh_put_hex(addr, "1F 20 03 D5");        // nop
 *     sh_put_hex(addr, "20008052C0035FD6");   // mov w0,#1 ; ret
 */
sh_status sh_put_hex(void *addr, const char *hex);

/* ---- branches --------------------------------------------------------- */
sh_status sh_put_b   (void *addr, void *dest);  /* b  dest, 4 B or RANGE  */
sh_status sh_put_bl  (void *addr, void *dest);  /* bl dest, 4 B or RANGE  */

/*
 * Unconditional redirect. A direct B when `dest` is within +-128MB (4
 * bytes, atomic), otherwise a 16-byte absolute jump that clobbers X17 -
 * safe at a function entry, where AAPCS64 makes X17 dead, but NOT in the
 * middle of a function. Check sh_size_jump() if that matters.
 */
sh_status sh_put_jump(void *addr, void *dest);

/* ---- how many bytes each of the above would write -------------------- */
size_t sh_size_int   (int32_t value);
size_t sh_size_long  (int64_t value);
size_t sh_size_float (float  value);
size_t sh_size_double(double value);
size_t sh_size_jump  (const void *addr, const void *dest);
size_t sh_size_hex   (const char *hex);          /* 0 if it will not parse */

/* Encode a B (with_link = 0) or BL (with_link = 1). 0 if out of imm26. */
uint32_t sh_enc_branch(const void *from, const void *to, int with_link);

/* ======================================================================
 * Hook-side utilities
 * ====================================================================== */

/* Remove every installed hook. Returns how many were removed. */
size_t sh_unhook_all(void);

/* Is there a hook registered exactly at `addr`? */
int sh_is_hooked(const void *addr);

/* ======================================================================
 * Finding targets
 * ====================================================================== */

/*
 * Load address of the first mapping whose pathname contains
 * `name_substring`, from /proc/self/maps - the base to add a file offset
 * to. NULL if not mapped. If `out_span` is non-NULL it receives the number
 * of bytes from that base to the end of the module's last mapping.
 *
 *     void *base = sh_module_base("libil2cpp.so", NULL);
 */
void *sh_module_base(const char *name_substring, size_t *out_span);

/* sh_module_base(name) + offset, or NULL if the module is not mapped. */
void *sh_resolve(const char *name_substring, size_t offset);

/* dlopen + dlsym in one call, for exported symbols. NULL on failure. */
void *sh_sym(const char *soname, const char *symbol);

/* Human readable form of an sh_status. */
const char *sh_strerror(sh_status st);

#ifdef __cplusplus
}
#endif
#endif /* SLOPHOOK_H */
