#ifndef SH_MEM_H
#define SH_MEM_H
#include <stdint.h>
#include <stddef.h>
#include "../include/slophook.h"

/*
 * AArch64 Top Byte Ignore: bits 63:56 of a pointer are not part of the
 * address, and Android's allocator puts a tag there. The CPU ignores it on
 * load/store, but it must be stripped before any page arithmetic or any
 * syscall argument, or the computed range is nonsense.
 */
#define SH_UNTAG(p) ((uint64_t)(uintptr_t)(p) & 0x00FFFFFFFFFFFFFFULL)

/*
 * Current protection of the mapping containing `addr`, as PROT_* bits.
 * Returns 1 on success, 0 if /proc/self/maps is unreadable or `addr` is not
 * mapped at all.
 */
int sh_mem_prot_of(uint64_t addr, int *out_prot);

/*
 * Is [addr, addr+len) safe to overwrite as code? It must be one mapping,
 * executable, and readable (we have to copy the original bytes out).
 *
 *    1  yes
 *    0  no - not mapped, not executable, not readable, or it straddles two
 *       mappings
 *   -1  cannot tell (/proc/self/maps unreadable); caller should proceed
 *
 * This is the guard that turns "patch something that is not code" from
 * silent page-permission damage into a clean refusal.
 */
int sh_mem_patchable(uint64_t addr, size_t len);

/* Reserve `size` bytes of executable memory within +-120MB of `anchor`,
 * so that a single 4-byte B instruction can reach it. */
void *sh_mem_alloc_near(uint64_t anchor, size_t size);

/* Open/close a write window on trampoline memory. These are no-ops when the
 * arena is already RWX; otherwise they flip RW <-> RX around the write. */
sh_status sh_mem_begin_write(void *p, size_t n);
sh_status sh_mem_end_write(void *p, size_t n);

/* Overwrite instructions at a (normally read-only, file-backed) address. */
sh_status sh_code_write(void *dst, const void *src, size_t n);

/* Replace exactly one aligned instruction with a single release store. */
sh_status sh_code_patch_word(void *dst, uint32_t insn);

void sh_flush_icache(void *start, size_t n);

/* Executable memory anywhere in the address space (used when no page is
 * free within branch range of the target). */
void *sh_mem_alloc_any(size_t size);

#endif
