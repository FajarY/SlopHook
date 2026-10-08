#ifndef ARM64_RELOCATE_H
#define ARM64_RELOCATE_H
#include <stdint.h>
#include <stddef.h>
#include "../include/slophook.h"


sh_status sh_relocate(const uint32_t *src, uint64_t src_pc, size_t min_bytes,
                      uint32_t *dst, uint64_t dst_pc, size_t dst_cap_bytes,
                      size_t *out_src_bytes, size_t *out_dst_bytes);

int sh_region_ends_unconditionally(const uint32_t *src, size_t bytes);

sh_status sh_emit_tail_jump(uint32_t *dst, uint64_t dst_pc, size_t dst_cap_bytes,
                            uint64_t resume_pc, size_t *out_bytes);

sh_status sh_emit_detour(uint32_t *dst, uint64_t at_pc, size_t dst_cap_bytes,
                         uint64_t dest_pc, size_t *out_bytes);
#endif
