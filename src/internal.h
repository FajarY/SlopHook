/* Cross-module region bookkeeping, so a hook and a direct patch can never
 * be installed over the same bytes. See the overlap discussion in hook.c. */
#ifndef SH_INTERNAL_H
#define SH_INTERNAL_H
#include <stddef.h>

/* Does [addr, addr+len) overlap a region currently held by a hook? */
int sh_hook_region_overlaps(const void *addr, size_t len);

/* Does [addr, addr+len) overlap a region currently held by a direct patch? */
int sh_patch_region_overlaps(const void *addr, size_t len);

#endif
