/* Compiled with -fomit-frame-pointer so the FP chain breaks here and the
 * fuzzy scan has to carry the trace. */
#include <stddef.h>
#include "../include/slophook.h"

size_t nofp_depth3(void **out, size_t max, sh_backtrace_mode m);

__attribute__((noinline)) size_t nofp_leaf(void **out, size_t max, sh_backtrace_mode m) {
    return sh_backtrace(out, max, m);
}
__attribute__((noinline)) size_t nofp_mid(void **out, size_t max, sh_backtrace_mode m) {
    size_t n = nofp_leaf(out, max, m);
    __asm__ volatile("" ::: "memory");
    return n;
}
__attribute__((noinline)) size_t nofp_depth3(void **out, size_t max, sh_backtrace_mode m) {
    size_t n = nofp_mid(out, max, m);
    __asm__ volatile("" ::: "memory");
    return n;
}
