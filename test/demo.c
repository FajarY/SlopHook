/*
 * End-to-end test. Builds for aarch64 and runs under qemu-aarch64.
 */
#include "../include/slophook.h"
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(cond, fmt, ...) do {                                  \
    if (cond) printf("PASS  " fmt "\n", ##__VA_ARGS__);             \
    else { printf("FAIL  " fmt "\n", ##__VA_ARGS__); fails++; }     \
} while (0)

/* ---- 1. plain replace + call through ---------------------------------- */
__attribute__((noinline)) int add_i(int a, int b) { return a + b; }

static int (*orig_add)(int, int);
static int my_add(int a, int b) { return orig_add(a, b) * 100; }

/* ---- 2. a prologue containing ADRP ------------------------------------ */
const char g_msg[] = "the quick brown fox";
__attribute__((noinline)) const char *get_msg(void) { return g_msg; }
static const char *(*orig_get_msg)(void);
static const char *my_get_msg(void) { return "replaced"; }

/* ---- 3. instrumentation ----------------------------------------------- */
__attribute__((noinline)) int triple(int x) { return x * 3; }
static void bump_arg(sh_context *ctx, void *user) {
    (void)user;
    ctx->x[0] = 10;             /* rewrite the first argument in flight */
}

/* ---- 4. x17 liveness across an instrument hook ------------------------- */
__attribute__((noinline)) int uses_x17(int x) {
    register long marker asm("x17") = 0x1234567;
    asm volatile("" : "+r"(marker));
    int r = x * 2;
    asm volatile("" : : "r"(marker));
    return r + (int)(marker & 0xFF);
}
static int x17_seen_ok = 0;
static void peek(sh_context *ctx, void *user) {
    (void)user;
    x17_seen_ok = 1;
    ctx->x[9] = 0xDEAD;         /* scribble on a caller-saved register */
}

int main(void) {
    sh_status st;

    /* 1 ------------------------------------------------------------------ */
    int before = add_i(2, 3);
    st = sh_hook((void *)add_i, (void *)my_add, (void **)&orig_add);
    CHECK(st == SH_OK, "sh_hook(add_i) -> %s", sh_strerror(st));
    CHECK(add_i(2, 3) == 500, "replacement runs (got %d, want 500)", add_i(2, 3));
    CHECK(orig_add(2, 3) == 5, "origin trampoline reaches original (got %d)", orig_add(2, 3));
    st = sh_unhook((void *)add_i);
    CHECK(st == SH_OK, "sh_unhook -> %s", sh_strerror(st));
    CHECK(add_i(2, 3) == before, "original restored byte for byte");

    /* 2 ------------------------------------------------------------------ */
    const char *m0 = get_msg();
    st = sh_hook((void *)get_msg, (void *)my_get_msg, (void **)&orig_get_msg);
    CHECK(st == SH_OK, "sh_hook(get_msg, ADRP prologue) -> %s", sh_strerror(st));
    CHECK(strcmp(get_msg(), "replaced") == 0, "ADRP-prologue function replaced");
    CHECK(orig_get_msg() == m0,
          "relocated ADRP still computes the right page (%p vs %p)",
          (void *)orig_get_msg(), (void *)m0);
    CHECK(strcmp(orig_get_msg(), "the quick brown fox") == 0,
          "relocated ADRP + untouched ADD yield the original string");
    sh_unhook((void *)get_msg);

    /* 3 ------------------------------------------------------------------ */
    CHECK(triple(1) == 3, "triple(1) == 3 before instrumenting");
    st = sh_instrument((void *)triple, bump_arg, NULL);
    CHECK(st == SH_OK, "sh_instrument(triple) -> %s", sh_strerror(st));
    CHECK(triple(1) == 30, "callback rewrote the argument (got %d, want 30)", triple(1));
    st = sh_unhook((void *)triple);
    CHECK(st == SH_OK, "sh_unhook(triple) -> %s", sh_strerror(st));
    CHECK(triple(1) == 3, "behaviour restored after uninstrumenting");

    /* 4 ------------------------------------------------------------------ */
    int want = uses_x17(21);
    st = sh_instrument((void *)uses_x17, peek, NULL);
    CHECK(st == SH_OK, "sh_instrument(uses_x17) -> %s", sh_strerror(st));
    int got = uses_x17(21);
    CHECK(x17_seen_ok, "callback ran");
    CHECK(got == want, "X17 survived the bridge (got %d, want %d)", got, want);
    sh_unhook((void *)uses_x17);

    /* 5 ------------------------------------------------------------------ */
    st = sh_hook((void *)add_i, (void *)my_add, (void **)&orig_add);
    sh_status st2 = sh_hook((void *)add_i, (void *)my_add, NULL);
    CHECK(st2 == SH_ERR_ALREADY, "double hook refused -> %s", sh_strerror(st2));
    sh_unhook((void *)add_i);
    CHECK(sh_unhook((void *)add_i) == SH_ERR_NOTFOUND, "double unhook refused");
    CHECK(sh_hook((void *)((char *)add_i + 1), (void *)my_add, NULL) == SH_ERR_ALIGN,
          "misaligned target refused");

    printf("\n%s (%d failure%s)\n", fails ? "FAILED" : "ALL PASS",
           fails, fails == 1 ? "" : "s");
    return fails ? 1 : 0;
}
