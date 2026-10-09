/* Backtracing across real shared libraries, with symbol names. */
#define _GNU_SOURCE
#include "../include/slophook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static void *frames[24];
static size_t nframes;
static int captured;
static int hits;
static void *volatile sink;
static void on_hit(sh_context *ctx, void *user){
    (void)user;
    hits++;
    if (captured) return;              /* keep the FIRST hit, not the last */
    nframes = sh_backtrace_from(ctx, frames, 24, SH_BT_AUTO);
    captured = 1;
}
static void dump(const char *what){
    printf("  %s: %zu frames\n", what, nframes);
    char buf[4096];
    sh_format_backtrace(frames, nframes, buf, sizeof buf);
    fputs(buf, stdout);
}
/* the pointer has to escape, or -O2 deletes the malloc/free pair outright */
__attribute__((noinline)) static void inner(void){
    void *p = malloc(177);
    sink = p;
    __asm__ volatile("" :: "r"(p) : "memory");
    free(p);
}
__attribute__((noinline)) static void middle(void){ inner(); __asm__ volatile("":::"memory"); }
__attribute__((noinline)) static void outer(void){ middle(); __asm__ volatile("":::"memory"); }

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    printf("executable ranges: %zu\n\n", sh_refresh_modules());

    sh_frame_info fi;
    char l[256];
    sh_format_frame((void*)strlen, l, sizeof l); printf("strlen -> %s\n", l);
    sh_format_frame((void*)main,   l, sizeof l); printf("main   -> %s\n", l);
    if (sh_addr_info((void*)strlen, &fi))
        printf("         base=%p offset=0x%zx\n\n", fi.module_base, fi.module_offset);

    void *mallocp = sh_sym("libc.so.6", "malloc");
    printf("hooking malloc at %p\n", mallocp);
    sh_status st = sh_instrument(mallocp, on_hit, NULL);
    printf("sh_instrument(malloc) -> %s\n\n", sh_strerror(st));
    if (st == SH_OK) {
        nframes = 0; captured = 0; hits = 0;
        outer();
        sh_unhook(mallocp);
        printf("  malloc hook fired %d time(s)\n", hits);
        dump("backtrace from inside malloc");
    }
    return 0;
}
