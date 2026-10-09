/* Backtracing: FP chain, fuzzy scan, from an instrument context, and
 * symbolication. */
#define _GNU_SOURCE
#include "../include/slophook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>

static int fails;
#define CK(c,f,...) do{ if(c) printf("  PASS  " f "\n", ##__VA_ARGS__); \
    else { printf("  FAIL  " f "\n", ##__VA_ARGS__); fails++; } }while(0)
#define SEC(n) printf("\n%s\n", n)
#define NOINL __attribute__((noinline,used))

/* ---- a call chain with known bounds we can check frames against ---- */
typedef struct { void *lo, *hi; const char *name; } fnrange;
static void **g_out; static size_t g_max, g_n; static sh_backtrace_mode g_mode;

NOINL void level_a(void){ g_n = sh_backtrace(g_out, g_max, g_mode); __asm__ volatile("":::"memory"); }
NOINL void level_b(void){ level_a(); __asm__ volatile("":::"memory"); }
NOINL void level_c(void){ level_b(); __asm__ volatile("":::"memory"); }
NOINL void level_d(void){ level_c(); __asm__ volatile("":::"memory"); }
NOINL void level_end(void){ level_d(); __asm__ volatile("":::"memory"); }

/* Does `addr` fall inside [fn, fn+span)? Function sizes are not available
 * at runtime, so bound generously and rely on ordering for the real check. */
static int within(const void *addr, const void *fn, size_t span) {
    const uintptr_t a=(uintptr_t)addr, f=(uintptr_t)fn;
    return a >= f && a < f + span;
}

/* ---- instrument path ---- */
NOINL int target_fn(int x){ return x * 3; }
NOINL int caller_1(int x){ int r = target_fn(x); __asm__ volatile("":::"memory"); return r; }
NOINL int caller_2(int x){ int r = caller_1(x);  __asm__ volatile("":::"memory"); return r; }
NOINL int caller_3(int x){ int r = caller_2(x);  __asm__ volatile("":::"memory"); return r; }
static void *cb_frames[32];
static size_t cb_n;
static uint64_t cb_pc;
static void bt_cb(sh_context *ctx, void *user){
    cb_pc = ctx->pc;
    cb_n = sh_backtrace_from(ctx, cb_frames, 32, (sh_backtrace_mode)(uintptr_t)user);
}

/* ---- deep recursion ---- */
NOINL size_t recurse(int n, void **out, size_t max){
    if (n == 0) return sh_backtrace(out, max, SH_BT_FP);
    size_t r = recurse(n-1, out, max);
    __asm__ volatile("":::"memory");
    return r;
}

/* ---- another thread ---- */
static void *thread_main(void *u){
    void **o = (void**)u;
    size_t n = sh_backtrace(o, 16, SH_BT_AUTO);
    return (void*)(uintptr_t)n;
}

extern size_t nofp_depth3(void **out, size_t max, sh_backtrace_mode m);

/* every frame must be a plausible return address */
static int all_frames_valid(void *const *f, size_t n){
    for (size_t i=0;i<n;i++){
        sh_frame_info fi;
        if (!sh_addr_info(f[i], &fi)) return 0;
        if (((uintptr_t)f[i] & 3) != 0) return 0;
    }
    return 1;
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    void *fr[64];

    SEC("1. module snapshot");
    size_t nranges = sh_refresh_modules();
    CK(nranges > 0, "sh_refresh_modules found %zu executable ranges", nranges);
    sh_frame_info self;
    CK(sh_addr_info((void*)main, &self), "resolved main()");
    printf("  ....  main() -> %s!0x%zx%s%s\n", self.module, self.module_offset,
           self.symbol[0]?" sym=":"", self.symbol[0]?self.symbol:"");
    CK(self.module[0] != '\0', "module name is known (%s)", self.module);
    CK((uintptr_t)self.module_base <= (uintptr_t)main, "module base <= main()");

    SEC("2. FP chain over a known 5-deep call chain");
    g_out=fr; g_max=64; g_mode=SH_BT_FP; g_n=0;
    level_end();
    printf("  ....  %zu frames\n", g_n);
    for (size_t i=0;i<g_n && i<8;i++){ char l[256]; sh_format_frame(fr[i],l,sizeof l);
        printf("        #%02zu %p  %s\n", i, fr[i], l); }
    CK(g_n >= 5, "at least 5 frames (got %zu)", g_n);
    CK(all_frames_valid(fr,g_n), "every frame resolves and is 4-byte aligned");
    /* frames must be the call sites inside level_a..level_end, in order */
    CK(g_n>=5 && within(fr[0],(void*)level_b,0x100), "frame0 is in level_b");
    CK(g_n>=5 && within(fr[1],(void*)level_c,0x100), "frame1 is in level_c");
    CK(g_n>=5 && within(fr[2],(void*)level_d,0x100), "frame2 is in level_d");
    CK(g_n>=5 && within(fr[3],(void*)level_end,0x100),"frame3 is in level_end");
    CK(g_n>=5 && within(fr[4],(void*)main,0x2000),   "frame4 is in main");

    SEC("3. fuzzy scan over the same chain");
    g_mode=SH_BT_FUZZY; g_n=0;
    level_end();
    size_t fuzzy_n = g_n;
    printf("  ....  %zu frames\n", fuzzy_n);
    for (size_t i=0;i<fuzzy_n && i<8;i++){ char l[256]; sh_format_frame(fr[i],l,sizeof l);
        printf("        #%02zu %p  %s\n", i, fr[i], l); }
    CK(fuzzy_n >= 5, "at least 5 frames (got %zu)", fuzzy_n);
    CK(all_frames_valid(fr,fuzzy_n), "every frame resolves");
    /* the fuzzy scan walks up the stack, so the real chain appears in order
     * somewhere in the result - find level_b's call site and check ordering */
    int idx=-1;
    for (size_t i=0;i<fuzzy_n;i++) if (within(fr[i],(void*)level_b,0x100)) { idx=(int)i; break; }
    CK(idx>=0, "found level_b's call site at #%d", idx);
    if (idx>=0 && (size_t)idx+4 <= fuzzy_n-1+1){
        CK(within(fr[idx+1],(void*)level_c,0x100), "next frame is level_c");
        CK(within(fr[idx+2],(void*)level_d,0x100), "then level_d");
        CK(within(fr[idx+3],(void*)level_end,0x100),"then level_end");
    }

    SEC("4. AUTO over the same chain");
    g_mode=SH_BT_AUTO; g_n=0;
    level_end();
    CK(g_n >= 5, "at least 5 frames (got %zu)", g_n);

    SEC("5. from an sh_instrument context");
    for (int m=0;m<3;m++){
        const char *nm = m==0?"FP":m==1?"FUZZY":"AUTO";
        cb_n=0; cb_pc=0;
        sh_status st = sh_instrument((void*)target_fn, bt_cb, (void*)(uintptr_t)m);
        CK(st==SH_OK, "%-5s instrument -> %s", nm, sh_strerror(st));
        if (st!=SH_OK) continue;
        int r = caller_3(4);
        sh_unhook((void*)target_fn);
        CK(r==12, "%-5s target still returns correctly (%d)", nm, r);
        CK(cb_n>=4, "%-5s got %zu frames", nm, cb_n);
        CK(cb_pc==(uint64_t)(uintptr_t)target_fn, "%-5s frame source pc == target_fn", nm);
        CK(cb_n>0 && cb_frames[0]==(void*)(uintptr_t)target_fn,
           "%-5s frame0 is the hooked instruction", nm);
        int ok1 = cb_n>1 && within(cb_frames[1],(void*)caller_1,0x100);
        int ok2 = cb_n>2 && within(cb_frames[2],(void*)caller_2,0x100);
        int ok3 = cb_n>3 && within(cb_frames[3],(void*)caller_3,0x100);
        CK(ok1&&ok2&&ok3, "%-5s caller chain is caller_1 -> caller_2 -> caller_3", nm);
        if (m==0) for (size_t i=0;i<cb_n && i<6;i++){ char l[256];
            sh_format_frame(cb_frames[i],l,sizeof l);
            printf("        #%02zu %p  %s\n", i, cb_frames[i], l); }
    }

    SEC("6. -fomit-frame-pointer target: FP degrades, FUZZY carries it");
    size_t n_fp    = nofp_depth3(fr, 64, SH_BT_FP);
    size_t n_fuzzy = nofp_depth3(fr, 64, SH_BT_FUZZY);
    size_t n_auto  = nofp_depth3(fr, 64, SH_BT_AUTO);
    printf("  ....  FP=%zu  FUZZY=%zu  AUTO=%zu frames\n", n_fp, n_fuzzy, n_auto);
    CK(n_fuzzy >= n_fp, "fuzzy finds at least as much as the frame chain");
    CK(n_auto >= 2, "AUTO still produced a usable trace (%zu)", n_auto);

    SEC("7. depth and bounds");
    size_t deep = recurse(60, fr, 64);
    CK(deep > 10, "deep recursion produced %zu frames", deep);
    CK(deep <= 64, "never exceeded max (%zu <= 64)", deep);
    void *one[1];
    CK(recurse(10, one, 1) == 1, "max=1 returns exactly 1");
    CK(sh_backtrace(NULL, 10, SH_BT_FP) == 0, "NULL out -> 0");
    CK(sh_backtrace(fr, 0, SH_BT_FP) == 0, "max=0 -> 0");
    CK(sh_backtrace_from(NULL, fr, 10, SH_BT_FP) == 0, "NULL ctx -> 0");

    SEC("8. a second thread has its own stack bounds");
    void *tfr[16]; pthread_t th;
    pthread_create(&th,NULL,thread_main,tfr);
    void *res=NULL; pthread_join(th,&res);
    size_t tn=(size_t)(uintptr_t)res;
    CK(tn >= 1, "worker thread captured %zu frames", tn);
    CK(all_frames_valid(tfr,tn), "worker frames all resolve");

    SEC("9. formatting");
    g_mode=SH_BT_FP; g_out=fr; g_max=64; g_n=0;
    level_end();
    char big[4096];
    size_t len = sh_format_backtrace(fr, g_n, big, sizeof big);
    CK(len>0 && strchr(big,'\n')!=NULL, "sh_format_backtrace produced %zu bytes", len);
    printf("%s", big);
    char tiny[24];
    size_t tl = sh_format_backtrace(fr, g_n, tiny, sizeof tiny);
    CK(tl < sizeof tiny, "truncates safely into a 24-byte buffer (%zu)", tl);
    char fb[8];
    CK(sh_format_frame(fr[0], fb, sizeof fb) < sizeof fb, "sh_format_frame truncates safely");
    CK(sh_format_frame((void*)0x1234, big, sizeof big) > 0, "unresolvable address still formats");
    printf("  ....  unresolvable -> %s\n", big);

    printf("\n%s (%d failure%s)\n", fails?"FAILED":"ALL PASS", fails, fails==1?"":"s");
    return fails?1:0;
}
