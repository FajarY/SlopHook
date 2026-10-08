/* Tests for the sh_patch_code primitive and the whole sh_put_* layer. */
#define _GNU_SOURCE
#include "../include/slophook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <signal.h>
#include <setjmp.h>

static int fails;
#define CK(c,f,...) do{ if(c) printf("  PASS  " f "\n", ##__VA_ARGS__); \
    else { printf("  FAIL  " f "\n", ##__VA_ARGS__); fails++; } }while(0)
#define SEC(n) printf("\n%s\n", n)

extern int    pt_caller(void);
extern void   pt_call_site(void);
extern int    pt_helper(void);
extern int    pt_cond(int);
extern void   pt_cond_br(void);
extern int    pt_long(void);
extern int    pt_jsrc(void);
extern int    pt_jdst(void);
extern float  pt_fret(void);
extern double pt_dret(void);
extern int    pt_s1(void);
extern int    pt_s2(void);

static int    (*volatile v_caller)(void) = pt_caller;
static int    (*volatile v_cond)(int)    = pt_cond;
static int    (*volatile v_long)(void)   = pt_long;
static int64_t(*volatile v_long64)(void) = (int64_t(*)(void))(void*)pt_long;
static int    (*volatile v_jsrc)(void)   = pt_jsrc;
static float  (*volatile v_fret)(void)   = pt_fret;
static double (*volatile v_dret)(void)   = pt_dret;
static int    (*volatile v_s1)(void)     = pt_s1;

static void flip_cond(void *code, void *addr, size_t size, void *user) {
    (void)addr; (void)size; (void)user;
    uint32_t w; memcpy(&w, code, 4);
    w = (w & ~0xFu) | ((w & 0xFu) ^ 1u);
    memcpy(code, &w, 4);
}

static sigjmp_buf jb; static volatile int trapped;
static void on_trap(int s){ (void)s; trapped=1; siglongjmp(jb,1); }

int main(void) {
    sh_status st;

    SEC("1. sh_nop_call / sh_put_nop - delete a BL");
    CK(v_caller()==778, "before: %d", v_caller());
    st = sh_nop_call((void*)pt_call_site);
    CK(st==SH_OK, "sh_nop_call -> %s", sh_strerror(st));
    CK(v_caller()==11, "call deleted: %d (want 11)", v_caller());
    CK(sh_is_patched((void*)pt_call_site), "sh_is_patched");
    CK(sh_revert((void*)pt_call_site)==SH_OK, "sh_revert");
    CK(!sh_is_patched((void*)pt_call_site), "no longer patched");
    CK(v_caller()==778, "restored: %d", v_caller());

    SEC("2. sh_patch_code - flip a b.eq to b.ne in place");
    CK(v_cond(0)==2 && v_cond(1)==1, "before: %d %d", v_cond(0), v_cond(1));
    st = sh_patch_code((void*)pt_cond_br, 4, flip_cond, NULL);
    CK(st==SH_OK, "sh_patch_code -> %s", sh_strerror(st));
    CK(v_cond(0)==1 && v_cond(1)==2, "flipped: %d %d", v_cond(0), v_cond(1));
    sh_revert((void*)pt_cond_br);
    CK(v_cond(0)==2 && v_cond(1)==1, "restored");

    SEC("3. sh_put_ret - function becomes a no-op");
    st = sh_put_ret((void*)pt_helper);
    CK(st==SH_OK, "sh_put_ret -> %s", sh_strerror(st));
    CK(v_caller()==11, "helper no-ops, x0 untouched: %d", v_caller());
    sh_revert((void*)pt_helper);
    CK(v_caller()==778, "restored");

    SEC("4. sh_put_true / sh_put_false");
    st = sh_put_true((void*)pt_long);
    CK(st==SH_OK && v_long()==1, "sh_put_true -> %d", v_long());
    sh_revert((void*)pt_long);
    st = sh_put_false((void*)pt_long);
    CK(st==SH_OK && v_long()==0, "sh_put_false -> %d", v_long());
    sh_revert((void*)pt_long);
    CK(v_long()==5, "restored: %d", v_long());

    SEC("5. sh_put_int (w0) incl. negatives, with MOVN shortcuts");
    int32_t iv[] = { 0, 1, -1, 7, 0x7FFF, -0x8000, 0x12345678, -2, (int32_t)0xFFFF0000 };
    for (unsigned i=0;i<sizeof iv/sizeof iv[0];i++){
        st = sh_put_int((void*)pt_long, iv[i]);
        int got = v_long();
        CK(st==SH_OK && got==iv[i], "return %-11d -> %-11d (%zu bytes)",
           iv[i], got, sh_size_int(iv[i]));
        sh_revert((void*)pt_long);
    }
    CK(sh_size_int(-1)==8,  "size_int(-1) = %zu (one MOVN + RET)", sh_size_int(-1));
    CK(sh_size_int(0x12345678)==12, "size_int(0x12345678) = %zu", sh_size_int(0x12345678));

    SEC("6. sh_put_long (x0)");
    int64_t lv[] = { 0, 1, -1, 0x100000000LL, (int64_t)0xDEADBEEFCAFEBABEULL, -4096 };
    for (unsigned i=0;i<sizeof lv/sizeof lv[0];i++){
        st = sh_put_long((void*)pt_long, lv[i]);
        int64_t got = v_long64();
        CK(st==SH_OK && got==lv[i], "return 0x%016llx -> 0x%016llx (%zu bytes)",
           (unsigned long long)lv[i], (unsigned long long)got, sh_size_long(lv[i]));
        sh_revert((void*)pt_long);
    }
    CK(sh_size_long(-1)==8, "size_long(-1) = %zu (one MOVN + RET)", sh_size_long(-1));

    SEC("7. sh_put_float (s0) / sh_put_double (d0)");
    CK(v_fret()==2.0f && v_dret()==2.0, "before: %f %f", v_fret(), v_dret());
    float fv[] = { 0.0f, 1.0f, -1.0f, 3.5f, 1e20f, -0.0f };
    for (unsigned i=0;i<sizeof fv/sizeof fv[0];i++){
        st = sh_put_float((void*)pt_fret, fv[i]);
        float got = v_fret();
        CK(st==SH_OK && memcmp(&got,&fv[i],4)==0, "float %-12g -> %-12g (%zu bytes)",
           fv[i], got, sh_size_float(fv[i]));
        sh_revert((void*)pt_fret);
    }
    double dv[] = { 0.0, 1.0, -1.0, 3.14159265358979, 1e300 };
    for (unsigned i=0;i<sizeof dv/sizeof dv[0];i++){
        st = sh_put_double((void*)pt_dret, dv[i]);
        double got = v_dret();
        CK(st==SH_OK && memcmp(&got,&dv[i],8)==0, "double %-18.12g -> %-18.12g (%zu bytes)",
           dv[i], got, sh_size_double(dv[i]));
        sh_revert((void*)pt_dret);
    }
    CK(sh_size_float(0.0f)==8, "size_float(0) = %zu (fmov s0,wzr + ret)", sh_size_float(0.0f));
    CK(sh_size_double(0.0)==8, "size_double(0) = %zu (fmov d0,xzr + ret)", sh_size_double(0.0));
    CK(v_fret()==2.0f && v_dret()==2.0, "both restored");

    SEC("8. sh_put_bytes / sh_put_hex");
    uint32_t code[2] = { 0x52800BE0u, SH_INSN_RET };
    st = sh_put_bytes((void*)pt_jsrc, code, 8);
    CK(st==SH_OK && v_jsrc()==95, "sh_put_bytes -> %d (want 95)", v_jsrc());
    sh_revert((void*)pt_jsrc);
    /* "20 00 80 52 C0 03 5F D6" = mov w0,#1 ; ret   (memory order) */
    st = sh_put_hex((void*)pt_jsrc, "20 00 80 52 C0 03 5F D6");
    CK(st==SH_OK && v_jsrc()==1, "sh_put_hex spaced -> %d (want 1)", v_jsrc());
    sh_revert((void*)pt_jsrc);
    st = sh_put_hex((void*)pt_jsrc, "0x20,0x00,0x80,0x52,0xC0,0x03,0x5F,0xD6");
    CK(st==SH_OK && v_jsrc()==1, "sh_put_hex 0x-prefixed -> %d", v_jsrc());
    sh_revert((void*)pt_jsrc);
    st = sh_put_hex((void*)pt_jsrc, "200080 52C0035FD6");
    CK(st==SH_OK && v_jsrc()==1, "sh_put_hex run-together -> %d", v_jsrc());
    sh_revert((void*)pt_jsrc);
    CK(v_jsrc()==100, "restored: %d", v_jsrc());
    CK(sh_size_hex("1F 20 03 D5")==4, "size_hex(nop) = %zu", sh_size_hex("1F 20 03 D5"));
    CK(sh_size_hex("1F 20 03")==0,    "size_hex rejects non-multiple-of-4");
    CK(sh_size_hex("1F 20 03 D")==0,  "size_hex rejects odd digit count");
    CK(sh_size_hex("1F 20 03 ZZ")==0, "size_hex rejects junk");
    CK(sh_size_hex("")==0,            "size_hex rejects empty");
    CK(sh_put_hex((void*)pt_jsrc,"1F 20 03")==SH_ERR_INVAL, "sh_put_hex refuses bad input");

    SEC("9. sh_put_b / sh_put_bl / sh_put_jump");
    CK(sh_size_jump((void*)pt_jsrc,(void*)pt_jdst)==4, "in-range jump = %zu bytes (atomic)",
       sh_size_jump((void*)pt_jsrc,(void*)pt_jdst));
    st = sh_put_b((void*)pt_jsrc,(void*)pt_jdst);
    CK(st==SH_OK && v_jsrc()==200, "sh_put_b -> %d (want 200)", v_jsrc());
    sh_revert((void*)pt_jsrc);
    st = sh_put_jump((void*)pt_jsrc,(void*)pt_jdst);
    CK(st==SH_OK && v_jsrc()==200, "sh_put_jump -> %d", v_jsrc());
    sh_revert((void*)pt_jsrc);
    CK(sh_enc_branch((void*)pt_jsrc,(void*)pt_jdst,0)!=0, "sh_enc_branch encodes B");
    CK(sh_enc_branch((void*)0x1000,(void*)0x40000000,0)==0, "sh_enc_branch rejects >128MB");
    CK(sh_put_b((void*)pt_jsrc,(void*)0x4000000000ULL)==SH_ERR_RANGE, "sh_put_b out of range");

    SEC("10. sh_put_brk - trap on entry");
    signal(SIGTRAP,on_trap); signal(SIGILL,on_trap); signal(SIGSEGV,on_trap);
    st = sh_put_brk((void*)pt_s1);
    CK(st==SH_OK, "sh_put_brk -> %s", sh_strerror(st));
    trapped = 0;
    if (sigsetjmp(jb,1)==0) { int r = v_s1(); printf("  ....  returned %d without trapping\n", r); }
    CK(trapped, "calling the patched function trapped");
    signal(SIGTRAP,SIG_DFL); signal(SIGILL,SIG_DFL); signal(SIGSEGV,SIG_DFL);
    sh_revert((void*)pt_s1);
    CK(v_s1()==11, "restored: %d", v_s1());

    SEC("11. sh_revert_all");
    sh_put_nop((void*)pt_call_site);
    sh_put_true((void*)pt_long);
    sh_put_float((void*)pt_fret, 9.0f);
    CK(sh_revert_all()==3, "reverted 3 patches at once");
    CK(v_caller()==778 && v_long()==5 && v_fret()==2.0f, "all three restored");
    CK(sh_revert_all()==0, "nothing left to revert");

    SEC("12. hook-side utilities");
    CK(sh_hook((void*)pt_s1,(void*)pt_s2,NULL)==SH_OK, "sh_hook");
    CK(sh_is_hooked((void*)pt_s1), "sh_is_hooked");
    CK(sh_hook((void*)pt_jsrc,(void*)pt_s2,NULL)==SH_OK, "second hook");
    CK(sh_unhook_all()==2, "sh_unhook_all removed 2");
    CK(!sh_is_hooked((void*)pt_s1), "no longer hooked");
    CK(v_s1()==11 && v_jsrc()==100, "both restored: %d %d", v_s1(), v_jsrc());

    SEC("13. a patch and a hook may not share bytes");
    CK(sh_put_nop((void*)pt_jsrc)==SH_OK, "patch installed");
    CK(sh_hook((void*)pt_jsrc,(void*)pt_s2,NULL)==SH_ERR_ALREADY, "hook over patch refused");
    sh_revert((void*)pt_jsrc);
    CK(sh_hook((void*)pt_jsrc,(void*)pt_s2,NULL)==SH_OK, "hook ok once reverted");
    CK(sh_put_nop((void*)pt_jsrc)==SH_ERR_ALREADY, "patch over hook refused");
    sh_unhook((void*)pt_jsrc);

    SEC("14. sh_module_base / sh_resolve / sh_sym");
    size_t span = 0;
    void *base = sh_module_base("puttest", &span);
    CK(base!=NULL, "sh_module_base(\"puttest\") = %p, span %zu KB", base, span/1024);
    if (base) {
        CK((void*)pt_s1 >= base && (char*)pt_s1 < (char*)base+span,
           "pt_s1 (%p) lies inside the module span", (void*)pt_s1);
        CK(sh_resolve("puttest",0x10)==(char*)base+0x10, "sh_resolve adds the offset");
    }
    CK(sh_module_base("no_such_module_xyz",NULL)==NULL, "missing module -> NULL");
    CK(sh_module_base(NULL,NULL)==NULL, "NULL name -> NULL");
    CK(sh_resolve("no_such_module_xyz",0)==NULL, "sh_resolve on missing module -> NULL");
    printf("  ....  sh_sym(\"libc.so\",\"open\") = %p (NULL expected in a static binary)\n",
           sh_sym("libc.so","open"));
    CK(sh_sym(NULL,NULL)==NULL, "sh_sym(NULL,NULL) -> NULL");

    SEC("15. argument validation");
    CK(sh_patch_code(NULL,4,flip_cond,NULL)==SH_ERR_INVAL, "NULL addr");
    CK(sh_patch_code((void*)pt_jsrc,4,NULL,NULL)==SH_ERR_INVAL, "NULL callback");
    CK(sh_patch_code((char*)pt_jsrc+1,4,flip_cond,NULL)==SH_ERR_ALIGN, "misaligned");
    CK(sh_patch_code((void*)pt_jsrc,6,flip_cond,NULL)==SH_ERR_INVAL, "size not a multiple of 4");
    CK(sh_patch_code((void*)pt_jsrc,0,flip_cond,NULL)==SH_ERR_INVAL, "zero size");
    CK(sh_put_nops((void*)pt_jsrc,0)==SH_ERR_INVAL, "zero nop count");
    CK(sh_put_b((void*)pt_jsrc,NULL)==SH_ERR_INVAL, "NULL branch dest");
    CK(sh_revert((void*)pt_helper)==SH_ERR_NOTFOUND, "revert of unpatched");

    printf("\n%s (%d failure%s)\n", fails?"FAILED":"ALL PASS", fails, fails==1?"":"s");
    return fails?1:0;
}
