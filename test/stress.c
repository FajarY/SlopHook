/* Aggressive ABI / prologue-shape stress harness for slophook.
 * Each test runs in a forked child so a crash is reported, not fatal. */
#define _GNU_SOURCE
#include "../include/slophook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdint.h>

static int fails;
#define CK(c,f,...) do{ if(c) printf("    PASS  " f "\n", ##__VA_ARGS__); \
        else { printf("    FAIL  " f "\n", ##__VA_ARGS__); fails++; } }while(0)

#define NOINL __attribute__((noinline,used))

/* ===================== targets: scalar / integer ===================== */
NOINL int t_add(int a,int b){ return a+b; }
NOINL long t_addl(long a,long b){ return a+b; }

/* 10 integer args -> args 9,10 on the stack */
NOINL long t_ten(long a,long b,long c,long d,long e,long f,long g,long h,long i,long j){
    return a+b*2+c*3+d*4+e*5+f*6+g*7+h*8+i*9+j*10;
}

/* ===================== targets: floating point ====================== */
NOINL double t_fadd(double a,double b){ return a*2.0+b*3.0; }
/* 8 double args + 2 stack doubles */
NOINL double t_tenf(double a,double b,double c,double d,double e,
                    double f,double g,double h,double i,double j){
    return a+b*2+c*3+d*4+e*5+f*6+g*7+h*8+i*9+j*10;
}
/* mixed: 8 GPR + 8 FPR + stack */
NOINL double t_mixed(long a,long b,long c,long d,long e,long f,long g,long h,
                     double p,double q,double r,double s,
                     double u,double v,double w,double x,
                     long stk1,double stk2){
    return (double)(a+b+c+d+e+f+g+h) + p+q+r+s+u+v+w+x + (double)stk1 + stk2;
}

/* ===================== targets: structs ============================= */
typedef struct { int a,b; } small_t;              /* 8 bytes  -> x0      */
typedef struct { long a,b; } pair_t;              /* 16 bytes -> x0,x1   */
typedef struct { long a,b,c,d,e; } big_t;         /* 40 bytes -> memory  */
typedef struct { float x,y,z,w; } hfa_t;          /* HFA      -> s0..s3  */

NOINL small_t t_small(small_t s){ small_t r={s.a+1,s.b+2}; return r; }
NOINL pair_t  t_pair(pair_t s){ pair_t r={s.a*3,s.b*5}; return r; }
NOINL big_t   t_big(big_t s){ big_t r={s.a+1,s.b+2,s.c+3,s.d+4,s.e+5}; return r; }
NOINL hfa_t   t_hfa(hfa_t s){ hfa_t r={s.x+1,s.y+2,s.z+3,s.w+4}; return r; }

/* ===================== targets: __int128 =========================== */
NOINL __int128 t_i128(__int128 a, __int128 b){ return a*3 + b; }

/* ===================== targets: varargs ============================ */
NOINL long t_va(int n, ...){
    va_list ap; va_start(ap,n); long s=0;
    for(int k=0;k<n;k++) s += va_arg(ap,long);
    va_end(ap); return s;
}
NOINL double t_vaf(int n, ...){
    va_list ap; va_start(ap,n); double s=0;
    for(int k=0;k<n;k++) s += va_arg(ap,double);
    va_end(ap); return s;
}

/* ===================== targets: prologue shapes ===================== */
const char g_str[] = "quick brown fox jumps";
NOINL const char *t_adrp(void){ return g_str; }

static volatile double g_sink;
/* a double constant often lands in a literal pool -> ldr d, literal */
NOINL double t_lit(double x){ return x * 3.14159265358979 + 2.718281828459045; }

/* first instruction is a compare+branch */
NOINL int t_cbz(int x){ if(!x) return -1; return x*7; }

/* leaf, single instruction body */
NOINL int t_leaf(int x){ return x; }

/* immediate tail call (prologue is a plain B) */
NOINL int t_tailcallee(int x){ return x+1000; }
NOINL int t_tailcaller(int x){ return t_tailcallee(x); }

/* recursion */
NOINL long t_fib(long n){ return n<2 ? n : t_fib(n-1)+t_fib(n-2); }

/* prologue containing a BL */
NOINL int t_bl_helper(int x){ return x^0x5A; }
NOINL int t_bl(int x){ int y=t_bl_helper(x); return y+1; }

/* ===================== volatile call-through pointers =============== */
#define VP(name) static __typeof__(&name) volatile vp_##name = &name
VP(t_add);
VP(t_addl);
VP(t_ten);
VP(t_fadd);
VP(t_tenf);
VP(t_mixed);
VP(t_small);
VP(t_pair);
VP(t_big);
VP(t_hfa);
VP(t_i128);
VP(t_va);
VP(t_vaf);
VP(t_adrp);
VP(t_lit);
VP(t_cbz);
VP(t_leaf);
VP(t_tailcaller);
VP(t_fib);
VP(t_bl);

/* ===================== replacements ================================= */
static int (*o_add)(int,int);
static int r_add(int a,int b){ return o_add(a,b)*100; }

static long (*o_ten)(long,long,long,long,long,long,long,long,long,long);
static long r_ten(long a,long b,long c,long d,long e,long f,long g,long h,long i,long j){
    return o_ten(a,b,c,d,e,f,g,h,i,j) + 1;
}

static double (*o_tenf)(double,double,double,double,double,double,double,double,double,double);
static double r_tenf(double a,double b,double c,double d,double e,double f,double g,double h,double i,double j){
    return o_tenf(a,b,c,d,e,f,g,h,i,j) + 0.5;
}

static double (*o_mixed)(long,long,long,long,long,long,long,long,double,double,double,double,double,double,double,double,long,double);
static double r_mixed(long a,long b,long c,long d,long e,long f,long g,long h,
                      double p,double q,double r,double s,double u,double v,double w,double x,
                      long k1,double k2){
    return o_mixed(a,b,c,d,e,f,g,h,p,q,r,s,u,v,w,x,k1,k2) + 1000.0;
}

static big_t (*o_big)(big_t);
static big_t r_big(big_t s){ big_t t=o_big(s); t.a+=10000; return t; }

static hfa_t (*o_hfa)(hfa_t);
static hfa_t r_hfa(hfa_t s){ hfa_t t=o_hfa(s); t.x+=100.f; return t; }

static __int128 (*o_i128)(__int128,__int128);
static __int128 r_i128(__int128 a,__int128 b){ return o_i128(a,b)+1; }

static long (*o_va)(int,...);
static double (*o_vaf)(int,...);
static double (*o_lit)(double);
static int (*o_cbz)(int);
static int (*o_leaf)(int);
static int (*o_tc)(int);
static int (*o_bl)(int);
static long (*o_fib)(long);
static int fib_hits;
static long r_fib(long n){ fib_hits++; return o_fib(n); }

/* ===================== instrument callbacks ========================= */
static int cb_ran;
static uint64_t cb_pc, cb_sp, cb_lr;
static void cb_note(sh_context *c, void *u){ (void)u;
    cb_ran++; cb_pc=c->pc; cb_sp=c->sp; cb_lr=c->x[30];
}
static void cb_setarg(sh_context *c, void *u){ (void)u; c->x[0]=10; }
static void cb_setfp(sh_context *c, void *u){ (void)u;
    double d=7.0; memcpy(&c->q[0], &d, sizeof d);   /* d0 = 7.0 */
}
/* A read-only callback. Being an ordinary C function it necessarily
 * clobbers the *real* x0-x18 and q0-q7, so if the target's arguments
 * still arrive intact the bridge's save/restore is correct. */
static volatile double g_churn;
static uint64_t cb_sum;
static void cb_scribble(sh_context *c, void *u){ (void)u;
    uint64_t s=0; for(int i=0;i<31;i++) s^=c->x[i];
    double d=1.0; for(int i=0;i<8;i++){ double t; memcpy(&t,&c->q[i],sizeof t); d+=t*1.5; }
    g_churn=d; cb_sum=s; cb_ran++;
}
/* Deliberate writeback test: proves modifications DO take effect. */
static void cb_wb_q(sh_context *c, void *u){ (void)u;
    float f=-5.0f; memcpy(&c->q[1],&f,sizeof f);   /* s1 = -5.0f */
    cb_ran++;
}
static uint64_t seen_nzcv;
static void cb_nzcv(sh_context *c, void *u){ (void)u; seen_nzcv=c->nzcv; cb_ran++; }

/* ===================== tests ======================================== */
static int T_basic(void){
    sh_status st=sh_hook((void*)t_add,(void*)r_add,(void**)&o_add);
    CK(st==SH_OK,"hook -> %s",sh_strerror(st));
    CK(vp_t_add(2,3)==500,"replacement runs (%d)",vp_t_add(2,3));
    CK(o_add(2,3)==5,"origin call-through (%d)",o_add(2,3));
    CK(sh_unhook((void*)t_add)==SH_OK,"unhook");
    CK(vp_t_add(2,3)==5,"restored");
    return 0;
}

static int T_stackargs(void){
    long want=t_ten(1,2,3,4,5,6,7,8,9,10);
    sh_status st=sh_hook((void*)t_ten,(void*)r_ten,(void**)&o_ten);
    CK(st==SH_OK,"hook 10-int-arg -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    long got=vp_t_ten(1,2,3,4,5,6,7,8,9,10);
    CK(got==want+1,"stack args survive (got %ld want %ld)",got,want+1);
    CK(o_ten(1,2,3,4,5,6,7,8,9,10)==want,"origin preserves stack args");
    return 0;
}

static int T_fp(void){
    double want=t_tenf(1,2,3,4,5,6,7,8,9,10);
    sh_status st=sh_hook((void*)t_tenf,(void*)r_tenf,(void**)&o_tenf);
    CK(st==SH_OK,"hook 10-double-arg -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    double got=vp_t_tenf(1,2,3,4,5,6,7,8,9,10);
    CK(got==want+0.5,"fp args survive (got %f want %f)",got,want+0.5);
    return 0;
}

static int T_mixedabi(void){
    double want=t_mixed(1,2,3,4,5,6,7,8, 1.5,2.5,3.5,4.5,5.5,6.5,7.5,8.5, 99, 0.25);
    sh_status st=sh_hook((void*)t_mixed,(void*)r_mixed,(void**)&o_mixed);
    CK(st==SH_OK,"hook mixed GPR+FPR+stack -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    double got=vp_t_mixed(1,2,3,4,5,6,7,8, 1.5,2.5,3.5,4.5,5.5,6.5,7.5,8.5, 99, 0.25);
    CK(got==want+1000.0,"mixed ABI preserved (got %f want %f)",got,want+1000.0);
    return 0;
}

static int T_structs(void){
    big_t in={1,2,3,4,5};
    big_t w=t_big(in);
    sh_status st=sh_hook((void*)t_big,(void*)r_big,(void**)&o_big);
    CK(st==SH_OK,"hook big struct (x8 indirect result) -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    big_t g=vp_t_big(in);
    CK(g.a==w.a+10000&&g.b==w.b&&g.e==w.e,"x8 indirect result ok (a=%ld e=%ld)",g.a,g.e);

    hfa_t hin={1,2,3,4}; hfa_t hw=t_hfa(hin);
    st=sh_hook((void*)t_hfa,(void*)r_hfa,(void**)&o_hfa);
    CK(st==SH_OK,"hook HFA (s0..s3) -> %s",sh_strerror(st));
    hfa_t hg=vp_t_hfa(hin);
    CK(hg.x==hw.x+100.f&&hg.w==hw.w,"HFA args/result ok (x=%f w=%f)",hg.x,hg.w);
    return 0;
}

static int T_i128(void){
    __int128 a=((__int128)123<<64)|456, b=((__int128)7<<64)|8;
    __int128 w=t_i128(a,b);
    sh_status st=sh_hook((void*)t_i128,(void*)r_i128,(void**)&o_i128);
    CK(st==SH_OK,"hook __int128 -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    __int128 g=vp_t_i128(a,b);
    CK(g==w+1,"__int128 reg pair ok (hi=%llx)",(unsigned long long)(g>>64));
    return 0;
}

static int T_varargs(void){
    long w=t_va(4,(long)10,(long)20,(long)30,(long)40);
    sh_status st=sh_hook((void*)t_va,(void*)r_add /*wrong sig on purpose: only origin used*/,(void**)&o_va);
    CK(st==SH_OK,"hook varargs(int) -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    long g=o_va(4,(long)10,(long)20,(long)30,(long)40);
    CK(g==w,"origin preserves integer varargs (%ld vs %ld)",g,w);
    sh_unhook((void*)t_va);

    double wf=t_vaf(4,1.5,2.5,3.5,4.5);
    st=sh_hook((void*)t_vaf,(void*)r_add,(void**)&o_vaf);
    CK(st==SH_OK,"hook varargs(double) -> %s",sh_strerror(st));
    double gf=o_vaf(4,1.5,2.5,3.5,4.5);
    CK(gf==wf,"origin preserves fp varargs (%f vs %f)",gf,wf);
    return 0;
}

static const char *(*o_adrp)(void);
static int T_adrp(void){
    const char *m=t_adrp();
    sh_status st=sh_hook((void*)t_adrp,(void*)t_adrp,(void**)&o_adrp);
    CK(st==SH_OK,"hook ADRP prologue -> %s",sh_strerror(st));
    CK(o_adrp()==m,"relocated ADRP page correct (%p vs %p)",(void*)o_adrp(),(void*)m);
    CK(strcmp(o_adrp(),"quick brown fox jumps")==0,"ADRP+ADD string intact");
    return 0;
}

static int T_literal(void){
    double w=t_lit(2.0);
    sh_status st=sh_hook((void*)t_lit,(void*)r_add,(void**)&o_lit);
    CK(st==SH_OK,"hook fp-literal prologue -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    double g=o_lit(2.0);
    CK(g==w,"literal-pool prologue relocated (%.17g vs %.17g)",g,w);
    return 0;
}

static int T_cbzpro(void){
    int w0=t_cbz(0), w5=t_cbz(5);
    sh_status st=sh_hook((void*)t_cbz,(void*)r_add,(void**)&o_cbz);
    printf("    note  hook(cbz prologue) -> %s\n",sh_strerror(st));
    if(st==SH_OK){
        CK(o_cbz(0)==w0,"cbz-prologue origin, zero path (%d vs %d)",o_cbz(0),w0);
        CK(o_cbz(5)==w5,"cbz-prologue origin, nonzero path (%d vs %d)",o_cbz(5),w5);
    } else {
        CK(st==SH_ERR_SELF_BRANCH,"refused with SELF_BRANCH (not a silent miscompile)");
    }
    return 0;
}

static int T_leafpro(void){
    sh_status st=sh_hook((void*)t_leaf,(void*)r_add,(void**)&o_leaf);
    CK(st==SH_OK,"hook 1-instruction leaf -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    if(st==SH_OK) CK(o_leaf(42)==42,"leaf origin (%d)",o_leaf(42));
    return 0;
}

static int T_tailcall(void){
    int w=t_tailcaller(5);
    sh_status st=sh_hook((void*)t_tailcaller,(void*)r_add,(void**)&o_tc);
    printf("    note  hook(tail-call thunk) -> %s\n",sh_strerror(st));
    if(st==SH_OK) CK(o_tc(5)==w,"tail-call thunk origin (%d vs %d)",o_tc(5),w);
    return 0;
}

static int T_blpro(void){
    int w=t_bl(5);
    sh_status st=sh_hook((void*)t_bl,(void*)r_add,(void**)&o_bl);
    printf("    note  hook(BL in prologue) -> %s\n",sh_strerror(st));
    if(st==SH_OK) CK(o_bl(5)==w,"BL-in-prologue origin (%d vs %d)",o_bl(5),w);
    return 0;
}

static int T_recursion(void){
    long w=t_fib(12);
    sh_status st=sh_hook((void*)t_fib,(void*)r_fib,(void**)&o_fib);
    CK(st==SH_OK,"hook recursive fn -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    fib_hits=0;
    long g=vp_t_fib(12);
    CK(g==w,"recursion through hook correct (%ld vs %ld)",g,w);
    CK(fib_hits>100,"every recursive entry re-entered the hook (%d)",fib_hits);
    return 0;
}

/* ---------------- instrumentation ---------------- */
static int T_instr_basic(void){
    CK(t_add(1,1)==2,"pre");
    sh_status st=sh_instrument((void*)t_add,cb_setarg,NULL);
    CK(st==SH_OK,"instrument -> %s",sh_strerror(st));
    CK(vp_t_add(1,1)==11,"callback rewrote x0 (got %d want 11)",vp_t_add(1,1));
    CK(sh_unhook((void*)t_add)==SH_OK,"uninstrument");
    CK(vp_t_add(1,1)==2,"restored");
    return 0;
}

static int T_instr_ctx(void){
    cb_ran=0;
    sh_status st=sh_instrument((void*)t_add,cb_note,NULL);
    CK(st==SH_OK,"instrument -> %s",sh_strerror(st));
    (void)vp_t_add(3,4);
    CK(cb_ran==1,"callback ran once");
    CK(cb_pc==(uint64_t)(uintptr_t)t_add,"ctx.pc == target (%llx vs %llx)",
       (unsigned long long)cb_pc,(unsigned long long)(uintptr_t)t_add);
    CK((cb_sp&15)==0,"ctx.sp is 16-byte aligned (%llx)",(unsigned long long)cb_sp);
    CK(cb_lr!=0,"ctx.x[30] (LR) populated (%llx)",(unsigned long long)cb_lr);
    return 0;
}

static int T_instr_full_abi(void){
    double want=t_mixed(1,2,3,4,5,6,7,8, 1.5,2.5,3.5,4.5,5.5,6.5,7.5,8.5, 99, 0.25);
    cb_ran=0;
    sh_status st=sh_instrument((void*)t_mixed,cb_scribble,NULL);
    CK(st==SH_OK,"instrument mixed-ABI fn -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    double got=vp_t_mixed(1,2,3,4,5,6,7,8, 1.5,2.5,3.5,4.5,5.5,6.5,7.5,8.5, 99, 0.25);
    CK(cb_ran==1,"callback ran");
    CK(got==want,"all 8 GPR + 8 FPR args + stack args survived the bridge (%f vs %f)",got,want);
    return 0;
}

static int T_instr_fp(void){
    cb_ran=0;
    sh_status st=sh_instrument((void*)t_fadd,cb_setfp,NULL);
    CK(st==SH_OK,"instrument fp fn -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    double got=vp_t_fadd(1.0,1.0);
    CK(got==7.0*2.0+1.0*3.0,"callback wrote back q0 (got %f want %f)",got,7.0*2.0+3.0);
    return 0;
}

static int T_instr_nzcv(void){
    cb_ran=0; seen_nzcv=~0ULL;
    sh_status st=sh_instrument((void*)t_cbz,cb_nzcv,NULL);
    printf("    note  instrument(cbz prologue) -> %s\n",sh_strerror(st));
    if(st!=SH_OK) return 0;
    int g=vp_t_cbz(5);
    CK(cb_ran==1,"callback ran");
    CK(g==35,"behaviour unchanged with instrument (%d)",g);
    CK((seen_nzcv&~0xF0000000ULL)==0,"nzcv has only NZCV bits set (%llx)",(unsigned long long)seen_nzcv);
    return 0;
}

static int T_instr_hfa(void){
    hfa_t in={1,2,3,4}; hfa_t w=t_hfa(in);
    cb_ran=0;
    sh_status st=sh_instrument((void*)t_hfa,cb_scribble,NULL);
    CK(st==SH_OK,"instrument HFA fn -> %s",sh_strerror(st));
    if(st!=SH_OK) return 0;
    hfa_t g=vp_t_hfa(in);
    CK(cb_ran==1,"callback ran");
    CK(g.x==w.x&&g.y==w.y&&g.z==w.z&&g.w==w.w,
       "s0..s3 HFA args intact across the bridge (%f %f %f %f)",g.x,g.y,g.z,g.w);
    CK(sh_unhook((void*)t_hfa)==SH_OK,"uninstrument HFA");
    /* now prove writeback reaches the vector regs */
    sh_status st2=sh_instrument((void*)t_hfa,cb_wb_q,NULL);
    CK(st2==SH_OK,"re-instrument for writeback -> %s",sh_strerror(st2));
    hfa_t g2=vp_t_hfa(in);
    CK(g2.y==-5.0f+2.0f,"callback writeback to q1 took effect (y=%f want %f)",g2.y,-3.0f);
    CK(g2.x==w.x&&g2.z==w.z&&g2.w==w.w,"only q1 changed (%f %f %f)",g2.x,g2.z,g2.w);
    return 0;
}

/* ---------------- arena / many hooks ---------------- */
#define MK(n) NOINL int f##n(int x){ return x+n; }
#define MKREF(n) f##n,
MK(0)MK(1)MK(2)MK(3)MK(4)MK(5)MK(6)MK(7)MK(8)MK(9)
MK(10)MK(11)MK(12)MK(13)MK(14)MK(15)MK(16)MK(17)MK(18)MK(19)
MK(20)MK(21)MK(22)MK(23)MK(24)MK(25)MK(26)MK(27)MK(28)MK(29)
MK(30)MK(31)MK(32)MK(33)MK(34)MK(35)MK(36)MK(37)MK(38)MK(39)
MK(40)MK(41)MK(42)MK(43)MK(44)MK(45)MK(46)MK(47)MK(48)MK(49)
MK(50)MK(51)MK(52)MK(53)MK(54)MK(55)MK(56)MK(57)MK(58)MK(59)
static int (*manyf[60])(int) = {
MKREF(0)MKREF(1)MKREF(2)MKREF(3)MKREF(4)MKREF(5)MKREF(6)MKREF(7)MKREF(8)MKREF(9)
MKREF(10)MKREF(11)MKREF(12)MKREF(13)MKREF(14)MKREF(15)MKREF(16)MKREF(17)MKREF(18)MKREF(19)
MKREF(20)MKREF(21)MKREF(22)MKREF(23)MKREF(24)MKREF(25)MKREF(26)MKREF(27)MKREF(28)MKREF(29)
MKREF(30)MKREF(31)MKREF(32)MKREF(33)MKREF(34)MKREF(35)MKREF(36)MKREF(37)MKREF(38)MKREF(39)
MKREF(40)MKREF(41)MKREF(42)MKREF(43)MKREF(44)MKREF(45)MKREF(46)MKREF(47)MKREF(48)MKREF(49)
MKREF(50)MKREF(51)MKREF(52)MKREF(53)MKREF(54)MKREF(55)MKREF(56)MKREF(57)MKREF(58)MKREF(59)
};
static int (*manyo[60])(int);
static int r_many(int x){ return x; }

static int T_many(void){
    int ok=0,err=0;
    for(int i=0;i<60;i++){
        sh_status st=sh_hook((void*)manyf[i],(void*)r_many,(void**)&manyo[i]);
        if(st==SH_OK) ok++; else { err++; if(err<3) printf("    note  hook#%d -> %s\n",i,sh_strerror(st)); }
    }
    CK(ok+err==60,"60 hook attempts resolved (%d installed, %d refused)",ok,err);
    int bad=0;
    for(int i=0;i<60;i++) if(manyo[i] && manyo[i](i)!=i+i) bad++;
    CK(bad==0,"all 60 origin trampolines correct (%d bad)",bad);
    int uerr=0;
    for(int i=0;i<60;i++) if(manyo[i] && sh_unhook((void*)manyf[i])!=SH_OK) uerr++;
    CK(uerr==0,"every installed hook unhooked (%d err)",uerr);
    int rb=0;
    for(int i=0;i<60;i++) if(manyf[i](1)!=1+i) rb++;
    CK(rb==0,"all 60 restored (%d bad)",rb);
    return 0;
}

static int T_rehook(void){
    int bad=0;
    for(int i=0;i<200;i++){
        if(sh_hook((void*)t_add,(void*)r_add,(void**)&o_add)!=SH_OK){bad++;break;}
        if(vp_t_add(1,2)!=300) bad++;
        if(sh_unhook((void*)t_add)!=SH_OK){bad++;break;}
        if(vp_t_add(1,2)!=3) bad++;
    }
    CK(bad==0,"200 hook/unhook cycles stable (%d bad)",bad);
    return 0;
}

static int T_midfunc(void){
    /* hook 2 instructions into a function: not a function entry, so X17
       is not architecturally dead there. Just check it does not crash
       and the engine reports something sane. */
    void *mid=(char*)t_ten+8;
    sh_status st=sh_hook(mid,(void*)r_many,NULL);
    printf("    note  hook(target+8, mid-function) -> %s\n",sh_strerror(st));
    if(st==SH_OK) CK(sh_unhook(mid)==SH_OK,"mid-function unhook");
    return 0;
}

static int T_errs(void){
    CK(sh_hook(NULL,(void*)r_add,NULL)==SH_ERR_INVAL,"NULL target refused");
    CK(sh_hook((void*)t_add,NULL,NULL)==SH_ERR_INVAL,"NULL replacement refused");
    CK(sh_hook((char*)t_add+1,(void*)r_add,NULL)==SH_ERR_ALIGN,"misaligned refused");
    CK(sh_unhook((void*)t_leaf)==SH_ERR_NOTFOUND,"unhook of unhooked refused");
    CK(sh_instrument((void*)t_add,NULL,NULL)==SH_ERR_INVAL,"NULL callback refused");
    return 0;
}

/* ===================== driver ======================================= */
typedef int (*tfn)(void);
static struct { const char *n; tfn f; } TESTS[] = {
    {"basic replace + call-through",       T_basic},
    {"10 integer args (stack args)",       T_stackargs},
    {"10 double args",                     T_fp},
    {"mixed 8 GPR + 8 FPR + stack",        T_mixedabi},
    {"structs: x8 indirect result + HFA",  T_structs},
    {"__int128 register pairs",            T_i128},
    {"varargs (int and double)",           T_varargs},
    {"ADRP prologue",                      T_adrp},
    {"fp literal-pool prologue",           T_literal},
    {"CBZ prologue",                       T_cbzpro},
    {"single-instruction leaf",            T_leafpro},
    {"tail-call thunk prologue",           T_tailcall},
    {"BL in prologue",                     T_blpro},
    {"recursion through the hook",         T_recursion},
    {"instrument: basic arg rewrite",      T_instr_basic},
    {"instrument: ctx fields",             T_instr_ctx},
    {"instrument: full ABI preservation",  T_instr_full_abi},
    {"instrument: fp writeback",           T_instr_fp},
    {"instrument: nzcv",                   T_instr_nzcv},
    {"instrument: HFA + vector scribble",  T_instr_hfa},
    {"60 concurrent hooks (arena)",        T_many},
    {"200 hook/unhook cycles",             T_rehook},
    {"mid-function hook",                  T_midfunc},
    {"argument validation",                T_errs},
};

int main(int argc,char**argv){
    int only=-1;
    if(argc>1) only=atoi(argv[1]);
    int n=(int)(sizeof TESTS/sizeof TESTS[0]);
    int crashed=0,failed=0;
    for(int i=0;i<n;i++){
        if(only>=0 && i!=only) continue;
        printf("[%2d] %s\n",i,TESTS[i].n); fflush(stdout);
        pid_t p=fork();
        if(p==0){ fails=0; TESTS[i].f(); fflush(stdout); _exit(fails?1:0); }
        int ws=0; waitpid(p,&ws,0);
        if(WIFSIGNALED(ws)){ printf("    CRASH signal %d\n",WTERMSIG(ws)); crashed++; }
        else if(WEXITSTATUS(ws)!=0) failed++;
        fflush(stdout);
    }
    printf("\n==== %d groups, %d with failures, %d crashed ====\n",n,failed,crashed);
    return (failed||crashed)?1:0;
}
