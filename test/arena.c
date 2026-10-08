/*
 * Arena page sharing under a policy that denies RWX anonymous pages (the
 * Android SELinux case the RW+flip fallback exists for).
 *
 * Installing hook #2 has to flip its arena page to RW. If that page also
 * holds hook #1's trampoline, hook #1 becomes non-executable for the
 * duration and any thread inside it faults. Run with SH_TEST_NO_RWX=1.
 */
#define _GNU_SOURCE
#include "../include/slophook.h"
#include "../src/mem.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <setjmp.h>
#include <unistd.h>

static int fails;
#define CK(c,f,...) do{ if(c) printf("  PASS  " f "\n", ##__VA_ARGS__); \
    else { printf("  FAIL  " f "\n", ##__VA_ARGS__); fails++; } }while(0)

#define NOINL __attribute__((noinline,used))
NOINL int fa(int x){ return x+1; }
NOINL int fb(int x){ return x+2; }
NOINL int fc(int x){ return x+3; }
static int (*oa)(int),(*ob)(int),(*oc)(int);
static int repl(int x){ return x; }

static sigjmp_buf jb; static volatile int faulted;
static void on_fault(int s){ (void)s; faulted=1; siglongjmp(jb,1); }

static int perms_of(const void *p, char out[8]) {
    FILE *f=fopen("/proc/self/maps","re"); if(!f) return 0;
    char line[512]; const unsigned long long a=(unsigned long long)(uintptr_t)p;
    int found=0;
    while(fgets(line,sizeof line,f)){
        unsigned long long s,e; char pm[8];
        if(sscanf(line,"%llx-%llx %4s",&s,&e,pm)!=3) continue;
        if(a>=s&&a<e){ memcpy(out,pm,5); found=1; break; }
    }
    fclose(f); return found;
}
static unsigned long pageof(const void *p){
    return (unsigned long)((uintptr_t)p & ~(uintptr_t)(sysconf(_SC_PAGESIZE)-1));
}

int main(void){
    setvbuf(stdout,NULL,_IONBF,0);
    const int no_rwx = getenv("SH_TEST_NO_RWX") != NULL;
    printf("SH_TEST_NO_RWX=%s\n", no_rwx ? "1 (RWX denied)" : "unset (RWX allowed)");

    CK(sh_hook((void*)fa,(void*)repl,(void**)&oa)==SH_OK, "hook fa");
    CK(sh_hook((void*)fb,(void*)repl,(void**)&ob)==SH_OK, "hook fb");
    CK(sh_hook((void*)fc,(void*)repl,(void**)&oc)==SH_OK, "hook fc");
    char p[8]={0}; perms_of((void*)oa,p);
    printf("  trampolines: %p %p %p   arena perms %s\n",(void*)oa,(void*)ob,(void*)oc,p);

    if (no_rwx) {
        CK(pageof(oa)!=pageof(ob) && pageof(ob)!=pageof(oc) && pageof(oa)!=pageof(oc),
           "each trampoline is on its OWN page (%lx %lx %lx)",
           pageof(oa),pageof(ob),pageof(oc));
    } else {
        CK(pageof(oa)==pageof(ob), "RWX arena shares a page, as intended (%lx)", pageof(oa));
    }

    /* The real test: open a write window as installing another hook does,
     * then run an already-installed trampoline. */
    printf("\n  opening a write window on fa's arena page\n");
    CK(sh_mem_begin_write((void*)oa,256)==SH_OK, "sh_mem_begin_write");
    char q[8]={0}; perms_of((void*)oa,q);
    printf("  fa's page is now %s\n", q);

    struct sigaction sa={0},old; sa.sa_handler=on_fault;
    sigaction(SIGSEGV,&sa,&old); sigaction(SIGBUS,&sa,NULL);
    faulted=0; int v=-1;
    if(sigsetjmp(jb,1)==0) v=ob(1);        /* a DIFFERENT hook's trampoline */
    sigaction(SIGSEGV,&old,NULL);
    CK(!faulted && v==3, "fb's trampoline still runs while fa's page is open (got %d)", v);
    sh_mem_end_write((void*)oa,256);

    CK(oa(1)==2 && ob(1)==3 && oc(1)==4, "all three trampolines correct");
    sh_unhook_all();
    CK(fa(1)==2 && fb(1)==3 && fc(1)==4, "all restored");

    printf("\n%s (%d failure%s)\n", fails?"FAILED":"ALL PASS", fails, fails==1?"":"s");
    return fails?1:0;
}
