#define _GNU_SOURCE
#include "../include/slophook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <signal.h>
#include <ucontext.h>
#define NOINL __attribute__((noinline,used))
NOINL int hot(int x){ return x+1; }
static int (*o_hot)(int);
static int r_hot(int x){ return o_hot(x)+1000; }
static atomic_int stop,calls,weird;
static void *lo_arena,*hi_arena;

static void segv(int s,siginfo_t *si,void *uc){
    (void)s;
    ucontext_t *u=uc;
    unsigned long pc=u->uc_mcontext.pc;
    const char *where="elsewhere";
    if(pc>=(unsigned long)hot && pc<(unsigned long)hot+64) where="inside hot()";
    else if(o_hot && pc>=(unsigned long)o_hot && pc<(unsigned long)o_hot+256) where="inside the trampoline";
    else if(pc>=(unsigned long)r_hot && pc<(unsigned long)r_hot+256) where="inside the replacement";
    char buf[320];
    int n=snprintf(buf,sizeof buf,
      "\n  SIGSEGV  fault addr=%p  PC=%#lx (%s)\n"
      "    hot()=%p  r_hot()=%p  trampoline=%p\n"
      "    word at hot(): %08x\n",
      si->si_addr,pc,where,(void*)hot,(void*)r_hot,(void*)o_hot,
      *(volatile unsigned*)hot);
    write(2,buf,n);
    _exit(9);
}
static void *spin(void *u){ (void)u;
    while(!atomic_load(&stop)){
        int v=hot(1); atomic_fetch_add(&calls,1);
        if(v!=2&&v!=1002) atomic_fetch_add(&weird,1);
    }
    return NULL;
}
int main(int argc,char**argv){
    setvbuf(stdout,NULL,_IONBF,0);
    int nthread = argc>1?atoi(argv[1]):1;
    int cycles  = argc>2?atoi(argv[2]):50;
    int do_unhook = argc>3?atoi(argv[3]):1;
    struct sigaction sa={0}; sa.sa_sigaction=segv; sa.sa_flags=SA_SIGINFO;
    sigaction(SIGSEGV,&sa,NULL); sigaction(SIGBUS,&sa,NULL); sigaction(SIGILL,&sa,NULL);
    (void)lo_arena;(void)hi_arena;
    printf("threads=%d cycles=%d unhook=%d\n",nthread,cycles,do_unhook);
    pthread_t t[8];
    for(int i=0;i<nthread;i++) pthread_create(&t[i],NULL,spin,NULL);
    usleep(30000);
    for(int r=0;r<cycles;r++){
        sh_status a=sh_hook((void*)hot,(void*)r_hot,(void**)&o_hot);
        if(a!=SH_OK){ printf("hook failed at %d: %s\n",r,sh_strerror(a)); break; }
        usleep(500);
        if(do_unhook){ sh_unhook((void*)hot); usleep(500); }
        else { sh_unhook((void*)hot); }
    }
    atomic_store(&stop,1);
    for(int i=0;i<nthread;i++) pthread_join(t[i],NULL);
    printf("  %d calls, %d unexpected results, no crash\n",
           atomic_load(&calls),atomic_load(&weird));
    return 0;
}
