#define _GNU_SOURCE
#include "../include/slophook.h"
#include "../src/arm64_relocate.h"
#include "../src/mem.h"
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>
typedef long (*fn1)(long);
extern long shape_x17_nop(long);
#define MAGIC 0x0ABC00L
static long call_x17(fn1 f,long a){
    register long r0 asm("x0")=a; register long r17 asm("x17")=MAGIC;
    asm volatile("blr %2":"+r"(r0),"+r"(r17):"r"(f)
      :"x1","x2","x3","x4","x5","x6","x7","x8","x9","x10","x11","x12",
       "x13","x14","x15","x16","x18","x30","memory");
    return r0;
}
static void *tramp(void *fn,uint8_t *dst,size_t cap){
    size_t su=0,du=0,tail=0;
    if(sh_relocate((uint32_t*)fn,(uint64_t)fn,4,(uint32_t*)dst,(uint64_t)dst,cap,&su,&du)!=SH_OK) return NULL;
    if(sh_emit_tail_jump((uint32_t*)(dst+du),(uint64_t)(dst+du),cap-du,(uint64_t)fn+su,&tail)!=SH_OK) return NULL;
    sh_flush_icache(dst,du+tail);
    printf("    trampoline words:");
    for(size_t i=0;i<(du+tail)/4;i++) printf(" %08x",((uint32_t*)dst)[i]);
    printf("\n");
    return dst;
}
int main(void){
    uint8_t *nr=sh_mem_alloc_near((uint64_t)shape_x17_nop,4096);
    uint8_t *fr=mmap((void*)0x100000000000ULL,4096,PROT_READ|PROT_WRITE|PROT_EXEC,
                     MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
    long want=call_x17(shape_x17_nop,0);
    printf("baseline (x17=0x%lx): %ld  [expect %ld]\n",(long)MAGIC,want,(long)MAGIC);
    printf("\nNEAR trampoline %p:\n",(void*)nr);
    void *t1=tramp((void*)shape_x17_nop,nr,4096);
    printf("    result %ld  -> %s\n",call_x17(t1,0),call_x17(t1,0)==want?"X17 PRESERVED":"X17 CLOBBERED");
    printf("\nFAR trampoline %p:\n",(void*)fr);
    void *t2=tramp((void*)shape_x17_nop,fr,4096);
    long g=call_x17(t2,0);
    printf("    result %ld  -> %s\n",g,g==want?"X17 PRESERVED":"X17 CLOBBERED");
    printf("    (0x%lx is the trampoline literal address, not the caller's X17)\n",(unsigned long)g);
    return 0;
}
