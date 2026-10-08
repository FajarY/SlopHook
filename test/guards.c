/*
 * Guards against patching something that is not code, and against the
 * page-permission damage that used to follow.
 *
 * The headline case is the one from the field: a heap pointer reaches
 * sh_patch_code() (classic swapped sh_put_bytes arguments), its page gets
 * mprotected, PROT_WRITE is stripped on the way out, and the next ordinary
 * heap write faults in the allocator with SEGV_ACCERR - arbitrarily far from
 * the real mistake.
 */
#define _GNU_SOURCE
#include "../include/slophook.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <unistd.h>

static int fails;
#define CK(c,f,...) do{ if(c) printf("  PASS  " f "\n", ##__VA_ARGS__); \
    else { printf("  FAIL  " f "\n", ##__VA_ARGS__); fails++; } }while(0)
#define SEC(n) printf("\n%s\n", n)

extern int pt_s1(void);
extern int pt_long(void);
static int (*volatile v_s1)(void)   = pt_s1;
static int (*volatile v_long)(void) = pt_long;

static int g_data_int = 1234;                  /* a data symbol */
static sigjmp_buf jb; static volatile int faulted;
static void on_segv(int s){ (void)s; faulted=1; siglongjmp(jb,1); }

/* perms string of the mapping containing p, e.g. "r-xp" */
static int perms_of(const void *p, char out[8]) {
    FILE *f = fopen("/proc/self/maps","re");
    if (!f) return 0;
    char line[512];
    const uint64_t a = (uint64_t)(uintptr_t)p & 0x00FFFFFFFFFFFFFFULL;
    int found = 0;
    while (fgets(line,sizeof line,f)) {
        unsigned long long s,e; char pm[8];
        if (sscanf(line,"%llx-%llx %4s",&s,&e,pm)!=3) continue;
        if (a>=s && a<e) { memcpy(out,pm,5); found=1; break; }
    }
    fclose(f);
    return found;
}

/* does writing to this address fault? */
static int write_faults(volatile uint8_t *p) {
    struct sigaction sa={0}, old;
    sa.sa_handler=on_segv; sigaction(SIGSEGV,&sa,&old);
    faulted=0;
    if (sigsetjmp(jb,1)==0) *p = 0x5A;
    sigaction(SIGSEGV,&old,NULL);
    return faulted;
}

int main(void) {
    SEC("1. the field crash: a heap pointer passed as the patch target");
    uint32_t code[2] = { 0x52800BE0u /* mov w0,#95 */, SH_INSN_RET };
    uint8_t *buf = (uint8_t *)malloc(4096);
    CK(buf != NULL, "allocated a heap buffer at %p", (void*)buf);
    char before[8] = {0}, after[8] = {0};
    perms_of(buf, before);
    /* arguments swapped: the buffer is where the ADDRESS should go */
    sh_status st = sh_put_bytes(buf, code, 8);
    CK(st == SH_ERR_NOTCODE, "refused -> %s", sh_strerror(st));
    perms_of(buf, after);
    CK(strcmp(before, after) == 0, "heap page perms unchanged (%s -> %s)", before, after);
    CK(!write_faults(buf + 2048), "the heap page is still writable");
    free(buf);                     /* this is what used to SEGV_ACCERR */
    printf("  PASS  free() of the heap buffer succeeded\n");

    SEC("2. other non-code targets");
    st = sh_patch_code(&g_data_int, 4, NULL, NULL);
    CK(st == SH_ERR_INVAL, "NULL callback still caught first -> %s", sh_strerror(st));
    CK(sh_put_nop(&g_data_int) == SH_ERR_NOTCODE, "a data symbol is refused");
    int on_stack = 0;
    CK(sh_put_nop(&on_stack) == SH_ERR_NOTCODE, "a stack address is refused");
    CK(sh_put_nop((void*)0x10000000000ULL) == SH_ERR_NOTCODE, "an unmapped address is refused");
    void *ro = mmap(NULL, 4096, PROT_READ, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    CK(sh_put_nop(ro) == SH_ERR_NOTCODE, "a non-executable mapping is refused");
    munmap(ro, 4096);
    CK(sh_hook(&g_data_int, (void*)pt_s1, NULL) == SH_ERR_NOTCODE, "sh_hook refuses data too");
    CK(sh_instrument(&g_data_int, (sh_instrument_cb)pt_s1, NULL) == SH_ERR_NOTCODE,
       "sh_instrument refuses data too");

    SEC("3. real code is still patchable, and its page keeps its protection");
    char p_before[8]={0}, p_after[8]={0};
    perms_of((void*)pt_long, p_before);
    CK(sh_put_int((void*)pt_long, 77) == SH_OK, "sh_put_int on real code");
    CK(v_long() == 77, "patch took effect (%d)", v_long());
    perms_of((void*)pt_long, p_after);
    CK(strcmp(p_before,p_after)==0, "text page perms unchanged (%s -> %s)", p_before, p_after);
    sh_revert((void*)pt_long);
    CK(v_long() == 5, "reverted");

    SEC("4. an RWX page stays RWX (JIT-style target)");
    uint8_t *jit = (uint8_t *)mmap(NULL, 4096, PROT_READ|PROT_WRITE|PROT_EXEC,
                                   MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
    CK(jit != MAP_FAILED, "mapped an rwx page at %p", (void*)jit);
    uint32_t stub[2] = { 0x528000A0u /* mov w0,#5 */, SH_INSN_RET };
    memcpy(jit, stub, sizeof stub);
    __builtin___clear_cache((char*)jit, (char*)jit+4096);
    int (*jf)(void) = (int(*)(void))jit;
    CK(jf() == 5, "stub runs (%d)", jf());
    char j_before[8]={0}, j_after[8]={0};
    perms_of(jit, j_before);
    CK(sh_put_int(jit, 9) == SH_OK, "sh_put_int on the rwx page");
    CK(jf() == 9, "patch took effect (%d)", jf());
    perms_of(jit, j_after);
    CK(strcmp(j_before,j_after)==0, "rwx page NOT downgraded (%s -> %s)", j_before, j_after);
    CK(!write_faults(jit + 2048), "the rwx page is still writable");
    sh_revert(jit);
    munmap(jit, 4096);

    SEC("5. tagged pointers (AArch64 top-byte ignore)");
    void *tagged = (void *)((uintptr_t)pt_s1 | (0xB4ULL << 56));
    printf("  ....  pt_s1 = %p, tagged = %p\n", (void*)pt_s1, tagged);
    CK(sh_put_int(tagged, 55) == SH_OK, "sh_put_int through a tagged pointer");
    CK(v_s1() == 55, "patch took effect (%d)", v_s1());
    CK(sh_is_patched((void*)pt_s1), "registry found via the UNtagged address");
    CK(sh_is_patched(tagged), "registry found via the tagged address");
    CK(sh_revert((void*)pt_s1) == SH_OK, "revert via the untagged address");
    CK(v_s1() == 11, "reverted (%d)", v_s1());
    CK(sh_hook(tagged, (void*)pt_long, NULL) == SH_OK, "sh_hook through a tagged pointer");
    CK(sh_is_hooked((void*)pt_s1) && sh_is_hooked(tagged), "hook found either way");
    CK(sh_unhook(tagged) == SH_OK, "unhook via the tagged address");
    CK(v_s1() == 11, "restored (%d)", v_s1());

    printf("\n%s (%d failure%s)\n", fails?"FAILED":"ALL PASS", fails, fails==1?"":"s");
    return fails?1:0;
}
