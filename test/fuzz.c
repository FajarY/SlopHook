/* Emit a machine-readable trace of many relocations for independent checking. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "../src/arm64_relocate.h"
static uint64_t rs = 0x12345678ULL;
static uint64_t rnd(void){ rs ^= rs<<13; rs ^= rs>>7; rs ^= rs<<17; return rs; }
static int64_t sx(uint64_t v,unsigned b){ uint64_t m=1ULL<<(b-1); return (int64_t)((v^m)-m); }

int main(void){
    uint32_t out[512];
    /* families: encode an instruction with a random in-range immediate */
    for (int iter=0; iter<40000; iter++) {
        uint32_t in; const char *fam;
        unsigned imm_bits; int64_t imm;
        int k = iter % 15;
        switch (k) {
        case 0: imm_bits=26; imm=sx(rnd(),26); in=0x14000000u|((uint32_t)imm&0x03FFFFFF); fam="b"; break;
        case 1: imm_bits=26; imm=sx(rnd(),26); in=0x94000000u|((uint32_t)imm&0x03FFFFFF); fam="bl"; break;
        case 2: imm_bits=19; imm=sx(rnd(),19); in=0x54000000u|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0xF); fam="bcond"; break;
        case 3: imm_bits=19; imm=sx(rnd(),19); in=0x34000000u|(uint32_t)((rnd()&1)<<24)|(uint32_t)((rnd()&1)<<31)|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0x1F); fam="cbz"; break;
        case 4: imm_bits=14; imm=sx(rnd(),14); in=0x36000000u|(uint32_t)((rnd()&1)<<24)|(uint32_t)((rnd()&1)<<31)|(uint32_t)((rnd()&0x1F)<<19)|(((uint32_t)imm&0x3FFF)<<5)|(rnd()&0x1F); fam="tbz"; break;
        case 5: { imm_bits=21; imm=sx(rnd(),21);
                  uint32_t lo=(uint32_t)imm&3, hi=((uint32_t)imm>>2)&0x7FFFF;
                  in=0x10000000u|(lo<<29)|(hi<<5)|(rnd()&0x1F); fam="adr"; break; }
        case 6: { imm_bits=21; imm=sx(rnd(),21);
                  uint32_t lo=(uint32_t)imm&3, hi=((uint32_t)imm>>2)&0x7FFFF;
                  in=0x90000000u|(lo<<29)|(hi<<5)|(rnd()&0x1F); fam="adrp"; break; }
        case 7: imm_bits=19; imm=sx(rnd(),19); in=0x58000000u|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0x1F); fam="ldr_x"; break;
        case 8: imm_bits=19; imm=sx(rnd(),19); in=0x18000000u|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0x1F); fam="ldr_w"; break;
        case 9:  imm_bits=19; imm=sx(rnd(),19); in=0x98000000u|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0x1F); fam="ldrsw"; break;
        case 10: imm_bits=19; imm=sx(rnd(),19); in=0x1C000000u|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0x1F); fam="ldr_s"; break;
        case 11: imm_bits=19; imm=sx(rnd(),19); in=0x5C000000u|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0x1F); fam="ldr_d"; break;
        case 12: imm_bits=19; imm=sx(rnd(),19); in=0x9C000000u|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0x1F); fam="ldr_q"; break;
        case 13: imm_bits=19; imm=sx(rnd(),19); in=0xD8000000u|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0x1F); fam="prfm"; break;
        default: imm_bits=19; imm=sx(rnd(),19); in=0x54000010u|(((uint32_t)imm&0x7FFFF)<<5)|(rnd()&0xF); fam="bccond"; break;
        }
        (void)imm_bits;
        uint64_t src_pc = (rnd() & 0x0000FFFFFFFFFFFCULL);
        uint64_t dst_pc = (rnd() & 0x0000FFFFFFFFFFFCULL);
        size_t su=0,du=0;
        memset(out,0,sizeof out);
        sh_status st = sh_relocate(&in,src_pc,4,out,dst_pc,sizeof out,&su,&du);
        printf("C %s %08x %llu %llu %d %zu",fam,in,
               (unsigned long long)src_pc,(unsigned long long)dst_pc,(int)st,du/4);
        if(st==SH_OK) for(size_t i=0;i<du/4;i++) printf(" %08x",out[i]);
        printf("\n");
    }
    return 0;
}
