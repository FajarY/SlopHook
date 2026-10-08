#!/usr/bin/env python3
"""Independent re-derivation of what each relocated sequence must mean.
Written straight from the ARM ARM field definitions, not from the C code."""
import sys
from collections import Counter

M64 = (1<<64)-1
def sx(v,b):
    m = 1<<(b-1); return (v ^ m) - m

def orig_meaning(fam, insn, pc):
    """(kind, absolute_value) the original instruction denotes."""
    if fam in ("b","bl"):      return ("branch", (pc + sx(insn & 0x3FFFFFF,26)*4) & M64)
    if fam in ("bcond","bccond"): return ("branch", (pc + sx((insn>>5)&0x7FFFF,19)*4) & M64)
    if fam == "cbz":           return ("branch", (pc + sx((insn>>5)&0x7FFFF,19)*4) & M64)
    if fam == "tbz":           return ("branch", (pc + sx((insn>>5)&0x3FFF,14)*4) & M64)
    if fam == "adr":
        imm = sx((((insn>>5)&0x7FFFF)<<2) | ((insn>>29)&3), 21)
        return ("const", (pc + imm) & M64)
    if fam == "adrp":
        imm = sx((((insn>>5)&0x7FFFF)<<2) | ((insn>>29)&3), 21)
        return ("const", ((pc & ~0xFFF) + (imm<<12)) & M64)
    if fam == "prfm":          return ("nop", None)
    if fam in ("ldr_x","ldr_w","ldr_q","ldr_s","ldr_d","ldrsw"):
        return ("const", (pc + sx((insn>>5)&0x7FFFF,19)*4) & M64)
    raise AssertionError(fam)

def decode_seq(fam, insn, words, dst_pc):
    """What the emitted sequence actually resolves to, by reading the words."""
    q = lambda i: words[i] | (words[i+1]<<32)
    n = len(words)
    for i in range(n-3):
        # ldr x17,#8 ; br x17 ; .quad T          (long branch island)
        if words[i]==0x58000051 and words[i+1]==0xD61F0220: return ("branch", q(i+2))
    for i in range(n-4):
        # ldr x17,#12 ; blr x17 ; b #12 ; .quad T   (absolute call)
        if words[i]==0x58000071 and words[i+1]==0xD63F0220: return ("branch", q(i+3))
    for i in range(n-3):
        # ldr xd,#8 ; b #12 ; .quad V            (constant materialisation)
        if (words[i] & 0xFFFFFFE0)==0x58000040 and words[i+1]==0x14000003:
            return ("const", q(i+2))
    for i in range(n-3):
        # vector literal: str x17 ; ldr x17,#8 ; b #12 ; .quad V ; ldr vt,[x17] ; ldr x17
        if words[i]==0xF81F0FF1 and words[i+1]==0x58000051 and words[i+2]==0x14000003:
            return ("const", q(i+3))
    # plain re-encoded branch, still in range
    for i,w in enumerate(words):
        if (w & 0xFC000000) in (0x14000000,0x94000000):
            return ("branch",(dst_pc+i*4+sx(w&0x3FFFFFF,26)*4)&M64)
        if (w & 0xFF000010)==0x54000000 or (w & 0x7E000000)==0x34000000:
            return ("branch",(dst_pc+i*4+sx((w>>5)&0x7FFFF,19)*4)&M64)
        if (w & 0x7E000000)==0x36000000:
            return ("branch",(dst_pc+i*4+sx((w>>5)&0x3FFF,14)*4)&M64)
    return (None,None)

stats=Counter(); bad=[]; n=0
for line in sys.stdin:
    f=line.split()
    if not f or f[0]!="C": continue
    fam, insn, src_pc, dst_pc, st, nw = f[1], int(f[2],16), int(f[3]), int(f[4]), int(f[5]), int(f[6])
    words=[int(x,16) for x in f[7:]]
    n+=1
    if st!=0:
        stats["status%d"%st]+=1
        continue
    want_kind, want = orig_meaning(fam, insn, src_pc)
    if want_kind == "nop":
        if words != [0xD503201F]:
            bad.append((fam,hex(insn),"prfm not lowered to nop",[hex(w) for w in words]))
        stats["prfm:nop"]+=1
        continue
    got_kind, got = decode_seq(fam, insn, words, dst_pc)
    stats[fam+":"+str(nw)+"w"]+=1
    if got_kind!=want_kind or got!=want:
        bad.append((fam,hex(insn),hex(src_pc),hex(dst_pc),want_kind,hex(want),
                    got_kind,hex(got) if got is not None else None,
                    [hex(w) for w in words]))

print(f"{n} relocations checked")
for k in sorted(stats): print(f"  {k:18s} {stats[k]}")
print()
if bad:
    print(f"!!! {len(bad)} MISMATCHES, first 5:")
    for b in bad[:5]: print("   ",b)
    sys.exit(1)
print("no mismatches: every relocated sequence resolves to the original target")
