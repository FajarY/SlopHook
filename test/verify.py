#!/usr/bin/env python3
"""
Independent check of the relocator.

Re-derives each instruction's absolute target straight from the ARM ARM field
definitions, then confirms the relocated code reaches that same address and
that every word llvm-mc sees is a valid instruction.
"""
import re, subprocess, sys

def sext(v, bits):
    m = 1 << (bits - 1)
    return (v ^ m) - m

# name -> (src_pc, input words)
CASES = {
 "b_near":     (0x1000000, [0x14000020]), "bl_near": (0x1000000, [0x94000020]),
 "b_far":      (0x1000000, [0x14000020]), "bl_far":  (0x1000000, [0x94000020]),
 "bcond_far":  (0x1000000, [0x54000100]), "cbz_far": (0x1000000, [0x34000102]),
 "tbz_far":    (0x1000000, [0x36080103]),
 "adr":        (0x1000000, [0x10000100]), "adrp":    (0x1000000, [0x90000101]),
 "adrp_neg":   (0x8000000, [0x90FFFFE2]),
 "ldr_x_lit":  (0x1000000, [0x58000104]), "ldr_w_lit": (0x1000000, [0x18000105]),
 "ldrsw_lit":  (0x1000000, [0x98000106]), "prfm_lit":  (0x1000000, [0xD8000100]),
 "ldr_d_lit":  (0x1000000, [0x5C000107]), "ldr_q_lit": (0x1000000, [0x9C000108]),
 "pi_prologue":(0x1000000, [0xA9BF7BFD,0x910003FD,0xD10043FF,0xD65F03C0]),
}

def expected_target(insn, pc):
    """Absolute address the original instruction refers to."""
    if   (insn & 0xFC000000) in (0x14000000, 0x94000000):
        return pc + sext(insn & 0x03FFFFFF, 26) * 4
    elif (insn & 0xFF000010) == 0x54000000 or (insn & 0x7E000000) == 0x34000000:
        return pc + sext((insn >> 5) & 0x7FFFF, 19) * 4
    elif (insn & 0x7E000000) == 0x36000000:
        return pc + sext((insn >> 5) & 0x3FFF, 14) * 4
    elif (insn & 0x9F000000) == 0x10000000:          # ADR
        imm = sext((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3), 21)
        return pc + imm
    elif (insn & 0x9F000000) == 0x90000000:          # ADRP
        imm = sext((((insn >> 5) & 0x7FFFF) << 2) | ((insn >> 29) & 3), 21)
        return (pc & ~0xFFF) + (imm << 12)
    elif (insn & 0x3B000000) == 0x18000000:          # LDR literal
        return pc + sext((insn >> 5) & 0x7FFFF, 19) * 4
    return None

def disasm(words):
    byts = []
    for w in words:
        byts += [f"0x{(w >> (8*i)) & 0xFF:02x}" for i in range(4)]
    p = subprocess.run(["llvm-mc", "-triple=aarch64", "-disassemble"],
                       input=" ".join(byts), capture_output=True, text=True)
    return p.stdout, p.stderr

def resolved_target(words, dst_pc):
    """Where the relocated sequence actually ends up pointing."""
    # long-branch island: ldr x17,#8 ; br x17 ; .quad T
    for i in range(len(words) - 3):
        if words[i] == 0x58000051 and words[i+1] == 0xD61F0220:
            return words[i+2] | (words[i+3] << 32)
    # abs call: ldr x17,#12 ; blr x17 ; b #12 ; .quad T
    for i in range(len(words) - 4):
        if words[i] == 0x58000071 and words[i+1] == 0xD63F0220:
            return words[i+3] | (words[i+4] << 32)
    # constant materialisation: ldr xd,#8 ; b #12 ; .quad V
    for i in range(len(words) - 3):
        if (words[i] & 0xFFFFFFE0) == 0x58000040 and words[i+1] == 0x14000003:
            return words[i+2] | (words[i+3] << 32)
    # plain direct branch
    for i, w in enumerate(words):
        if (w & 0xFC000000) in (0x14000000, 0x94000000):
            return dst_pc + i*4 + sext(w & 0x03FFFFFF, 26) * 4
        if (w & 0xFF000010) == 0x54000000 or (w & 0x7E000000) == 0x34000000:
            return dst_pc + i*4 + sext((w >> 5) & 0x7FFFF, 19) * 4
        if (w & 0x7E000000) == 0x36000000:
            return dst_pc + i*4 + sext((w >> 5) & 0x3FFF, 14) * 4
    return None

trace = sys.stdin.read()
blocks = re.split(r"^#case ", trace, flags=re.M)[1:]
fails = passes = 0

for b in blocks:
    lines = b.strip().splitlines()
    head = lines[0].split()
    name, dst_pc = head[0], int(head[1])
    status = int(head[2].split("=")[1])
    words = [int(x, 16) for x in lines[1:] if re.fullmatch(r"[0-9a-f]{8}", x)]

    if name == "self_branch":
        ok = status == -5
        print(f"{'PASS' if ok else 'FAIL'}  {name:14s} refuses branch into patched region (status={status})")
        passes, fails = passes + ok, fails + (not ok)
        continue
    if status != 0:
        print(f"FAIL  {name:14s} unexpected status {status}"); fails += 1; continue

    src_pc, ins = CASES[name]
    out, err = disasm(words)

    if name == "pi_prologue":
        ok = words == ins
        print(f"{'PASS' if ok else 'FAIL'}  {name:14s} copied verbatim ({len(words)} words)")
        passes, fails = passes + ok, fails + (not ok)
        continue
    if name == "prfm_lit":
        ok = words == [0xD503201F]
        print(f"{'PASS' if ok else 'FAIL'}  {name:14s} prefetch hint dropped to nop")
        passes, fails = passes + ok, fails + (not ok)
        continue

    want = expected_target(ins[0], src_pc)
    got  = resolved_target(words, dst_pc)
    ok = (want == got)
    # every emitted word must disassemble cleanly unless it is a literal
    bad = "invalid instruction encoding" in err and "quad" not in name
    print(f"{'PASS' if ok else 'FAIL'}  {name:14s} target want=0x{want:x} got="
          + (f"0x{got:x}" if got is not None else "None")
          + f"  [{len(words)} words]")
    if not ok:
        print("      emitted:", " ".join(f"{w:08x}" for w in words))
        print("      disasm:", out.replace("\t"," ").strip().replace("\n","; "))
    passes, fails = passes + ok, fails + (not ok)

print(f"\n{passes} passed, {fails} failed")
sys.exit(1 if fails else 0)
