# Additional test suite for slophook

Drop these into `test/` and build against `libslophook.a`.

| file | what it does |
|---|---|
| `stress.c` | 24 groups of ABI shapes: stack args, 8 GPR + 8 FPR + stack, HFA, x8 indirect struct return, `__int128`, varargs (int and double), recursion, 60 concurrent hooks, 200 hook/unhook cycles, instrument context/writeback. Forks per group so one crash does not hide the rest. |
| `shapes.S` | 27 assembler-generated prologue shapes, one per PC-relative form plus PAC/BTI/self-branch/packed-function cases. Authoritative encodings. |
| `reloc_exec.c` | Relocate-and-execute differential tester. Displaces each shape into a NEAR page and a page >128MB away, then runs it and requires an identical result. |
| `fuzz.c` + `fuzz_verify.py` | 40k random relocations over all 14 PC-relative encodings with random 48-bit src/dst, checked against a model re-derived independently from the ARM ARM. |
| `conc2.c` | Hot-patches a function while N threads execute it; SIGSEGV handler reports the faulting PC and whether it was in the target, trampoline or replacement. |
| `arena.c` | Shows whether opening a write window on a shared arena page de-executes a live trampoline (set `SH_NO_RWX=1` with the knob described in the review). |
| `puttest.c` | 100 assertions over `sh_patch_code` and the whole `sh_put_*` layer: deleting a BL, flipping a condition, int/long/float/double constant returns checked against the full result register, hex parsing and its rejections, branches, `BRK` trapping under a signal handler, `sh_revert_all`, `sh_unhook_all`, module/symbol resolution, and the hook/patch overlap refusals. |

Build/run (x86 host, aarch64 cross + qemu):

```bash
apt-get install -y gcc-aarch64-linux-gnu qemu-user-static
make -f Makefile.hosttests libslophook.a
aarch64-linux-gnu-gcc -c -o shapes.o test/shapes.S
aarch64-linux-gnu-gcc -O2 -static -o stress     test/stress.c     libslophook.a
aarch64-linux-gnu-gcc -O2 -static -o reloc_exec test/reloc_exec.c shapes.o libslophook.a
aarch64-linux-gnu-gcc -O2 -static -pthread -o conc2 test/conc2.c  libslophook.a
aarch64-linux-gnu-gcc -O2 -static -o puttest test/puttest.c shapes.o libslophook.a -lm
cc -O1 -o fuzz test/fuzz.c src/arm64_relocate.c
qemu-aarch64-static ./stress && qemu-aarch64-static ./reloc_exec
qemu-aarch64-static ./puttest
aarch64-linux-gnu-gcc -O2 -static -o guards test/guards.c shapes.o libslophook.a
aarch64-linux-gnu-gcc -O2 -static -o arena  test/arena.c  libslophook.a
aarch64-linux-gnu-gcc -O2 -static -pthread -o bttest test/bttest.c bt_nofp.o libslophook.a
aarch64-linux-gnu-gcc -O2 -fPIC -fomit-frame-pointer -c test/bt_nofp.c -o bt_nofp.o
aarch64-linux-gnu-gcc -O2 -o btdyn test/btdyn.c libslophook.a   # dynamic, for dladdr
qemu-aarch64-static ./guards
qemu-aarch64-static ./bttest
qemu-aarch64-static -L /usr/aarch64-linux-gnu ./btdyn
qemu-aarch64-static ./arena && SH_TEST_NO_RWX=1 qemu-aarch64-static ./arena
qemu-aarch64-static ./conc2 8 300 1
./fuzz | python3 test/fuzz_verify.py
```

## Test-only knobs

`Makefile.hosttests` builds with `-DSH_TEST_HOOKS`, which compiles in two
environment knobs for reaching fallback paths deliberately. The Android build
never defines it, so a normal `libslophook.a` contains neither.

| | |
|---|---|
| `SH_TEST_NO_RWX=1` | pretend the kernel refuses RWX anonymous pages, forcing the RW+flip-to-RX arena path |
| `SH_TEST_NO_NEAR=1` | pretend no page is free within ±128MB, forcing the 16-byte absolute detour |
