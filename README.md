# SlopHook
SlopHook is an android arm64 lightweight inline hook implementation that may resembles Dobby. I didn't able to get to build the dobby hook library for my android arm64 use case so i just ask AI to make this for me. Warning this is slopped by Opus 5 high, from my testing it works quite well but just keep it in mind if some implementation are weird. This may be useful for you if you just want to get something working or testing fast, and no need to waste your token again to build new hooking things for the android arm64.

Below is Opus 5 SlopHook instruction, end of human interaction here.

# slophook — building your own inline hook engine for Android arm64

A working, minimal inline hooking engine (~700 lines) built the same way Dobby
is: near-memory trampolines, a real instruction relocator, and a single-word
atomic patch. This document is the reasoning; the code is the proof.

```
ndk-build                                     # Android build (see section 9)
make -f Makefile.hosttests check-reloc        # relocator units, vs llvm-mc
make -f Makefile.hosttests run                # full engine under qemu-aarch64
```

---

## 1. What you are actually building

Replacing a function at runtime on arm64 means solving five problems, and
almost everything in the design falls out of problem 2 and problem 5.

| # | Problem | Solution here |
|---|---------|---------------|
| 1 | Reach an arbitrary 64-bit address when `B` only reaches ±128 MB | trampoline in *near memory*, or a 16-byte absolute detour |
| 2 | The instructions you overwrite must still run | **relocate** them into a trampoline |
| 3 | Code pages are read-only and usually file-backed | `mprotect`, falling back to `/proc/self/mem` |
| 4 | I-cache and D-cache are not coherent | `dc cvau` / `ic ivau` / `isb` |
| 5 | Other threads are executing the bytes you are rewriting | patch **one aligned word**, atomically |

---

## 2. Why "near memory" is the whole trick

The naive detour is 16 bytes:

```asm
ldr  x17, #8
br   x17
.quad replacement
```

That costs you two things. You must relocate **four** instructions instead of
one, which multiplies the chance of hitting something you cannot relocate. And
a 16-byte write is not atomic — a thread can be executing instruction 3 of the
prologue while you rewrite instruction 1.

So instead, allocate a page **within ±128 MB of the target**, put the absolute
jump *there*, and patch the target with a single 4-byte `B`:

```
target:        b     near_stub          <- the only byte you change
near_stub:     ldr   x17, #8
               br    x17
               .quad replacement
```

`src/mem.c` finds that page by walking `/proc/self/maps`, collecting gaps
inside the window, sorting candidates by distance from the target, and mapping
with `MAP_FIXED_NOREPLACE` so the kernel refuses rather than silently
unmapping something. Verified on the real engine:

```
target first word: 11000400 -> 140361d4
is single B:       YES
branch displacement: 886608 bytes (0.8 MB)
```

### The atomicity argument, precisely

A naturally aligned 32-bit store is *single-copy atomic* on AArch64, so no
other core can observe a torn instruction.

Be honest about the limit, though. The Arm ARM's rules on concurrent
modification and execution (CMODX) only guarantee that a thread sees either the
old or the new instruction without synchronisation when **both** instructions
come from a small set: `B`, `BL`, `B.cond`, `BRK`, `SVC`, `HVC`, `SMC`, `ISB`,
`NOP`. Your new instruction is a `B`, which qualifies. The *old* one is usually
`stp`/`sub sp`, which does not.

In practice everyone ships this, and it works. If you need the guarantee —
patching something hot, in a product — you suspend the other threads, or you
patch a `NOP` that the compiler left there (`-fpatchable-function-entry`),
which puts both the old and new instruction inside the safe set.

---

## 3. Instruction relocation

This is the part people get wrong. The good news: **A64 has exactly nine
PC-relative instruction forms.** Everything else is position independent and
can be memcpy'd. That closed set is what makes a correct relocator tractable:

`B` · `BL` · `B.cond` (and `BC.cond`) · `CBZ/CBNZ` · `TBZ/TBNZ` · `ADR` ·
`ADRP` · `LDR (literal)` (which covers `LDRSW` and `PRFM` literal)

### Branches that no longer reach

Re-encode the displacement if it still fits. If not, expand to a long-branch
island. For a conditional branch you keep the condition and jump *over* the
island:

```asm
b.eq   #8          ; +0   taken -> island
b      #20         ; +4   not taken -> past it
ldr    x17, #8     ; +8
br     x17         ; +12
.quad  target      ; +16
                   ; +24  next relocated instruction
```

`TBZ/TBNZ` only reaches ±32 KB, so it takes this path almost always.

### Address formation — and why it uses no scratch register

`ADRP x1, sym` becomes:

```asm
ldr    x1, #8
b      #12
.quad  <absolute page address>
```

Note it clobbers **only x1**, the instruction's own destination. That matters:
this sits mid-function where every other register may be live. Same for `ADR`
and the GPR forms of `LDR (literal)`.

The test that actually proves this works relocates a real `adrp` out of a
function prologue and leaves the matching `add xN, xN, #:lo12:sym` in place at
`target+4`:

```
PASS  relocated ADRP still computes the right page (0x46f1b8 vs 0x46f1b8)
PASS  relocated ADRP + untouched ADD yield the original string
```

For the **vector** forms (`LDR d0, literal`) you have no choice but to borrow a
GPR, so the relocator spills and restores it:

```asm
str    x17, [sp, #-16]!
ldr    x17, #8
b      #12
.quad  <literal address>
ldr    d0, [x17]
ldr    x17, [sp], #16
```

`PRFM (literal)` is a prefetch hint with no architectural effect worth
preserving, so it becomes a `NOP`.

### Is clobbering X17 legitimate?

For branches, yes, and the reason is worth knowing. AAPCS64 lets a
linker-inserted **branch veneer** clobber X16/X17 at any branch site, so no
correct code may assume X17 survives a branch. That is exactly the situation a
long-branch island creates.

Mid-function, with no branch involved, that argument does not hold — which is
why the ADR/ADRP/literal paths above either use the destination register or
spill X17 to the stack.

### What the relocator refuses

A prologue that branches back into the bytes you are about to overwrite cannot
work: the destination becomes the middle of your patch. The relocator detects
it and returns `SH_ERR_SELF_BRANCH` rather than producing a function that jumps
into half an instruction.

---

## 4. Cache maintenance

I-cache and D-cache are not coherent on AArch64. After writing instructions you
must, for every affected line:

```asm
dc  cvau, Xn      ; clean data cache to point of unification
dsb ish
ic  ivau, Xn      ; invalidate instruction cache
dsb ish
isb
```

`__builtin___clear_cache()` emits exactly this and reads `CTR_EL0` for the
correct line sizes, so use it rather than hardcoding 64 bytes.

---

## 5. Getting write access to code pages

First try `mprotect(..., PROT_READ|PROT_WRITE|PROT_EXEC)`. On Android this can
be denied by SELinux for file-backed executable pages (`execmod`).

**Put back the protection the page actually had.** Restoring a hardcoded
`PROT_READ|PROT_EXEC` is wrong on anything that was not `r-x` to begin with:
it silently strips `PROT_WRITE`, and the next ordinary write to that page
faults with `SEGV_ACCERR` somewhere with no visible connection to the patch.
The engine reads the real protection from `/proc/self/maps` first and asks for
`orig | PROT_WRITE` rather than RWX, so a non-executable page never briefly
becomes executable either.

**And refuse anything that is not code.** `sh_mem_patchable()` checks the
target is one mapping, readable and executable before any of the above runs.
A mis-resolved address — a data symbol, a GOT slot, a heap buffer passed where
the address belonged — returns `SH_ERR_NOTCODE` instead of having its page
mprotected and its write permission stripped. This matters more than it looks:
the damage and the crash are decoupled, so without the guard the fault lands
in whatever touches that page next, typically the allocator.

**Strip the pointer tag.** AArch64 Top Byte Ignore means bits 63:56 are not
part of the address, and Android's allocator puts a tag there. The CPU ignores
it on load and store, but it must be masked off before page arithmetic, before
`mprotect`, and before using an address as a `pwrite` offset into
`/proc/self/mem`. The engine normalises addresses on entry, so a tagged and an
untagged pointer to the same function refer to the same registry entry.

The fallback is `/proc/self/mem`, which goes through the kernel's
`access_process_vm()` and ignores VMA write protection entirely:

```c
int fd = open("/proc/self/mem", O_RDWR | O_CLOEXEC);
pwrite(fd, &insn, 4, (off_t)(uintptr_t)addr);
```

For the **trampoline** pages you control the mapping, so the engine asks for
RWX and falls back to RW + flip-to-RX.

That fallback used to carry a real hazard: one arena page is shared by many
hooks, so flipping it to RW in order to install hook #2 made hook #1's
trampoline non-executable for the duration, and any thread running in it
faulted. Skipping the flip when the arena is already RWX — the original
mitigation — only covered the case that never had the problem.

The engine now **only shares an arena page when it is RWX**. When RWX was
denied, each hook gets its own page, so a write window can never de-execute
somebody else's live trampoline. That costs a page instead of 256 bytes per
hook, which is the right trade. If you would rather not have RWX pages at all,
the alternative is a **memfd dual mapping** — map the same `memfd_create`
region RW at one address and RX at another, write through the RW alias, execute
at the RX one. No race, no RWX, no per-hook page.

---

## 6. Instrumentation: capturing register state

`sh_instrument()` runs a callback with full register context and then continues
the original code. The target branches to a per-hook **closure** that saves X17,
passes its own info pointer on the stack, and jumps to one shared assembly
bridge.

The awkward part is the return path. The bridge must restore *every* register
including X16/X17, yet it needs a register to hold the address it branches to.
The way out is a two-instruction stub in front of the relocated prologue:

```asm
; bridge, after restoring everything:
    add  sp, sp, #400
    ldr  x17, [sp, #0]      ; x17 = resume stub (clobbered deliberately)
    br   x17

; resume stub:
    ldr  x17, [sp, #8]      ; reload X17 as the callback left it
    add  sp, sp, #16        ; drop the closure's block
    <relocated prologue>
    <jump back to target+N>
```

X17 is restored *at the destination* rather than before the branch. The test
`uses_x17` keeps a live value in X17 across an instrumented call and checks it
survives.

**On Android, do not touch X18** — it is the reserved shadow call stack
pointer. The bridge saves and restores it and never uses it as scratch.

---

## 7. Android specifics worth knowing

**BTI.** On pages compiled with branch protection, an *indirect* branch (`BR
X17`) must land on a `BTI` instruction. Your trampoline's tail jump goes back
into the *middle* of the original function, where no landing pad exists — a
`BR` there would fault. This is why `sh_emit_tail_jump()` prefers a direct `B`
whenever the target is in range: direct branches are exempt from BTI checks.
Since the trampoline is in near memory by construction, it almost always is.

`src/bridge_arm64.S` carries a matching `.note.gnu.property` (conditional on
`-mbranch-protection=`), so the linker does not find one unmarked object and
silently drop BTI/PAC marking from your entire shared library. It also has a
`bti c` landing pad, because the per-hook closure reaches it via `BR X17`.
Build with `SLOPHOOK_BRANCH_PROTECTION=true` to turn this on.

**PAC.** Prologues beginning with `paciasp` are position independent and copy
verbatim; signing and authentication stay balanced because both see the same SP
and key.

**16 KB pages.** Android 15+ devices ship a 16 KB page size. Never hardcode
4096 — the code uses `sysconf(_SC_PAGESIZE)` throughout.

**Finding targets.** `dlopen`/`dlsym` for exported symbols. For non-exported
ones, get the module base from `/proc/self/maps` and add a file offset you
resolved from the ELF `.symtab`/`.dynsym` beforehand.

---

## 8. Direct code patching

Hooking is not always what you want. Sometimes the job is to *edit* an
instruction: delete a call, flip a condition, stub a function to return a
constant. `sh_patch_code()` is that primitive — the equivalent of Frida's
`Memory.patchCode()`.

```c
sh_status sh_patch_code(void *addr, size_t size, sh_patch_cb cb, void *user);
sh_status sh_revert(void *addr);
```

The callback receives a **scratch copy** of the region, pre-loaded with the
bytes currently at `addr`. Write your instructions into it; they are committed
when you return. `addr` is passed in as well, because the scratch pointer is
not the target address and any PC-relative arithmetic must use the real one.

```c
/* turn a b.eq into a b.ne, in place */
static void flip(void *code, void *addr, size_t size, void *user) {
    uint32_t w; memcpy(&w, code, 4);
    w = (w & ~0xFu) | ((w & 0xFu) ^ 1u);
    memcpy(code, &w, 4);
}
sh_patch_code(branch_addr, 4, flip, NULL);
```

One place gets the hard parts right, so everything below inherits them: page
write access (`mprotect`, falling back to `/proc/self/mem`), the `dc`/`ic`/`isb`
sequence, remembering the original bytes for `sh_revert()`, and — when the patch
is exactly one word — a single naturally aligned store, which is atomic against
concurrently executing threads. **A patch larger than 4 bytes is not atomic**;
see §2.

### The `sh_put_*` layer

Named operations for the things you actually do to a function. The 4-byte ones
are atomic.

| | writes | what it does |
|---|---|---|
| `sh_put_nop(addr)` | 4 B | one `NOP` |
| `sh_put_nops(addr, n)` | 4n B | `n` `NOP`s |
| `sh_nop_call(site)` | 4 B | delete a `BL`. Same bytes as `sh_put_nop`, named for the intent |
| `sh_put_ret(addr)` | 4 B | `RET` — the function becomes a no-op, returning whatever was in x0 |
| `sh_put_brk(addr)` | 4 B | `BRK #0` — trap when anything reaches here |
| `sh_put_true(addr)` | 8 B | `return 1` |
| `sh_put_false(addr)` | 8 B | `return 0` |
| `sh_put_int(addr, v)` | 8–12 B | `return v` in w0 |
| `sh_put_long(addr, v)` | 8–20 B | `return v` in x0 |
| `sh_put_float(addr, v)` | 8–16 B | `return v` in s0 |
| `sh_put_double(addr, v)` | 8–24 B | `return v` in d0 |
| `sh_put_bytes(addr, src, n)` | n B | copy instructions verbatim |
| `sh_put_hex(addr, "1F 20 03 D5")` | n B | the same, as a hex string in memory order |
| `sh_put_b(addr, dest)` | 4 B | `B dest`, or `SH_ERR_RANGE` |
| `sh_put_bl(addr, dest)` | 4 B | `BL dest`, or `SH_ERR_RANGE` |
| `sh_put_jump(addr, dest)` | 4 or 16 B | direct `B` when in range, else a 16-byte absolute jump |

The integer forms pick the shortest encoding, using `MOVN` where it helps — so
`sh_put_int(addr, -1)` is one `MOVN` plus a `RET`, 8 bytes, not four `MOVK`s.
The float forms stage the bit pattern in X16 (IP0, dead at a function entry) and
`FMOV` it across, except for zero, which is `FMOV s0, wzr`.

`sh_put_hex()` takes bytes in **memory order** — exactly what you copy out of a
hex editor or IDA. Separators (space, comma, `:`, `-`) and `0x` prefixes are
ignored, so all three of these are the same patch:

```c
sh_put_hex(addr, "20 00 80 52 C0 03 5F D6");            /* mov w0,#1 ; ret */
sh_put_hex(addr, "0x20,0x00,0x80,0x52,0xC0,0x03,0x5F,0xD6");
sh_put_hex(addr, "200080 52C0035FD6");
```

### Undoing, and asking what is installed

| | |
|---|---|
| `sh_revert(addr)` | restore the bytes as they were before the *first* patch there |
| `sh_revert_all()` | revert every outstanding patch; returns the count |
| `sh_is_patched(addr)` | is there a patch registered exactly here? |
| `sh_unhook_all()` | remove every hook; returns the count |
| `sh_is_hooked(addr)` | is there a hook registered exactly here? |
| `sh_read_code(addr, dst, n)` | read a region, e.g. to save it yourself |
| `sh_enc_branch(from, to, link)` | encode a `B`/`BL`, or 0 if out of imm26 range |

Because `sh_revert()` goes back to the *first* original, re-patching the same
`[addr, size)` several times and then reverting once still lands you on
untouched code.

Two things are refused, both to prevent one failure mode — two writers each
saving the other's bytes as "original", leaving the target corrupted after
revert:

- a patch overlapping a *different* existing patch,
- a patch overlapping a region held by a hook (and vice versa).

### Finding targets

| | |
|---|---|
| `sh_module_base(name, &span)` | load address of the first mapping whose path contains `name`, from `/proc/self/maps`; `span` receives the module's extent |
| `sh_resolve(name, offset)` | that base plus `offset` — the usual way to reach a non-exported function |
| `sh_sym(soname, symbol)` | `dlopen` + `dlsym` in one call, for exported symbols |

### The one thing none of this knows

**How long your function is.** `sh_put_long()` with a 64-bit value writes 20
bytes; if the function is shorter, you have just overwritten whatever follows
it. Overlap detection only protects a neighbour that is *itself* hooked or
patched. Every multi-word form has a size query — `sh_size_int`,
`sh_size_long`, `sh_size_float`, `sh_size_double`, `sh_size_jump`,
`sh_size_hex` — so check against something you trust: a symbol size from
`.symtab`, or the distance to the next symbol.

```c
#include "slophook.h"

void neuter_checks(void) {
    void *base = sh_module_base("libtarget.so", NULL);
    if (!base) return;

    /* a validity check that should always pass */
    sh_put_true((char *)base + 0x4A18);

    /* a BL we do not want - 4 bytes, so atomic */
    sh_nop_call((char *)base + 0x1C40);

    /* a float getter that should always read 100.0 */
    sh_put_float((char *)base + 0x7120, 100.0f);

    /* trap the first time anything calls this, to see who does */
    sh_put_brk((char *)base + 0x9004);

    /* ... and put it all back */
    sh_revert_all();
}
```

---

## 9. Building for Android

The build is `Android.mk` (ndk-build). Drop the tree into your project and add
one line at the **end** of your own `jni/Android.mk`:

```makefile
include $(LOCAL_PATH)/slophook/Android.mk
```

then link it from your module:

```makefile
LOCAL_STATIC_LIBRARIES := slophook
```

`LOCAL_EXPORT_C_INCLUDES` means you do not need to add an include path. Set
`APP_ABI := arm64-v8a` in `jni/Application.mk`; the ABI guard in `Android.mk`
fails with an explicit message on anything else.

Options, settable in `Application.mk` or on the `ndk-build` command line:

| variable | effect |
|---|---|
| `SLOPHOOK_BRANCH_PROTECTION=true` | build with `-mbranch-protection=standard` and keep the BTI/PAC property note |
| `SLOPHOOK_BUILD_SHARED=true` | also produce a standalone `libslophook.so` |

`CMakeLists.txt` is there for Gradle `externalNativeBuild { cmake { } }`
projects. `Makefile.hosttests` is the host/qemu test harness and plays no part
in an Android build. See `IMPORT.md` for the full walkthrough.

Usage:

```c
#include "slophook.h"

static int (*orig_open)(const char *, int, ...);

static int my_open(const char *path, int flags, ...) {
    LOGI("open(%s)", path);
    return orig_open(path, flags);
}

void install(void) {
    void *h = dlopen("libc.so", RTLD_NOW);
    sh_status st = sh_hook(dlsym(h, "open"), my_open, (void **)&orig_open);
    if (st != SH_OK) LOGE("hook failed: %s", sh_strerror(st));
}
```

---

## 10. Known limitations

- **No thread suspension.** See the CMODX discussion in §2. Installing and
  removing a 4-byte detour is a single atomic store, but a 16-byte detour is
  not.
- **Not reentrant.** The hook, patch and arena registries are plain linked
  lists with no lock; take a mutex if you install from multiple threads.
- **`sh_unhook` does not reclaim arena memory.** Trampolines are leaked by
  design, because another thread may still be inside one. Real reclamation
  needs epoch-based reclamation or RCU. `sh_unhook` also frees the instrument
  closure's info block immediately, with no grace period.
- **Targets must be in a readable, executable mapping.** Anything else is
  refused with `SH_ERR_NOTCODE`. An execute-only (`--x`) mapping is refused
  too, because the original bytes cannot be read out to save them.
- **No function-length knowledge.** A 16-byte detour, or a long
  `sh_put_long`, will happily overwrite whatever follows a short
  function. Overlapping hooks and patches are refused, but a *neighbour that is
  not itself hooked* is not protected. Supply the length from `.symtab` if it
  matters.
- **Far placement is refused rather than approximated.** If no page can be
  found within ±128MB of the target and the displaced prologue still needs a
  tail jump back, `sh_hook` returns `SH_ERR_RANGE`. Resuming mid-function from
  out of range would require clobbering X17, which the original straight-line
  code may have live — and would fault under BTI. The fallback is still used
  when the displaced region contains an unconditional transfer, so no tail jump
  is needed.
- **Vector literal loads cost 7 instructions** and briefly use 16 bytes below
  SP.
- **8-byte literals in a trampoline may be only 4-byte aligned.** `LDR
  (literal)` scales its immediate by 4, so a 64-bit literal can land at a
  4-mod-8 address. Linux and Android run with `SCTLR_EL1.A = 0`, where this is
  permitted; it is not architecturally guaranteed.

---

# Importing slophook into your Android project

arm64-v8a only. Needs NDK r19 or newer (anything with a unified clang toolchain).

---

## 1. ndk-build (Android.mk) — the documented path

### Layout

Put the tree inside your `jni/` directory:

```
jni/
├── Android.mk            <- yours
├── Application.mk        <- yours
├── myhook.c              <- your code
└── slophook/
    ├── Android.mk        <- ships with the library
    ├── include/slophook.h
    └── src/...
```

### Your `jni/Android.mk`

```makefile
LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE           := myhook
LOCAL_SRC_FILES        := myhook.c
LOCAL_STATIC_LIBRARIES := slophook
LOCAL_LDLIBS           := -llog
include $(BUILD_SHARED_LIBRARY)

# Must come LAST: slophook/Android.mk calls $(call my-dir) and resets
# LOCAL_PATH, so include it once you are done with your own modules.
include $(LOCAL_PATH)/slophook/Android.mk
```

You do **not** need `LOCAL_C_INCLUDES` — `slophook/Android.mk` sets
`LOCAL_EXPORT_C_INCLUDES`, so `#include "slophook.h"` just works in any module
that lists `slophook` in `LOCAL_STATIC_LIBRARIES`.

### Your `jni/Application.mk`

```makefile
APP_ABI      := arm64-v8a
APP_PLATFORM := android-29
APP_STL      := none
```

`arm64-v8a` is required. If `TARGET_ARCH_ABI` is anything else the build stops
with an explicit message rather than failing later at link time.

### Build

```bash
cd jni && ndk-build -j$(nproc)
# -> libs/arm64-v8a/libmyhook.so
```

### Options

```bash
ndk-build SLOPHOOK_BRANCH_PROTECTION=true   # keep BTI / PAC-ret marking
ndk-build SLOPHOOK_BUILD_SHARED=true        # also emit libslophook.so
ndk-build NDK_DEBUG=1                        # debuggable
```

Or set them in `Application.mk`. If your app is built with branch protection,
turn `SLOPHOOK_BRANCH_PROTECTION=true` on — the asm bridge ships a matching
`.note.gnu.property`, and without the flag reaching it the linker would drop
BTI/PAC marking from your whole `.so`.

---

## 2. Alternative: `import-module`

Keep slophook outside `jni/` and reference it by name.

```makefile
# jni/Android.mk, at the end
$(call import-add-path, $(LOCAL_PATH)/../third_party)
$(call import-module, slophook)
```

with the tree at `third_party/slophook/`. Or set `NDK_MODULE_PATH`:

```bash
ndk-build NDK_MODULE_PATH=/path/to/third_party
```

---

## 3. Gradle

### With ndk-build

```gradle
android {
    defaultConfig {
        ndk { abiFilters "arm64-v8a" }
        externalNativeBuild {
            ndkBuild { arguments "SLOPHOOK_BRANCH_PROTECTION=true" }
        }
    }
    externalNativeBuild {
        ndkBuild { path "src/main/jni/Android.mk" }
    }
}
```

### With CMake

`CMakeLists.txt` is included for this. In your own `CMakeLists.txt`:

```cmake
add_subdirectory(slophook)
target_link_libraries(myhook PRIVATE slophook)
```

```gradle
android {
    defaultConfig { ndk { abiFilters "arm64-v8a" } }
    externalNativeBuild { cmake { path "src/main/cpp/CMakeLists.txt" } }
}
```

---

## 4. Smoke test

`jni/myhook.c`:

```c
#include <android/log.h>
#include <dlfcn.h>
#include <stdlib.h>
#include "slophook.h"

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "slophook", __VA_ARGS__)

static int (*orig_open)(const char *, int, ...);

static int my_open(const char *path, int flags, ...) {
    LOGI("open(%s)", path);
    return orig_open(path, flags);
}

__attribute__((constructor))
static void install(void) {
    void *h = dlopen("libc.so", RTLD_NOW);
    void *target = dlsym(h, "open");

    /* 1. replace a function, keeping a way to call the original */
    sh_status st = sh_hook(target, (void *)my_open, (void **)&orig_open);
    LOGI("sh_hook(open) -> %s", sh_strerror(st));

    /* 2. patch instructions directly, no trampoline involved */
    void *getuid_p = sh_sym("libc.so", "getuid");
    if (getuid_p) {
        st = sh_put_int(getuid_p, 0);              /* getuid() -> 0 */
        LOGI("sh_put_int(getuid, 0) -> %s  [%zu bytes]",
             sh_strerror(st), sh_size_int(0));
    }

    /* 3. and undo everything */
    LOGI("reverted %zu patches, removed %zu hooks",
         sh_revert_all(), sh_unhook_all());
}
```

Expected `logcat`:

```
I slophook: sh_hook(open) -> ok
I slophook: sh_put_int(getuid, 0) -> ok  [8 bytes]
I slophook: open(/data/...)
I slophook: reverted 1 patches, removed 1 hooks
```

---

## 5. Finding targets

`dlopen`/`dlsym` for exported symbols. For non-exported ones, take the module
base from `/proc/self/maps` and add a file offset you resolved beforehand from
the ELF `.symtab`/`.dynsym`:

```c
void *t = sh_resolve("libtarget.so", 0x4A18);   /* base + offset  */
void *e = sh_sym("libc.so", "open");            /* exported symbol */

size_t span = 0;
void *base = sh_module_base("libtarget.so", &span);
```

While you are reading the ELF, record the **symbol size** too. Neither
`sh_hook` nor `sh_put_*` can know how long a function is, and a 16-byte detour
or a 20-byte `sh_put_long` stub over a shorter function overwrites its
neighbour. Check the `sh_size_*` queries against that size. See §10 of the
README.

---

## 6. Troubleshooting

| symptom | cause |
|---|---|
| `slophook supports arm64-v8a only` | set `APP_ABI := arm64-v8a` / `abiFilters "arm64-v8a"` |
| `slophook.h: No such file` | your module is missing `LOCAL_STATIC_LIBRARIES := slophook`, or you included `slophook/Android.mk` before your own module instead of after |
| `undefined reference to sh_bridge_entry` | `src/bridge_arm64.S` was dropped from the source list — ndk-build needs the `.S` |
| `sh_hook` / `sh_put_*` returns `target is not in a readable, executable mapping` | the address is not code. Almost always a mis-resolved target: a data symbol, a GOT slot, or arguments swapped (`sh_put_bytes(buf, addr, n)` instead of `sh_put_bytes(addr, buf, n)`). Log the `/proc/self/maps` line for the address — if it is not `r-xp` against an `.so`, that is the bug |
| a `SEGV_ACCERR` in the allocator, or any unrelated write faulting after a patch | you are on a tree from before the second fix round; the patched page had `PROT_WRITE` stripped. See README §11 |
| `sh_hook` returns `could not make target page writable` | SELinux denied `execmod` *and* `/proc/self/mem` was unavailable; check the process is not running under a restrictive domain |
| `sh_hook` returns `target out of branch range` | no page free within ±128MB of the target and the prologue needs a tail jump back. Refused on purpose; see README §10 |
| `sh_hook` / `sh_put_*` returns `already hooked` for a fresh address | its region overlaps an existing hook or patch — likely a very short neighbouring function |
| `sh_put_hex` returns `invalid argument` | the string did not parse, or did not come to a non-zero multiple of 4 bytes. Check with `sh_size_hex()` |
| `sh_put_b` / `sh_put_bl` returns `target out of branch range` | more than ±128MB away; use `sh_put_jump` (16 bytes, clobbers X17) or a hook |
| `sh_hook` returns `prologue branches into the patched region` | the first instruction branches into the bytes being replaced; this target cannot be hooked at its entry |
| crash in the replacement on the first call | you are on an unfixed tree where `*origin` is published after the detour goes live; see README §11 |

---

## 7. Host-side tests

Not part of an Android build, but useful when changing the relocator.

```bash
apt-get install -y gcc-aarch64-linux-gnu qemu-user-static llvm
make -f Makefile.hosttests check-reloc    # relocator units vs llvm-mc
make -f Makefile.hosttests run            # full engine under qemu
```

`test/README-tests.md` documents the wider suite (ABI shapes, relocate-and-
execute, fuzzing, concurrency).