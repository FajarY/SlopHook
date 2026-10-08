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
