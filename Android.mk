# slophook - inline hook + direct code patch engine for AArch64 / Android
#
# Add to your project with ONE line at the END of your own jni/Android.mk:
#
#     include $(LOCAL_PATH)/slophook/Android.mk
#
# then reference it from your module:
#
#     LOCAL_STATIC_LIBRARIES := slophook
#
# See IMPORT.md for the full walkthrough (including Gradle and CMake).

LOCAL_PATH := $(call my-dir)

# ---------------------------------------------------------------------------
# arm64 only. The relocator, the register bridge and every instruction
# encoding in here are A64; there is no 32-bit or x86 path.
# ---------------------------------------------------------------------------
ifneq ($(TARGET_ARCH_ABI),arm64-v8a)
  $(error slophook supports arm64-v8a only, but TARGET_ARCH_ABI is '$(TARGET_ARCH_ABI)'. \
          Set 'APP_ABI := arm64-v8a' in jni/Application.mk, or \
          'ndk.abiFilters "arm64-v8a"' in build.gradle.)
endif

SLOPHOOK_SRC := \
    src/hook.c \
    src/mem.c \
    src/patch.c \
    src/put.c \
    src/backtrace.c \
    src/arm64_relocate.c \
    src/bridge_arm64.S

SLOPHOOK_CFLAGS := -O2 -Wall -Wextra -fvisibility=hidden -ffunction-sections -fdata-sections

# Optional: keep BTI / PAC-ret marking on the library.
#
# The asm bridge carries a matching .note.gnu.property, so the linker will
# NOT silently drop branch protection from your whole .so. This must reach
# both the C and the .S compiles, which is why it is in ASFLAGS too.
#
# Enable with:  make SLOPHOOK_BRANCH_PROTECTION=true
#               (or set it in Application.mk / your own Android.mk)
ifeq ($(SLOPHOOK_BRANCH_PROTECTION),true)
  SLOPHOOK_CFLAGS += -mbranch-protection=standard
endif

# ---------------------------------------------------------------------------
# libslophook.a - the normal way to use this: linked into your own .so
# ---------------------------------------------------------------------------
include $(CLEAR_VARS)
LOCAL_MODULE            := slophook
LOCAL_SRC_FILES         := $(SLOPHOOK_SRC)
LOCAL_C_INCLUDES        := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS            := $(SLOPHOOK_CFLAGS)
LOCAL_ASFLAGS           := $(SLOPHOOK_CFLAGS)
LOCAL_EXPORT_LDLIBS     := -llog
include $(BUILD_STATIC_LIBRARY)

# ---------------------------------------------------------------------------
# libslophook.so - standalone, for injection / LD_PRELOAD style use.
# Off by default. Enable with:  SLOPHOOK_BUILD_SHARED := true
# Note this one drops -fvisibility=hidden so the sh_* API is exported.
# ---------------------------------------------------------------------------
ifeq ($(SLOPHOOK_BUILD_SHARED),true)
include $(CLEAR_VARS)
LOCAL_MODULE            := slophook_shared
LOCAL_MODULE_FILENAME   := libslophook
LOCAL_SRC_FILES         := $(SLOPHOOK_SRC)
LOCAL_C_INCLUDES        := $(LOCAL_PATH)/include
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_CFLAGS            := $(filter-out -fvisibility=hidden,$(SLOPHOOK_CFLAGS))
LOCAL_ASFLAGS           := $(filter-out -fvisibility=hidden,$(SLOPHOOK_CFLAGS))
LOCAL_LDLIBS            := -llog
include $(BUILD_SHARED_LIBRARY)
endif
