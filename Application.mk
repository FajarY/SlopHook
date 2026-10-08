# Sample jni/Application.mk for a project using slophook.
# arm64 only - see the ABI guard in Android.mk.

APP_ABI      := arm64-v8a
APP_PLATFORM := android-29
APP_STL      := none
APP_OPTIM    := release

# Uncomment to keep BTI / PAC-ret marking on the library:
# SLOPHOOK_BRANCH_PROTECTION := true

# Uncomment to also build a standalone libslophook.so:
# SLOPHOOK_BUILD_SHARED := true
