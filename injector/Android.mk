# injector/Android.mk — builds libinjector.a (C, static archive)
#
# The daemon (Rust) links this archive via build.rs FFI. The injector is a
# 64-bit binary that cross-injects both 32- and 64-bit targets.
#
# Build: ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk
#        (or via the top-level Makefile: make build-native)

LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)
LOCAL_MODULE := injector
LOCAL_SRC_FILES := injector.c elf_resolve.c regs.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)
LOCAL_CFLAGS := -Wall -Wextra -Werror -O2 -fvisibility=hidden
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)
include $(BUILD_STATIC_LIBRARY)
