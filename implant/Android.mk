# implant/Android.mk — builds libimplant.so (C++, per-ABI)
#
# The in-process loader: acquires JavaVM, loads agent dex via
# InMemoryDexClassLoader, inits LSPlant with Dobby hooks + safe_resolve_symbol.
# Injected via ptrace (the injector calls __loader_dlopen + implant_init).
#
# Build constraints (build-and-signing spec):
#   - c++_static (system libc++_shared on Android 9 conflicts by ABI)
#   - LOG_DISABLED at dir scope (reaches C++23-module BMIs)
#   - lsplant.hpp from source (Maven InitInfo ABI diverged)
#   - -flto removed
#
# Build: ndk-build NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=Android.mk

LOCAL_PATH := $(call my-dir)

# ---- prebuilt static Dobby ----
include $(CLEAR_VARS)
LOCAL_MODULE := dobby_static
LOCAL_SRC_FILES := $(LOCAL_PATH)/../prebuilt/$(TARGET_ARCH_ABI)/libdobby.a
LOCAL_EXPORT_C_INCLUDES := $(LOCAL_PATH)/include
include $(PREBUILT_STATIC_LIBRARY)

# ---- libimplant.so ----
include $(CLEAR_VARS)
LOCAL_MODULE := implant
LOCAL_SRC_FILES := implant.cpp safe_resolve.cpp dobby_adapter.cpp
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include
LOCAL_STATIC_LIBRARIES := dobby_static
LOCAL_CPP_FEATURES := exceptions rtti
# C++20 for lsplant compatibility; c++_static (not shared) per build-and-signing
LOCAL_CPPFLAGS := -std=c++20 -fvisibility=hidden
# LOG_DISABLED at dir scope — critical: target_compile_definitions does not
# reach BMI C++23 modules, so we use compile definitions here
LOCAL_CFLAGS := -Wall -Wextra -DLOG_DISABLED -O2 -fvisibility=hidden
# No LTO (build-and-signing: -flto removed for LSPlant C++23 modules)
LOCAL_LDLIBS := -llog -ldl
include $(BUILD_SHARED_LIBRARY)
