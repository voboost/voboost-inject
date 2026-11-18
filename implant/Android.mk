# implant/Android.mk — builds libimplant.so (C++, per-ABI)
#
# The in-process loader: acquires JavaVM, loads agent dex via
# InMemoryDexClassLoader, inits LSPlant with Dobby hooks + safe_resolve_symbol.
# Injected via ptrace (the injector calls __loader_dlopen + implant_init).
#
# Build constraints (release-verification spec):
#   - c++_static (system libc++_shared on Android 9 conflicts by ABI)
#   - liblog only for safe_resolve diagnostics; implant diagnostics use the log-pipe
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

include $(CLEAR_VARS)
LOCAL_MODULE := dex_builder_static
LOCAL_SRC_FILES := $(LOCAL_PATH)/../prebuilt/$(TARGET_ARCH_ABI)/libdex_builder_static.a
include $(PREBUILT_STATIC_LIBRARY)

include $(CLEAR_VARS)
LOCAL_MODULE := lsplant_static
LOCAL_SRC_FILES := $(LOCAL_PATH)/../prebuilt/$(TARGET_ARCH_ABI)/liblsplant_static.a
LOCAL_STATIC_LIBRARIES := dex_builder_static
include $(PREBUILT_STATIC_LIBRARY)

# ---- libimplant.so ----
include $(CLEAR_VARS)
LOCAL_MODULE := implant
LOCAL_SRC_FILES := implant.cpp safe_resolve.cpp dobby_adapter.cpp ../third_party/yyjson/src/yyjson.c
LOCAL_C_INCLUDES := $(LOCAL_PATH)/include $(LOCAL_PATH)/../third_party/yyjson/src
LOCAL_STATIC_LIBRARIES := lsplant_static dex_builder_static dobby_static
LOCAL_CPP_FEATURES := exceptions rtti
# C++20 for lsplant compatibility; c++_static (not shared) per release-verification
LOCAL_CPPFLAGS := -std=c++20 -g0 -fvisibility=hidden
LOCAL_CFLAGS := -Wall -Wextra -O2 -g0 -fvisibility=hidden
# No LTO (release-verification: -flto removed for LSPlant C++23 modules)
LOCAL_LDLIBS := -ldl -llog -lz
LOCAL_LDFLAGS := -Wl,--version-script,$(LOCAL_PATH)/implant.map -Wl,--strip-all
LOCAL_ALLOW_UNDEFINED_VERSION_SCRIPT_SYMBOLS := false
include $(BUILD_SHARED_LIBRARY)
$(LOCAL_BUILT_MODULE): $(LOCAL_PATH)/implant.map
