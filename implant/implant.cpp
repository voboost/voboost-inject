/*
 * implant.cpp — libimplant.so, the in-process loader (C++, per-ABI).
 *
 * Injected into the target via ptrace (see native-payload: injector calls
 * __loader_dlopen then explicit remote-call implant_init). Runs its full
 * startup from implant_init ONLY — not from __attribute__((constructor)) or
 * JNI_OnLoad (ctors do not run under ptrace-dlopen in a hijacked-thread
 * context).
 *
 * Startup chain:
 *   1. Acquire JavaVM via JNI_GetCreatedJavaVMs
 *   2. Load native deps (liblsplant, libc++_shared) via dlopen
 *   3. Init LSPlant with Dobby inline-hooker slots + safe_resolve_symbol
 *   4. Load agent .dex via InMemoryDexClassLoader (pure JNI)
 *   5. Call the fixed Java seam: ru.voboost.agents.AgentEntry.init(configPath)
 *
 * Production cleanups vs PoC (bootstrap.cpp):
 *   - Single entry point: implant_init only (no ctor, no JNI_OnLoad)
 *   - Re-entry guard (prevent double-startup)
 *   - Debug counters removed (g_hook_calls/g_hook_ok/g_resolver_calls)
 *   - Config path passed as parameter (not hardcoded)
 *   - Dobby logger silenced via no-op log_internal_impl
 */

#ifndef LOG_DISABLED
/* If not built with -DLOG_DISABLED, use android log.
 * build-and-signing: LOG_DISABLED at dir scope via add_compile_definitions. */
#include <android/log.h>
#define IMPLANT_LOGI(...) __android_log_print(ANDROID_LOG_INFO, "VoboostImplant", __VA_ARGS__)
#define IMPLANT_LOGE(...) __android_log_print(ANDROID_LOG_ERROR, "VoboostImplant", __VA_ARGS__)
#else
/* LOG_DISABLED: no-op logging (production builds). */
#define IMPLANT_LOGI(...) ((void)0)
#define IMPLANT_LOGE(...) ((void)0)
#endif

#include <jni.h>
#include <dlfcn.h>
#include <atomic>
#include <string>
#include <cstring>
#include <pthread.h>

#include "lsplant/lsplant.hpp"
#include "agent_entry_seam.h"

/* ---- Dobby logger silencer ----
 *
 * Dobby's log_internal_impl crashes inside an ART inline-hook trampoline
 * (vsnprintf on a bad pointer SIGSEGVs). log_set_level() cannot suppress it:
 * Dobby's gate uses an unsigned comparison (b.hi) and some call sites pass
 * severity = -1 (0xFFFFFFFF), which is larger than any level. We override
 * the symbol with a no-op stub so the linker resolves every call here.
 */
extern "C" __attribute__((visibility("default")))
void log_internal_impl(int /*severity*/, const char * /*fmt*/, ...) {
    /* intentionally empty — silence all Dobby internal logging */
}

/* ---- safe_resolve_symbol (from safe_resolve.cpp) ---- */
void *safe_resolve_symbol(const char *libname, const char *symname);

/* ---- Dobby adapter (from dobby_adapter.cpp) ---- */
extern "C" void *vbi_dobby_inline_hooker(void *target, void *hooker);
extern "C" bool vbi_dobby_inline_unhooker(void *func);

/* ---- LSPlant function pointer types (resolved via dlsym) ---- */
typedef bool (*lsplant_init_t)(JNIEnv *, const lsplant::InitInfo &);

static lsplant_init_t p_lsplant_init = nullptr;
static std::atomic<bool> g_initialized{false};
static std::atomic<bool> g_libs_loaded{false};

/* The fixed Java entry seam (see agent-entry-seam spec + agent_entry_seam.h). */
static const char *ENTRY_CLASS = AGENT_ENTRY_CLASS_NAME;

/* ---- load native dependencies ---- */

static bool load_native_libs() {
    if (g_libs_loaded.load(std::memory_order_acquire)) {
        return true;
    }

    /* liblsplant.so — dlopen with RTLD_GLOBAL so C++ symbols are visible. */
    void *p = dlopen("liblsplant.so", RTLD_NOW | RTLD_GLOBAL);
    if (!p) {
        IMPLANT_LOGE("dlopen liblsplant failed: %s", dlerror());
        return false;
    }

    /* Resolve lsplant::Init via mangled name (same NDK libc++ ABI). */
    p_lsplant_init = (lsplant_init_t)dlsym(
        p, "_ZN7lsplant2v24InitEP7_JNIEnvRKNS0_8InitInfoE");
    if (!p_lsplant_init) {
        IMPLANT_LOGE("dlsym lsplant::Init failed");
        return false;
    }

    g_libs_loaded.store(true, std::memory_order_release);
    return true;
}

/* ---- LSPlant init ---- */

static bool init_lsplant(JNIEnv *env) {
    if (!load_native_libs()) {
        return false;
    }

    lsplant::InitInfo info{
        .inline_hooker = [](void *target, void *hooker) -> void * {
                             return vbi_dobby_inline_hooker(target, hooker);
                         },
        .inline_unhooker = [](void *func) -> bool {
                               return vbi_dobby_inline_unhooker(func);
                           },
        .art_symbol_resolver = [](std::string_view sym) -> void * {
                                   std::string name(sym);
                                   return safe_resolve_symbol("libart.so", name.c_str());
                               },
        .art_symbol_prefix_resolver = [](std::string_view) -> void * {
                                          return nullptr; /* LSPlant marks this "May be null" */
                                      },
    };

    bool ok = p_lsplant_init(env, info);
    if (!ok) {
        IMPLANT_LOGE("lsplant::Init FAILED");
        return false;
    }
    return true;
}

/* ---- hidden-API exemption ----
 *
 * setHiddenApiExemptions("L") must be called before any reflection-heavy
 * agent (proven <1.2ms, reflection works immediately). See agent-entry-seam.
 */
static void exempt_hidden_api(JNIEnv *env) {
    jclass cls = env->FindClass("dalvik/system/VMRuntime");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return;
    }
    jmethodID mid = env->GetStaticMethodID(
        cls, "setHiddenApiExemptions", "([Ljava/lang/String;)Z");
    if (env->ExceptionCheck() || !mid) {
        env->ExceptionClear();
        return;
    }

    jclass stringCls = env->FindClass("java/lang/String");
    jobjectArray args = env->NewObjectArray(1, stringCls, nullptr);
    jstring exempt = env->NewStringUTF("L");
    env->SetObjectArrayElement(args, 0, exempt);

    env->CallStaticBooleanMethod(cls, mid, args);
    env->ExceptionClear();

    env->DeleteLocalRef(exempt);
    env->DeleteLocalRef(args);
    env->DeleteLocalRef(cls);
}

/* ---- load agent dex via InMemoryDexClassLoader ---- */

static bool load_and_call_agent(JNIEnv *env, const char *config_path) {
    /* Read dex path from config. The config_path points to a channel-B file
     * containing the agent dex path. For the initial port we read the dex
     * from a known location; the full channel-B config delivery is wired
     * in update-planes. */
    const char *dex_path = "/data/voboost-inject/payload/agents.dex";

    /* Read dex bytes. */
    FILE *df = fopen(dex_path, "rb");
    if (!df) {
        IMPLANT_LOGE("open dex %s failed", dex_path);
        return false;
    }
    fseek(df, 0, SEEK_END);
    long dsize = ftell(df);
    fseek(df, 0, SEEK_SET);

    jbyteArray dexBytes = env->NewByteArray(dsize);
    void *dbuf = malloc(dsize);
    fread(dbuf, 1, dsize, df);
    fclose(df);
    env->SetByteArrayRegion(dexBytes, 0, dsize, (jbyte *)dbuf);
    free(dbuf);

    /* Get the app ClassLoader for proper class resolution. */
    jclass atCls = env->FindClass("android/app/ActivityThread");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        IMPLANT_LOGE("FindClass ActivityThread failed");
        return false;
    }
    jmethodID curAppMid = env->GetStaticMethodID(
        atCls, "currentApplication", "()Landroid/app/Application;");
    jobject app = env->CallStaticObjectMethod(atCls, curAppMid);
    if (env->ExceptionCheck() || !app) {
        env->ExceptionClear();
        IMPLANT_LOGE("currentApplication failed");
        return false;
    }
    jclass appCls = env->GetObjectClass(app);
    jmethodID gclMid =
        env->GetMethodID(appCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
    jobject appLoader = env->CallObjectMethod(app, gclMid);
    if (env->ExceptionCheck() || !appLoader) {
        env->ExceptionClear();
        IMPLANT_LOGE("getClassLoader failed");
        return false;
    }

    /* InMemoryDexClassLoader(dexBytes, appLoader) */
    jclass bbCls = env->FindClass("java/nio/ByteBuffer");
    jmethodID wrapMid =
        env->GetStaticMethodID(bbCls, "wrap", "([B)Ljava/nio/ByteBuffer;");
    jobject bb = env->CallStaticObjectMethod(bbCls, wrapMid, dexBytes);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        IMPLANT_LOGE("ByteBuffer.wrap failed");
        return false;
    }
    jclass imdcCls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    jmethodID ctorMid = env->GetMethodID(
        imdcCls, "<init>",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    jobject loader = env->NewObject(imdcCls, ctorMid, bb, appLoader);
    if (env->ExceptionCheck() || !loader) {
        env->ExceptionClear();
        IMPLANT_LOGE("InMemoryDexClassLoader failed");
        return false;
    }

    /* loadClass(ENTRY_CLASS) */
    jclass loaderCls = env->GetObjectClass(loader);
    jmethodID loadClassMid = env->GetMethodID(
        loaderCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    jstring className = env->NewStringUTF(ENTRY_CLASS);
    jclass entryCls = (jclass)env->CallObjectMethod(loader, loadClassMid, className);
    if (env->ExceptionCheck() || !entryCls) {
        env->ExceptionClear();
        IMPLANT_LOGE("loadClass %s failed", ENTRY_CLASS);
        return false;
    }

    /* Call AgentEntry.init(String configPath) — the fixed seam.
     * Defensive: clear any exception so a throwing agent/seam does not
     * crash the target (see agent-entry-seam spec). */
    jmethodID initMid =
        env->GetStaticMethodID(entryCls, "init", "(Ljava/lang/String;)V");
    if (env->ExceptionCheck() || !initMid) {
        env->ExceptionClear();
        IMPLANT_LOGE("AgentEntry.init method not found");
        return false;
    }

    jstring configStr = env->NewStringUTF(config_path ? config_path : "");
    env->CallStaticVoidMethod(entryCls, initMid, configStr);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        IMPLANT_LOGE("AgentEntry.init threw — contained, target keeps running");
        /* Not fatal: the seam is defensive. The target continues running. */
    }

    env->DeleteLocalRef(configStr);
    env->DeleteLocalRef(className);
    return true;
}

/* ---- single entry point: implant_init ----
 *
 * extern "C" void implant_init(const char* cfg)
 *
 * Called by the injector via explicit remote-call AFTER __loader_dlopen
 * (ctors don't run under ptrace-dlopen). This is the ONLY entry point —
 * no __attribute__((constructor)), no JNI_OnLoad.
 *
 * cfg — the channel-B config file path (agent reads + watches it for live
 *       updates; see update-planes).
 */

extern "C" __attribute__((visibility("default")))
void implant_init(const char *cfg) {
    /* Re-entry guard: ignore redundant calls (a second load must not run
     * startup twice — the PoC raised UnsatisfiedLinkError when it did). */
    if (g_initialized.exchange(true, std::memory_order_acq_rel)) {
        IMPLANT_LOGI("implant_init: already initialized, ignoring re-entry");
        return;
    }

    IMPLANT_LOGI("implant_init: start (cfg=%s)", cfg ? cfg : "(null)");

    /* 1. Acquire JavaVM via JNI_GetCreatedJavaVMs. */
    void *libart = dlopen("libart.so", RTLD_NOW);
    if (!libart) {
        IMPLANT_LOGE("dlopen libart.so failed: %s", dlerror());
        return;
    }
    typedef jint (*GetVMs_t)(JavaVM **, jsize, jsize *);
    GetVMs_t getVMs = (GetVMs_t)dlsym(libart, "JNI_GetCreatedJavaVMs");
    if (!getVMs) {
        IMPLANT_LOGE("dlsym JNI_GetCreatedJavaVMs failed");
        return;
    }
    JavaVM *vm = nullptr;
    jsize n = 0;
    if (getVMs(&vm, 1, &n) != JNI_OK || n < 1 || !vm) {
        IMPLANT_LOGE("no JavaVM found");
        return;
    }

    JNIEnv *env = nullptr;
    if (vm->GetEnv((void **)&env, JNI_VERSION_1_6) != JNI_OK) {
        if (vm->AttachCurrentThread(&env, nullptr) != JNI_OK) {
            IMPLANT_LOGE("AttachCurrentThread failed");
            return;
        }
    }

    /* 2. Exempt hidden API before any agent reflection. */
    exempt_hidden_api(env);

    /* 3. Init LSPlant (Dobby backend + safe_resolve_symbol). */
    if (!init_lsplant(env)) {
        IMPLANT_LOGE("LSPlant init failed — aborting");
        return;
    }

    /* 4. Load agent dex and call the seam. */
    load_and_call_agent(env, cfg);

    IMPLANT_LOGI("implant_init: complete");
}

/* JNI_OnLoad is intentionally NOT used for startup.
 * The injector calls implant_init explicitly. If a Java dlopen loads this
 * .so, JNI_OnLoad is a no-op (it must not run the startup chain twice). */
JNIEXPORT jint JNI_OnLoad(JavaVM * /*vm*/, void * /*reserved*/) {
    return JNI_VERSION_1_6;
}
