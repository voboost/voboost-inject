/*
 * implant.cpp — libimplant.so, the in-process loader (C++, per-ABI).
 *
 * Injected into the target via ptrace (see injector-remote-execution: injector
 * calls the target linker then explicit remote-call implant_init). Runs its
 * full startup from implant_init ONLY. Native ELF constructors are executed
 * by the target linker; this entry remains explicit for bootstrap ordering.
 * JNI_OnLoad is not involved because the library is loaded natively.
 *
 * Startup chain:
 *   1. Acquire JavaVM via JNI_GetCreatedJavaVMs
 *   2. Init statically linked LSPlant with Dobby slots + safe_resolve_symbol
 *   3. Load agent .dex via InMemoryDexClassLoader (pure JNI)
 *   4. Call the fixed Java seam with the daemon-authored desired snapshot
 *
 * implant_init is the sole guarded startup entry. Bootstrap descriptors come
 * from the owning daemon; Dobby diagnostics use the no-op log_internal_impl.
 */

#include "cache_quiescence_ack.h"
#include <jni.h>
#include <dlfcn.h>
#include <link.h>
#include <atomic>
#include <exception>
#include <memory>
#include <new>
#include <string>
#include <vector>
#include <cstring>
#include <unordered_set>
#include <cstdarg>
#include <pthread.h>
#include <poll.h>
#include <cerrno>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <linux/memfd.h>
#include <time.h>
#include <unistd.h>

#include "lsplant.hpp"
#include "agent_entry_seam.h"
#include "bootstrap_descriptor.h"
#include "bootstrap_worker.h"
#include "bootstrap_fd_ownership.h"
#include "pipe_bootstrap.h"
#include "pipe_bootstrap_phase.h"
#include "pipe_bootstrap_manifest.h"
#include "downlink_framer.h"
#include "downlink_snapshots.h"
#include "owned_intent_lane.h"
#include "owned_intent_wake.h"
#include "downlink_watch_apply.h"
#include "main_thread_snapshot_scope.h"
#include "downlink_watch_read.h"
#include "settings_loaded.h"
#include "jni_attachment.h"
#include "loader_probe.h"
#include "system_server_loader.h"
#include "scoped_jni_attachment.h"
#include "sigpipe_safe_write.h"
#include "hook_stage_record.h"
#include "log_transport.h"
#include "event_uplink.h"
#include "state_rpc_serialization.h"
#include "state_reply_decode.h"
#include "strict_utf8.h"
#include "../injector/handoff_result.h"

static void implant_log(int level, const char *format, ...);
static void log_hook_stage(const char *stage, uint64_t elapsed) noexcept;
#define IMPLANT_LOGD(...) implant_log(3, __VA_ARGS__) /* developer bootstrap diagnostics */
#define IMPLANT_LOGW(...) implant_log(1, __VA_ARGS__) /* warning: anomalous, same priority as error */
#define IMPLANT_LOGE(...) implant_log(1, __VA_ARGS__)

static void log_detach_failure() {
    IMPLANT_LOGE("DetachCurrentThread failed");
}

template <typename T>
static bool jni_result_failed(JNIEnv *env, T result, const char *operation) {
    bool failed = !result || env->ExceptionCheck();
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    if (failed) {
        IMPLANT_LOGE("JNI %s failed", operation);
    }
    return failed;
}

static bool jni_call_failed(JNIEnv *env, const char *operation) {
    if (!env->ExceptionCheck()) {
        return false;
    }
    /* Extract the exception message before clearing. */
    jobject exc = env->ExceptionOccurred();
    env->ExceptionClear();
    if (exc) {
        jmethodID getMessage = env->GetMethodID(
            env->FindClass("java/lang/Throwable"), "getMessage", "()Ljava/lang/String;");
        if (getMessage) {
            jstring msg = (jstring)env->CallObjectMethod(exc, getMessage);
            if (msg) {
                const char *str = env->GetStringUTFChars(msg, nullptr);
                if (str) {
                    IMPLANT_LOGE("JNI %s raised: %s", operation, str);
                    env->ReleaseStringUTFChars(msg, str);
                } else {
                    IMPLANT_LOGE("JNI %s raised (no message)", operation);
                }
            } else {
                IMPLANT_LOGE("JNI %s raised (null message)", operation);
            }
        } else {
            env->ExceptionClear();
            IMPLANT_LOGE("JNI %s raised (no getMessage)", operation);
        }
    } else {
        IMPLANT_LOGE("JNI %s raised", operation);
    }
    return true;
}

class ScopedJniLocalFrame {
public:
ScopedJniLocalFrame(JNIEnv *env, jint capacity) : env_(env) {
    pushed_ = env_->PushLocalFrame(capacity) >= 0;
    if (!pushed_ && env_->ExceptionCheck()) {
        env_->ExceptionClear();
    }
}
~ScopedJniLocalFrame() {
    if (pushed_) {
        env_->PopLocalFrame(nullptr);
    }
}
bool valid() const {
    return pushed_;
}

private:
JNIEnv *env_;
bool pushed_ = false;
};

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
/* File-based .symtab resolver (exact + prefix). Resolves hidden ART symbols
 * that are absent from .dynsym but present in the full .symtab section. */
void *safe_resolve_symbol_symtab(const char *libname, const char *symname,
                                 bool prefix_match);

/* Resolve diagnostics use the owned agent pipe once phase two establishes it. */
void vbi_symtab_trace(const char *stage, const char *detail, long value) {
    implant_log(3, "symtab-resolver: %s (%s, %ld)", stage, detail ? detail : "?",
                 value);
}

/* ---- Dobby adapter (from dobby_adapter.cpp) ---- */
extern "C" void *vbi_dobby_inline_hooker(void *target, void *hooker);
extern "C" bool vbi_dobby_inline_unhooker(void *func);

typedef jboolean (*hook_backup_publisher_t)(JNIEnv *, jobject, jobject);
extern "C" jobject voboost_lsplant_hook_with_backup(
    JNIEnv *, jobject, jobject, jobject, hook_backup_publisher_t);
using stage_callback_t = void (*)(const char *, uint64_t) noexcept;
extern "C" void voboost_lsplant_set_stage_callback(stage_callback_t) noexcept;
static std::atomic<bool> g_initialized{false};
static std::atomic<bool> g_resident_ready{false};

/*
 * Outcome of the agent-load attempt (see agent_entry_seam.h). Deferred is
 * reported when currentApplication() is null after the bounded early-boot
 * re-poll: the daemon retries on the same live PID (a Deferred attempt does
 * NOT set the re-entry guard, so a later implant_init re-run can retry).
 */

/* Early-boot readiness bounds for the currentApplication() re-poll. The host
 * Application binds shortly after zygote fork; this is a tight, real-condition
 * poll (not a blind one-shot delay) that lets the agent run as soon as the
 * Application is available, without holding the ptrace-hijacked thread for
 * long. If the Application still has not bound after the bound, the implant
 * returns Deferred and the daemon takes over the longer same-PID retry.
 *
 * The poll runs on the ptrace-hijacked thread (a UI-critical thread in the
 * host process), so the total bound MUST stay short — a 2 s hold risked ANR.
 * 20 tries × 10 ms = 200 ms keeps real-condition readiness without a visible
 * stall. */
#define AGENT_APP_POLL_TRIES   20  /* attempts */
#define AGENT_APP_POLL_SLEEP_MS 10  /* between attempts → ~200 ms total bound */

static void sleep_ms(int ms) {
    struct timespec ts {};
    ts.tv_sec = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    nanosleep(&ts, nullptr);
}

/* ---- host loader probes (loader_probe.h contract) ----
 *
 * Each probe runs inside its own local frame and returns the accepted loader
 * promoted through PopLocalFrame, or nullptr when this probe cannot produce
 * one. The probes are optional capabilities: a failed lookup only clears the
 * exception the probe itself raised. They set *foreign_pending when they
 * observe an exception they did not raise — the caller must abort the whole
 * attempt without clearing it. */

/* ---- process self-identity (loader provenance oracle) ----
*
* The only loader the implant may hand to the agent runtime is one whose
* provenance is proven against THIS process: the bound application's own
* loader, or the LoadedApk of the AppBindData whose package/process names
* equal the process the implant is actually running in. A non-boot thread
* context loader proves nothing by its name alone — the system
* PathClassLoader is also a dalvik.system.PathClassLoader. */

static bool read_cmdline_process(char *out, size_t size) {
    int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        return false;
    }
    ssize_t n = read(fd, out, size - 1);
    close(fd);
    if (n <= 0) {
        return false;
    }
    out[n] = '\0';
    return true;
}

/* "package" is the cmdline token up to ':' (manifest process suffix). */
static void package_of_process(const char *process, char *out, size_t size) {
    size_t i = 0;
    for (; i + 1 < size && process[i] != '\0' && process[i] != ':'; ++i) {
        out[i] = process[i];
    }
    out[i] = '\0';
}

/* pid + starttime (field 22 of /proc/self/stat, after the `(comm)` pair). */
static bool read_pid_starttime(long *pid, unsigned long *starttime) {
    FILE *f = fopen("/proc/self/stat", "re");
    if (!f) {
        return false;
    }
    char line[512];
    const char *cursor = fgets(line, sizeof(line), f);
    fclose(f);
    if (!cursor) {
        return false;
    }
    const char *close_paren = strrchr(line, ')');
    if (!close_paren) {
        return false;
    }
    long parsed_pid = 0;
    unsigned long parsed_start = 0;
    /* Tokens after `)` start at field 3; starttime is field 22, i.e. the
     * 20th token after the paren pair. */
    int parsed = sscanf(close_paren + 1,
                        " %*s %*s %*s %*s %*s %*s %*s %*s %*s %*s"
                        " %*s %*s %*s %*s %*s %*s %*s %*s %*s %lu",
                        &parsed_start);
    if (parsed != 1 || sscanf(line, "%ld", &parsed_pid) != 1) {
        return false;
    }
    *pid = parsed_pid;
    *starttime = parsed_start;
    return true;
}

static void log_selection_attempt_begin() {
    long pid = 0;
    unsigned long starttime = 0;
    char process[256] = {0};
    read_cmdline_process(process, sizeof(process));
    if (!read_pid_starttime(&pid, &starttime)) {
        IMPLANT_LOGD("loader selection attempt: process=%s pid/starttime unreadable",
                     process);
        return;
    }
    IMPLANT_LOGD("loader selection attempt: process=%s pid=%ld starttime=%lu",
                 process, pid, starttime);
}

/* Reads a String field into a bounded buffer without leaving an exception
 * pending. Returns false when the field is absent or unreadable. */
static bool read_string_field(JNIEnv *env, jobject obj, jclass cls,
                              const char *field, char *out, size_t size) {
    loader_probe_copy_name(out, size, "");
    char sig[64];
    snprintf(sig, sizeof(sig), "Ljava/lang/String;");
    jfieldID fid = env->GetFieldID(cls, field, sig);
    if (fid == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    jobject value = env->GetObjectField(obj, fid);
    if (value == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return false;
    }
    const char *chars = env->GetStringUTFChars((jstring)value, nullptr);
    if (chars == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(value);
        return false;
    }
    loader_probe_copy_name(out, size, chars);
    env->ReleaseStringUTFChars((jstring)value, chars);
    env->DeleteLocalRef(value);
    return true;
}

/* Purely diagnostic: reports whether the current thread's context loader
 * and the system class loader ARE the already-proven host reference. The
 * thread context loader is NEVER an admission source: equality with the
 * proven reference is the only meaningful fact about it. */
static void log_loader_identity_diagnostics(JNIEnv *env, jobject host) {
    if (env->PushLocalFrame(8) < 0) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return;
    }
    int same_as_thread = -1;
    int same_as_system = -1;
    jclass thread_cls = env->FindClass("java/lang/Thread");
    if (thread_cls != nullptr && !env->ExceptionCheck()) {
        jmethodID current_thread = env->GetStaticMethodID(
            thread_cls, "currentThread", "()Ljava/lang/Thread;");
        if (current_thread != nullptr && !env->ExceptionCheck()) {
            jobject thread = env->CallStaticObjectMethod(thread_cls, current_thread);
            if (thread != nullptr && !env->ExceptionCheck()) {
                jmethodID get_loader = env->GetMethodID(
                    thread_cls, "getContextClassLoader",
                    "()Ljava/lang/ClassLoader;");
                if (get_loader != nullptr && !env->ExceptionCheck()) {
                    jobject candidate =
                        env->CallObjectMethod(thread, get_loader);
                    if (!env->ExceptionCheck()) {
                        same_as_thread = candidate
                                             ? env->IsSameObject(candidate, host)
                                             : 0;
                    } else {
                        env->ExceptionClear();
                    }
                    if (candidate != nullptr) {
                        env->DeleteLocalRef(candidate);
                    }
                } else {
                    env->ExceptionClear();
                }
            } else if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
        } else if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
    } else if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    jclass loader_cls = env->FindClass("java/lang/ClassLoader");
    if (loader_cls != nullptr && !env->ExceptionCheck()) {
        jmethodID get_system = env->GetStaticMethodID(
            loader_cls, "getSystemClassLoader", "()Ljava/lang/ClassLoader;");
        if (get_system != nullptr && !env->ExceptionCheck()) {
            jobject system = env->CallStaticObjectMethod(loader_cls, get_system);
            if (!env->ExceptionCheck()) {
                same_as_system =
                    system ? env->IsSameObject(system, host) : 0;
                if (system != nullptr) {
                    env->DeleteLocalRef(system);
                }
            } else {
                env->ExceptionClear();
            }
        } else {
            env->ExceptionClear();
        }
    } else if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    IMPLANT_LOGD(
        "loader identity: sameAsThreadContext=%d sameAsSystem=%d "
        "(diagnostics only; thread context is not an admission source)",
        same_as_thread, same_as_system);
    env->PopLocalFrame(nullptr);
}

static jobject probe_bound_application_loader(JNIEnv *env, bool *foreign_pending,
                                              const char *expected_package,
                                              const char *expected_process) {
    if (env->PushLocalFrame(8) < 0) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        return nullptr;
    }
    jobject accepted = nullptr;
    do {
        jclass at_cls = env->FindClass("android/app/ActivityThread");
        if (at_cls == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        jmethodID current_at = env->GetStaticMethodID(
            at_cls, "currentActivityThread", "()Landroid/app/ActivityThread;");
        if (current_at == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        jobject at = env->CallStaticObjectMethod(at_cls, current_at);
        if (at == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        jfieldID bound_fid = env->GetFieldID(
            at_cls, "mBoundApplication",
            "Landroid/app/ActivityThread$AppBindData;");
        if (bound_fid == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        jobject bound_app = env->GetObjectField(at, bound_fid);
        if (bound_app == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        jclass bind_cls = env->GetObjectClass(bound_app);
        if (bind_cls == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        /* AppBindData declares no getClassLoader (AOSP android-11.0.0_r1);
         * the LoadedApk is its `info` field. */
        jfieldID info_fid = env->GetFieldID(
            bind_cls, "info", "Landroid/app/LoadedApk;");
        if (info_fid == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        jobject loaded_apk = env->GetObjectField(bound_app, info_fid);
        if (loaded_apk == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        jclass apk_cls = env->GetObjectClass(loaded_apk);
        if (apk_cls == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        /* Provenance: the LoadedApk is only a host-loader authority when its
         * package (and the AppBindData process name) match the process the
         * implant is running in. A mismatched binding is not this host. */
        char bound_package[256] = {0};
        if (!read_string_field(env, loaded_apk, apk_cls, "mPackageName",
                               bound_package, sizeof(bound_package))) {
            IMPLANT_LOGD(
                "skipping mBoundApplication candidate (mPackageName unreadable)");
            break;
        }
        if (strcmp(bound_package, expected_package) != 0) {
            IMPLANT_LOGD(
                "skipping mBoundApplication candidate (package %s != process package %s)",
                bound_package, expected_package);
            break;
        }
        char bound_process[256] = {0};
        if (read_string_field(env, bound_app, bind_cls, "processName",
                              bound_process, sizeof(bound_process)) &&
            bound_process[0] != '\0' && strcmp(bound_process, expected_process) != 0) {
            IMPLANT_LOGD(
                "skipping mBoundApplication candidate (process %s != cmdline %s)",
                bound_process, expected_process);
            break;
        }
        /* Read the EXISTING mClassLoader reference only: LoadedApk's
         * getClassLoader() lazily CREATES the loader (and with it the host
         * application/resources), which must not run while the process group
         * is stopped under ptrace. A missing reference means the host has no
         * loader yet — Deferred, not synthesis. */
        jfieldID loader_fid = env->GetFieldID(
            apk_cls, "mClassLoader", "Ljava/lang/ClassLoader;");
        if (loader_fid == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        jobject existing = env->GetObjectField(loaded_apk, loader_fid);
        if (existing == nullptr || env->ExceptionCheck()) {
            env->ExceptionClear();
            break;
        }
        {
            char loader_name[128];
            LoaderProbeOutcome outcome = probe_loader_class_name(
                env, existing, loader_name, sizeof(loader_name));
            if (outcome == LoaderProbeOutcome::PENDING_INCOMING) {
                *foreign_pending = true;
                break;
            }
            if (outcome == LoaderProbeOutcome::IS_BOOT_CLASSLOADER) {
                IMPLANT_LOGD("skipping mBoundApplication candidate (boot loader)");
                break;
            }
            if (outcome == LoaderProbeOutcome::PROBE_FAILED) {
                IMPLANT_LOGD("skipping mBoundApplication candidate (name unresolved)");
                break;
            }
            /* NOT_BOOT_CLASSLOADER alone is not admission: this candidate is
             * accepted only because its LoadedApk package/process identity
             * was verified above. The name is a diagnostic. */
            IMPLANT_LOGD(
                "host loader from mBoundApplication.info.mClassLoader "
                "(verified package=%s process=%s): %s",
                bound_package, expected_process, loader_name);
            accepted = existing;
        }
    } while (false);
    return (jobject)env->PopLocalFrame(accepted);
}

/* The fixed Java entry seam (see agent-entry-seam spec + agent_entry_seam.h). */
static const char *ENTRY_CLASS = AGENT_ENTRY_CLASS_NAME;


/* ---- Java Hooker bridge: nativeHook / nativeUnhook ----
 *
 * ru.voboost.agents.HookNative native methods. Registered in implant_init
 * after lsplant::Init, before loading the agent dex. Each delegates to the
 * statically linked LSPlant hook and unhook functions.
 *
 * Signature (HookNative.java):
 *   static native Method nativeHook(Object targetMethod, Object hookerObject, Method callbackMethod);
 *   static native boolean nativeUnhook(Object targetMethod);
 */
static const char *HOOKER_NATIVE_CLASS = "ru/voboost/agents/HookNative";

static jboolean publish_hook_backup(JNIEnv *env, jobject hooker_object, jobject backup) {
    if (!env || !hooker_object || !backup || env->ExceptionCheck()) {
        return JNI_FALSE;
    }
    jboolean published = JNI_FALSE;
    jclass hooker_cls = env->GetObjectClass(hooker_object);
    if (env->ExceptionCheck() || !hooker_cls) {
        IMPLANT_LOGE("nativeHook: hooker class unavailable for backup publication");
        return JNI_FALSE;
    }
    jmethodID set_backup_mid = env->GetMethodID(
        hooker_cls, "setBackup", "(Ljava/lang/reflect/Method;)V");
    if (env->ExceptionCheck() || !set_backup_mid) {
        IMPLANT_LOGE("nativeHook: HookCallback.setBackup not found");
    } else {
        env->CallVoidMethod(hooker_object, set_backup_mid, backup);
        if (env->ExceptionCheck()) {
            IMPLANT_LOGE("nativeHook: backup publication call threw");
        } else {
            IMPLANT_LOGD("nativeHook: backup published before target activation");
            published = JNI_TRUE;
        }
    }
    env->DeleteLocalRef(hooker_cls);
    return published;
}

static jobject native_hook_impl(JNIEnv *env, jclass, jobject target_method,
                                jobject hooker_object, jobject callback_method) {
    struct timespec started {};
    clock_gettime(CLOCK_MONOTONIC, &started);
    IMPLANT_LOGD("nativeHook: stage=lsplant-enter pid=%d tid=%ld", getpid(),
                 syscall(SYS_gettid));
    jobject backup = voboost_lsplant_hook_with_backup(
        env, target_method, hooker_object, callback_method, publish_hook_backup);
    struct timespec finished {};
    clock_gettime(CLOCK_MONOTONIC, &finished);
    long elapsed_ms = (finished.tv_sec - started.tv_sec) * 1000L
                      + (finished.tv_nsec - started.tv_nsec) / 1000000L;
    IMPLANT_LOGD("nativeHook: stage=lsplant-return pid=%d tid=%ld elapsed_ms=%ld backup=%d exception=%d",
                 getpid(), syscall(SYS_gettid), elapsed_ms, backup != nullptr,
                 env->ExceptionCheck() == JNI_TRUE);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        IMPLANT_LOGE("nativeHook: lsplant::Hook threw");
        return nullptr;
    }
    if (!backup) {
        return nullptr;
    }
    /* Publication already occurred before DoHook; Java's afterreturn setter
     * remains an idempotent write of this genuine reflected backup. */
    return backup;
}

static jboolean native_unhook_impl(JNIEnv *env, jclass, jobject target_method) {
    bool ok = lsplant::UnHook(env, target_method);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return JNI_FALSE;
    }
    return ok ? JNI_TRUE : JNI_FALSE;
}

/* Register the two native methods on HookNative so the Java Hooker facade
 * can call them. Called once, after the dex is loaded, with the dex
 * classloader (HookNative lives in the dex, so FindClass must use that
 * loader, not the system one). */
static bool register_hooker_natives(JNIEnv *env, jobject loader) {
    jclass loaderCls = env->GetObjectClass(loader);
    if (jni_result_failed(env, loaderCls, "HookNative loader class")) {
        return false;
    }
    jmethodID loadClassMid =
        env->GetMethodID(loaderCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (jni_result_failed(env, loadClassMid, "HookNative loadClass method")) {
        return false;
    }
    jstring name = env->NewStringUTF(HOOKER_NATIVE_CLASS);
    if (jni_result_failed(env, name, "HookNative class name")) {
        return false;
    }
    jclass cls = (jclass)env->CallObjectMethod(loader, loadClassMid, name);
    env->DeleteLocalRef(name);
    if (jni_result_failed(env, cls, "HookNative loadClass")) {
        IMPLANT_LOGE("register_hooker_natives: loadClass %s failed", HOOKER_NATIVE_CLASS);
        return false;
    }
    JNINativeMethod methods[] = {
        {"nativeHook",   "(Ljava/lang/Object;Ljava/lang/Object;Ljava/lang/reflect/Method;)Ljava/lang/reflect/Method;",
         (void *)native_hook_impl},
        {"nativeUnhook", "(Ljava/lang/Object;)Z",
         (void *)native_unhook_impl},
    };
    jint rc = env->RegisterNatives(cls, methods, 2);
    if (rc != 0) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        IMPLANT_LOGE("register_hooker_natives: RegisterNatives failed rc=%d", (int)rc);
        env->DeleteLocalRef(cls);
        return false;
    }
    IMPLANT_LOGD("register_hooker_natives: registered HookNative");
    env->DeleteLocalRef(cls);
    return true;
}

/* ---- Multiplexed agent pipe: Log / State / Reads / Events (L/S/R/E) ----
 *
 * One pipe (created by implant_init) carries three record types, distinguished
 * by a single-char prefix. Each record is one '\n'-terminated line:
 *   L|<ts_ms>|<source>|<level>|<message>\n    (Log    — Log.log)
 *   S|<ts_ms>|<source>|<key>|<value>\n         (State  — State.set)
 *   R|<request_id>|<source>|<key>\n             (State  — State.get)
 *   E|<request_id>|<source>|<type>|<payload>\n (Events — Events.emit)
 * The daemon parses the first field (type) and routes the rest to the matching
 * drain (log::agent / state / events). Embedded '\n' in the trailing field is
 * rewritten to '\r' so every '\n' in the stream is a record boundary.
 *
 * Signatures (Java):
 *   static native void log(long ts, int level, String source, String message);
 *   static native void set (long ts, String source, String key,    String value);
 *   static native void emit(long requestId, String source, String type, String payload);
 *
 * AgentLog lives in ru.voboost.agents (renamed back from ru.voboost.reflect.Log);
 * State and Events stay in ru.voboost.agents. All three are registered on the
 * just-loaded dex classloader, before AgentEntry.init.
 *
 * fd < 0 → pipe unavailable → silent no-op (agents never crash on logging).
 * fd is O_NONBLOCK: a full pipe yields EAGAIN and the line is dropped (log,
 * not control; loss is acceptable, the agent thread never blocks).
 */
static const char *LOG_NATIVE_CLASS    = "ru/voboost/agents/AgentLog";
static const char *STATE_NATIVE_CLASS  = "ru/voboost/agents/AgentState";
static const char *EVENTS_NATIVE_CLASS = "ru/voboost/agents/AgentEvents";
static const char *STATUS_NATIVE_CLASS = "ru/voboost/agents/AgentStatusTransport";
static const char *LOGS_NATIVE_CLASS   = "ru/voboost/agents/logs/LogsNativeTransport";

/* Target-local pipe ends created by implant_init. The injector duplicates the
 * read-end into the daemon, then asks the implant to close its read-end copy.
 * A negative write-end means agent logging is disabled. */
static int g_agent_log_fd = -1;
static LogTransport g_log_transport;
static EventUplink g_event_uplink;
/* Early ERROR records survive failed bootstrap attempts until an owned pipe
 * exists. Access is serialized by g_pipe_mutex; no target stdout/file fallback. */
struct EarlyNativeLog { char bytes[4096]; size_t size; long long timestamp; };
static EarlyNativeLog g_early_native_logs[8]{};
static size_t g_early_native_count = 0;
static uint64_t g_early_native_dropped = 0;
static void flush_early_native_logs_locked();

static int g_agent_log_read_fd = -1;
static int g_state_reply_fd = -1;
static int g_state_reply_write_fd = -1;
static std::atomic<unsigned long long> g_state_request_id{1};
static bool g_pipe_bootstrap_ready = false;
static bool g_pipe_bootstrap_channel_ready = false;
static PipeBootstrapEnvelope g_pipe_bootstrap;
static BootstrapFdOwnership g_bootstrap_fds;
static std::string g_resident_generation;
static std::string g_resident_catalog_sha256;
static SettingsLoaded g_settings_loaded;
struct BootstrapWorkerCapsule : BootstrapWorkerChannels {
    const BootstrapDescriptor descriptor;
    const pthread_t borrowed_thread = pthread_self();
    std::atomic<pthread_t> owned_thread{pthread_t{}};
    BootstrapWorkerGate gate;
    std::atomic<bool> finished{false};
    StatusUplink pending_status;
    BootstrapWorkerCapsule(BootstrapDescriptor descriptor, BootstrapWorkerBinding binding,
                           int completion, int commit)
        : BootstrapWorkerChannels(completion, commit), descriptor(std::move(descriptor)), gate(binding) {
    }
};
/* Published capsule handles remain process-owned so concurrent native abort
 * observations never dereference reclaimed memory. Only the worker owns its
 * duplicate FDs; completed failed/deferred attempts release their descriptors. */
static std::atomic<BootstrapWorkerCapsule *> g_bootstrap_worker{nullptr};
static size_t g_bootstrap_worker_attempts = 0;
static bool bootstrap_worker_live() {
    auto *capsule = g_bootstrap_worker.load(std::memory_order_acquire);
    return capsule && !capsule->finished.load(std::memory_order_acquire);
}

static pthread_mutex_t g_pipe_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_downlink_mutex = PTHREAD_MUTEX_INITIALIZER;
static StateRpcSerialization g_state_rpc_serialization;
static const size_t MAX_DESIRED_DOCUMENT_BYTES = (size_t)60U * 1024U;
static DownlinkFramer g_downlink_framer(MAX_DESIRED_DOCUMENT_BYTES + 128);
static DownlinkSnapshots g_downlink_snapshots(MAX_DESIRED_DOCUMENT_BYTES);
static std::atomic<uint32_t> g_downlink_transport_epoch{0};

// Caller holds g_pipe_mutex, including while the bootstrap status is fragmented.
static bool bootstrap_status_owns_stream() {
    auto *worker = g_bootstrap_worker.load(std::memory_order_acquire);
    return worker && worker->gate.phase() == BootstrapWorkerPhase::Publishing
           && worker->pending_status.partial();
}

// All callers hold g_pipe_mutex. Never splice bytes into a partial E or S.

static ssize_t write_uplink_record(const void *bytes, size_t size) {
    if (bootstrap_status_owns_stream()) {
        errno = EAGAIN; return -1;
    }
    g_event_uplink.bind(g_agent_log_fd,
                        g_downlink_transport_epoch.load(std::memory_order_acquire));
    return g_event_uplink.write_other(bytes, size, [](const void *record, size_t length) {
        return sigpipe_safe_write(g_agent_log_fd, record, length);
    });
}

static void service_event_uplink() {
    pthread_mutex_lock(&g_pipe_mutex);
    if (bootstrap_status_owns_stream()) {
        pthread_mutex_unlock(&g_pipe_mutex); return;
    }
    g_event_uplink.bind(g_agent_log_fd,
                        g_downlink_transport_epoch.load(std::memory_order_acquire));
    if (!g_event_uplink.flush([](const char *bytes, size_t size) {
        return sigpipe_safe_write(g_agent_log_fd, bytes, size);
    })) {
        if (g_agent_log_fd >= 0) {
            close(g_agent_log_fd);
        }
        g_agent_log_fd = -1;
    }
    pthread_mutex_unlock(&g_pipe_mutex);
}
static std::atomic<bool> g_vehicle_transport_live{false};
static pthread_mutex_t g_owned_intent_mutex = PTHREAD_MUTEX_INITIALIZER;
static std::array<OwnedIntentLane, 2> g_owned_intents = {
    OwnedIntentLane(owned_intent_sources[0]), OwnedIntentLane(owned_intent_sources[1])
};
static bool owned_intents_pending() {
    for (const auto &lane : g_owned_intents) {
        if (lane.pending()) {
            return true;
        }
    }
    return false;
}
static std::atomic<bool> g_owned_intent_pending{false};
static std::atomic<int> g_owned_intent_wake_fd{-1};
static void service_owned_intent();
static void abandon_owned_intent(uint32_t epoch, const char *reason);

/* ---- downlink desired-state watcher ----
 *
 * Daemon live updates arrive as D|desired and A|ack frames on the downlink
 * (g_state_reply_fd). RPC paths drain that fd on demand and only while they
 * hold g_downlink_mutex; without a resident drain a pushed document would sit
 * in the pipe unapplied forever (the daemon then treats the target as
 * un-acked until its next natural restart). This watcher is the resident
 * drain: it polls the fd, consumes D/A frames under g_downlink_mutex (it can
 * never steal an R/Q RPC reply — those are only sent while the RPC owner
 * holds the same mutex), and hands each NEW desired document to
 * AgentEntry.applyDesiredSnapshot on the dex classloader. Best effort: one
 * detached thread, never touches the guard state, failures only log. */
static std::atomic<bool> g_downlink_watch_started{false};
static JavaVM *g_downlink_watch_jvm = nullptr;
static jclass g_downlink_watch_entry_class = nullptr;
static jmethodID g_downlink_watch_apply_mid = nullptr;
static jmethodID g_downlink_watch_cache_mid = nullptr;
static jmethodID g_downlink_watch_page_mid = nullptr;
static jclass g_downlink_watch_cluster_class = nullptr;
static jmethodID g_downlink_watch_cluster_mid = nullptr;
static jmethodID g_downlink_watch_cluster_clear_mid = nullptr;
static jstring new_strict_utf8_string(JNIEnv *env, std::string_view value);

static void *downlink_watch_main(void * /*arg*/) {
    JavaVM *vm = g_downlink_watch_jvm;
    ScopedJniAttachment<JavaVM, JNIEnv> attachment(
        vm, JNI_OK, JNI_EDETACHED, JNI_VERSION_1_6, 0, nullptr);
    JNIEnv *env = attachment.env();
    if (!env || !g_downlink_watch_entry_class || !g_downlink_watch_apply_mid) {
        g_downlink_watch_started.store(false, std::memory_order_release);
        abandon_owned_intent(g_downlink_transport_epoch.load(std::memory_order_acquire),
                             "watcher-unavailable-before-receipt");
        const int wake = g_owned_intent_wake_fd.exchange(-1, std::memory_order_acq_rel);
        if (wake >= 0) {
            close(wake);
        }
        return nullptr;
    }
    IMPLANT_LOGD("downlink watcher attached");
    std::string last_pushed;
    std::string last_cluster;
    uint32_t last_cluster_epoch = 0;
    uint32_t observed_cluster_epoch = g_downlink_transport_epoch.load(std::memory_order_acquire);
    bool cluster_disconnected = false;
    std::string rejected_cluster;
    uint32_t rejected_cluster_epoch = 0;
    while (true) {
        service_event_uplink();
        service_owned_intent();
        /* Never hold g_downlink_mutex across poll(): an OEM main thread
         * blocked on this mutex during an RPC would ANR. Snapshot the fd,
         * sleep without the mutex, then take it only for the bounded drain.
         * The fd re-check under the mutex closes the close/rebind race. */
        pthread_mutex_lock(&g_downlink_mutex);
        int fd = g_state_reply_fd;
        pthread_mutex_unlock(&g_downlink_mutex);
        if (fd < 0) {
            struct timespec idle {0, 500L * 1000L * 1000L};
            nanosleep(&idle, nullptr);
            continue;
        }
        const int wake_fd = g_owned_intent_wake_fd.load(std::memory_order_acquire);
        struct pollfd polled[2] {{fd, POLLIN, 0}, {wake_fd, POLLIN, 0}};
        int rc = poll(polled, 2, g_owned_intent_pending.load(std::memory_order_acquire) ? 50 : 1000);
        if (polled[1].revents & POLLIN) {
            uint64_t wake;
            ssize_t drained = read(wake_fd, &wake, sizeof(wake));
            (void)drained;
            service_event_uplink();
            service_owned_intent();
        }
        const struct pollfd &poll_fd = polled[0];
        /* POLLHUP/POLLERR mean the daemon closed the transport: stop polling
         * this fd in a tight loop. The 1 s poll timeout alone never fires
         * while the fd reports volatile hangup/error events. Fall back to
         * the idle sleep until the rebind closes and replaces the fd. */
        std::string document;
        bool closed = false;
        uint32_t closed_epoch = 0;
        if (rc > 0 && poll_fd.revents) {
            pthread_mutex_lock(&g_downlink_mutex);
            if (g_state_reply_fd == fd) {
                closed = DownlinkWatchRead::drain(
                    fd, poll_fd.revents, g_downlink_framer, g_downlink_snapshots);
                if (closed) {
                    g_vehicle_transport_live.store(false, std::memory_order_release);
                    closed_epoch = g_downlink_transport_epoch.load(std::memory_order_acquire);
                }
            }
            /* The locked drain and the locked snapshot read below use the
             * same non-recursive mutex: the drain MUST release it here or
             * the very first POLLIN deadlocks the watcher when the "observe"
             * lock below re-enters it (and every later State.get RPC on any
             * Java thread then blocks on this orphaned hold forever). */
            pthread_mutex_unlock(&g_downlink_mutex);
        }
        /* Always observe the current buffered desired document under the
         * mutex — also when a concurrent RPC (State.get) already consumed
         * the D frame from the pipe: apply progress must not wait for the
         * next POLLIN frame that may never arrive. */
        pthread_mutex_lock(&g_downlink_mutex);
        document = g_downlink_snapshots.desired();
        pthread_mutex_unlock(&g_downlink_mutex);

        /* Upcall strictly outside g_downlink_mutex: the reconcile may wait
        * for the OEM main thread, which must never find the mutex held. */
        if (DownlinkWatchApply::needs_attempt(document, last_pushed)) {
            jstring jdoc = env->NewStringUTF(document.c_str());
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            if (jdoc) {
                jboolean accepted = env->CallStaticBooleanMethod(
                    g_downlink_watch_entry_class, g_downlink_watch_apply_mid, jdoc);
                bool exception = env->ExceptionCheck() != JNI_OK;
                if (exception) {
                    env->ExceptionClear();
                }
                env->DeleteLocalRef(jdoc);
                /* Only the accepted apply acknowledged the document: commit
                 * last_pushed after the call so an applyDesiredSnapshot
                 * answer of false (or a thrown exception) retries the same
                 * document on the next wakeup instead of being dropped. */
                if (DownlinkWatchApply::acknowledged(accepted, exception)) {
                    g_settings_loaded.accepted(
                        document, g_resident_generation, g_resident_catalog_sha256);
                    last_pushed = document;
                    IMPLANT_LOGD("downlink watcher applied desired document %zu bytes",
                                 document.size());
                } else {
                    pthread_mutex_lock(&g_downlink_mutex);
                    g_settings_loaded.rejected(document, g_downlink_snapshots.desired());
                    pthread_mutex_unlock(&g_downlink_mutex);
                    IMPLANT_LOGE("downlink watcher apply rejected/failed: %s",
                                 exception ? "exception" : "applyDesiredSnapshot false");
                }
            }
        }
        // K observations are independent of desired-state application and its ACK.
        // Keep rejected publications retryable, and replay after endpoint replacement.
        std::string cluster;
        pthread_mutex_lock(&g_downlink_mutex);
        uint32_t cluster_epoch = g_downlink_transport_epoch.load(std::memory_order_acquire);
        cluster = g_downlink_snapshots.cluster();
        pthread_mutex_unlock(&g_downlink_mutex);
        if (g_downlink_watch_cluster_class && g_downlink_watch_cluster_clear_mid
            && (cluster_epoch != observed_cluster_epoch || (closed && !cluster_disconnected))) {
            env->CallStaticVoidMethod(
                g_downlink_watch_cluster_class, g_downlink_watch_cluster_clear_mid);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            } else {
                observed_cluster_epoch = cluster_epoch;
                cluster_disconnected = closed;
                last_cluster.clear();
                rejected_cluster.clear();
            }
        }
        if (g_downlink_watch_cluster_class && g_downlink_watch_cluster_mid
            && g_downlink_watch_cluster_clear_mid && observed_cluster_epoch == cluster_epoch
            && !cluster_disconnected && !closed && !cluster.empty()
            && (cluster != last_cluster || cluster_epoch != last_cluster_epoch)) {
            jstring snapshot = new_strict_utf8_string(env, cluster);
            if (snapshot) {
                jboolean accepted = env->CallStaticBooleanMethod(
                    g_downlink_watch_cluster_class, g_downlink_watch_cluster_mid, snapshot);
                bool exception = env->ExceptionCheck() != JNI_OK;
                if (exception) env->ExceptionClear();
                env->DeleteLocalRef(snapshot);
                if (accepted && !exception
                    && cluster_epoch == g_downlink_transport_epoch.load(std::memory_order_acquire)) {
                    last_cluster = cluster;
                    last_cluster_epoch = cluster_epoch;
                    cluster_disconnected = false;
                    rejected_cluster.clear();
                    IMPLANT_LOGD("downlink watcher published cluster snapshot %zu bytes", cluster.size());
                } else if (cluster != rejected_cluster || cluster_epoch != rejected_cluster_epoch) {
                    IMPLANT_LOGE("downlink watcher cluster publication rejected/failed");
                    rejected_cluster = cluster;
                    rejected_cluster_epoch = cluster_epoch;
                }
            } else if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
        }
        std::string page_command;
        pthread_mutex_lock(&g_downlink_mutex);
        uint32_t page_epoch = g_downlink_transport_epoch.load(std::memory_order_acquire);
        page_command = g_downlink_snapshots.page_command();
        pthread_mutex_unlock(&g_downlink_mutex);
        if (g_downlink_watch_page_mid && !page_command.empty()) {
            jstring command = env->NewStringUTF(page_command.c_str());
            jstring result = command ? static_cast<jstring>(env->CallStaticObjectMethod(
                                                                g_downlink_watch_entry_class, g_downlink_watch_page_mid, command)) : nullptr;
            bool exception = env->ExceptionCheck();
            if (exception) {
                env->ExceptionClear();
            }
            if (result && !exception) {
                const jchar *bytes = env->GetStringChars(result, nullptr);
                if (bytes) {
                    std::string response;
                    jsize length = env->GetStringLength(result);
                    for (jsize index = 0; index < length && response.size() <= 16 * 1024; ++index) {
                        if (bytes[index] <= 0x7f) {
                            response.push_back(static_cast<char>(bytes[index]));
                        }else {
                            char escaped[7];
                            snprintf(escaped, sizeof(escaped), "\\u%04x", static_cast<unsigned int>(bytes[index]));
                            response += escaped;
                        }
                    }
                    env->ReleaseStringChars(result, bytes);
                    if (response.size() <= 16 * 1024 && response.find('\n') == std::string::npos) {
                        std::string frame = "P|" + response + "\n";
                        pthread_mutex_lock(&g_pipe_mutex);
                        pthread_mutex_lock(&g_downlink_mutex);
                        bool current = page_epoch == g_downlink_transport_epoch.load(std::memory_order_acquire)
                                       && page_command == g_downlink_snapshots.page_command();
                        pthread_mutex_unlock(&g_downlink_mutex);
                        bool sent = false;
                        if (current && !g_event_uplink.pending()) {
                            struct timespec started {};
                            clock_gettime(CLOCK_MONOTONIC, &started);
                            size_t offset = 0;
                            while (offset < frame.size()) {
                                struct timespec now {};
                                clock_gettime(CLOCK_MONOTONIC, &now);
                                int64_t elapsed = (now.tv_sec - started.tv_sec) * 1000
                                                  + (now.tv_nsec - started.tv_nsec) / 1000000;
                                if (elapsed >= 100) {
                                    break;
                                }
                                struct pollfd writable {g_agent_log_fd, POLLOUT, 0};
                                if (poll(&writable, 1, static_cast<int>(100 - elapsed)) <= 0) {
                                    break;
                                }
                                ssize_t count = write_uplink_record(frame.data() + offset, frame.size() - offset);
                                if (count < 0 && (errno == EAGAIN || errno == EINTR)) {
                                    continue;
                                }
                                if (count <= 0) {
                                    break;
                                }
                                offset += static_cast<size_t>(count);
                            }
                            sent = offset == frame.size();
                            if (!sent && offset > 0) {
                                close(g_agent_log_fd);
                                g_agent_log_fd = -1;
                            }
                        }
                        pthread_mutex_unlock(&g_pipe_mutex);
                        if (sent) {
                            pthread_mutex_lock(&g_downlink_mutex);
                            g_downlink_snapshots.acknowledge_page_command(page_command);
                            pthread_mutex_unlock(&g_downlink_mutex);
                        }
                    }
                }
            }
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            if (result) {
                env->DeleteLocalRef(result);
            }
            if (command) {
                env->DeleteLocalRef(command);
            }
        }
        std::string cache_command;
        pthread_mutex_lock(&g_downlink_mutex);
        uint64_t cache_epoch = g_downlink_transport_epoch.load(std::memory_order_acquire);
        cache_command = g_downlink_snapshots.cache_command();
        pthread_mutex_unlock(&g_downlink_mutex);
        if (g_downlink_watch_cache_mid && CacheQuiescenceAck::may_apply(
                cache_epoch, g_downlink_transport_epoch.load(std::memory_order_acquire), cache_command)) {
            jstring command = env->NewStringUTF(cache_command.c_str());
            if (command) {
                jboolean accepted = env->CallStaticBooleanMethod(
                    g_downlink_watch_entry_class, g_downlink_watch_cache_mid, command);
                bool exception = env->ExceptionCheck() != JNI_OK;
                if (exception) {
                    env->ExceptionClear();
                }
                env->DeleteLocalRef(command);
                if (accepted && !exception) {
                    std::string ack = "C|" + cache_command + "\n";
                    pthread_mutex_lock(&g_pipe_mutex);
                    pthread_mutex_lock(&g_downlink_mutex);
                    bool current = CacheQuiescenceAck::may_ack(accepted, exception,
                                                               cache_epoch, g_downlink_transport_epoch.load(std::memory_order_acquire),
                                                               cache_command, g_downlink_snapshots.cache_command());
                    pthread_mutex_unlock(&g_downlink_mutex);
                    ssize_t sent = current ? write_uplink_record(ack.data(), ack.size()) : -1;
                    pthread_mutex_unlock(&g_pipe_mutex);
                    if (sent == static_cast<ssize_t>(ack.size())) {
                        pthread_mutex_lock(&g_downlink_mutex);
                        g_downlink_snapshots.acknowledge_cache_command(cache_command);
                        pthread_mutex_unlock(&g_downlink_mutex);
                    }
                }
            } else if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
        }
        if (closed) {
            service_owned_intent(); // Consume a final exact receipt before declaring uncertainty.
            abandon_owned_intent(closed_epoch, "endpoint-closed-before-receipt");
            struct timespec idle {0, 500L * 1000L * 1000L};
            nanosleep(&idle, nullptr);
        }
    }
    return nullptr;
}

static void prepare_downlink_watch(JNIEnv *env, jclass entryClass, jobject loader) {
    bool expected = false;
    if (!g_downlink_watch_started.compare_exchange_strong(expected, true)) {
        return;
    }
    if (env->GetJavaVM(&g_downlink_watch_jvm) != JNI_OK) {
        g_downlink_watch_started.store(false);
        return;
    }
    g_downlink_watch_entry_class =
        (jclass)env->NewGlobalRef(entryClass);
    g_downlink_watch_apply_mid = env->GetStaticMethodID(
        entryClass, "applyDesiredSnapshot", "(Ljava/lang/String;)Z");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    g_downlink_watch_page_mid = env->GetStaticMethodID(
        entryClass, "observeLauncherPage", "(Ljava/lang/String;)Ljava/lang/String;");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    g_downlink_watch_cache_mid = env->GetStaticMethodID(
        entryClass, "quiesceLauncherIconCache", "(Ljava/lang/String;)Z");
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    // Resolve on the admitted common loader, never the watcher thread's FindClass context.
    jclass loader_class = env->GetObjectClass(loader);
    jmethodID load_class = loader_class ? env->GetMethodID(
        loader_class, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jstring cluster_name = load_class
        ? env->NewStringUTF("ru.voboost.agents.AgentClusterState") : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    jclass cluster_class = load_class && cluster_name ? static_cast<jclass>(
        env->CallObjectMethod(loader, load_class, cluster_name)) : nullptr;
    if (env->ExceptionCheck()) env->ExceptionClear();
    if (cluster_class) {
        g_downlink_watch_cluster_class = static_cast<jclass>(env->NewGlobalRef(cluster_class));
        if (env->ExceptionCheck()) env->ExceptionClear();
        g_downlink_watch_cluster_mid = g_downlink_watch_cluster_class ? env->GetStaticMethodID(
            cluster_class, "publishSnapshot", "(Ljava/lang/String;)Z") : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        g_downlink_watch_cluster_clear_mid = g_downlink_watch_cluster_class ? env->GetStaticMethodID(
            cluster_class, "clear", "()V") : nullptr;
        if (env->ExceptionCheck()) env->ExceptionClear();
        env->DeleteLocalRef(cluster_class);
    }
    if (cluster_name) env->DeleteLocalRef(cluster_name);
    if (loader_class) env->DeleteLocalRef(loader_class);
    if (!g_downlink_watch_cluster_class || !g_downlink_watch_cluster_mid
        || !g_downlink_watch_cluster_clear_mid) {
        IMPLANT_LOGE("downlink watcher cluster publication seam unavailable");
    }
    if (!g_downlink_watch_entry_class || !g_downlink_watch_apply_mid) {
        IMPLANT_LOGE("downlink watcher seam unavailable");
        g_downlink_watch_started.store(false);
        return;
    }
}

static void launch_downlink_watch() {
    if (!g_downlink_watch_started.load() || !g_downlink_watch_jvm
        || !g_downlink_watch_entry_class || !g_downlink_watch_apply_mid) {
        return;
    }
    const int wake_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (wake_fd < 0) {
        IMPLANT_LOGE("downlink watcher wake descriptor failed");
        g_downlink_watch_started.store(false);
        return;
    }
    g_owned_intent_wake_fd.store(wake_fd, std::memory_order_release);
    pthread_t thread;
    if (pthread_create(&thread, nullptr, downlink_watch_main, nullptr) != 0) {
        g_owned_intent_wake_fd.store(-1, std::memory_order_release);
        close(wake_fd);
        IMPLANT_LOGE("downlink watcher thread create failed");
        g_downlink_watch_started.store(false);
        return;
    }
    pthread_detach(thread);
    IMPLANT_LOGD("downlink watcher started");
}

static jstring new_strict_utf8_string(JNIEnv *env, std::string_view value) {
    std::vector<uint16_t> utf16;
    if (!strict_utf8_to_utf16(value, &utf16)) {
        return nullptr;
    }
    const jchar *characters = reinterpret_cast<const jchar *>(utf16.data());
    jstring result = env->NewString(characters, static_cast<jsize>(utf16.size()));
    if (!result && env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    return result;
}

static void close_bootstrap_storage() {
    g_bootstrap_fds.discard_staged();
    g_pipe_bootstrap = PipeBootstrapEnvelope{};
    g_pipe_bootstrap_ready = false;
}

static void reset_pre_resident_bootstrap() {
    g_vehicle_transport_live.store(false, std::memory_order_release);
    close_bootstrap_storage();
    g_pipe_bootstrap_channel_ready = false;
    g_resident_generation.clear();
    g_resident_catalog_sha256.clear();
    g_settings_loaded.reset();
    pthread_mutex_lock(&g_pipe_mutex);
    g_log_transport.abandon_pending();
    g_event_uplink.reset();
    pthread_mutex_unlock(&g_pipe_mutex);
    for (int *fd : {&g_agent_log_read_fd, &g_agent_log_fd,
                    &g_state_reply_fd, &g_state_reply_write_fd}) {
        if (*fd >= 0) {
            close(*fd);
            *fd = -1;
        }
    }
    g_initialized.store(false, std::memory_order_release);
    g_resident_ready.store(false, std::memory_order_release);
}

static void vbi_fail_log(int line) {
    IMPLANT_LOGE("IMPLANT_INIT_FAILED at line %d", line);
}
static int fail_bootstrap_attempt(int result) {
    /* Phase two is transactional.  Once loading fails, no endpoint, staged
     * memfd, envelope byte, generation identity, or initialization guard from
     * this attempt may survive.  The daemon can start a complete fresh phase
     * one on the same live process. */
    if (result == IMPLANT_INIT_DEFERRED) {
        IMPLANT_LOGD("bootstrap deferred result=%d", result);
    } else {
        IMPLANT_LOGE("fail_bootstrap_attempt result=%d", result);
    }
    reset_pre_resident_bootstrap();
    return result;
}

static bool create_pipe_pair(int fds[2]) {
#if defined(__linux__)
    if (pipe2(fds, O_CLOEXEC) != 0) {
        return false;
    }
    /* Increase the pipe buffer to 1MB so burst logging during contract
     * selection (80+ records in <40ms) does not overflow the default 64KB
     * pipe and silently drop status/log records before the daemon drains. */
    fcntl(fds[0], F_SETPIPE_SZ, 1024 * 1024);
    fcntl(fds[1], F_SETPIPE_SZ, 1024 * 1024);
    return true;
#else
    if (pipe(fds) != 0) {
        return false;
    }
    fcntl(fds[0], F_SETFD, FD_CLOEXEC);
    fcntl(fds[1], F_SETFD, FD_CLOEXEC);
    return true;
#endif
}

static bool replace_daemon_pipes_for_rebind() {
    int records[2] = {-1, -1};
    int replies[2] = {-1, -1};
    if (!create_pipe_pair(records) || !create_pipe_pair(replies)) {
        if (records[0] >= 0) {
            close(records[0]);
        }
        if (records[1] >= 0) {
            close(records[1]);
        }
        if (replies[0] >= 0) {
            close(replies[0]);
        }
        if (replies[1] >= 0) {
            close(replies[1]);
        }
        return false;
    }
    int flags = fcntl(records[1], F_GETFL, 0);
    bool records_nonblocking =
        flags >= 0 && fcntl(records[1], F_SETFL, flags | O_NONBLOCK) == 0;
    flags = fcntl(replies[0], F_GETFL, 0);
    bool replies_nonblocking =
        flags >= 0 && fcntl(replies[0], F_SETFL, flags | O_NONBLOCK) == 0;
    if (!records_nonblocking || !replies_nonblocking) {
        close(records[0]);
        close(records[1]);
        close(replies[0]);
        close(replies[1]);
        return false;
    }
    char identity[192];
    int length = snprintf(identity, sizeof(identity), "B|%s|%s|%d|%lld\n",
                          g_resident_generation.c_str(),
                          g_resident_catalog_sha256.c_str(),
                          g_settings_loaded.loaded() ? 1 : 0,
                          static_cast<long long>(g_settings_loaded.document_generation()));
    if (length <= 0 || length >= static_cast<int>(sizeof(identity)) ||
        sigpipe_safe_write(records[1], identity,
                           static_cast<size_t>(length)) != length) {
        close(records[0]);
        close(records[1]);
        close(replies[0]);
        close(replies[1]);
        return false;
    }

    pthread_mutex_lock(&g_pipe_mutex);
    pthread_mutex_lock(&g_downlink_mutex);
    if (g_agent_log_fd >= 0) {
        close(g_agent_log_fd);
    }
    if (g_agent_log_read_fd >= 0) {
        close(g_agent_log_read_fd);
    }
    if (g_state_reply_fd >= 0) {
        close(g_state_reply_fd);
    }
    if (g_state_reply_write_fd >= 0) {
        close(g_state_reply_write_fd);
    }
    g_vehicle_transport_live.store(false, std::memory_order_release);
    g_downlink_transport_epoch.fetch_add(1, std::memory_order_acq_rel);
    g_downlink_framer.reset();
    g_downlink_snapshots.reset();
    g_log_transport.abandon_pending();
    g_event_uplink.reset();
    g_agent_log_read_fd = records[0];
    g_agent_log_fd = records[1];
    g_state_reply_fd = replies[0];
    g_state_reply_write_fd = replies[1];
    flush_early_native_logs_locked();
    pthread_mutex_unlock(&g_downlink_mutex);
    pthread_mutex_unlock(&g_pipe_mutex);
    const int wake_fd = g_owned_intent_wake_fd.load(std::memory_order_acquire);
    if (wake_fd >= 0) {
        const uint64_t wake = 1;
        ssize_t sent = write(wake_fd, &wake, sizeof(wake));
        (void)sent;
    }
    return true;
}

/* Downlink frames share one framer and target-local snapshot store. D is an
 * ordinary desired-state update; only correlated A can confirm a Settings
 * mutation. Both are guarded by g_downlink_mutex so they cannot race a
 * State.get RPC on the same fd. */
static void consume_downlink_line(JNIEnv *env, const std::string &line,
                                  bool expect_reply, unsigned long long request_id,
                                  jstring *result, bool *matched,
                                  std::string *status = nullptr) {
    if (line.rfind("D|", 0) == 0 || line.rfind("A|", 0) == 0
        || line.rfind("C|", 0) == 0 || line.rfind("P|", 0) == 0
        || line.rfind("I|", 0) == 0 || line.rfind("K|", 0) == 0 || line.rfind("V|", 0) == 0
        || line.rfind("U|", 0) == 0) {
        g_downlink_snapshots.consume(line);
        return;
    }
    if (!expect_reply) {
        return;
    }
    /* Shared reply decoding keeps native bridge and host behavior identical. */
    state_reply::Reply reply = state_reply::parse_reply_line(line, request_id);
    if (!reply.matched) {
        return;
    }
    *matched = true;
    if (status != nullptr) {
        *status = reply.status;
    }
    if (reply.status == "ok") {
        *result = new_strict_utf8_string(env, reply.value);
    }
}

/* Serializes pipe writes so concurrent JNI calls (Log/State/Events on different
 * threads) never interleave bytes within a record. write(2) is only atomic up
 * to PIPE_BUF; a formatted record can exceed it, so the mutex keeps the whole
 * line contiguous regardless of size. */
/* Guards reads of the downlink fd and the target-local snapshot store:
 * State.get RPC waits and takeMutationAck drains the same stream.
 * Kept separate from g_pipe_mutex so a slow RPC reply never blocks uplink
 * writes (Log/State.set/Events) from other Java threads. */

static bool is_safe_state_token(const char *value, size_t max_bytes) {
    if (!value) {
        return false;
    }
    size_t length = strlen(value);
    if (length == 0 || length > max_bytes) {
        return false;
    }
    for (size_t i = 0; i < length; i++) {
        unsigned char byte = (unsigned char)value[i];
        bool alphanumeric = (byte >= '0' && byte <= '9') ||
                            (byte >= 'A' && byte <= 'Z') ||
                            (byte >= 'a' && byte <= 'z');
        if (!(alphanumeric || byte == '-' || byte == '_')) {
            return false;
        }
    }
    return true;
}

/* Caller holds g_pipe_mutex. Transfer ownership to the bounded LogTransport,
 * which retains errors on EAGAIN and reports its own overflow. */
static void flush_early_native_logs_locked() {
    if (g_agent_log_fd < 0) return;
    auto writer = [](const char *record, size_t size) {
        return write_uplink_record(record, size) == static_cast<ssize_t>(size);
    };
    for (size_t i = 0; i < g_early_native_count; ++i) {
        const auto &record = g_early_native_logs[i];
        g_log_transport.submit(1, record.timestamp, record.bytes, record.size, writer);
    }
    g_early_native_count = 0;
    if (g_early_native_dropped) {
        char message[128], record[256];
        snprintf(message, sizeof(message), "early.native.errors.dropped count=%llu",
                 static_cast<unsigned long long>(g_early_native_dropped));
        int n = format_pipe_record(record, sizeof(record), 'L', 0, "implant", "1", message);
        if (n > 0) g_log_transport.submit(1, 0, record, static_cast<size_t>(n), writer);
        g_early_native_dropped = 0;
    }
}

/* Build and atomically write one typed record:
 *   <type>|<ts_ms>|<source>|<field3>|<field4>\n
 * The trailing field is appended byte-by-byte with '\n' → '\r' rewriting. The
 * whole write is under g_pipe_mutex so records from other threads do not
 * interleave. fd < 0 / null args → silent no-op. */
static void write_status_record(long long ts_ms, const char *source, const char *document) {
    char buf[StatusUplink::max_record];
    int n = format_status_record(buf, sizeof(buf), ts_ms, source, document);
    if (n < 0) {
        IMPLANT_LOGE("status snapshot rejected at 64KiB JSON bound: documentBytes=%zu",
                     document ? strnlen(document, StatusUplink::max_document + 1) : 0);
        return;
    }
    int status_error = 0;
    pthread_mutex_lock(&g_pipe_mutex);
    if (g_agent_log_fd < 0) {
        pthread_mutex_unlock(&g_pipe_mutex); return;
    }
    auto *worker = g_bootstrap_worker.load(std::memory_order_acquire);
    if (worker && worker->gate.phase() != BootstrapWorkerPhase::Ready) {
        if (worker->gate.phase() == BootstrapWorkerPhase::Running
            || worker->gate.phase() == BootstrapWorkerPhase::Completed
            || worker->gate.phase() == BootstrapWorkerPhase::Publishing) {
            worker->pending_status.submit(buf, static_cast<size_t>(n));
        }
        pthread_mutex_unlock(&g_pipe_mutex);
        return;
    }
    g_event_uplink.bind(g_agent_log_fd,
                        g_downlink_transport_epoch.load(std::memory_order_acquire));
    ssize_t admitted = g_event_uplink.write_status(buf, static_cast<size_t>(n),
                                                   [](const void *record, size_t size) {
        return sigpipe_safe_write(g_agent_log_fd, record, size);
    });
    if (admitted < 0) {
        status_error = errno;
        if (g_agent_log_fd >= 0) {
            close(g_agent_log_fd);
        }
        g_agent_log_fd = -1;
    }
    pthread_mutex_unlock(&g_pipe_mutex);
    if (status_error) {
        IMPLANT_LOGE("status snapshot send failed: bytes=%d errno=%d", n, status_error);
    }
}

static void write_pipe_record(char type, long long ts_ms, const char *source,
                              const char *field3, const char *field4) {
    if (!source || !field3 || !field4) {
        return;
    }
    if (type == 'S') {
        write_status_record(ts_ms, source, field4); return;
    }
    char buf[4096];
    int n = format_pipe_record(buf, sizeof(buf), type, ts_ms, source, field3, field4);
    if (n < 0) {
        return;
    }
    pthread_mutex_lock(&g_pipe_mutex);
    if (g_agent_log_fd < 0) {
        if (type == 'L' && field3[0] == '1') {
            if (g_early_native_count < 8) {
                auto &pending = g_early_native_logs[g_early_native_count++];
                memcpy(pending.bytes, buf, static_cast<size_t>(n));
                pending.size = static_cast<size_t>(n);
                pending.timestamp = ts_ms;
            } else if (g_early_native_dropped != UINT64_MAX) {
                ++g_early_native_dropped;
            }
        }
        pthread_mutex_unlock(&g_pipe_mutex);
        return;
    }
    flush_early_native_logs_locked();
    if (type == 'L') {
        g_log_transport.submit(field3[0] - '0', ts_ms, buf, static_cast<size_t>(n),
                               [](const char *record, size_t size) {
            return write_uplink_record(record, size) == static_cast<ssize_t>(size);
        });
    } else {
        ssize_t written = write_uplink_record(buf, static_cast<size_t>(n));
        (void)written;
    }
    pthread_mutex_unlock(&g_pipe_mutex);
}

// Process-owned retry work survives Java logical-agent close. Never waits for
// daemon acknowledgement on an OEM UI thread. The watcher owns all pipe IO.
static uint64_t owned_intent_now_ns() {
    struct timespec now {};
    if (clock_gettime(CLOCK_BOOTTIME, &now) != 0) {
        return 0;
    }
    return static_cast<uint64_t>(now.tv_sec) * 1000000000 + now.tv_nsec;
}
static void service_owned_intent_slot(size_t index) {
    pthread_mutex_lock(&g_owned_intent_mutex);
    OwnedIntentLane work = g_owned_intents[index];
    pthread_mutex_unlock(&g_owned_intent_mutex);
    if (!work.pending()) {
        return;
    }
    char diagnostic[320] = {};
    int level = 2;
    pthread_mutex_lock(&g_pipe_mutex);
    const uint32_t epoch = g_downlink_transport_epoch.load(std::memory_order_acquire);
    bool lost = work.abandon(epoch);
    if (!lost && g_agent_log_fd < 0) {
        lost = work.abandon(epoch + 1);
    }
    if (lost) {
        level = 1;
        snprintf(diagnostic, sizeof(diagnostic),
                 "intent handoff uncertain source=%s request=%llu reason=endpoint-teardown-before-receipt",
                 work.source().c_str(), static_cast<unsigned long long>(work.request()));
    } else {
        pthread_mutex_lock(&g_downlink_mutex);
        const auto receipt = work.confirm(g_downlink_snapshots.owned_intent_receipt(work.source()));
        pthread_mutex_unlock(&g_downlink_mutex);
        if (receipt != OwnedIntentLane::Receipt::None) {
            snprintf(diagnostic, sizeof(diagnostic),
                     "intent handoff %s source=%s request=%llu choice=%s captureBootNs=%llu receiptBootNs=%llu",
                     receipt == OwnedIntentLane::Receipt::Committed ? "root-committed" : "superseded",
                     work.source().c_str(),
                     static_cast<unsigned long long>(work.request()), work.choice().c_str(),
                     static_cast<unsigned long long>(work.capture_ns()),
                     static_cast<unsigned long long>(owned_intent_now_ns()));
        } else {
            const std::string record = work.record();
            ssize_t written = write_uplink_record(record.data(), record.size());
            if (written == static_cast<ssize_t>(record.size()) && work.mark_delivered()) {
                snprintf(diagnostic, sizeof(diagnostic),
                         "intent handoff pending-first-delivery source=%s request=%llu choice=%s captureBootNs=%llu deliveryBootNs=%llu",
                         work.source().c_str(),
                         static_cast<unsigned long long>(work.request()), work.choice().c_str(),
                         static_cast<unsigned long long>(work.capture_ns()),
                         static_cast<unsigned long long>(owned_intent_now_ns()));
            }
        }
    }
    pthread_mutex_unlock(&g_pipe_mutex);
    pthread_mutex_lock(&g_owned_intent_mutex);
    // A newer input may supersede this copy while IO is in progress.
    if (g_owned_intents[index].same(work)) {
        g_owned_intents[index] = work;
    }
    g_owned_intent_pending.store(owned_intents_pending(), std::memory_order_release);
    pthread_mutex_unlock(&g_owned_intent_mutex);
    if (diagnostic[0]) {
        implant_log(level, "%s", diagnostic);
    }
}

static void service_owned_intent() {
    for (size_t index = 0; index < g_owned_intents.size(); ++index) {
        service_owned_intent_slot(index);
    }
}

static void abandon_owned_intent(uint32_t epoch, const char *reason) {
    std::array<uint64_t, 2> abandoned{};
    pthread_mutex_lock(&g_owned_intent_mutex);
    for (size_t index = 0; index < g_owned_intents.size(); ++index) {
        auto &lane = g_owned_intents[index];
        if (lane.pending() && lane.epoch() == epoch) {
            abandoned[index] = lane.request();
            lane.abandon(epoch + 1);
        }
    }
    g_owned_intent_pending.store(owned_intents_pending(), std::memory_order_release);
    pthread_mutex_unlock(&g_owned_intent_mutex);
    for (size_t index = 0; index < abandoned.size(); ++index) {
        if (abandoned[index]) {
            IMPLANT_LOGE("intent handoff uncertain source=%s request=%llu reason=%s",
                         owned_intent_sources[index],
                         static_cast<unsigned long long>(abandoned[index]), reason);
        }
    }
}

/* Missing stages are unavailable evidence, not proof a stage was not reached.
 * A later writable callback reports the dropped observation explicitly. */
static void log_hook_stage(const char *stage, uint64_t elapsed) noexcept {
    static thread_local bool unavailable = false;
    struct timespec now {};
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        unavailable = true;
        return;
    }
    long long timestamp = static_cast<long long>(now.tv_sec) * 1000LL
                          + now.tv_nsec / 1000000LL;
    int pid = getpid();
    long tid = syscall(SYS_gettid);
    if (unavailable) {
        if (!write_hook_stage_record(g_agent_log_fd, &g_pipe_mutex, timestamp,
                                     "unavailable", pid, tid, elapsed,
                                     [](int, const void *bytes, size_t size) {
            return write_uplink_record(bytes, size);
        })) {
            return;
        }
        unavailable = false;
    }
    unavailable = !write_hook_stage_record(g_agent_log_fd, &g_pipe_mutex, timestamp,
                                           stage, pid, tid, elapsed,
                                           [](int, const void *bytes, size_t size) {
        return write_uplink_record(bytes, size);
    });
}

/* Log record: L|<ts_ms>|<source>|<level>|<message>. level is validated here so
 * internal implant_log calls and the JNI log() share one gate. */
static void write_log_record(long long ts_ms, int level, const char *source,
                             const char *message) {
    if (level < 1 || level > 3 || !source || !message) {
        return;
    }
    char lvl[4];
    snprintf(lvl, sizeof(lvl), "%d", level);
    write_pipe_record('L', ts_ms, source, lvl, message);
}

static void implant_log(int level, const char *format, ...) {
    char message[3072];
    va_list args;
    va_start(args, format);
    int n = vsnprintf(message, sizeof(message), format, args);
    va_end(args);
    if (n < 0) {
        return;
    }

    struct timespec now {};
    if (clock_gettime(CLOCK_REALTIME, &now) != 0) {
        return;
    }
    long long ts_ms = (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000LL;
    write_log_record(ts_ms, level, "implant", message);
}

static void native_log_impl(JNIEnv *env, jclass, jlong ts_ms, jint level,
                            jstring source, jstring message) {
    if (g_agent_log_fd < 0) {
        return;                              /* pipe unavailable — silent */
    }
    if (level < 1 || level > 3) {
        return;                               /* NONE(0) and garbage: skip */

    }
    if (!source || !message) {
        return;
    }
    const char *src = env->GetStringUTFChars(source, nullptr);
    if (!src) {
        env->ExceptionClear();
        return;
    }
    const char *msg = env->GetStringUTFChars(message, nullptr);
    if (!msg) {
        env->ExceptionClear();
        env->ReleaseStringUTFChars(source, src);
        return;
    }

    write_log_record((long long)ts_ms, (int)level, src, msg);

    env->ReleaseStringUTFChars(source, src);
    env->ReleaseStringUTFChars(message, msg);
}

/* ---- Java State bridge: set(long, String, String, String) ----
 *
 * ru.voboost.agents.State native method. Writes a State record into the same
 * pipe as Log. value is the trailing field, so embedded '\n' → '\r'
 * (write_pipe_record). fd < 0 → silent no-op.
 */
static void native_state_set_impl(JNIEnv *env, jclass, jlong ts_ms,
                                  jstring source, jstring key, jstring value) {
    if (g_agent_log_fd < 0 || !source || !key || !value) {
        return;
    }
    const char *src = env->GetStringUTFChars(source, nullptr);
    if (!src) {
        env->ExceptionClear();
        return;
    }
    const char *k = env->GetStringUTFChars(key, nullptr);
    if (!k) {
        env->ExceptionClear();
        env->ReleaseStringUTFChars(source, src);
        return;
    }
    const char *v = env->GetStringUTFChars(value, nullptr);
    if (!v) {
        env->ExceptionClear();
        env->ReleaseStringUTFChars(source, src);
        env->ReleaseStringUTFChars(key, k);
        return;
    }

    if (!is_safe_state_token(src, 64) || !is_safe_state_token(k, 96) ||
        strlen(v) > 4000) {
        env->ReleaseStringUTFChars(source, src);
        env->ReleaseStringUTFChars(key, k);
        env->ReleaseStringUTFChars(value, v);
        return;
    }

    write_pipe_record('W', (long long)ts_ms, src, k, v);

    env->ReleaseStringUTFChars(source, src);
    env->ReleaseStringUTFChars(key, k);
    env->ReleaseStringUTFChars(value, v);
}

/* ---- Java State bridge: get(String, String) ----
 *
 * Emits R|<request_id>|<source>|<key> on the typed record pipe and waits for
 * R|<request_id>|ok|<value> on the dedicated reply pipe. One mutex serializes
 * State.get with all record writes so replies cannot be consumed by another
 * Java thread. The 1500ms timeout covers more than one normal 500ms daemon
 * poll interval and fails closed without blocking the target indefinitely.
 */
static jstring native_state_request_impl(JNIEnv *env, jstring source,
                                         jstring key, jstring expected) {
    /* the downlink mutex is
     * held for the whole RPC window, and the UI thread's takeMutationAck
     * also takes it — so the wait must stay short. 500 ms bounds the ANR risk
     * (the daemon answers a state RPC in tens of ms; a longer wait indicates
     * a stuck daemon and the RPC returns null). A full mutex split is a
     * future refinement. */
    static const int STATE_READ_TIMEOUT_MS = 500;
    static const size_t MAX_SOURCE_BYTES = 64;
    static const size_t MAX_KEY_BYTES = 96;
    if (g_agent_log_fd < 0 || g_state_reply_fd < 0 || !source || !key) {
        return nullptr;
    }

    const char *src = env->GetStringUTFChars(source, nullptr);
    if (!src) {
        env->ExceptionClear();
        return nullptr;
    }
    const char *k = env->GetStringUTFChars(key, nullptr);
    if (!k) {
        env->ExceptionClear();
        env->ReleaseStringUTFChars(source, src);
        return nullptr;
    }
    if (!is_safe_state_token(src, MAX_SOURCE_BYTES) ||
        !is_safe_state_token(k, MAX_KEY_BYTES)) {
        env->ReleaseStringUTFChars(source, src);
        env->ReleaseStringUTFChars(key, k);
        return nullptr;
    }

    unsigned long long request_id =
        g_state_request_id.fetch_add(1, std::memory_order_relaxed);
    char request[512];
    int request_len;
    if (expected) {
        const char *value = env->GetStringUTFChars(expected, nullptr);
        if (!value) {
            env->ExceptionClear();
            env->ReleaseStringUTFChars(source, src);
            env->ReleaseStringUTFChars(key, k);
            return nullptr;
        }
        bool valid = value[0] != '\0' && strlen(value) <= 255;
        for (const unsigned char *p = reinterpret_cast<const unsigned char *>(value); valid && *p; ++p) {
            valid = (*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') ||
                    (*p >= '0' && *p <= '9') || *p == '_' || *p == '.';
        }
        request_len = valid ? snprintf(request, sizeof(request), "X|%llu|%s|%s|%s\n", request_id, src, k, value) : -1;
        env->ReleaseStringUTFChars(expected, value);
    } else {
        request_len = snprintf(request, sizeof(request), "R|%llu|%s|%s\n", request_id, src, k);
    }
    env->ReleaseStringUTFChars(source, src);
    env->ReleaseStringUTFChars(key, k);
    if (request_len <= 0 || request_len >= (int)sizeof(request)) {
        return nullptr;
    }

    StateRpcGuard rpc_guard(&g_state_rpc_serialization);
    /* Preserve the global pipe -> downlink lock order used by endpoint
     * replacement. The RPC gate prevents another State.get from holding the
     * pipe lock while waiting for this request's downlink window. */
    pthread_mutex_lock(&g_pipe_mutex);
    pthread_mutex_lock(&g_downlink_mutex);
    ssize_t written = write_uplink_record(request,
                                          (size_t)request_len);
    pthread_mutex_unlock(&g_pipe_mutex);
    if (written != request_len) {
        pthread_mutex_unlock(&g_downlink_mutex);
        return nullptr;
    }

    char response[8192];
    struct timespec started {};
    clock_gettime(CLOCK_MONOTONIC, &started);
    jstring result = nullptr;
    bool matched = false;
    while (!matched) {
        struct timespec now {};
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - started.tv_sec) * 1000L +
                          (now.tv_nsec - started.tv_nsec) / 1000000L;
        int remaining_ms = STATE_READ_TIMEOUT_MS - (int)elapsed_ms;
        if (remaining_ms <= 0) {
            break;
        }
        struct pollfd poll_fd {g_state_reply_fd, POLLIN, 0};
        int poll_rc = poll(&poll_fd, 1, remaining_ms);
        if (poll_rc <= 0 || !(poll_fd.revents & POLLIN)) {
            break;
        }
        ssize_t count = read(g_state_reply_fd, response, sizeof(response));
        if (count < 0) {
            /* EAGAIN/EWOULDBLOCK: poll reported POLLIN but the data raced away
             * (another reader, or non-blocking fd drained between poll and
             * read). Re-arm the loop and poll again instead of treating it as
             * EOF — the RPC must not abort on a transient retry. EINTR
             * likewise retries. */
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            break; /* hard error */
        }
        if (count == 0) {
            break; /* EOF */
        }
        g_downlink_framer.feed(response, static_cast<size_t>(count),
                               [&](const std::string &line) {
            consume_downlink_line(env, line, true, request_id,
                                  &result, &matched);
        });
    }

    pthread_mutex_unlock(&g_downlink_mutex);
    return result;
}

static jstring native_state_get_impl(JNIEnv *env, jclass, jstring source, jstring key) {
    return native_state_request_impl(env, source, key, nullptr);
}

static jboolean native_state_clear_if_impl(JNIEnv *env, jclass, jstring source, jstring key, jstring expected) {
    if (!expected) {
        return JNI_FALSE;
    }
    jstring result = native_state_request_impl(env, source, key, expected);
    if (!result) {
        return JNI_FALSE;
    }
    const char *value = env->GetStringUTFChars(result, nullptr);
    bool cleared = value && strcmp(value, "true") == 0;
    if (value) {
        env->ReleaseStringUTFChars(result, value);
    }else {
        env->ExceptionClear();
    }
    env->DeleteLocalRef(result);
    return cleared ? JNI_TRUE : JNI_FALSE;
}

/* ---- Java State bridge: getNativeDetailed(String, String) ----
*
* getNativeDetailed distinguishes an absent key from unavailable state service.
* This tagged read uses the same R| wire request and surfaces
* the daemon's status field:
*
*   "value|<value>" → VALUE   (daemon answered ok)
*   "absent|"       → ABSENT  (daemon answered missing: clean absence,
*                              including a not-yet-created state dir)
*   nullptr         → UNAVAILABLE (no pipe, unsafe tokens, write risk,
*                              read error status, bounded timeout)
*
* Unambiguous encoding: daemon state values are validated scalars and
* cannot contain '|'; the "value|"/"absent|" prefixes are not valid
* scalars either, so the tags cannot collide with real values. */
static jstring native_state_get_detailed_impl(JNIEnv *env, jclass,
                                              jstring source, jstring key) {
    if (g_agent_log_fd < 0 || g_state_reply_fd < 0 || !source || !key) {
        return nullptr;
    }

    const char *src = env->GetStringUTFChars(source, nullptr);
    if (!src) {
        env->ExceptionClear();
        return nullptr;
    }
    const char *k = env->GetStringUTFChars(key, nullptr);
    if (!k) {
        env->ExceptionClear();
        env->ReleaseStringUTFChars(source, src);
        return nullptr;
    }
    if (!is_safe_state_token(src, 64) || !is_safe_state_token(k, 96)) {
        env->ReleaseStringUTFChars(source, src);
        env->ReleaseStringUTFChars(key, k);
        return nullptr;
    }

    unsigned long long request_id =
        g_state_request_id.fetch_add(1, std::memory_order_relaxed);
    char request[256];
    int request_len = snprintf(request, sizeof(request), "R|%llu|%s|%s\n",
                               request_id, src, k);
    env->ReleaseStringUTFChars(source, src);
    env->ReleaseStringUTFChars(key, k);
    if (request_len <= 0 || request_len >= (int)sizeof(request)) {
        return nullptr;
    }

    StateRpcGuard rpc_guard(&g_state_rpc_serialization);
    pthread_mutex_lock(&g_pipe_mutex);
    pthread_mutex_lock(&g_downlink_mutex);
    ssize_t written = write_uplink_record(request,
                                         (size_t)request_len);
    pthread_mutex_unlock(&g_pipe_mutex);
    if (written != request_len) {
        pthread_mutex_unlock(&g_downlink_mutex);
        return nullptr;
    }

    static const int STATE_READ_TIMEOUT_MS = 500;
    char response[8192];
    struct timespec started {};
    clock_gettime(CLOCK_MONOTONIC, &started);
    jstring result = nullptr;
    bool matched = false;
    std::string reply_status;
    while (!matched) {
        struct timespec now {};
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed_ms = (now.tv_sec - started.tv_sec) * 1000L +
                          (now.tv_nsec - started.tv_nsec) / 1000000L;
        int remaining_ms = STATE_READ_TIMEOUT_MS - (int)elapsed_ms;
        if (remaining_ms <= 0) {
            break;
        }
        struct pollfd poll_fd {g_state_reply_fd, POLLIN, 0};
        int poll_rc = poll(&poll_fd, 1, remaining_ms);
        if (poll_rc <= 0 || !(poll_fd.revents & POLLIN)) {
            break;
        }
        ssize_t count = read(g_state_reply_fd, response, sizeof(response));
        if (count < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                continue;
            }
            break; /* hard error */
        }
        if (count == 0) {
            break; /* EOF */
        }
        g_downlink_framer.feed(response, static_cast<size_t>(count),
                               [&](const std::string &line) {
            consume_downlink_line(env, line, true, request_id,
                                  &result, &matched, &reply_status);
        });
    }
    pthread_mutex_unlock(&g_downlink_mutex);
    if (!matched) {
        return nullptr; /* bounded timeout / hard error: UNAVAILABLE */
    }
    if (reply_status == "ok") {
        const char *value = nullptr;
        if (result != nullptr) {
            value = env->GetStringUTFChars(result, nullptr);
            if (value == nullptr) {
                env->ExceptionClear();
                env->DeleteLocalRef(result);
                /* Failed materialization remains UNAVAILABLE, never empty VALUE. */
                result = nullptr;
            }
        }
        std::string contents = value != nullptr ? std::string(value) : std::string();
        if (value != nullptr) {
            env->ReleaseStringUTFChars(result, value);
            env->DeleteLocalRef(result);
        }
        std::string tagged =
            state_reply::tagged_reply(reply_status, value != nullptr, contents);
        if (tagged.empty()) {
            return nullptr;
        }
        return new_strict_utf8_string(env, tagged);
    }
    /* "missing", "error" and any unknown status: shared conversion —
     * missing → "absent|", everything else → UNAVAILABLE marker. */
    std::string tagged = state_reply::tagged_reply(reply_status, true, "");
    if (tagged.empty()) {
        return nullptr;
    }
    return new_strict_utf8_string(env, tagged);
}

/* Saved receipts (U) correlate exactly; applied snapshots (A) remain separately replayable. */
static jstring native_events_take_saved_impl(JNIEnv *env, jclass, jlong requested_id) {
    if (g_state_reply_fd < 0 || requested_id <= 0) {
        return nullptr;
    }
    pthread_mutex_lock(&g_downlink_mutex);
    DownlinkWatchRead::poll_and_drain(
        g_state_reply_fd, g_downlink_framer, g_downlink_snapshots);
    std::string saved;
    jstring result = nullptr;
    if (g_downlink_snapshots.take_saved(static_cast<uint64_t>(requested_id), &saved)) {
        result = new_strict_utf8_string(env, saved);
    }
    pthread_mutex_unlock(&g_downlink_mutex);
    return result;
}

static jstring native_events_take_mutation_ack_impl(JNIEnv *env, jclass,
                                                    jlong requested_id) {
    if (g_state_reply_fd < 0 || requested_id <= 0) {
        return nullptr;
    }
    pthread_mutex_lock(&g_downlink_mutex);
    DownlinkWatchRead::poll_and_drain(
        g_state_reply_fd, g_downlink_framer, g_downlink_snapshots);
    std::string confirmed;
    jstring result = nullptr;
    if (g_downlink_snapshots.take_mutation_ack(
            static_cast<uint64_t>(requested_id), &confirmed)) {
        result = new_strict_utf8_string(env, confirmed);
    }
    pthread_mutex_unlock(&g_downlink_mutex);
    return result;
}

// Local snapshots only. The downlink watcher or an existing state reader owns pipe IO.
static jstring native_vehicle_command(JNIEnv *env, jstring source, bool take) {
    try {
        if (!source || env->GetStringLength(source) > 96 ||
            !g_vehicle_transport_live.load(std::memory_order_acquire)) {
            return nullptr;
        }
        const auto release = [env, source](const char *value) {
                                 env->ReleaseStringUTFChars(source, value);
                             };
        const std::unique_ptr<const char, decltype(release)> name(
            env->GetStringUTFChars(source, nullptr), release);
        if (!name) {
            return nullptr;
        }
        std::string document = take ? g_downlink_snapshots.take_vehicle_command(name.get())
                                   : g_downlink_snapshots.peek_vehicle_command(name.get());
        if (!g_vehicle_transport_live.load(std::memory_order_acquire)) {
            return nullptr;
        }
        return document.empty() ? nullptr : new_strict_utf8_string(env, document);
    } catch (const std::bad_alloc &) {
        jclass failure = env->FindClass("java/lang/OutOfMemoryError");
        if (failure) {
            env->ThrowNew(failure, "vehicle command snapshot allocation failed");
            env->DeleteLocalRef(failure);
        }
        return nullptr;
    } catch (...) {
        IMPLANT_LOGE("vehicle command snapshot read failed");
        return nullptr;
    }
}
static jstring native_take_vehicle_command(JNIEnv *env, jclass, jstring source) {
    return native_vehicle_command(env, source, true);
}
static jstring native_peek_vehicle_command(JNIEnv *env, jclass, jstring source) {
    return native_vehicle_command(env, source, false);
}
static jlong native_vehicle_transport_epoch(JNIEnv *, jclass) {
    return g_vehicle_transport_live.load(std::memory_order_acquire)
           ? static_cast<jlong>(g_downlink_transport_epoch.load(std::memory_order_acquire)) : 0;
}

/* ---- Java Events bridge: emit(requestId, source, type, payload) ----
 *
 * ru.voboost.agents.Events native method. Writes an Events record into the same
 * pipe as Log. payload is the trailing field, so embedded '\n' → '\r'
 * (EventUplink). Success means queued only; rejection throws to the Java facade.
 */
static void native_events_emit_impl(JNIEnv *env, jclass, jlong request_id,
                                    jstring source, jstring type, jstring payload) {
    if (!source || !type || !payload) {
        jclass failure = env->FindClass("java/lang/IllegalArgumentException");
        if (failure) {
            env->ThrowNew(failure, "Missing event field");
            env->DeleteLocalRef(failure);
        }
        return;
    }
    const char *src = env->GetStringUTFChars(source, nullptr);
    if (!src) {
        return;
    }
    const char *t = env->GetStringUTFChars(type, nullptr);
    if (!t) {
        env->ReleaseStringUTFChars(source, src);
        return;
    }
    const char *p = env->GetStringUTFChars(payload, nullptr);
    if (!p) {
        env->ReleaseStringUTFChars(source, src);
        env->ReleaseStringUTFChars(type, t);
        return;
    }

    pthread_mutex_lock(&g_pipe_mutex);
    g_event_uplink.bind(g_agent_log_fd,
                        g_downlink_transport_epoch.load(std::memory_order_acquire));
    struct pollfd endpoint {g_agent_log_fd, POLLOUT, 0};
    bool accepted = g_downlink_watch_started.load(std::memory_order_acquire)
               && g_agent_log_fd >= 0 && poll(&endpoint, 1, 0) >= 0
               && !(endpoint.revents & (POLLERR | POLLHUP | POLLNVAL))
               && g_event_uplink.enqueue((long long)request_id, src, t, p);
    pthread_mutex_unlock(&g_pipe_mutex);
    if (accepted) {
        notify_owned_intent(g_owned_intent_wake_fd.load(std::memory_order_acquire),
                            [](int fd, const void *bytes, size_t size) {
            return write(fd, bytes, size);
        });
    }

    env->ReleaseStringUTFChars(source, src);
    env->ReleaseStringUTFChars(type, t);
    env->ReleaseStringUTFChars(payload, p);
    if (!accepted) {
        jclass failure = env->FindClass("java/lang/IllegalStateException");
        if (failure) {
            env->ThrowNew(failure, "Event uplink unavailable or full");
            env->DeleteLocalRef(failure);
        }
    }
}

// Narrow authenticated FEV option lane; true means pending memory ownership,
// not root durability or vehicle-side effect. Lane mutex covers only a small state copy, never transport/ACK work.
static jboolean native_events_submit_owned_intent_impl(JNIEnv *env, jclass,
                                                       jlong request_id, jstring source, jstring type, jstring payload) {
    if (request_id <= 0 || !source || !type || !payload ||
        !g_downlink_watch_started.load(std::memory_order_acquire) ||
        g_owned_intent_wake_fd.load(std::memory_order_acquire) < 0) {
        return JNI_FALSE;
    }
    const char *src = env->GetStringUTFChars(source, nullptr);
    const char *kind = src ? env->GetStringUTFChars(type, nullptr) : nullptr;
    const char *value = kind ? env->GetStringUTFChars(payload, nullptr) : nullptr;
    bool accepted = false;
    const size_t source_index = src ? owned_intent_source_index(src) : owned_intent_sources.size();
    if (value && source_index < g_owned_intents.size() && std::strcmp(kind, "option") == 0) {
        const std::string prefix = std::string(src) + "/intent:";
        const size_t prefix_len = prefix.size();
        if (std::strncmp(value, prefix.c_str(), prefix_len) == 0 &&
            (std::strcmp(value + prefix_len, "on") == 0 ||
             std::strcmp(value + prefix_len, "off") == 0)) {
            pthread_mutex_lock(&g_owned_intent_mutex);
            auto &lane = g_owned_intents[source_index];
            uint64_t capture = owned_intent_now_ns();
            if (capture && capture <= lane.capture_ns() && lane.capture_ns() != UINT64_MAX) {
                capture = lane.capture_ns() + 1;
            }
            if (capture) {
                accepted = lane.submit(static_cast<uint64_t>(request_id),
                                       g_downlink_transport_epoch.load(std::memory_order_acquire),
                                       value + prefix_len, capture);
            }
            g_owned_intent_pending.store(owned_intents_pending(), std::memory_order_release);
            pthread_mutex_unlock(&g_owned_intent_mutex);
        }
    }

    if (value) {
        env->ReleaseStringUTFChars(payload, value);
    }
    if (kind) {
        env->ReleaseStringUTFChars(type, kind);
    }
    if (src) {
        env->ReleaseStringUTFChars(source, src);
    }
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    if (accepted) {
        notify_owned_intent(g_owned_intent_wake_fd.load(std::memory_order_acquire),
                            [](int fd, const void *bytes, size_t size) {
            return write(fd, bytes, size);
        });
    }
    // No logger/IPC mutex acquisition on the OEM input thread.
    return accepted ? JNI_TRUE : JNI_FALSE;
}

static jstring native_logs_exchange_impl(JNIEnv *env, jclass, jstring operation,
                                         jstring request_id, jstring request_json) {
    static const int LOGS_TIMEOUT_MS = 1000;
    if (g_agent_log_fd < 0 || g_state_reply_fd < 0 || !operation || !request_id || !request_json) {
        return nullptr;
    }
    const char *op = env->GetStringUTFChars(operation, nullptr);
    const char *id = env->GetStringUTFChars(request_id, nullptr);
    const char *json = env->GetStringUTFChars(request_json, nullptr);
    if (!op || !id || !json) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        if (op) {
            env->ReleaseStringUTFChars(operation, op);
        }
        if (id) {
            env->ReleaseStringUTFChars(request_id, id);
        }
        if (json) {
            env->ReleaseStringUTFChars(request_json, json);
        }
        return nullptr;
    }
    bool valid_op = strcmp(op, "logs-query") == 0 || strcmp(op, "logs-follow") == 0 ||
                    strcmp(op, "logs-stop") == 0;
    bool valid = valid_op && is_safe_state_token(id, 64) && strlen(json) <= (size_t)64 * 1024 &&
                 strchr(json, '\n') == nullptr && strchr(json, '\r') == nullptr;
    std::string frame;
    if (valid) {
        frame = std::string("Q|") + op + "|" + id + "|" + json + "\n";
    }
    std::string expected_id(id);
    env->ReleaseStringUTFChars(operation, op);
    env->ReleaseStringUTFChars(request_id, id);
    env->ReleaseStringUTFChars(request_json, json);
    if (!valid || frame.size() > (size_t)65 * 1024) {
        return nullptr;
    }

    StateRpcGuard rpc_guard(&g_state_rpc_serialization);
    pthread_mutex_lock(&g_pipe_mutex);
    pthread_mutex_lock(&g_downlink_mutex);
    ssize_t written = write_uplink_record(frame.data(), frame.size());
    pthread_mutex_unlock(&g_pipe_mutex);
    if (written != static_cast<ssize_t>(frame.size())) {
        pthread_mutex_unlock(&g_downlink_mutex);
        return nullptr;
    }
    struct timespec started {};
    clock_gettime(CLOCK_MONOTONIC, &started);
    jstring result = nullptr;
    bool matched = false;
    while (!matched) {
        struct timespec now {};
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - started.tv_sec) * 1000L +
                       (now.tv_nsec - started.tv_nsec) / 1000000L;
        int remaining = LOGS_TIMEOUT_MS - static_cast<int>(elapsed);
        if (remaining <= 0) {
            break;
        }
        struct pollfd poll_fd {g_state_reply_fd, POLLIN, 0};
        if (poll(&poll_fd, 1, remaining) <= 0 || !(poll_fd.revents & POLLIN)) {
            break;
        }
        char response[8192];
        ssize_t count = read(g_state_reply_fd, response, sizeof(response));
        if (count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            continue;
        }
        if (count <= 0) {
            break;
        }
        g_downlink_framer.feed(response, static_cast<size_t>(count), [&](const std::string &line) {
            if (line.rfind("D|", 0) == 0 || line.rfind("A|", 0) == 0
                || line.rfind("C|", 0) == 0 || line.rfind("P|", 0) == 0
                || line.rfind("I|", 0) == 0 || line.rfind("K|", 0) == 0 || line.rfind("V|", 0) == 0
                || line.rfind("U|", 0) == 0) {
                g_downlink_snapshots.consume(line);
                return;
            }
            std::string prefix = "Q|" + expected_id + "|ok|";
            if (line.rfind(prefix, 0) == 0) {
                matched = true;
                result = new_strict_utf8_string(env, std::string_view(line).substr(prefix.size()));
            }
        });
    }
    pthread_mutex_unlock(&g_downlink_mutex);
    return result;
}

/* Status snapshots use their own record type. The JSON document is the final
 * field, therefore the same bounded/non-blocking pipe writer can carry it
 * without granting the OEM process filesystem access. */
static void native_status_emit_impl(JNIEnv *env, jclass, jlong ts_ms,
                                    jstring process, jstring document) {
    if (g_agent_log_fd < 0 || !process || !document) {
        return;
    }
    const char *src = env->GetStringUTFChars(process, nullptr);
    if (!src) {
        env->ExceptionClear(); return;
    }
    const char *doc = env->GetStringUTFChars(document, nullptr);
    if (!doc) {
        env->ExceptionClear();
        env->ReleaseStringUTFChars(process, src);
        return;
    }
    write_pipe_record('S', (long long)ts_ms, src, "snapshot", doc);
    env->ReleaseStringUTFChars(process, src);
    env->ReleaseStringUTFChars(document, doc);
}

/* Load <className> via the dex classloader and register <methods> on it. Log,
 * State and Events all live in the agent dex, so FindClass must use that loader
 * (not the system one). Returns true on success; failures are logged but never
 * abort startup. */
static bool register_natives_on(JNIEnv *env, jobject loader,
                                const char *className,
                                const JNINativeMethod *methods, jint count) {
    jclass loaderCls = env->GetObjectClass(loader);
    if (jni_result_failed(env, loaderCls, "pipe native loader class")) {
        return false;
    }
    jmethodID loadClassMid =
        env->GetMethodID(loaderCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (jni_result_failed(env, loadClassMid, "pipe native loadClass method")) {
        return false;
    }
    jstring name = env->NewStringUTF(className);
    if (jni_result_failed(env, name, "pipe native class name")) {
        return false;
    }
    jclass cls = (jclass)env->CallObjectMethod(loader, loadClassMid, name);
    env->DeleteLocalRef(name);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    if (!cls) {
        /* Class not in DEX — skip registration. Some pipe-native bridge
         * classes (e.g. AgentEvents, LogsNativeTransport) are optional and
         * may be absent from the core DEX. Do not block the whole agent. */
        IMPLANT_LOGD("register_natives_on: %s not in DEX, skipping", className);
        return true;
    }
    jint rc = env->RegisterNatives(cls, methods, count);
    if (rc != 0) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        IMPLANT_LOGE("register_natives_on: RegisterNatives %s failed rc=%d",
                     className, (int)rc);
        env->DeleteLocalRef(cls);
        return false;
    }
    env->DeleteLocalRef(cls);
    return true;
}

/* Register the three pipe-forwarding natives (Log.log, State.set, Events.emit)
 * on the just-loaded dex classloader. Called once, alongside
 * register_hooker_natives, before AgentEntry.init, so agents resolve their
 * native on first call. Each class is registered independently; one missing
 * class does not block the others. */
static bool register_agent_pipe_natives(JNIEnv *env, jobject loader) {
    JNINativeMethod log_methods[] = {
        {"log", "(JILjava/lang/String;Ljava/lang/String;)V", (void *)native_log_impl},
    };
    if (!register_natives_on(env, loader, LOG_NATIVE_CLASS, log_methods, 1)) {
        return false;
    }
    IMPLANT_LOGD("register_agent_pipe_natives: registered Log");

    JNINativeMethod state_methods[] = {
        {"set", "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
         (void *)native_state_set_impl},
        {"getNative", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
         (void *)native_state_get_impl},
        {"getNativeDetailed", "(Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
         (void *)native_state_get_detailed_impl},
        {"clearNativeIf", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z",
         (void *)native_state_clear_if_impl},
    };
    if (!register_natives_on(env, loader, STATE_NATIVE_CLASS, state_methods,
                             sizeof(state_methods) / sizeof(state_methods[0]))) {
        return false;
    }
    IMPLANT_LOGD("register_agent_pipe_natives: registered State");

    JNINativeMethod events_methods[] = {
        {"emit", "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)V",
         (void *)native_events_emit_impl},
        {"takeMutationAck", "(J)Ljava/lang/String;",
         (void *)native_events_take_mutation_ack_impl},
        {"takeSavedNative", "(J)Ljava/lang/String;", (void *)native_events_take_saved_impl},
        {"takeVehicleCommandNative", "(Ljava/lang/String;)Ljava/lang/String;",
         (void *)native_take_vehicle_command},
        {"peekVehicleCommandNative", "(Ljava/lang/String;)Ljava/lang/String;",
         (void *)native_peek_vehicle_command},
        {"vehicleCommandTransportEpochNative", "()J", (void *)native_vehicle_transport_epoch},
        {"submitOwnedIntent", "(JLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Z",
         (void *)native_events_submit_owned_intent_impl},
    };
    if (!register_natives_on(env, loader, EVENTS_NATIVE_CLASS, events_methods,
                            sizeof(events_methods) / sizeof(events_methods[0]))) {
        return false;
    }
    IMPLANT_LOGD("register_agent_pipe_natives: registered AgentEvents");

    JNINativeMethod status_methods[] = {
        {"emit", "(JLjava/lang/String;Ljava/lang/String;)V",
         (void *)native_status_emit_impl},
    };
    if (!register_natives_on(env, loader, STATUS_NATIVE_CLASS, status_methods, 1)) {
        return false;
    }
    IMPLANT_LOGD("register_agent_pipe_natives: registered AgentStatusTransport");

    JNINativeMethod logs_methods[] = {
        {"exchange", "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;",
         (void *)native_logs_exchange_impl},
    };
    if (!register_natives_on(env, loader, LOGS_NATIVE_CLASS, logs_methods, 1)) {
        return false;
    }
    IMPLANT_LOGD("register_agent_pipe_natives: registered NativeLogsTransport");
    return true;
}

/* ---- LSPlant init ---- */

static bool init_lsplant(JNIEnv *env) {
    voboost_lsplant_set_stage_callback(log_hook_stage);

    lsplant::InitInfo info{
        .inline_hooker = [](void *target, void *hooker) -> void * {
                             void *r = vbi_dobby_inline_hooker(target, hooker);
                             /* A failed hook prevents LSPlant initialization. */
                             if (!r) {
                                 IMPLANT_LOGW("lsplant-diag: hooker FAILED target=%p", target);
                             }
                             return r;
                         },
        .inline_unhooker = [](void *func) -> bool {
                               return vbi_dobby_inline_unhooker(func);
                           },
        .art_symbol_resolver = [](std::string_view sym) -> void * {
                                   std::string name(sym);
                                   /* Trace resolution stages through the owned debug channel. */
                                   IMPLANT_LOGD("lsplant-diag: resolve req %s", name.c_str());
                                   void *p = safe_resolve_symbol("libart.so", name.c_str());
                                   /* Runtime initialization requires a live singleton value. */
                                   if (name.rfind("_ZN3art7Runtime9instance_E", 0) == 0) {
                                       p = safe_resolve_symbol_symtab("libart.so", name.c_str(), false);
                                       void *live = p ? *(void **)p : nullptr;
                                       IMPLANT_LOGD(
                                           "lsplant-diag: instance_E addr=%p live=%p", p, live);
                                   }
                                   if (p) {
                                       IMPLANT_LOGD("lsplant-diag: resolve dynsym %s = %p", name.c_str(), p);
                                       return p;
                                   }
                                   /* Hidden ART symbols (mangled) are absent from
                                    * .dynsym but present in the full .symtab section. */
                                   p = safe_resolve_symbol_symtab("libart.so", name.c_str(), false);
                                   if (p) {
                                       IMPLANT_LOGD("lsplant-diag: resolve symtab %s = %p", name.c_str(), p);
                                   }
                                   return p;
                               },
        .art_symbol_prefix_resolver = [](std::string_view prefix) -> void * {
                                          std::string p(prefix);
                                          return safe_resolve_symbol_symtab("libart.so", p.c_str(), true);
                                      },
        .executable_memory_allocator = nullptr, /* optional; default pool is used */
        .executable_memory_recycler = nullptr,  /* optional; must mirror allocator */
    };

    bool ok = lsplant::Init(env, info);
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
static bool exempt_hidden_api(JNIEnv *env) {
    ScopedJniLocalFrame frame(env, 16);
    if (!frame.valid()) {
        IMPLANT_LOGE("JNI PushLocalFrame hidden API failed");
        return false;
    }
    /* Use reflection instead of direct GetStaticMethodID: on Android 11+
    * setHiddenApiExemptions is a hidden API that GetStaticMethodID refuses
    * to resolve. Class.forName + getDeclaredMethod + setAccessible(true)
    * bypasses the hidden API check when the calling class has access. */
    jclass cls = env->FindClass("dalvik/system/VMRuntime");
    if (jni_result_failed(env, cls, "FindClass VMRuntime")) {
        return false;
    }
    jmethodID forName = env->GetStaticMethodID(
        env->FindClass("java/lang/Class"), "forName", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (jni_result_failed(env, forName, "Class.forName")) {
        return false;
    }
    jstring clsName = env->NewStringUTF("dalvik.system.VMRuntime");
    if (jni_result_failed(env, clsName, "NewStringUTF VMRuntime")) {
        return false;
    }
    jclass classCls = env->FindClass("java/lang/Class");
    jclass vmRuntimeCls = (jclass)env->CallStaticObjectMethod(classCls, forName, clsName);
    if (jni_call_failed(env, "Class.forName VMRuntime") || !vmRuntimeCls) {
        IMPLANT_LOGE("Class.forName VMRuntime failed");
        return false;
    }
    jmethodID getDeclaredMethod = env->GetMethodID(
        env->FindClass("java/lang/Class"), "getDeclaredMethod",
        "(Ljava/lang/String;[Ljava/lang/Class;)Ljava/lang/reflect/Method;");
    if (jni_result_failed(env, getDeclaredMethod, "getDeclaredMethod")) {
        return false;
    }
    jstring methodName = env->NewStringUTF("setHiddenApiExemptions");
    if (jni_result_failed(env, methodName, "NewStringUTF method name")) {
        return false;
    }
    jclass stringCls = env->FindClass("java/lang/String");
    jobjectArray paramTypes = env->NewObjectArray(1, classCls, nullptr);
    if (jni_result_failed(env, paramTypes, "param types array")) {
        return false;
    }
    /* param: String[] */
    jclass stringArrayCls = env->FindClass("[Ljava/lang/String;");
    env->SetObjectArrayElement(paramTypes, 0, stringArrayCls);
    if (jni_call_failed(env, "SetObjectArrayElement paramTypes")) {
        return false;
    }
    jobject method = env->CallObjectMethod(vmRuntimeCls, getDeclaredMethod, methodName, paramTypes);
    if (jni_call_failed(env, "getDeclaredMethod setHiddenApiExemptions") || !method) {
        IMPLANT_LOGE("getDeclaredMethod setHiddenApiExemptions failed");
        return false;
    }
    jmethodID setAccessible = env->GetMethodID(
        env->FindClass("java/lang/reflect/Method"), "setAccessible", "(Z)V");
    if (jni_result_failed(env, setAccessible, "setAccessible")) {
        return false;
    }
    env->CallVoidMethod(method, setAccessible, JNI_TRUE);
    if (jni_call_failed(env, "setAccessible")) {
        return false;
    }
    /* Build the String[] argument: ["L"] */
    jobjectArray args = env->NewObjectArray(1, stringCls, nullptr);
    if (jni_result_failed(env, args, "hidden API argument array")) {
        return false;
    }
    jstring exempt = env->NewStringUTF("L");
    if (jni_result_failed(env, exempt, "hidden API exemption string")) {
        return false;
    }
    env->SetObjectArrayElement(args, 0, exempt);
    if (jni_call_failed(env, "SetObjectArrayElement args")) {
        return false;
    }
    jmethodID invoke = env->GetMethodID(
        env->FindClass("java/lang/reflect/Method"), "invoke",
        "(Ljava/lang/Object;[Ljava/lang/Object;)Ljava/lang/Object;");
    if (jni_result_failed(env, invoke, "Method.invoke")) {
        return false;
    }
    /* invoke: setHiddenApiExemptions is an instance method on VMRuntime.
     * Get the singleton via VMRuntime.getRuntime(). */
    jmethodID getRuntime = env->GetStaticMethodID(
        vmRuntimeCls, "getRuntime", "()Ldalvik/system/VMRuntime;");
    if (jni_result_failed(env, getRuntime, "VMRuntime.getRuntime")) {
        return false;
    }
    jobject runtimeInstance = env->CallStaticObjectMethod(vmRuntimeCls, getRuntime);
    if (jni_call_failed(env, "VMRuntime.getRuntime invoke") || !runtimeInstance) {
        IMPLANT_LOGE("VMRuntime.getRuntime returned null");
        return false;
    }
    /* Wrap the String[] arg in an Object[] for Method.invoke. */
    jobject invokeArgs = env->NewObjectArray(1, env->FindClass("java/lang/Object"), nullptr);
    env->SetObjectArrayElement((jobjectArray)invokeArgs, 0, args);
    if (jni_call_failed(env, "SetObjectArrayElement invokeArgs")) {
        return false;
    }
    env->CallObjectMethod(method, invoke, runtimeInstance, invokeArgs);
    if (jni_call_failed(env, "setHiddenApiExemptions invoke")) {
        return false;
    }

    return true;
}

/* ---- load agent dex via InMemoryDexClassLoader ---- */

/* Read the sealed memfd payload directly through the already-open descriptor.
 * Opening /proc/self/fd/<n> re-performs the SELinux open check against the
 * memfd's tmpfs type (system_app_tmpfs via the domain's tmpfs transition) and
 * is denied on this OEM policy; an inherited already-open fd needs no such
 * check (SELinux sdcard/proc-fd re-validation applies to open(2), not to
 * reads on a descriptor the process created itself). */
static jbyteArray read_dex_fd(JNIEnv *env, int fd) {
    if (fd < 0) {
        IMPLANT_LOGW("lsplant-diag: read_dex_fd invalid fd");
        return nullptr;
    }
    struct stat metadata {};
    if (fstat(fd, &metadata) != 0 || !S_ISREG(metadata.st_mode)
        || metadata.st_size <= 0 || metadata.st_size > (off_t)64 * 1024 * 1024) {
        IMPLANT_LOGW("lsplant-diag: read_dex_fd fstat failed errno=%d size=%lld",
                     errno, (long long)metadata.st_size);
        return nullptr;
    }
    size_t size = static_cast<size_t>(metadata.st_size);
    std::vector<jbyte> bytes(size);
    size_t done = 0;
    while (done < size) {
        ssize_t count = pread(fd, bytes.data() + done, size - done,
                              static_cast<off_t>(done));
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            IMPLANT_LOGW("lsplant-diag: read_dex_fd pread short errno=%d done=%zu",
                         errno, done);
            return nullptr;
        }
        done += static_cast<size_t>(count);
    }
    jbyteArray result = env->NewByteArray(size);
    if (jni_result_failed(env, result, "NewByteArray dex")) {
        IMPLANT_LOGW("lsplant-diag: read_dex NewByteArray failed size=%zu", size);
        return nullptr;
    }
    env->SetByteArrayRegion(result, 0, size, bytes.data());
    if (jni_call_failed(env, "SetByteArrayRegion dex")) {
        env->DeleteLocalRef(result);
        return nullptr;
    }
    return result;
}

[[maybe_unused]] static jbyteArray read_dex(JNIEnv *env, const char *path) {
    /* Legacy /proc/self/fd path reader retained for diagnostics only: the
     * SELinux re-open of a sealed memfd through /proc/self/fd is denied on
     * this OEM policy (system_app -> system_app_tmpfs open), so production
     * reads go through read_dex_fd on the already-open descriptor. */
    FILE *file = fopen(path, "rb");
    if (!file) {
        IMPLANT_LOGW("lsplant-diag: read_dex fopen %s failed errno=%d", path, errno);
        return nullptr;
    }
    if (fseek(file, 0, SEEK_END) != 0) {
        IMPLANT_LOGW("lsplant-diag: read_dex seek-end failed errno=%d", errno);
        fclose(file); return nullptr;
    }
    long size = ftell(file);
    if (size <= 0 || size > (long)64 * 1024 * 1024 || fseek(file, 0, SEEK_SET) != 0) {
        IMPLANT_LOGW("lsplant-diag: read_dex size=%ld invalid", size);
        fclose(file);
        return nullptr;
    }
    std::vector<jbyte> bytes(static_cast<size_t>(size));
    if (fread(bytes.data(), 1, bytes.size(), file) != bytes.size()) {
        IMPLANT_LOGW("lsplant-diag: read_dex fread short errno=%d", errno);
        fclose(file);
        return nullptr;
    }
    fclose(file);
    jbyteArray result = env->NewByteArray(size);
    if (jni_result_failed(env, result, "NewByteArray dex")) {
        IMPLANT_LOGW("lsplant-diag: read_dex NewByteArray failed size=%ld", size);
        return nullptr;
    }
    env->SetByteArrayRegion(result, 0, size, bytes.data());
    if (jni_call_failed(env, "SetByteArrayRegion dex")) {
        env->DeleteLocalRef(result);
        return nullptr;
    }
    return result;
}

static bool write_all_fd(int fd, const uint8_t *bytes, size_t size) {
    /* fd is a newly created memfd retained by this process, never a pipe. */
    while (size) {
        ssize_t count = write(fd, bytes, size);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return false;
        }
        bytes += count; size -= static_cast<size_t>(count);
    }
    return lseek(fd, 0, SEEK_SET) == 0;
}

static bool pipe_bootstrap_descriptor(const PipeBootstrapEnvelope &envelope,
                                      BootstrapDescriptor *out) {
    PipeBootstrapManifest manifest;
    std::vector<std::string> file_names;
    file_names.reserve(envelope.files.size());
    for (const auto &file : envelope.files) {
        file_names.push_back(file.name);
    }
    if (!parse_pipe_bootstrap_manifest(envelope.manifest.data(), envelope.manifest.size(),
                                       file_names, &manifest)) {
        return false;
    }

    /* Structural validation passed — materialize the payload as anonymous
     * memfds. On failure close everything opened so far. */
    g_bootstrap_fds.discard_staged();
    for (size_t index = 0; index < envelope.files.size(); ++index) {
        const auto &file = envelope.files[index];
#ifdef __NR_memfd_create
        int fd = static_cast<int>(syscall(__NR_memfd_create, file.name.c_str(),
                                          MFD_CLOEXEC | MFD_ALLOW_SEALING));
#else
        int fd = -1;
#endif
        if (fd < 0 || !write_all_fd(fd, file.bytes.data(), file.bytes.size())) {
            if (fd >= 0) {
                close(fd);
            }
            g_bootstrap_fds.discard_staged();
            return false;
        }
        if (fcntl(fd, F_ADD_SEALS,
                  F_SEAL_WRITE | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL) != 0) {
            close(fd);
            close_bootstrap_storage();
            return false;
        }
        bool artifact = false;
        for (const auto &entry : manifest.artifacts) {
            if (entry.file_index == index) {
                artifact = true;
                break;
            }
        }
        g_bootstrap_fds.stage(fd, artifact);
    }
    auto fd_path = [](size_t slot) -> std::string {
                       return "/proc/self/fd/" +
                              std::to_string(g_bootstrap_fds.staged_fd(slot));
                   };
    auto fd_of = [](size_t slot) -> int {
                     return g_bootstrap_fds.staged_fd(slot);
                 };
    out->generation = manifest.generation;
    out->catalog_sha256 = manifest.catalog_sha256;
    out->desired_json = manifest.desired_json;
    out->core_path = fd_path(manifest.core_index);
    out->core_fd = fd_of(manifest.core_index);
    for (const auto &module : manifest.modules) {
        out->modules.push_back(
            {module.id, module.entry_class, module.processes, fd_path(module.file_index),
             fd_of(module.file_index)});
    }
    for (const auto &module : manifest.executors) {
        out->executors.push_back(
            {module.id, module.entry_class, module.processes, fd_path(module.file_index),
             fd_of(module.file_index)});
    }
    for (const auto &artifact : manifest.artifacts) {
        out->artifacts.push_back({artifact.id, fd_path(artifact.file_index),
                                  fd_of(artifact.file_index)});
    }
    return true;
}

static AgentLoadResult load_and_call_agent_impl(JNIEnv *env, const BootstrapDescriptor &bootstrap);

/* Wrapper: push a local frame so
 * every local ref created inside impl (entryCls, atCls, appCls, loaders, dex,
 * config strings, …) is freed automatically on return — including on the
 * ~20 early-return paths. Without this, daemon retries (Deferred → re-call)
 * would accumulate refs and overflow the local ref table (FatalError). */
static AgentLoadResult load_and_call_agent(JNIEnv *env, const BootstrapDescriptor &bootstrap) {
    jint push_result = env->PushLocalFrame(16);
    if (push_result < 0) {
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
        }
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED; /* OOM pushing frame */
    }
    AgentLoadResult result = load_and_call_agent_impl(env, bootstrap);
    env->PopLocalFrame(nullptr);
    return result;
}

/* Only the signed launcher's system_server scope may use an existing services loader.
 * findLoadedClass reads already defined classes; it never loads/initializes service code. */
static jobject probe_system_server_loader(JNIEnv *env) {
    if (env->ExceptionCheck()) {
        return nullptr;
    }
    if (env->PushLocalFrame(32) < 0) {
        env->ExceptionClear();
        return nullptr;
    }
    jobject accepted = nullptr;
    const char *stage = "activity-service";
    do {
        // LoadedApk may replace the main-thread context loader with a warning
        // wrapper. Resolve the defining loader of the existing local activity
        // service instead; the provenance checks below still admit services.jar only.
        stage = "activity-service";
        jclass manager = env->FindClass("android/os/ServiceManager");
        if (!manager || env->ExceptionCheck()) {
            break;
        }
        jmethodID check_service = env->GetStaticMethodID(
            manager, "checkService", "(Ljava/lang/String;)Landroid/os/IBinder;");
        if (!check_service || env->ExceptionCheck()) {
            break;
        }
        jstring activity_name = env->NewStringUTF("activity");
        if (!activity_name || env->ExceptionCheck()) {
            break;
        }
        jobject activity = env->CallStaticObjectMethod(manager, check_service, activity_name);
        if (!activity || env->ExceptionCheck()) {
            break;
        }
        jclass activity_class = env->GetObjectClass(activity);
        jclass class_type = env->FindClass("java/lang/Class");
        if (!activity_class || !class_type || env->ExceptionCheck()) {
            break;
        }
        stage = "activity-service-loader";
        jmethodID service_loader = env->GetMethodID(
            class_type, "getClassLoader", "()Ljava/lang/ClassLoader;");
        if (!service_loader || env->ExceptionCheck()) {
            break;
        }
        jobject candidate = env->CallObjectMethod(activity_class, service_loader);
        if (!candidate || env->ExceptionCheck()) {
            break;
        }
        stage = "loader-type";
        char loader_name[128] = {0};
        const LoaderProbeOutcome loader_outcome =
            probe_loader_class_name(env, candidate, loader_name, sizeof(loader_name));
        IMPLANT_LOGD("system_server loader candidate type=%s outcome=%d",
                     loader_name, static_cast<int>(loader_outcome));
        if (loader_outcome != LoaderProbeOutcome::NOT_BOOT_CLASSLOADER
            || std::strcmp(loader_name, "dalvik.system.PathClassLoader") != 0) {
            break;
        }
        stage = "loaded-activity-record";
        jclass loader_class = env->FindClass("java/lang/ClassLoader");
        if (!loader_class || env->ExceptionCheck()) {
            break;
        }
        jmethodID find_loaded = env->GetMethodID(loader_class, "findLoadedClass", "(Ljava/lang/String;)Ljava/lang/Class;");
        if (!find_loaded || env->ExceptionCheck()) {
            break;
        }
        jobject record = nullptr;
        for (const char *name : {"com.android.server.am.ActivityRecord", "com.android.server.wm.ActivityRecord"}) {
            jstring text = env->NewStringUTF(name);
            if (!text || env->ExceptionCheck()) {
                break;
            }
            record = env->CallObjectMethod(candidate, find_loaded, text);
            env->DeleteLocalRef(text);
            if (record || env->ExceptionCheck()) {
                break;
            }
        }
        if (!record || env->ExceptionCheck()) {
            break;
        }
        stage = "defining-loader";
        jclass class_class = env->FindClass("java/lang/Class");
        if (!class_class || env->ExceptionCheck()) {
            break;
        }
        jmethodID defining = env->GetMethodID(class_class, "getClassLoader", "()Ljava/lang/ClassLoader;");
        if (!defining || env->ExceptionCheck()) {
            break;
        }
        jobject owner = env->CallObjectMethod(record, defining);
        if (!owner || env->ExceptionCheck() || !env->IsSameObject(owner, candidate)) {
            break;
        }
        stage = "dex-path-list";
        jclass base_class = env->FindClass("dalvik/system/BaseDexClassLoader");
        if (!base_class || env->ExceptionCheck()) {
            break;
        }
        jfieldID path_field = env->GetFieldID(base_class, "pathList", "Ldalvik/system/DexPathList;");
        if (!path_field || env->ExceptionCheck()) {
            break;
        }
        jobject path = env->GetObjectField(candidate, path_field);
        if (!path || env->ExceptionCheck()) {
            break;
        }
        jclass path_class = env->GetObjectClass(path);
        if (!path_class || env->ExceptionCheck()) {
            break;
        }
        stage = "dex-elements";
        jfieldID elements_field = env->GetFieldID(path_class, "dexElements", "[Ldalvik/system/DexPathList$Element;");
        if (!elements_field || env->ExceptionCheck()) {
            break;
        }
        jobjectArray elements = (jobjectArray)env->GetObjectField(path, elements_field);
        if (!elements || env->ExceptionCheck()) {
            break;
        }
        jsize count = env->GetArrayLength(elements);
        if (env->ExceptionCheck() || count < 1 || count > 32) {
            break;
        }
        stage = "framework-paths";
        bool services = false;
        bool protected_paths = true;
        for (jsize index = 0; index < count; ++index) {
            jobject element = env->GetObjectArrayElement(elements, index);
            if (!element || env->ExceptionCheck()) {
                protected_paths = false; break;
            }
            jclass element_class = env->GetObjectClass(element);
            if (!element_class || env->ExceptionCheck()) {
                protected_paths = false; break;
            }
            jfieldID dex_field = env->GetFieldID(element_class, "dexFile", "Ldalvik/system/DexFile;");
            if (!dex_field || env->ExceptionCheck()) {
                protected_paths = false; break;
            }
            jobject dex = env->GetObjectField(element, dex_field);
            if (!dex || env->ExceptionCheck()) {
                protected_paths = false; break;
            }
            jclass dex_class = env->GetObjectClass(dex);
            if (!dex_class || env->ExceptionCheck()) {
                protected_paths = false; break;
            }
            jmethodID get_name = env->GetMethodID(dex_class, "getName", "()Ljava/lang/String;");
            if (!get_name || env->ExceptionCheck()) {
                protected_paths = false; break;
            }
            jstring name = (jstring)env->CallObjectMethod(dex, get_name);
            if (!name || env->ExceptionCheck()) {
                protected_paths = false; break;
            }
            const char *chars = env->GetStringUTFChars(name, nullptr);
            if (!chars || env->ExceptionCheck()) {
                protected_paths = false; break;
            }
            protected_paths = system_server_framework_jar(chars);
            services = services || std::strcmp(chars, "/system/framework/services.jar") == 0;
            env->ReleaseStringUTFChars(name, chars);
            env->DeleteLocalRef(name); env->DeleteLocalRef(dex_class); env->DeleteLocalRef(dex);
            env->DeleteLocalRef(element_class); env->DeleteLocalRef(element);
            if (!protected_paths || env->ExceptionCheck()) {
                break;
            }
        }
        if (protected_paths && services && !env->ExceptionCheck()) {
            accepted = candidate;
        }
    } while (false);
    if (!accepted) {
        IMPLANT_LOGD("system_server loader deferred stage=%s exception=%d",
                     stage, env->ExceptionCheck() ? 1 : 0);
    }
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
    }
    return env->PopLocalFrame(accepted);
}

static AgentLoadResult load_and_call_agent_impl(JNIEnv *env, const BootstrapDescriptor &bootstrap) {
    g_settings_loaded.reset();
    g_resident_generation = bootstrap.generation;
    g_resident_catalog_sha256 = bootstrap.catalog_sha256;
    if (!bootstrap_files_present(bootstrap)) {
        IMPLANT_LOGE("bootstrap references a missing or invalid payload file");
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jbyteArray dexBytes = read_dex_fd(env, bootstrap.core_fd);
    if (!dexBytes) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }

    char self_process[256] = {0};
    char self_package[256] = {0};
    if (read_cmdline_process(self_process, sizeof(self_process))) {
        package_of_process(self_process, self_package, sizeof(self_package));
    }
    const bool system_server = std::strcmp(self_process, "system_server") == 0;
    jobject appLoader = nullptr;
    const char *loader_origin = "none";
    if (system_server) {
        if (!system_server_bootstrap_authorized(getuid(), self_process, bootstrap)) {
            return AGENT_LOAD_FAILED;
        }
        appLoader = probe_system_server_loader(env);
        if (!appLoader) {
            IMPLANT_LOGD("system_server loader: activity-service provenance not ready");
            return AGENT_LOAD_DEFERRED;
        }
        IMPLANT_LOGD("system_server loader: verified activity-service services.jar");
        loader_origin = "system_server.services.jar";
    } else {
        /* Get the app ClassLoader for proper class resolution.
         *
         * Early-boot readiness: currentApplication() returns null before the host
         * Application is bound (right after zygote fork). That is NOT a terminal
         * failure — the agent simply cannot run yet. Re-poll the real condition
         * (currentApplication() becoming non-null) for a tight bounded window so
         * the agent runs as soon as the Application is available. If it still has
         * not bound after the bound, return Deferred so the daemon retries on the
         * same live PID (a Deferred attempt does NOT set the re-entry guard). */
        jclass atCls = env->FindClass("android/app/ActivityThread");
        if (jni_result_failed(env, atCls, "FindClass ActivityThread")) {
            IMPLANT_LOGE("FindClass ActivityThread failed");
            IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
        }
        jmethodID curAppMid = env->GetStaticMethodID(
            atCls, "currentApplication", "()Landroid/app/Application;");
        if (jni_result_failed(env, curAppMid, "ActivityThread.currentApplication")) {
            IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
        }
        log_selection_attempt_begin();

        /* The bind that must create the application runs on the process's main
         * thread. When THIS (ptrace-hijacked) thread is the main thread, waiting
         * for currentApplication() would wait for ourselves: never sleep, a
         * missing application is an immediate Deferred for the daemon's bounded
         * same-PID retry. Off-main, the tight real-condition poll stays. */
        bool on_main_thread = (syscall(SYS_gettid) == getpid());
        int poll_tries = on_main_thread ? 1 : AGENT_APP_POLL_TRIES;
        jobject app = nullptr;
        for (int i = 0; i < poll_tries; i++) {
            app = env->CallStaticObjectMethod(atCls, curAppMid);
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
            }
            if (app) {
                break;
            }
            if (i == 0) {
                if (on_main_thread) {
                    IMPLANT_LOGD(
                        "currentApplication() null on the hijacked MAIN thread — "
                        "immediate Deferred (bind cannot run while we hold it)");
                } else {
                    IMPLANT_LOGD(
                        "load_and_call_agent: currentApplication() null — "
                        "deferring agent init until Application bound (try %d/%d)",
                        i + 1, poll_tries);
                }
            }
            if (!on_main_thread) {
                sleep_ms(AGENT_APP_POLL_SLEEP_MS);
            }
        }
        if (!app) {
            IMPLANT_LOGD("currentApplication() null after %d tries — trying fallbacks", poll_tries);

            /* Fallback: ActivityThread.currentActivityThread().getApplication() */
            jmethodID catMid = env->GetStaticMethodID(atCls, "currentActivityThread", "()Landroid/app/ActivityThread;");
            if (catMid) {
                jobject at = env->CallStaticObjectMethod(atCls, catMid);
                if (env->ExceptionCheck()) {
                    env->ExceptionClear();
                }
                if (at) {
                    jmethodID gaMid = env->GetMethodID(atCls, "getApplication", "()Landroid/app/Application;");
                    if (gaMid) {
                        app = env->CallObjectMethod(at, gaMid);
                        if (env->ExceptionCheck()) {
                            env->ExceptionClear();
                        }
                        if (app) {
                            IMPLANT_LOGD("fallback currentActivityThread.getApplication() succeeded");
                        }
                    }
                }
            }
        }

        /* Normal path: the loader of the ACTUAL bound application. This is the
         * primary host authority; the Application's own getClassLoader returns
         * its LoadedApk's loader. */
        if (app) {
            jclass appCls = env->GetObjectClass(app);
            if (jni_result_failed(env, appCls, "Application class")) {
                IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
            }
            jmethodID gclMid = env->GetMethodID(appCls, "getClassLoader", "()Ljava/lang/ClassLoader;");
            if (jni_result_failed(env, gclMid, "Application.getClassLoader")) {
                IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
            }
            appLoader = env->CallObjectMethod(app, gclMid);
            if (env->ExceptionCheck() || !appLoader) {
                env->ExceptionClear();
                IMPLANT_LOGE("getClassLoader failed");
                return AGENT_LOAD_FAILED;
            }
            loader_origin = "Application.getClassLoader";
            IMPLANT_LOGD("host loader from Application.getClassLoader");
        }

        /* Early-phase provenance fallback: the EXISTING mBoundApplication.info
         * loader, admitted only when the AppBindData's package/process identity
         * matches this process. Each probe only READS existing process state —
         * no loader is created and no PackageManager round-trip runs while the
         * process group is stopped. A pending exception observed mid-probe
         * aborts the attempt as Deferred without clearing it (foreign-thread
         * JNI boundary).
         *
         * Removed as an admission source: Thread.getContextClassLoader() — a
         * non-boot thread context loader (including the system PathClassLoader)
         * proves nothing by name; it is reported only as an IsSameObject
         * diagnostic against the proven reference below. Also removed earlier:
         * Class.getClassLoader() on a framework class, and the sourceDir→new
         * PathClassLoader construction. */
        if (!appLoader && self_package[0] != '\0' && self_process[0] != '\0') {
            bool foreign_pending = false;
            appLoader = probe_bound_application_loader(env, &foreign_pending,
                                                       self_package, self_process);
            if (foreign_pending) {
                IMPLANT_LOGW(
                    "pending exception observed during loader probes — deferring attempt");
                return AGENT_LOAD_DEFERRED;
            }
            if (appLoader) {
                loader_origin = "mBoundApplication.info.mClassLoader";
            }
        }

        if (!appLoader) {
            IMPLANT_LOGE(
                "no provenance-verified host loader available — agent init deferred");
            return AGENT_LOAD_DEFERRED;
        }

    }

    IMPLANT_LOGD("host loader accepted (origin=%s)", loader_origin);
    log_loader_identity_diagnostics(env, appLoader);

    /* InMemoryDexClassLoader(dexBytes, appLoader) */
    jclass bbCls = env->FindClass("java/nio/ByteBuffer");
    if (jni_result_failed(env, bbCls, "FindClass ByteBuffer")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jmethodID wrapMid =
        env->GetStaticMethodID(bbCls, "wrap", "([B)Ljava/nio/ByteBuffer;");
    if (jni_result_failed(env, wrapMid, "ByteBuffer.wrap method")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jobject bb = env->CallStaticObjectMethod(bbCls, wrapMid, dexBytes);
    if (jni_result_failed(env, bb, "ByteBuffer.wrap")) {
        IMPLANT_LOGE("ByteBuffer.wrap failed");
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jclass imdcCls = env->FindClass("dalvik/system/InMemoryDexClassLoader");
    if (jni_result_failed(env, imdcCls, "FindClass InMemoryDexClassLoader")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jmethodID ctorMid = env->GetMethodID(
        imdcCls, "<init>",
        "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
    if (jni_result_failed(env, ctorMid, "InMemoryDexClassLoader constructor")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jobject loader = env->NewObject(imdcCls, ctorMid, bb, appLoader);
    if (env->ExceptionCheck() || !loader) {
        env->ExceptionClear();
        IMPLANT_LOGE("InMemoryDexClassLoader failed");
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }

    /* Register the HookNative bridge (lsplant::Hook/UnHook) on the just-
     * loaded dex classloader. Must happen before AgentEntry.init so the
     * agents' Hooker facade resolves nativeHook/nativeUnhook on first use. */
    if (!register_hooker_natives(env, loader)) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }

    /* Register the multiplexed pipe natives (Log.log / State.set / Events.emit)
     * on the same dex classloader. Also before AgentEntry.init so agents'
     * Log/State/Events resolve their native on first call. fd < 0 → silent
     * no-op (see agent-logging). Some pipe-native classes (AgentEvents,
     * LogsNativeTransport) live in module DEXes, not core — they are
     * re-registered on each module classloader below. */
    if (!register_agent_pipe_natives(env, loader)) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }

    /* loadClass(ENTRY_CLASS) */
    jclass loaderCls = env->GetObjectClass(loader);
    if (jni_result_failed(env, loaderCls, "agent loader class")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jmethodID loadClassMid = env->GetMethodID(
        loaderCls, "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    if (jni_result_failed(env, loadClassMid, "agent loadClass method")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jstring className = env->NewStringUTF(ENTRY_CLASS);
    if (jni_result_failed(env, className, "AgentEntry class name")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jclass entryCls = (jclass)env->CallObjectMethod(loader, loadClassMid, className);
    if (env->ExceptionCheck() || !entryCls) {
        env->ExceptionClear();
        IMPLANT_LOGE("loadClass %s failed", ENTRY_CLASS);
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }

    /* One loader per module DEX, shared by agents (registerModule) and
     * executors (registerExecutor). Executors register FIRST: the resident
     * runtime starts them before the first desired-snapshot reconcile. */
    /* Failure contract: this bool callback answers one question — "did every
     * module/executor register?" Any hard failure (dex read, classloader,
     * pipe natives, registration call) must return false so the bootstrap
     * callers stop; the enum sentinel belongs to the outer
     * load_and_call_agent result, not to a bool callback, and returning it
     * here coerced to true and let partial registrations look successful. */
    auto register_modules = [&](const std::vector<BootstrapModule> &modules,
                                const char *method_name) -> bool {
                                jmethodID registerMid = env->GetStaticMethodID(
                                    entryCls, method_name, AGENT_ENTRY_REGISTER_METHOD_SIG);
                                if (env->ExceptionCheck() || !registerMid) {
                                    env->ExceptionClear();
                                    IMPLANT_LOGE("AgentEntry.%s method not found", method_name);
                                    return false;
                                }
                                for (const BootstrapModule &module : modules) {
                                    jbyteArray moduleBytes = read_dex_fd(env, module.fd);
                                    if (!moduleBytes) {
                                        IMPLANT_LOGE("open module dex %s failed", module.path.c_str());
                                        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                    }
                                    jobject moduleBuffer = env->CallStaticObjectMethod(bbCls, wrapMid, moduleBytes);
                                    if (jni_result_failed(env, moduleBuffer, "module ByteBuffer.wrap")) {
                                        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                    }
                                    jobject moduleLoader = env->NewObject(imdcCls, ctorMid, moduleBuffer, loader);
                                    if (env->ExceptionCheck() || !moduleLoader) {
                                        env->ExceptionClear();
                                        IMPLANT_LOGE("module classloader failed for %s", module.id.c_str());
                                        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                    }
                                    /* Re-register pipe natives on the module classloader: classes like
                                     * AgentEvents and LogsNativeTransport live in module DEXes, not core.
                                     * register_natives_on skips classes not found, so core-only classes
                                     * (Log, AgentState) are harmlessly re-registered here. */
                                    if (!register_agent_pipe_natives(env, moduleLoader)) {
                                        IMPLANT_LOGE("register_agent_pipe_natives on module %s failed", module.id.c_str());
                                        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                    }
                                    jstring moduleId = env->NewStringUTF(module.id.c_str());
                                    if (jni_result_failed(env, moduleId, "module id string")) {
                                        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                    }
                                    jstring moduleClass = env->NewStringUTF(module.entry_class.c_str());
                                    if (jni_result_failed(env, moduleClass, "module class string")) {
                                        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                    }
                                    jclass stringClass = env->FindClass("java/lang/String");
                                    if (jni_result_failed(env, stringClass, "String class")) {
                                        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                    }
                                    jobjectArray moduleProcesses = env->NewObjectArray(
                                        static_cast<jsize>(module.processes.size()), stringClass, nullptr);
                                    if (jni_result_failed(env, moduleProcesses, "module process array")) {
                                        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                    }
                                    for (size_t index = 0; index < module.processes.size(); ++index) {
                                        jstring process = env->NewStringUTF(module.processes[index].c_str());
                                        if (jni_result_failed(env, process, "module process string")) {
                                            IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                        }
                                        env->SetObjectArrayElement(moduleProcesses, static_cast<jsize>(index), process);
                                        env->DeleteLocalRef(process);
                                        if (env->ExceptionCheck()) {
                                            env->ExceptionClear();
                                            IMPLANT_LOGE("module process array failed for %s", module.id.c_str());
                                            IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                        }
                                    }
                                    IMPLANT_LOGD("registerModule: id=%s entryClass=%s processes=%zu",
                                                 module.id.c_str(), module.entry_class.c_str(), module.processes.size());
                                    env->CallStaticVoidMethod(
                                        entryCls, registerMid, moduleId, moduleClass, moduleProcesses, moduleLoader);
                                    if (env->ExceptionCheck()) {
                                        env->ExceptionClear();
                                        IMPLANT_LOGE("module registration failed for %s", module.id.c_str());
                                        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return false;
                                    }
                                    env->DeleteLocalRef(moduleId);
                                    env->DeleteLocalRef(moduleClass);
                                    env->DeleteLocalRef(moduleProcesses);
                                    env->DeleteLocalRef(stringClass);
                                    env->DeleteLocalRef(moduleLoader);
                                    env->DeleteLocalRef(moduleBuffer);
                                    env->DeleteLocalRef(moduleBytes);
                                }
                                return true;
                            };
    if (!register_modules(bootstrap.executors, "registerExecutor")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    if (!register_modules(bootstrap.modules, AGENT_ENTRY_REGISTER_METHOD_NAME)) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jmethodID artifactMid = env->GetStaticMethodID(
        entryCls, "registerArtifact", "(Ljava/lang/String;[B)V");
    if (env->ExceptionCheck() || !artifactMid) {
        env->ExceptionClear();
        IMPLANT_LOGE("AgentEntry.registerArtifact method not found");
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    for (const BootstrapArtifact &artifact : bootstrap.artifacts) {
        jstring artifactId = env->NewStringUTF(artifact.id.c_str());
        if (jni_result_failed(env, artifactId, "artifact id string")) {
            IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
        }
        /* Artifacts are sealed memfds; SELinux forbids reopening their
         * /proc/self/fd paths from Java. Pass the exact fd content instead —
         * the same read the module DEX loader already relies on. */
        jbyteArray artifactBytes = read_dex_fd(env, artifact.fd);
        if (!artifactBytes) {
            env->DeleteLocalRef(artifactId);
            IMPLANT_LOGE("read artifact %s fd failed", artifact.id.c_str());
            IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
        }
        env->CallStaticVoidMethod(entryCls, artifactMid, artifactId, artifactBytes);
        if (env->ExceptionCheck()) {
            env->ExceptionClear();
            IMPLANT_LOGE("artifact registration failed for %s", artifact.id.c_str());
            IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
        }
        env->DeleteLocalRef(artifactId);
        env->DeleteLocalRef(artifactBytes);
    }

    jmethodID generationMid = env->GetStaticMethodID(
        entryCls, "registerGeneration", "(Ljava/lang/String;Ljava/lang/String;)V");
    if (env->ExceptionCheck() || !generationMid) {
        env->ExceptionClear();
        IMPLANT_LOGE("AgentEntry.registerGeneration method not found");
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jstring generationId = env->NewStringUTF(bootstrap.generation.c_str());
    if (jni_result_failed(env, generationId, "generation id string")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    jstring catalogSha = env->NewStringUTF(bootstrap.catalog_sha256.c_str());
    if (jni_result_failed(env, catalogSha, "catalog digest string")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    env->CallStaticVoidMethod(entryCls, generationMid, generationId, catalogSha);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        IMPLANT_LOGE("generation registration failed (gen=%s catalog=%s)",
                     bootstrap.generation.c_str(), bootstrap.catalog_sha256.c_str());
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    env->DeleteLocalRef(generationId);
    env->DeleteLocalRef(catalogSha);

    /* Call AgentEntry.init(String desiredJson) — the fixed seam.
     * Defensive: clear any exception so a throwing agent/seam does not
     * crash the target (see agent-entry-seam spec). */
    jmethodID initMid =
        env->GetStaticMethodID(entryCls, "init", "(Ljava/lang/String;)V");
    if (env->ExceptionCheck() || !initMid) {
        env->ExceptionClear();
        IMPLANT_LOGE("AgentEntry.init method not found");
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }

    jstring configStr = new_strict_utf8_string(env, bootstrap.desired_json);
    if (jni_result_failed(env, configStr, "desired document string")) {
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    IMPLANT_LOGD("calling AgentEntry.init: desiredJson size=%zu modules=%zu generation=%s",
                 bootstrap.desired_json.size(), bootstrap.modules.size(),
                 bootstrap.generation.c_str());
    IMPLANT_LOGD("desiredJson content: %.800s", bootstrap.desired_json.c_str());
    env->CallStaticVoidMethod(entryCls, initMid, configStr);
    if (env->ExceptionCheck()) {
        /* Extract exception details before clearing. */
        jobject exc = env->ExceptionOccurred();
        env->ExceptionClear();
        if (exc) {
            jmethodID getMessage = env->GetMethodID(
                env->FindClass("java/lang/Throwable"), "getMessage", "()Ljava/lang/String;");
            if (getMessage) {
                jstring msg = (jstring)env->CallObjectMethod(exc, getMessage);
                if (msg) {
                    const char *str = env->GetStringUTFChars(msg, nullptr);
                    if (str) {
                        IMPLANT_LOGE("AgentEntry.init threw: %s", str);
                        env->ReleaseStringUTFChars(msg, str);
                    } else {
                        IMPLANT_LOGE("AgentEntry.init threw (null message)");
                    }
                } else {
                    IMPLANT_LOGE("AgentEntry.init threw (null msg)");
                }
            } else {
                env->ExceptionClear();
                IMPLANT_LOGE("AgentEntry.init threw (no getMessage)");
            }
        } else {
            IMPLANT_LOGE("AgentEntry.init threw (null exception)");
        }
        env->DeleteLocalRef(configStr);
        env->DeleteLocalRef(className);
        IMPLANT_LOGW("lsplant-diag: AGENT_LOAD_FAILED at line %d", __LINE__); return AGENT_LOAD_FAILED;
    }
    IMPLANT_LOGD("AgentEntry.init returned without exception");
    /* Optional diagnostics run only after the canonical init has returned. */
    MainThreadSnapshotScope::dispatch(self_process, [&](const char *observed_process) {
        jmethodID snapshot = env->GetStaticMethodID(
            entryCls, "scheduleMainThreadSnapshot", "(Ljava/lang/String;)V");
        if (env->ExceptionCheck() || !snapshot) {
            env->ExceptionClear();
            implant_log(3, "main-thread snapshot seam unavailable");
        } else {
            jstring process = new_strict_utf8_string(env, observed_process);
            if (process && !env->ExceptionCheck()) {
                env->CallStaticVoidMethod(entryCls, snapshot, process);
            }
            if (env->ExceptionCheck()) {
                env->ExceptionClear();
                IMPLANT_LOGW("main-thread snapshot scheduling failed");
            }
            if (process) {
                env->DeleteLocalRef(process);
            }
        }
    });
    IMPLANT_LOGD("post-init pipe state: g_agent_log_fd=%d g_agent_log_read_fd=%d g_state_reply_fd=%d g_pipe_bootstrap_channel_ready=%d",
                 g_agent_log_fd, g_agent_log_read_fd, g_state_reply_fd,
                 (int)g_pipe_bootstrap_channel_ready);

    /* Resident drain for daemon live updates (D/A frames): without it a
     * committed Settings mutation never reaches a running runtime. */
    prepare_downlink_watch(env, entryCls, loader);

    env->DeleteLocalRef(configStr);
    env->DeleteLocalRef(className);
    bool settings_module_loaded = false;
    for (const auto &module : bootstrap.modules) {
        settings_module_loaded = settings_module_loaded || module.id == "settings";
    }
    g_settings_loaded.bootstrap(bootstrap.desired_json, bootstrap.generation,
                                bootstrap.catalog_sha256, settings_module_loaded);
    return AGENT_LOAD_OK;
}

/* ---- single entry point: implant_init ----
 *
 * extern "C" int implant_init(const char* cfg)
 *
 * Called by the injector via explicit remote-call after target-linker loading.
 * Native constructors have already run; this is the ONLY product bootstrap
 * entry point —
 * no __attribute__((constructor)), no JNI_OnLoad.
 *
 * cfg     — one exact pipe-only sentinel: @pipe-bootstrap-init,
 *           @pipe-bootstrap-load, or @pipe-rebind.
 * Returns a target-local pipe fd for @pipe-bootstrap-init, or one of the
 *   IMPLANT_INIT_* sentinels (agent_entry_seam.h) for load/rebind outcomes:
 *     >= 0                    bootstrap pipe established; valid uplink read fd
 *     IMPLANT_INIT_PIPE_OK    agent reached through the streamed bootstrap
 *     IMPLANT_INIT_REBOUND    resident generation rebound to fresh pipes
 *     IMPLANT_INIT_DEFERRED   agent deferred (currentApplication null after the
 *                             bounded re-poll) — retryable on the same live PID
 *     IMPLANT_INIT_FAILED     hard agent-init failure (dex/seam) — not retryable
 *   The injector adopts the negotiated pipe endpoints and completes their
 *   ownership handoff before the daemon consumes the outcome.
 *
 * Re-entry semantics: a Deferred attempt does NOT set the g_initialized guard,
 *   so the daemon may re-inject (re-call implant_init) on the same live PID.
 *   An Ok or hard-failed attempt sets the guard, so a second call is a no-op.
 */

static int run_managed_bootstrap(const BootstrapDescriptor &bootstrap) {
    auto *owner = g_bootstrap_worker.load(std::memory_order_acquire);
    if (!owner || owner->owned_thread.load(std::memory_order_acquire) == pthread_t{}
        || pthread_equal(pthread_self(), owner->borrowed_thread)
        || !pthread_equal(pthread_self(), owner->owned_thread.load(std::memory_order_acquire))) {
        IMPLANT_LOGE("managed bootstrap rejected: thread is not the owned worker");
        return IMPLANT_INIT_FAILED;
    }

    /* 1. Acquire JavaVM via JNI_GetCreatedJavaVMs from the already loaded ART.
     * Every failure below is a
     * hard native-init failure and must report IMPLANT_INIT_FAILED, never a
     * pipe fd: a non-negative return makes the injector/daemon mark the agent
     * active. The log pipe stays open, so the injector still adopts it via
     * implant_log_read_fd() and the daemon drains these diagnostics. */
    typedef jint (*GetVMs_t)(JavaVM **, jsize, jsize *);
    GetVMs_t getVMs = reinterpret_cast<GetVMs_t>(
        safe_resolve_symbol("libart.so", "JNI_GetCreatedJavaVMs"));
    if (!getVMs) {
        // safe_resolve_symbol now also parses /proc/self/maps as a fallback
        // when dl_iterate_phdr (caller-namespace only) misses libart.so, which
        // happens when the implant is loaded into an isolated linker
        // namespace. If the maps fallback also failed, try the caller's
        // namespace dlsym as a last resort.
        IMPLANT_LOGD("safe_resolve_symbol missed JNI_GetCreatedJavaVMs; trying dlsym(RTLD_DEFAULT)");
        void *sym = dlsym(RTLD_DEFAULT, "JNI_GetCreatedJavaVMs");
        getVMs = reinterpret_cast<GetVMs_t>(sym);
    }
    if (!getVMs) {
        IMPLANT_LOGE("loaded ART JNI_GetCreatedJavaVMs resolution failed");
        return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
    }
    JavaVM *vm = nullptr;
    jsize n = 0;
    jint get_vms_result = getVMs(&vm, 1, &n);
    if (get_vms_result != JNI_OK || n < 1 || !vm) {
        IMPLANT_LOGE("no JavaVM found");
        return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
    }

    ScopedJniAttachment<JavaVM, JNIEnv> attachment(
        vm, JNI_OK, JNI_EDETACHED, JNI_VERSION_1_6, IMPLANT_INIT_FAILED,
        log_detach_failure);
    JNIEnv *env = attachment.env();
    if (env && attachment.decision() != JniAttachmentDecision::ATTACH) {
        IMPLANT_LOGE("managed bootstrap rejected: worker JNI attachment was not owned");
        return attachment.finish(IMPLANT_INIT_FAILED);
    }
    if (!env) {
        if (attachment.decision() == JniAttachmentDecision::ATTACH) {
            IMPLANT_LOGE("AttachCurrentThread failed");
        } else {
            IMPLANT_LOGE("GetEnv failed");
        }
        return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
    }

    int attached_result = [&]() -> int {
                              /* The worker owns this fresh JNI attachment. A
                               * pending exception still prevents startup; the
                               * existing Deferred policy is retained. */
                              if (env->ExceptionCheck()) {
                                  IMPLANT_LOGW(
                                      "target thread already has a pending exception"
                                      " at bootstrap entry — deferring attempt");
                                  return fail_bootstrap_attempt(IMPLANT_INIT_DEFERRED);
                              }

                              /* 2. Exempt hidden API before any agent reflection. */
                              if (!exempt_hidden_api(env)) {
                                  return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
                              }

                              /* 3. Init LSPlant (Dobby backend + safe_resolve_symbol). */
                              if (!init_lsplant(env)) {
                                  IMPLANT_LOGE("LSPlant init failed — aborting");
                                  return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
                              }

                              /* 3b. Register the Java Hooker bridge natives (lsplant::Hook/UnHook), so
                               * the agents' Hooker facade can hook methods once the seam runs. This is
                               * called AFTER the dex is loaded (see load_and_call_agent), because
                               * HookNative lives in the dex and FindClass must use the dex classloader. */

                              /* 4. Load agent dex and call the seam. The outcome is observable so the
                               * daemon can avoid marking the agent active on native-load success alone
                               * and can apply a bounded same-live-PID retry when the agent is deferred. */
                              AgentLoadResult agent_result = load_and_call_agent(env, bootstrap);

                              if (agent_result == AGENT_LOAD_DEFERRED) {
                                  /* The agent was NOT reached (Application not bound). Release the
                                   * re-entry guard so the daemon can re-inject on the same live PID,
                                   * and report the Deferred sentinel. Tear down the log pipe: a retry
                                   * will create a fresh one, and the daemon never adopted this fd. */
                                  /* The retry re-runs the FULL two-phase bootstrap on a fresh pipe
                                   * pair: the envelope must be re-read and re-materialized. Drop the
                                   * stored envelope and every memfd from this attempt so the load
                                   * phase cannot silently reuse stale payload while the daemon writer
                                   * blocks on a pipe nobody reads. */
                                  IMPLANT_LOGD("implant_init: agent deferred — daemon will retry");
                                  return fail_bootstrap_attempt(IMPLANT_INIT_DEFERRED);
                              }

                              if (agent_result == AGENT_LOAD_FAILED) {
                                  /* Intentional: a hard agent-init failure sets the g_initialized guard
                                   * permanently, so re-injection on this PID is refused. This prevents
                                   * crash loops where a broken agent is re-loaded into the same process
                                   * on every retry. The daemon may still drain diagnostics via the log
                                   * pipe (adopt_failed_log_pipe), but it must not re-inject this PID.
                                   * The PID dies naturally when the target process exits, and a fresh
                                   * PID re-injects clean on the next poll pass. */
                                  IMPLANT_LOGE("implant_init: agent load failed — reporting failure");
                                  return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
                              }

                              /* Core/module DEX bytes were consumed synchronously above. Artifact paths
                               * were only registered with Java and are opened lazily by agents, so retain
                               * their sealed memfds for the complete resident-generation lifetime. */
                              /* Resident publication follows owned JNI detach,
                               * cancellation and current-capsule ownership checks. */
                              IMPLANT_LOGD("owned managed bootstrap returned (publication pending)");
                              return IMPLANT_INIT_PIPE_OK;
                          }();
    return attachment.finish(attached_result);
}

static bool worker_write_record(int fd, const char *bytes, size_t length) {
    struct timespec deadline {};
    if (!pipe_deadline_init(&deadline)) {
        return false;
    }
    size_t offset = 0;
    while (offset < length) {
        PipePollResult polled = pipe_poll_writable(fd, &deadline);
        if (polled == PipePollResult::Retry) {
            continue;
        }
        if (polled == PipePollResult::Failed) {
            return false;
        }
        ssize_t written = sigpipe_safe_write(fd, bytes + offset,
                                             length - offset);
        if (written < 0 && (errno == EINTR || errno == EAGAIN)) {
            continue;
        }
        if (written <= 0) {
            return false;
        }
        offset += static_cast<size_t>(written);
    }
    return true;
}
static bool worker_completion(BootstrapWorkerCapsule *capsule, const char *outcome) {
    const auto &binding = capsule->gate.binding();
    char nonce[33] = {};
    static const char hex[] = "0123456789abcdef";
    for (size_t index = 0; index < binding.nonce.size(); ++index) {
        nonce[index * 2] = hex[binding.nonce[index] >> 4];
        nonce[index * 2 + 1] = hex[binding.nonce[index] & 15];
    }
    char record[256];
    int length = snprintf(record, sizeof(record), "B|%s|%u|%llu|%.64s|%.64s|%s\n", nonce,
                          binding.pid, static_cast<unsigned long long>(binding.starttime), binding.generation.data(),
                          binding.catalog.data(), outcome);
    if (length <= 0 || static_cast<size_t>(length) >= sizeof(record)) {
        return false;
    }
    return worker_write_record(capsule->completion_fd, record, static_cast<size_t>(length));
}

static bool worker_channel_open(BootstrapWorkerCapsule *capsule) {
    struct pollfd channel = {capsule->commit_fd, POLLIN, 0};
    int result = poll(&channel, 1, 0);
    return result >= 0 && !(channel.revents & (POLLERR | POLLHUP | POLLNVAL));
}

static bool worker_publish(BootstrapWorkerCapsule *capsule) {
    struct timespec deadline {};
    if (!pipe_deadline_init(&deadline)) {
        return false;
    }
    while (!pipe_deadline_passed(&deadline)) {
        pthread_mutex_lock(&g_pipe_mutex);
        if (g_bootstrap_worker.load(std::memory_order_acquire) != capsule
            || capsule->gate.phase() != BootstrapWorkerPhase::Publishing
            || !worker_channel_open(capsule)) {
            capsule->gate.cancel();
            pthread_mutex_unlock(&g_pipe_mutex);
            return false;
        }
        // A status may start only after the current resident frame's suffix.
        // Once bootstrap S owns the stream, queued E must wait for its end.
        if (!capsule->pending_status.partial() && g_event_uplink.partial()) {
            if (!g_event_uplink.flush([&](const char *bytes, size_t size) {
                return sigpipe_safe_write(capsule->completion_fd, bytes, size);
            }, 1)) {
                pthread_mutex_unlock(&g_pipe_mutex); return false;
            }
            if (g_event_uplink.partial()) {
                pthread_mutex_unlock(&g_pipe_mutex);
                if (pipe_poll_writable(capsule->completion_fd, &deadline) == PipePollResult::Failed) {
                    return false;
                }
                continue;
            }
        }
        int progress = capsule->pending_status.flush_one([&](const char *bytes, size_t size) {
            return sigpipe_safe_write(capsule->completion_fd, bytes, size);
        });
        if (progress < 0) {
            pthread_mutex_unlock(&g_pipe_mutex); return false;
        }
        if (!capsule->pending_status.pending()) {
            bool ready = capsule->gate.publish(capsule->gate.binding());
            if (ready) {
                g_bootstrap_fds.publish();
                g_resident_ready.store(true, std::memory_order_release);
                g_pipe_bootstrap_channel_ready = false;
            }
            pthread_mutex_unlock(&g_pipe_mutex);
            return ready;
        }
        pthread_mutex_unlock(&g_pipe_mutex);
        if (progress) {
            continue;
        }
        PipePollResult result = pipe_poll_writable(capsule->completion_fd, &deadline);
        if (result == PipePollResult::Failed) {
            return false;
        }
    }
    return false;
}

static void *bootstrap_worker_main(void *opaque) {
    auto *capsule = static_cast<BootstrapWorkerCapsule *>(opaque);
    capsule->owned_thread.store(pthread_self(), std::memory_order_release);
    int outcome = IMPLANT_INIT_FAILED;
    uint8_t frame[BOOTSTRAP_WORKER_FRAME_SIZE] = {};
    BootstrapWorkerBinding commit;
    struct timespec deadline {};
    long pid = 0;
    unsigned long starttime = 0;
    bool allowed = pipe_deadline_init(&deadline)
                   && pipe_read_exact(capsule->commit_fd, frame, sizeof(frame), &deadline)
                   && bootstrap_worker_decode(frame, sizeof(frame), "WKSC", &commit)
                   && read_pid_starttime(&pid, &starttime) && commit.pid == static_cast<uint32_t>(pid)
                   && commit.starttime == starttime;
    if (allowed) {
        allowed = capsule->gate.run(commit, [&] {
            IMPLANT_LOGD("bootstrap worker committed pid=%ld; entering owned JNI thread", pid);
            try {
                outcome = run_managed_bootstrap(capsule->descriptor);
            } catch (const std::exception &error) {
                IMPLANT_LOGE("bootstrap worker failed: %s", error.what());
            } catch (...) {
                IMPLANT_LOGE("bootstrap worker failed: unknown native exception");
            }
        });
    }
    if (!allowed) {
        capsule->gate.cancel();
    }
    bool completed = allowed && outcome == IMPLANT_INIT_PIPE_OK
                     && worker_channel_open(capsule) && capsule->gate.finish(true);
    bool ready = completed && capsule->gate.claim()
                 && worker_completion(capsule, "ready") && worker_publish(capsule);
    if (ready) {
        launch_downlink_watch();
    } else {
        g_resident_ready.store(false, std::memory_order_release);
        if (outcome == IMPLANT_INIT_DEFERRED) {
            capsule->gate.defer();
        }else {
            capsule->gate.finish(false); capsule->gate.cancel();
        }
        /* Retire old globals before terminal outcome can authorize a retry. */
        if (outcome == IMPLANT_INIT_DEFERRED || !allowed) {
            reset_pre_resident_bootstrap();
            g_bootstrap_worker.store(nullptr, std::memory_order_release);
        }
        capsule->close_commit();
        capsule->finished.store(true, std::memory_order_release);
        if (!worker_completion(capsule, outcome == IMPLANT_INIT_DEFERRED ? "deferred" : "failed")) {
            IMPLANT_LOGE("worker terminal failure publication unavailable");
        }
    }
    capsule->close_all();
    capsule->finished.store(true, std::memory_order_release);
    return nullptr;
}

static int stage_bootstrap_worker() {
    uint8_t frame[BOOTSTRAP_WORKER_FRAME_SIZE] = {};
    BootstrapWorkerBinding binding;
    struct timespec deadline {};
    long pid = 0;
    unsigned long starttime = 0;
    if (!pipe_deadline_init(&deadline)
        || !pipe_read_exact(g_state_reply_fd, frame, sizeof(frame), &deadline)
        || !bootstrap_worker_decode(frame, sizeof(frame), "WKSS", &binding)
        || !read_pid_starttime(&pid, &starttime) || binding.pid != static_cast<uint32_t>(pid)
        || binding.starttime != starttime || g_bootstrap_worker_attempts >= 32) {
        return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
    }
    BootstrapDescriptor descriptor;
    if (!pipe_bootstrap_descriptor(g_pipe_bootstrap, &descriptor)
        || descriptor.generation.size() != 64 || descriptor.catalog_sha256.size() != 64
        || memcmp(binding.generation.data(), descriptor.generation.data(), 64) != 0
        || memcmp(binding.catalog.data(), descriptor.catalog_sha256.data(), 64) != 0) {
        return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
    }
    int completion = fcntl(g_agent_log_fd, F_DUPFD_CLOEXEC, 0);
    int commit = fcntl(g_state_reply_fd, F_DUPFD_CLOEXEC, 0);
    if (completion < 0 || commit < 0) {
        if (completion >= 0) {
            close(completion);
        }
        if (commit >= 0) {
            close(commit);
        }
        return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
    }
    pthread_attr_t attributes;
    int attribute_result = pthread_attr_init(&attributes);
    if (attribute_result != 0) {
        close(completion); close(commit);
        return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
    }
    attribute_result = pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
    if (attribute_result != 0) {
        pthread_attr_destroy(&attributes);
        close(completion); close(commit);
        return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
    }
    auto *capsule = new BootstrapWorkerCapsule(std::move(descriptor), binding, completion, commit);
    g_bootstrap_worker.store(capsule, std::memory_order_release);
    ++g_bootstrap_worker_attempts;
    g_pipe_bootstrap = PipeBootstrapEnvelope{};
    g_pipe_bootstrap_ready = false;
    pthread_t thread;
    int created = pthread_create(&thread, &attributes, bootstrap_worker_main, capsule);
    pthread_attr_destroy(&attributes);
    if (created != 0) {
        g_bootstrap_worker.store(nullptr, std::memory_order_release);
        delete capsule;
        return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
    }
    IMPLANT_LOGD("bootstrap worker staged pid=%ld (not agent-ready)", pid);
    return IMPLANT_INIT_STAGED;
}

static int implant_init_impl(const char *cfg) {
    const bool abort_bootstrap = cfg && strcmp(cfg, "@pipe-bootstrap-abort") == 0;
    if (abort_bootstrap) {
        if (bootstrap_worker_live()) {
            pthread_mutex_lock(&g_pipe_mutex);
            g_bootstrap_worker.load(std::memory_order_acquire)->gate.cancel();
            pthread_mutex_unlock(&g_pipe_mutex);
            return IMPLANT_INIT_PIPE_OK;
        }
        /* The caller reached this symbol only through the daemon's attested
         * ptrace rail. Never tear down an established resident. */
        if (!g_resident_generation.empty() || !g_resident_catalog_sha256.empty()) {
            { vbi_fail_log(__LINE__); return IMPLANT_INIT_FAILED; }
        }
        reset_pre_resident_bootstrap();
        return IMPLANT_INIT_PIPE_OK;
    }
    const bool rebind = cfg && strcmp(cfg, "@pipe-rebind") == 0;
    if (rebind) {
        if (!pipe_resident_ready(g_initialized.load(std::memory_order_acquire),
                                 g_resident_ready.load(std::memory_order_acquire),
                                 g_resident_generation.size(), g_resident_catalog_sha256.size()) ||
            !replace_daemon_pipes_for_rebind()) {
            { vbi_fail_log(__LINE__); return IMPLANT_INIT_FAILED; }
        }
        return IMPLANT_INIT_REBOUND;
    }
    const bool pipe_init = cfg && strcmp(cfg, "@pipe-bootstrap-init") == 0;
    const bool pipe_load = cfg && strcmp(cfg, "@pipe-bootstrap-load") == 0;
    const bool pipe_mode = pipe_init || pipe_load;
    if (!pipe_mode) {
        { vbi_fail_log(__LINE__); return IMPLANT_INIT_FAILED; }
    }
    if (pipe_init) {
        if (bootstrap_worker_live()) {
            return IMPLANT_INIT_FAILED;
        }
        if (g_initialized.load(std::memory_order_acquire)) {
            if (!g_resident_ready.load(std::memory_order_acquire)) {
                IMPLANT_LOGE("bootstrap reuse rejected: Java startup is incomplete");
                return IMPLANT_INIT_FAILED;
            }
            /* A concurrent daemon flow re-calls init on an already-initialized
             * resident. That is an idempotent success, not a failure: the
             * race between the install and poll flows must not trip the
             * circuit breaker. */
            return IMPLANT_INIT_PIPE_OK;
        }
        if (!g_resident_generation.empty() || !g_resident_catalog_sha256.empty()) {
            { vbi_fail_log(__LINE__); return IMPLANT_INIT_FAILED; }
        }
        /* A repeated phase one abandons the incomplete transaction first. */
        reset_pre_resident_bootstrap();
    } else if (g_initialized.load(std::memory_order_acquire)
               && (!g_resident_generation.empty()
                   || !g_resident_catalog_sha256.empty())) {
        if (!g_resident_ready.load(std::memory_order_acquire)) {
            IMPLANT_LOGE("bootstrap load reuse rejected: Java startup is incomplete");
            return IMPLANT_INIT_FAILED;
        }
        /* A stale phase-two call must not tear down a committed resident.
         * A duplicate load on an initialized resident is idempotent success
         * (two daemon flows racing on one live PID). */
        return IMPLANT_INIT_PIPE_OK;
    } else if (!pipe_bootstrap_phase_two_ready(
                   g_pipe_bootstrap_channel_ready, g_agent_log_fd,
                   g_state_reply_fd)) {
        reset_pre_resident_bootstrap();
        { vbi_fail_log(__LINE__); return IMPLANT_INIT_FAILED; }
    }
    /* A second load must not run Java startup twice. */
    if (pipe_load && g_initialized.exchange(true, std::memory_order_acq_rel)) {
        if (!g_resident_ready.load(std::memory_order_acquire)) {
            IMPLANT_LOGE("concurrent bootstrap reuse rejected: Java startup is incomplete");
            return IMPLANT_INIT_FAILED;
        }
        /* Idempotent re-entry: the resident was already initialized by a
         * concurrent flow. Report the established pipe instead of a
         * failure so the racing flow does not trip the breaker. */
        return IMPLANT_INIT_PIPE_OK;
    }

    int fds[2] = {-1, -1};
    int reply_fds[2] = {-1, -1};
    /* Daemon-owned uplink writes use sigpipe_safe_write: it scopes SIGPIPE
     * blocking to the calling thread and never changes the host disposition. */
    bool pipes_ok = true;
    if (pipe_init) {
        pipes_ok = create_pipe_pair(fds) && create_pipe_pair(reply_fds);
    }
    if (pipe_init && pipes_ok) {
        g_agent_log_read_fd = fds[0];
        g_agent_log_fd = fds[1];
        int flags = fcntl(g_agent_log_fd, F_GETFL, 0);
        g_downlink_transport_epoch.fetch_add(1, std::memory_order_acq_rel);
        g_state_reply_fd = reply_fds[0];
        g_state_reply_write_fd = reply_fds[1];
        int reply_flags = fcntl(g_state_reply_fd, F_GETFL, 0);
        pipes_ok = flags >= 0 && reply_flags >= 0
                   && fcntl(g_agent_log_fd, F_SETFL, flags | O_NONBLOCK) == 0
                   && fcntl(g_state_reply_fd, F_SETFL, reply_flags | O_NONBLOCK) == 0;
    }
    if (pipe_init && !pipes_ok) {
        for (int fd : {fds[0], fds[1], reply_fds[0], reply_fds[1]}) {
            if (fd >= 0 && fd != g_agent_log_read_fd && fd != g_agent_log_fd
                && fd != g_state_reply_fd && fd != g_state_reply_write_fd) {
                close(fd);
            }
        }
        reset_pre_resident_bootstrap();
        { vbi_fail_log(__LINE__); return IMPLANT_INIT_FAILED; }
    }

    IMPLANT_LOGD("implant_init: start (cfg=%s)", cfg ? cfg : "(null)");

    /* Two-phase bootstrap: the first remote call only establishes the pipe
     * pair. The daemon adopts both ends, streams the verified envelope, then
     * calls implant_init again. No generation path is opened by the target. */
    if (pipe_init) {
        g_pipe_bootstrap_channel_ready = true;
        return g_agent_log_read_fd;
    }
    if (g_pipe_bootstrap.manifest.empty()) {
        int flags = fcntl(g_state_reply_fd, F_GETFL, 0);
        if (flags < 0 || fcntl(g_state_reply_fd, F_SETFL, flags & ~O_NONBLOCK) != 0) {
            return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
        }
        PipeBootstrapReadDiag diag = {nullptr, 0};
        if (!read_pipe_bootstrap_diag(g_state_reply_fd, &g_pipe_bootstrap, &diag)) {
            IMPLANT_LOGE("pipe bootstrap read failed: stage=%s errno=%d fd=%d",
                         diag.stage ? diag.stage : "unknown", diag.error,
                         g_state_reply_fd);
            return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
        }
        if (fcntl(g_state_reply_fd, F_SETFL, flags | O_NONBLOCK) != 0) {
            return fail_bootstrap_attempt(IMPLANT_INIT_FAILED);
        }
        g_pipe_bootstrap_ready = true;
    }

    return stage_bootstrap_worker();
}

static void cleanup_failed_implant_init() noexcept {
    reset_pre_resident_bootstrap();
}

#ifdef VOBOOST_IMPLANT_HOST_TEST
extern "C" {
int vbi_implant_test_throw = 0;
}
#endif

extern "C" __attribute__((visibility("default")))
int implant_init(const char *cfg) noexcept {
    try {
#ifdef VOBOOST_IMPLANT_HOST_TEST
        if (vbi_implant_test_throw != 0) {
            vbi_implant_test_throw = 0;
            throw std::bad_alloc();
        }
#endif
        return implant_init_impl(cfg);
    } catch (const std::exception &vbi_e) {
        IMPLANT_LOGE("implant_init exception: %s", vbi_e.what());
        cleanup_failed_implant_init();
        { vbi_fail_log(__LINE__); return IMPLANT_INIT_FAILED; }
    } catch (...) {
        IMPLANT_LOGE("implant_init unknown exception");
        cleanup_failed_implant_init();
        { vbi_fail_log(__LINE__); return IMPLANT_INIT_FAILED; }
    }
}

extern "C" __attribute__((visibility("default")))
unsigned int implant_finish_log_handoff(int accepted) noexcept {
    g_vehicle_transport_live.store((accepted & 3) == 3 && g_state_reply_fd >= 0 && g_agent_log_fd >= 0, std::memory_order_release);
    if (g_agent_log_read_fd >= 0) {
        close(g_agent_log_read_fd);
        g_agent_log_read_fd = -1;
    }
    if (!(accepted & 1) && g_agent_log_fd >= 0) {
        close(g_agent_log_fd);
        g_agent_log_fd = -1;
    }
    if (g_state_reply_write_fd >= 0) {
        close(g_state_reply_write_fd);
        g_state_reply_write_fd = -1;
    }
    if (!(accepted & 2) && g_state_reply_fd >= 0) {
        close(g_state_reply_fd);
        g_state_reply_fd = -1;
    }
    return VBI_HANDOFF_ACK;
}

/* Target-local number of the log pipe read-end, or -1 when no pipe exists.
 * The injector calls this after IMPLANT_INIT_FAILED: the sentinel return
 * code carries no fd number, yet the implant keeps the pipe open with the
 * init diagnostics already written into it. The injector duplicates this
 * fd via /proc so the daemon can drain the diagnostics through its normal
 * log router (agent-logging contract: all diagnostics ride the pipe). */
extern "C" __attribute__((visibility("default")))
int implant_log_read_fd(void) {
    return g_agent_log_read_fd;
}

extern "C" __attribute__((visibility("default")))
int implant_state_reply_write_fd(void) {
    return g_state_reply_write_fd;
}

/* JNI_OnLoad is intentionally NOT used for startup.
 * The injector calls implant_init explicitly. If a Java dlopen loads this
 * .so, JNI_OnLoad is a no-op (it must not run the startup chain twice). */
JNIEXPORT jint JNI_OnLoad(JavaVM * /*vm*/, void * /*reserved*/) {
    return JNI_VERSION_1_6;
}
