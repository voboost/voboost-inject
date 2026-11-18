#ifndef LOADER_PROBE_H
#define LOADER_PROBE_H

#include <jni.h>
#include <stddef.h>
#include <string.h>

/* Outcome of resolving a candidate ClassLoader's runtime class name on the
 * hijacked target thread.
 *
 * Reproducer: tombstone 2026-09-14, com.qinggan.app.setting PID 3190,
 * SIGABRT "No pending exception expected: java.lang.NoSuchMethodError:
 * no non-static method Ldalvik/system/PathClassLoader;.getName()". The
 * crashed lookup resolved the loader NAME via GetMethodID(loaderClass,
 * "getName", ...): a ClassLoader instance has no getName. A class name is
 * Class.getName(), an instance method of java/lang/Class, invoked on the
 * jclass returned by GetObjectClass(loader). The failed lookup left its
 * NoSuchMethodError pending on the thread; the target's own
 * handleBindApplication later crossed a JNI boundary, found the foreign
 * pending exception and aborted the process. */
enum class LoaderProbeOutcome {
    /* An exception was already pending when the probe started. It belongs to
     * the target thread, not to the implant: the probe leaves it pending and
     * performs no other JNI call. The caller must abort the whole attempt
     * without running further Java code or clearing it. */
    PENDING_INCOMING,
    /* The name resolved and names the boot class loader: the candidate cannot
     * load app classes and must be skipped. */
    IS_BOOT_CLASSLOADER,
    /* The name resolved and it is not the boot class loader. */
    NOT_BOOT_CLASSLOADER,
    /* One of the probe's own JNI steps failed or the name could not be read.
     * Any exception raised by the probe itself was cleared before returning.
     * An unreadable name proves nothing about the loader: the candidate must
     * NOT be accepted as an app class loader. */
    PROBE_FAILED,
};

/* Copies `source` into `out` bounded by `size`, always NUL-terminating. */
static inline void loader_probe_copy_name(char *out, size_t size,
                                          const char *source) {
    if (out == nullptr || size == 0) {
        return;
    }
    size_t i = 0;
    for (; i + 1 < size && source[i] != '\0'; ++i) {
        out[i] = source[i];
    }
    out[i] = '\0';
}

/* Resolves the runtime class name of `candidate_loader` via
 * Class.getName() on its jclass without creating anything and without
 * leaving an implant-owned exception pending. On a resolved outcome the
 * dotted name is copied into `out_name` for diagnostics. Every local
 * reference created by the probe is released before returning. */
static inline LoaderProbeOutcome probe_loader_class_name(JNIEnv *env,
                                                         jobject candidate_loader,
                                                         char *out_name,
                                                         size_t out_name_size) {
    loader_probe_copy_name(out_name, out_name_size, "");
    if (env->ExceptionCheck()) {
        return LoaderProbeOutcome::PENDING_INCOMING;
    }
    if (candidate_loader == nullptr) {
        return LoaderProbeOutcome::PROBE_FAILED;
    }
    jclass loader_class = env->GetObjectClass(candidate_loader);
    if (loader_class == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        return LoaderProbeOutcome::PROBE_FAILED;
    }
    /* Class.getName() is declared by java/lang/Class and runs on the jclass
     * receiver; the loader's own class declares no getName. */
    jclass java_class = env->FindClass("java/lang/Class");
    if (java_class == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(loader_class);
        return LoaderProbeOutcome::PROBE_FAILED;
    }
    jmethodID get_name = env->GetMethodID(java_class, "getName",
                                          "()Ljava/lang/String;");
    if (get_name == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(java_class);
        env->DeleteLocalRef(loader_class);
        return LoaderProbeOutcome::PROBE_FAILED;
    }
    jstring name = (jstring)env->CallObjectMethod(loader_class, get_name);
    if (name == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(java_class);
        env->DeleteLocalRef(loader_class);
        return LoaderProbeOutcome::PROBE_FAILED;
    }
    const char *chars = env->GetStringUTFChars(name, nullptr);
    if (chars == nullptr || env->ExceptionCheck()) {
        env->ExceptionClear();
        env->DeleteLocalRef(name);
        env->DeleteLocalRef(java_class);
        env->DeleteLocalRef(loader_class);
        return LoaderProbeOutcome::PROBE_FAILED;
    }
    bool is_boot = false;
    for (const char *c = chars; *c != '\0'; ++c) {
        if (strncmp(c, "BootClassLoader", sizeof("BootClassLoader") - 1) == 0) {
            is_boot = true;
            break;
        }
    }
    loader_probe_copy_name(out_name, out_name_size, chars);
    env->ReleaseStringUTFChars(name, chars);
    env->DeleteLocalRef(name);
    env->DeleteLocalRef(java_class);
    env->DeleteLocalRef(loader_class);
    if (env->ExceptionCheck()) {
        env->ExceptionClear();
        return LoaderProbeOutcome::PROBE_FAILED;
    }
    return is_boot ? LoaderProbeOutcome::IS_BOOT_CLASSLOADER
                   : LoaderProbeOutcome::NOT_BOOT_CLASSLOADER;
}

#endif /* LOADER_PROBE_H */
