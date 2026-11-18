#include "loader_probe.h"

#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <cstring>
#include <string>
#include <type_traits>

/* Host fixtures for probe_loader_class_name against a hand-built JNIEnv.
 *
 * The crash this file reproduces (tombstone 2026-09-14, PID 3190):
 * GetMethodID(loaderClass, "getName", ...) on dalvik/system/PathClassLoader
 * returns null and raises NoSuchMethodError; the old caller continued JNI
 * work with that exception pending and the target later aborted with
 * "No pending exception expected". The fixed probe must resolve the name via
 * Class.getName() declared on java/lang/Class, invoked on the jclass, and
 * must leave no implant-owned exception pending in every outcome. */

namespace {

jobject loader_obj = (jobject)0x1001;
jclass loader_class_ref = (jclass)0x2001;      /* GetObjectClass(loader) */
jclass java_lang_class_ref = (jclass)0x2002;   /* FindClass("java/lang/Class") */
jmethodID get_name_mid = (jmethodID)0x3001;
jstring name_string_ref = (jstring)0x4001;

enum class FailMode {
    NONE,
    GET_OBJECT_CLASS,
    FIND_CLASS,
    GET_METHOD_ID,
    CALL_GET_NAME,
    STRING_CHARS,
};

struct Fake {
    bool pending = false;
    FailMode fail = FailMode::NONE;
    const char *name = "dalvik.system.PathClassLoader";

    int exception_clears = 0;
    int get_object_class_calls = 0;
    int released_string_chars = 0;
    int deleted_loader_class = 0;
    int deleted_java_class = 0;
    int deleted_name_string = 0;

    jclass get_method_id_receiver = nullptr;
    jobject call_receiver = nullptr;
    bool get_method_id_looked_on_loader_class = false;
    std::string get_method_id_signature;
};

Fake g;

jboolean JNICALL fake_ExceptionCheck(JNIEnv *) {
    return g.pending ? JNI_TRUE : JNI_FALSE;
}

void JNICALL fake_ExceptionClear(JNIEnv *) {
    g.pending = false;
    g.exception_clears++;
}

jclass JNICALL fake_GetObjectClass(JNIEnv *, jobject obj) {
    g.get_object_class_calls++;
    if (g.fail == FailMode::GET_OBJECT_CLASS) {
        g.pending = true;
        return nullptr;
    }
    if (obj == loader_obj) {
        return loader_class_ref;
    }
    return nullptr;
}

jclass JNICALL fake_FindClass(JNIEnv *, const char *name) {
    if (g.fail == FailMode::FIND_CLASS) {
        g.pending = true;
        return nullptr;
    }
    if (std::strcmp(name, "java/lang/Class") == 0) {
        return java_lang_class_ref;
    }
    return nullptr;
}

jmethodID JNICALL fake_GetMethodID(JNIEnv *, jclass cls, const char *name,
                                   const char *sig) {
    g.get_method_id_receiver = cls;
    g.get_method_id_signature = std::string(name) + sig;
    /* The reproducer lookup: getName resolved on the loader's own class
     * (PathClassLoader declares none) raises and returns null. */
    if (cls == loader_class_ref) {
        g.get_method_id_looked_on_loader_class = true;
        g.pending = true;
        return nullptr;
    }
    if (g.fail == FailMode::GET_METHOD_ID) {
        g.pending = true;
        return nullptr;
    }
    if (cls == java_lang_class_ref && std::strcmp(name, "getName") == 0
        && std::strcmp(sig, "()Ljava/lang/String;") == 0) {
        return get_name_mid;
    }
    g.pending = true;
    return nullptr;
}

jobject JNICALL fake_CallObjectMethodV(JNIEnv *, jobject receiver, jmethodID mid,
                                       va_list) {
    g.call_receiver = receiver;
    if (g.fail == FailMode::CALL_GET_NAME) {
        g.pending = true;
        return nullptr;
    }
    if (receiver == loader_class_ref && mid == get_name_mid) {
        return name_string_ref;
    }
    g.pending = true;
    return nullptr;
}

const char *JNICALL fake_GetStringUTFChars(JNIEnv *, jstring s, jboolean *) {
    if (g.fail == FailMode::STRING_CHARS) {
        g.pending = true;
        return nullptr;
    }
    if (s == name_string_ref) {
        return g.name;
    }
    return nullptr;
}

void JNICALL fake_ReleaseStringUTFChars(JNIEnv *, jstring s, const char *chars) {
    if (s == name_string_ref && chars == g.name) {
        g.released_string_chars++;
    }
}

void JNICALL fake_DeleteLocalRef(JNIEnv *, jobject ref) {
    if (ref == loader_class_ref) {
        g.deleted_loader_class++;
    } else if (ref == java_lang_class_ref) {
        g.deleted_java_class++;
    } else if (ref == name_string_ref) {
        g.deleted_name_string++;
    }
}

}  // namespace

int main() {
    /* Build the JNIEnv with the fake function table. */
    std::remove_cvref_t<decltype(*JNIEnv{}.functions)> iface{};
    iface.ExceptionCheck = &fake_ExceptionCheck;
    iface.ExceptionClear = &fake_ExceptionClear;
    iface.GetObjectClass = &fake_GetObjectClass;
    iface.FindClass = &fake_FindClass;
    iface.GetMethodID = &fake_GetMethodID;
    iface.CallObjectMethodV = &fake_CallObjectMethodV;
    iface.GetStringUTFChars = &fake_GetStringUTFChars;
    iface.ReleaseStringUTFChars = &fake_ReleaseStringUTFChars;
    iface.DeleteLocalRef = &fake_DeleteLocalRef;
    JNIEnv env_storage{};
    env_storage.functions = &iface;
    JNIEnv *env = &env_storage;

    /* 1. Successful probe on a real app loader class. */
    {
        g = Fake{};
        char name[128] = {"garbage"};
        LoaderProbeOutcome outcome =
            probe_loader_class_name(env, loader_obj, name, sizeof(name));
        assert(outcome == LoaderProbeOutcome::NOT_BOOT_CLASSLOADER);
        assert(std::strcmp(name, "dalvik.system.PathClassLoader") == 0);
        assert(!g.pending);
        assert(g.exception_clears == 0);
        assert(g.get_method_id_receiver == java_lang_class_ref);
        assert(g.get_method_id_signature == "getName()Ljava/lang/String;");
        assert(!g.get_method_id_looked_on_loader_class);
        assert(g.call_receiver == loader_class_ref);
        assert(g.released_string_chars == 1);
        assert(g.deleted_loader_class == 1 && g.deleted_java_class == 1
               && g.deleted_name_string == 1);
    }

    /* 2. Boot class loader is reported as such. */
    {
        g = Fake{};
        g.name = "java.lang.BootClassLoader";
        char name[128];
        LoaderProbeOutcome outcome =
            probe_loader_class_name(env, loader_obj, name, sizeof(name));
        assert(outcome == LoaderProbeOutcome::IS_BOOT_CLASSLOADER);
        assert(std::strcmp(name, "java.lang.BootClassLoader") == 0);
        assert(!g.pending);
        assert(g.exception_clears == 0);
    }

    /* 3. Null candidate (null Application/loader) fails without JNI use. */
    {
        g = Fake{};
        char name[8];
        assert(probe_loader_class_name(env, nullptr, name, sizeof(name))
               == LoaderProbeOutcome::PROBE_FAILED);
        assert(name[0] == '\0');
        assert(!g.pending);
        assert(g.get_object_class_calls == 0);
    }

    /* 4. Incoming pending exception: reported, never cleared, no probing. */
    {
        g = Fake{};
        g.pending = true;
        char name[8];
        assert(probe_loader_class_name(env, loader_obj, name, sizeof(name))
               == LoaderProbeOutcome::PENDING_INCOMING);
        assert(g.pending);  /* left exactly as found */
        assert(g.exception_clears == 0);
        assert(g.get_object_class_calls == 0);
    }

    /* 5. Every failing own step: PROBE_FAILED with the probe's own exception
     * cleared and all created local references released. */
    const FailMode failures[] = {
        FailMode::GET_OBJECT_CLASS, FailMode::FIND_CLASS,
        FailMode::GET_METHOD_ID, FailMode::CALL_GET_NAME,
        FailMode::STRING_CHARS,
    };
    for (FailMode mode : failures) {
        g = Fake{};
        g.fail = mode;
        char name[8] = {"!"};
        LoaderProbeOutcome outcome =
            probe_loader_class_name(env, loader_obj, name, sizeof(name));
        assert(outcome == LoaderProbeOutcome::PROBE_FAILED);
        assert(name[0] == '\0');
        assert(!g.pending);  /* no implant-owned exception survives */
        assert(g.exception_clears == 1);
    }

    /* 6. Reference ownership per failure point. */
    {
        g = Fake{};
        g.fail = FailMode::GET_OBJECT_CLASS;
        probe_loader_class_name(env, loader_obj, nullptr, 0);
        assert(g.deleted_loader_class == 0 && g.deleted_java_class == 0);
    }
    {
        g = Fake{};
        g.fail = FailMode::FIND_CLASS;
        probe_loader_class_name(env, loader_obj, nullptr, 0);
        assert(g.deleted_loader_class == 1 && g.deleted_java_class == 0);
    }
    {
        g = Fake{};
        g.fail = FailMode::CALL_GET_NAME;
        probe_loader_class_name(env, loader_obj, nullptr, 0);
        assert(g.deleted_loader_class == 1 && g.deleted_java_class == 1
               && g.deleted_name_string == 0);
    }
    {
        g = Fake{};
        g.fail = FailMode::STRING_CHARS;
        probe_loader_class_name(env, loader_obj, nullptr, 0);
        assert(g.deleted_loader_class == 1 && g.deleted_java_class == 1
               && g.deleted_name_string == 1);
    }

    /* 7. Bounded copy: long names truncate NUL-terminated, zero-size and
     * null buffers are safe. */
    {
        g = Fake{};
        g.name = "dalvik.system.PathClassLoader$VeryLongSuffixClassName";
        char small[16];
        probe_loader_class_name(env, loader_obj, small, sizeof(small));
        assert(std::strlen(small) == sizeof(small) - 1);
        char zero[1] = {'x'};
        probe_loader_class_name(env, loader_obj, zero, 0);
        assert(zero[0] == 'x');  /* untouched */
        probe_loader_class_name(env, loader_obj, nullptr, 16);
        assert(!g.pending);
    }

    /* 8. Retry after a failed probe (daemon retry after Deferred): the same
     * env recovers and resolves a real loader on the second attempt. */
    {
        g = Fake{};
        g.fail = FailMode::GET_METHOD_ID;
        char name[128];
        assert(probe_loader_class_name(env, loader_obj, name, sizeof(name))
               == LoaderProbeOutcome::PROBE_FAILED);
        assert(!g.pending);
        g.fail = FailMode::NONE;
        assert(probe_loader_class_name(env, loader_obj, name, sizeof(name))
               == LoaderProbeOutcome::NOT_BOOT_CLASSLOADER);
        assert(!g.pending);
    }

    /* 9. The reproducer itself: a getName lookup attempted on the loader's
     * own class raises in the fake exactly like ART did. The probe never
     * performs that lookup; forcing it once proves the fake models the
     * crash and that any such exception is cleared, not carried. */
    {
        g = Fake{};
        assert(fake_GetMethodID(env, loader_class_ref, "getName",
                                "()Ljava/lang/String;")
               == nullptr);
        assert(g.pending);  /* NoSuchMethodError raised, as in the tombstone */
        env->ExceptionClear();
        assert(!g.pending);
        g.get_method_id_looked_on_loader_class = false;
        char name[128];
        assert(probe_loader_class_name(env, loader_obj, name, sizeof(name))
               == LoaderProbeOutcome::NOT_BOOT_CLASSLOADER);
        assert(!g.get_method_id_looked_on_loader_class);
    }

    std::fprintf(stderr, "loader_probe_test: all checks passed\n");
    return 0;
}
