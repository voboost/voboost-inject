#ifndef JNI_ATTACHMENT_H
#define JNI_ATTACHMENT_H

enum class JniAttachmentDecision {
    PRE_ATTACHED,
    ATTACH,
    FAIL,
};

static inline JniAttachmentDecision jni_attachment_decision(int get_env_result,
                                                            int jni_ok,
                                                            int jni_edetached) {
    if (get_env_result == jni_ok) {
        return JniAttachmentDecision::PRE_ATTACHED;
    }
    if (get_env_result == jni_edetached) {
        return JniAttachmentDecision::ATTACH;
    }
    return JniAttachmentDecision::FAIL;
}

static inline bool jni_attachment_is_owned(JniAttachmentDecision decision,
                                           bool attach_succeeded) {
    return decision == JniAttachmentDecision::ATTACH && attach_succeeded;
}

static inline int jni_detach_result(bool owned, int detach_result, int jni_ok,
                                    int result, int failed_result) {
    return !owned || detach_result == jni_ok ? result : failed_result;
}

#endif /* JNI_ATTACHMENT_H */
