#ifndef SCOPED_JNI_ATTACHMENT_H
#define SCOPED_JNI_ATTACHMENT_H

#include "jni_attachment.h"

template <typename Vm, typename Env>
class ScopedJniAttachment {
public:
using Diagnostic = void (*)();

ScopedJniAttachment(Vm *vm, int jni_ok, int jni_edetached,
                    int jni_version, int failed_result,
                    Diagnostic detach_failure)
    : vm_(vm), jni_ok_(jni_ok), failed_result_(failed_result),
    detach_failure_(detach_failure) {
    int get_env_result = vm_->GetEnv((void **)&env_, jni_version);
    decision_ = jni_attachment_decision(get_env_result, jni_ok,
                                        jni_edetached);
    if (decision_ == JniAttachmentDecision::PRE_ATTACHED) {
        valid_ = true;
    } else if (decision_ == JniAttachmentDecision::ATTACH &&
               vm_->AttachCurrentThread(&env_, nullptr) == jni_ok_) {
        valid_ = true;
        owned_ = true;
    }
}

~ScopedJniAttachment() {
    if (owned_ && !finished_ && vm_->DetachCurrentThread() != jni_ok_) {
        diagnose_detach_failure();
    }
}

Env *env() const {
    return valid_ ? env_ : nullptr;
}

JniAttachmentDecision decision() const {
    return decision_;
}

int finish(int result) {
    if (finished_) {
        return failed_result_;
    }
    finished_ = true;
    int detach_result = owned_ ? vm_->DetachCurrentThread() : jni_ok_;
    int final_result = jni_detach_result(owned_, detach_result, jni_ok_,
                                         result, failed_result_);
    if (owned_ && detach_result != jni_ok_) {
        diagnose_detach_failure();
    }
    return final_result;
}

private:
void diagnose_detach_failure() const {
    if (detach_failure_) {
        detach_failure_();
    }
}

Vm *vm_;
Env *env_ = nullptr;
int jni_ok_;
int failed_result_;
Diagnostic detach_failure_;
bool valid_ = false;
bool owned_ = false;
bool finished_ = false;
JniAttachmentDecision decision_ = JniAttachmentDecision::FAIL;
};

#endif /* SCOPED_JNI_ATTACHMENT_H */
