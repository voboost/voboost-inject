/*
 * dirname.h — pure directory-prefix helper (host-testable).
 *
 * Returns the directory prefix of a path (everything up to the last '/'), or
 * an empty string if the path has no '/'. Used by the implant to resolve its
 * payload directory from its own loaded path (native-payload: load
 * payload-shipped native deps by full path). Inline so it can be unit-tested
 * on the host with no C++ runtime/LSPlant/JNI dependency.
 */
#ifndef VOBOOST_INJECT_DIRNAME_H
#define VOBOOST_INJECT_DIRNAME_H

#include <string>

static inline std::string dirname_of(const char *path) {
    if (!path) {
        return {};
    }
    std::string s(path);
    size_t pos = s.find_last_of('/');
    if (pos == std::string::npos) {
        return {};
    }
    return s.substr(0, pos);
}

#endif /* VOBOOST_INJECT_DIRNAME_H */
