/*
 * dirname_test.cpp — host unit-test for dirname_of (implant/dirname.h).
 *
 * Pure string logic, no C++ runtime/LSPlant/JNI. Silent on success (codestyle).
 *
 * Build (see Makefile target test-implant):
 *   <host-c++> -std=c++20 -I implant -Wall -Wextra -Werror \
 *       implant/dirname_test.cpp -o build/dirname_test
 */

#include "dirname.h"

#include <cassert>
#include <cstdio>
#include <cstring>

static int failures = 0;

static void check_eq(const std::string &got, const char *want, const char *label) {
    if (got != want) {
        fprintf(stderr, "FAIL %-28s got=\"%s\" want=\"%s\"\n", label, got.c_str(), want);
        failures++;
    }
}

int main(void) {
    check_eq(dirname_of("/data/voboost-inject/payload/arm64-v8a/libimplant.so"),
             "/data/voboost-inject/payload/arm64-v8a", "full path");
    check_eq(dirname_of("/a/b/libimplant.so"), "/a/b", "simple path");
    check_eq(dirname_of("/libimplant.so"), "", "root only -> empty");
    check_eq(dirname_of("libimplant.so"), "", "no slash -> empty");
    check_eq(dirname_of(""), "", "empty string");
    check_eq(dirname_of(nullptr), "", "null -> empty");
    check_eq(dirname_of("/a/b/"), "/a/b", "trailing slash");
    check_eq(dirname_of("/a/b//"), "/a/b/", "double trailing slash");

    if (failures) {
        fprintf(stderr, "%d check(s) failed\n", failures);
        return 1;
    }
    return 0;
}
