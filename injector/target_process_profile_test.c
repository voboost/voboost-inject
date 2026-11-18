#include "target_process_profile.h"

#include <assert.h>

int main(void) {
    assert(vbi_target_app_process_path_matches("/system/bin/app_process64", 64));
    assert(vbi_target_app_process_path_matches("/system/bin/app_process64_real", 64));
    assert(vbi_target_app_process_path_matches("/system/bin/app_process32", 32));
    assert(vbi_target_app_process_path_matches("/system/bin/app_process32_real", 32));
    assert(!vbi_target_app_process_path_matches("/system/bin/app_process64", 32));
    assert(!vbi_target_app_process_path_matches("/system/bin/app_process32", 64));
    assert(!vbi_target_app_process_path_matches("/system/bin/not-app_process64", 64));
    assert(!vbi_target_app_process_path_matches("/system/bin/app_process64.old", 64));
    assert(!vbi_target_app_process_path_matches("/vendor/bin/app_process64", 64));
    assert(!vbi_target_app_process_path_matches("/system/bin/app_process64", 0));
    assert(!vbi_target_app_process_path_matches(NULL, 64));
    return 0;
}
