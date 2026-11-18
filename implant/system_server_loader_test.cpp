#include "system_server_loader.h"
#include <cassert>

int main() {
    BootstrapDescriptor bootstrap;
    bootstrap.modules.push_back({"launcher", "Launcher", {"system_server"}, "", -1});
    assert(system_server_bootstrap_authorized(1000, "system_server", bootstrap));
    assert(!system_server_bootstrap_authorized(0, "system_server", bootstrap));
    assert(!system_server_bootstrap_authorized(1000, "com.example.application", bootstrap));
    bootstrap.modules[0].id = "font-cyrillic";
    assert(!system_server_bootstrap_authorized(1000, "system_server", bootstrap));
    bootstrap.modules[0].id = "launcher";
    bootstrap.modules[0].processes = {"com.qinggan.app.launcher"};
    assert(!system_server_bootstrap_authorized(1000, "system_server", bootstrap));
    bootstrap.modules[0].processes = {"system_server"};
    bootstrap.executors.push_back({});
    assert(!system_server_bootstrap_authorized(1000, "system_server", bootstrap));
    assert(system_server_framework_jar("/system/framework/services.jar"));
    assert(!system_server_framework_jar("/data/local/tmp/services.jar"));
    assert(!system_server_framework_jar("/system/framework/../services.jar"));
    assert(!system_server_framework_jar("/system/framework/services.dex"));
}
