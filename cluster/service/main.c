static int same(const char *a, const char *b) {
    unsigned n = 0;
    if (!a || !b) {
        return 0;
    }
    while (a[n] && b[n] && a[n] == b[n] && n < 16) {
        ++n;
    }
    return n < 16 && a[n] == b[n];
}
extern int vbc_native_main(const char *, const char *, unsigned);
int main(int argc, const char *const *argv) {
    unsigned role;
    if (argc != 3) {
        return 2;
    }
    if (same(argv[1], "daemon")) {
        role = 0;
    }else if (same(argv[1], "prepare-boot")) {
        role = 4;
    }else if (same(argv[1], "prepare-stage")) {
        role = 5;
    }else if (same(argv[1], "observe-stock")) {
        role = 12;
    }else if (same(argv[1], "prepare-remove")) {
        role = 6;
    }else if (same(argv[1], "finish-remove")) {
        role = 7;
    }else if (same(argv[1], "finish-install")) {
        role = 8;
    }else if (same(argv[1], "observe-recover")) {
        role = 9;
    }else if (same(argv[1], "restore-offline")) {
        role = 11;
    }else if (same(argv[1], "repair-mode")) {
        role = 10;
    }else if (same(argv[1], "install")) {
        role = 1;
    }else if (same(argv[1], "restore")) {
        role = 2;
    }else if (same(argv[1], "uninstall")) {
        role = 3;
    }else {
        return 2;
    }
    return vbc_native_main(argv[0], argv[2], role);
}
