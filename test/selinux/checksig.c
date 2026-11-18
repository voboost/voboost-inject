/* checksig.c — standalone appended-signature verifier (host test helper).
 * Usage: checksig <file>  → exit 0 if the VOBOOST trailer signature is valid
 * against the embedded release pubkey, exit 1 otherwise. Never executes the
 * checked file, so a tampered ELF cannot wedge the test runner. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "tweetnacl.h"

static const unsigned char PK[] = {EMBEDDED_PUBKEY_HEX};

int main(int argc, char **argv)
{
    if (argc != 2)
        return 2;
    FILE *f = fopen(argv[1], "rb");
    if (!f)
        return 2;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    rewind(f);
    if (sz < 80)
        return 1;
    unsigned char *buf = malloc((size_t)sz);
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz)
        return 2;
    fclose(f);
    unsigned char *t = buf + sz - 80;
    unsigned long long off = 0;
    for (int i = 0; i < 8; i++)
        off |= (unsigned long long)t[8 + i] << (8 * i);
    if (memcmp(t, "VOBOOST\0", 8) != 0 || off != (unsigned long long)(sz - 80))
        return 1;
    static const unsigned char domain[] = "voboost-native-executable-v1";
    static const unsigned char role[] = "selinux";
    size_t transcript_len = sizeof(domain) + sizeof(role) + 8 + (size_t)off;
    unsigned char *sm = malloc(transcript_len + 64);
    memcpy(sm, t + 16, 64);
    size_t cursor = 64;
    memcpy(sm + cursor, domain, sizeof(domain)); cursor += sizeof(domain);
    memcpy(sm + cursor, role, sizeof(role)); cursor += sizeof(role);
    for (int i = 0; i < 8; i++) sm[cursor + i] = (unsigned char)(off >> (8 * i));
    cursor += 8;
    memcpy(sm + cursor, buf, (size_t)off);
    unsigned char *m = malloc(transcript_len + 64);
    unsigned long long ml = 0;
    int ok = crypto_sign_open(m, &ml, sm, (unsigned long long)transcript_len + 64, PK) == 0;
    free(sm);
    free(m);
    free(buf);
    return ok ? 0 : 1;
}
