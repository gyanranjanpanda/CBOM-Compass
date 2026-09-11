/* Nothing cryptographic. Names that look close but are not. */
#include <stdio.h>

struct aes_config { int unused; };     /* a type name, not a call */
static const char *DESCRIPTION = "data encryption summary";
static int shackle = 1;                /* contains 'sha' */

int checksum(const unsigned char *b, size_t n) {
    int acc = 0;
    for (size_t i = 0; i < n; i++) acc += b[i];
    return acc;
}

/* EVP_aes_128_cbc() appears only in this comment. */
