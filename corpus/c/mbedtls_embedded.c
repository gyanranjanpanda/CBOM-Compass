/* mbedTLS on a constrained device — the migration case with the longest Y. */
#include "mbedtls/aes.h"
#include "mbedtls/sha256.h"
#include "mbedtls/cipher.h"

static mbedtls_aes_context aes;

int provision(const unsigned char *key) {
    mbedtls_aes_setkey_enc(&aes, key, 128);
    return 0;
}

void fingerprint(const unsigned char *in, size_t len, unsigned char *out) {
    mbedtls_sha256(in, len, out, 0);
}

void legacy_fingerprint(const unsigned char *in, size_t len, unsigned char *out) {
    mbedtls_md5(in, len, out);
}

const mbedtls_cipher_type_t suite = MBEDTLS_CIPHER_AES_256_GCM;
const mbedtls_ecp_group_id group = MBEDTLS_ECP_DP_SECP384R1;
