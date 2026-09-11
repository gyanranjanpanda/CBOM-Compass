/* Windows CNG and the older CryptoAPI. */
#include <windows.h>
#include <bcrypt.h>
#include <wincrypt.h>

void open_algorithms(void) {
    BCRYPT_ALG_HANDLE h = NULL;
    BCryptOpenAlgorithmProvider(&h, BCRYPT_RSA_ALGORITHM, NULL, 0);
    BCryptOpenAlgorithmProvider(&h, BCRYPT_AES_ALGORITHM, NULL, 0);
    BCryptOpenAlgorithmProvider(&h, BCRYPT_SHA1_ALGORITHM, NULL, 0);
}

void legacy_capi(HCRYPTPROV prov) {
    HCRYPTHASH hash;
    CryptCreateHash(prov, CALG_MD5, 0, 0, &hash);
    HCRYPTKEY key;
    CryptGenKey(prov, CALG_RC4, 0, &key);
}
