/* OpenSSL, the way it is actually written in production C. */
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/ec.h>

int seal(const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);
    return 0;
}

int legacy_seal(const unsigned char *key, const unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);
    EVP_EncryptInit_ex(ctx, EVP_rc4(), NULL, key, NULL);
    return 0;
}

void digests(void) {
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    EVP_DigestInit_ex(m, EVP_md5(), NULL);
    EVP_DigestInit_ex(m, EVP_sha1(), NULL);
    EVP_DigestInit_ex(m, EVP_sha384(), NULL);
}

RSA *weak_key(void) {
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();
    RSA_generate_key_ex(rsa, 1024, e, NULL);
    return rsa;
}

DH *params(void) {
    DH *dh = DH_new();
    DH_generate_parameters_ex(dh, 2048, DH_GENERATOR_2, NULL);
    return dh;
}

EC_KEY *curve(void) {
    return EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
}

/* Commented-out code is not cryptography in use:
   EVP_EncryptInit_ex(ctx, EVP_bf_cbc(), NULL, key, iv); */
