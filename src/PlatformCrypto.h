#pragma once

#include <stdbool.h>

// Retain backwards compatibility with older USE_MBEDTLS
#if defined(USE_MBEDTLS) && !defined(USE_PSA_CRYPTO)
#define USE_PSA_CRYPTO
#endif

#ifdef USE_PSA_CRYPTO
#include <psa/crypto.h>
#else
// Hide the real OpenSSL definition from other code
typedef struct evp_cipher_ctx_st EVP_CIPHER_CTX;
#endif

typedef struct _PLT_CRYPTO_CONTEXT {
#ifdef USE_PSA_CRYPTO
    psa_key_id_t key;
    psa_cipher_operation_t cipherOp;
    bool initialized;
    bool cipherOpActive;
#else
    EVP_CIPHER_CTX* ctx;
    bool initialized;
#endif
} PLT_CRYPTO_CONTEXT, *PPLT_CRYPTO_CONTEXT;

#define ROUND_TO_PKCS7_PADDED_LEN(x) ((((x) + 15) / 16) * 16)

PPLT_CRYPTO_CONTEXT PltCreateCryptoContext(void);
void PltDestroyCryptoContext(PPLT_CRYPTO_CONTEXT ctx);

#define ALGORITHM_AES_CBC 1
#define ALGORITHM_AES_GCM 2

#define CIPHER_FLAG_RESET_IV          0x01
#define CIPHER_FLAG_FINISH            0x02
#define CIPHER_FLAG_PAD_TO_BLOCK_SIZE 0x04

bool PltEncryptMessage(PPLT_CRYPTO_CONTEXT ctx, int algorithm, int flags,
                       unsigned char* key, int keyLength,
                       unsigned char* iv, int ivLength,
                       unsigned char* tag, int tagLength,
                       unsigned char* inputData, int inputDataLength,
                       unsigned char* outputData, int* outputDataLength);

bool PltDecryptMessage(PPLT_CRYPTO_CONTEXT ctx, int algorithm, int flags,
                       unsigned char* key, int keyLength,
                       unsigned char* iv, int ivLength,
                       unsigned char* tag, int tagLength,
                       unsigned char* inputData, int inputDataLength,
                       unsigned char* outputData, int* outputDataLength);

// One-shot helpers used by client roaming (fresh context per call, no state)
bool PltAes128EncryptBlock(const unsigned char key[16], const unsigned char in[16], unsigned char out[16]);

bool PltAes128GcmSealAad(const unsigned char key[16], const unsigned char iv[12],
                         const unsigned char* aad, int aadLength,
                         const unsigned char* in, int dataLength,
                         unsigned char* out, unsigned char tag[16]);

bool PltAes128GcmOpenAad(const unsigned char key[16], const unsigned char iv[12],
                         const unsigned char* aad, int aadLength,
                         const unsigned char* in, int dataLength,
                         const unsigned char tag[16], unsigned char* out);

void PltGenerateRandomData(unsigned char* data, int length);
