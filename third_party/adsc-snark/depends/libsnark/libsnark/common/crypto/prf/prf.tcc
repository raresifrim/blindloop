/** @file
 *****************************************************************************
 *  Implementation of pseudo-random-function
 *
 *  See prf.hpp
 *****************************************************************************/

#ifndef PRF_TCC
#define PRF_TCC

#include <vector>
#include <assert.h>

#include <openssl/sha.h>
#include <openssl/conf.h>
#include <openssl/evp.h>

namespace libsnark {

template<typename FieldT>
FieldT prp(const FieldT key, size_t label) {

    std::vector<uint8_t> key_bytes = key.to_bytes();
    if (key_bytes.size() < 128 / 8){
        key_bytes.insert(key_bytes.end(), 128 / 8 - key_bytes.size(), 0);
    }

    assert(key_bytes.size() >= 128 / 8);
    uint8_t ciphertext[128 / 8];

    //This is mostly taken from the OpenSSL documentation
    int ciphertext_length = 0;
    int length = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    if (!ctx) {
        perror("EVP_CIPHER_CTX_new()");
        exit(-1);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, &key_bytes[0], NULL)) {
        perror("EVP_EncryptInit_ex()");
        exit(-1);
    }


    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &length, (unsigned char *) &label, sizeof(label))) {
        perror("EVP_EncryptUpdate()");
        exit(-1);
    }

    ciphertext_length += length;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + length, &length)) {
        perror("EVP_EncryptFinal_ex()");
        exit(-1);
    }

    ciphertext_length += length;
    EVP_CIPHER_CTX_free(ctx);

    FieldT result;
    std::vector<uint8_t> hash_bytes(ciphertext, ciphertext + 128 / 8);
    result.from_bytes(hash_bytes);

    return result;

}

}
#endif //PRF_TCC