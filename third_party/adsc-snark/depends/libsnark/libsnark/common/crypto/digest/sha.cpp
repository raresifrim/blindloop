#include <openssl/evp.h>


#include <iostream>
#include <stdexcept>

#include "sha.hpp"

namespace libsnark {

std::vector<uint8_t> digest_sha256_chunks(const std::vector<std::vector<uint8_t>>& chunks) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    const EVP_MD *sha256 = EVP_sha256();
    size_t digest_length = EVP_MD_get_size(sha256);
    std::vector<uint8_t> hash(digest_length);

    try {
        if (EVP_DigestInit(ctx, sha256) != 1) {
            throw std::runtime_error("EVP_DigestInit failed");
        }

        for (const auto& chunk : chunks) {
            if (EVP_DigestUpdate(ctx, chunk.data(), chunk.size()) != 1) {
                throw std::runtime_error("EVP_DigestUpdate failed");
            }
        }

        if (EVP_DigestFinal(ctx, hash.data(), nullptr) != 1) {
            throw std::runtime_error("EVP_DigestFinal failed");
        }
    } catch (...) {
        EVP_MD_CTX_free(ctx);
        throw; // Re-throw exception after cleanup
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

std::vector<uint8_t> digest_sha256(const std::vector<uint8_t>& data) {
    return digest_sha256_chunks({data});
}

std::vector<uint8_t> digest_sha512_chunks(const std::vector<std::vector<uint8_t>>& chunks) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    const EVP_MD *sha512 = EVP_sha512();
    size_t digest_length = EVP_MD_get_size(sha512);
    std::vector<uint8_t> hash(digest_length);

    try {
        if (EVP_DigestInit(ctx, sha512) != 1) {
            throw std::runtime_error("EVP_DigestInit failed");
        }

        for (const auto& chunk : chunks) {
            if (EVP_DigestUpdate(ctx, chunk.data(), chunk.size()) != 1) {
                throw std::runtime_error("EVP_DigestUpdate failed");
            }
        }

        if (EVP_DigestFinal(ctx, hash.data(), nullptr) != 1) {
            throw std::runtime_error("EVP_DigestFinal failed");
        }
    } catch (...) {
        EVP_MD_CTX_free(ctx);
        throw; // Re-throw exception after cleanup
    }

    EVP_MD_CTX_free(ctx);
    return hash;
}

std::vector<uint8_t> digest_sha512(const std::vector<uint8_t>& data) {
    return digest_sha512_chunks({data});
}

}