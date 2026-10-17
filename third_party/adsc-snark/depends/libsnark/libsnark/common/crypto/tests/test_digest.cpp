/** @file
 *****************************************************************************
 Test digest routines

 *****************************************************************************/
#include <cassert>
#include <iostream>
#include <iomanip>

#include <openssl/sha.h>

#include "libff/common/profiling.hpp"
#include "libsnark/common/crypto/digest/sha.hpp"

std::vector<uint8_t> digest_sha256_chunks_oldapi(const std::vector<std::vector<uint8_t>>& chunks) {
    std::vector<uint8_t> hash(SHA256_DIGEST_LENGTH);

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    for (const auto& chunk : chunks) {
        SHA256_Update(&sha256, chunk.data(), chunk.size());
    }

    SHA256_Final(hash.data(), &sha256);

    return hash;
}

std::vector<uint8_t> digest_sha256_oldapi(const std::vector<uint8_t>& data) {
    return digest_sha256_chunks_oldapi({data});
}

std::vector<uint8_t> digest_sha512_chunks_oldapi(const std::vector<std::vector<uint8_t>>& chunks) {
    std::vector<uint8_t> hash(SHA512_DIGEST_LENGTH);

    SHA512_CTX sha512;
    SHA512_Init(&sha512);

    for (const auto& chunk : chunks) {
        SHA512_Update(&sha512, chunk.data(), chunk.size());
    }

    SHA512_Final(hash.data(), &sha512);

    return hash;
}

std::vector<uint8_t> digest_sha512_oldapi(const std::vector<uint8_t>& data) {
    return digest_sha512_chunks_oldapi({data});
}

#ifndef NDEBUG
void test_sha256(size_t size)
{
    libff::enter_block("Test SHA256");
    std::vector<uint8_t> data;
    for (size_t i = 0; i < size; ++i){
        data.push_back((uint8_t) i);
    }

    libff::enter_block("New API");
    std::vector<uint8_t> hash1 = libsnark::digest_sha256(data);
    libff::leave_block("New API");
    libff::enter_block("Old API");
    std::vector<uint8_t> hash2 = digest_sha256_oldapi(data);
    libff::leave_block("Old API");
    std::cout << "Hash1 ";
    for (const auto& byte : hash1) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::endl << "Hash2 ";
    for (const auto& byte : hash2) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::endl;

    assert(hash1 == hash2);

    libff::leave_block("Test SHA256");
}

void test_sha512(size_t size)
{
    libff::enter_block("Test SHA512");
    std::vector<uint8_t> data;
    for (size_t i = 0; i < size; ++i){
        data.push_back((uint8_t) i);
    }

    libff::enter_block("New API");
    std::vector<uint8_t> hash1 = libsnark::digest_sha512(data);
    libff::leave_block("New API");
    libff::enter_block("Old API");
    std::vector<uint8_t> hash2 = digest_sha512_oldapi(data);
    libff::leave_block("Old API");
    std::cout << "Hash1 ";
    for (const auto& byte : hash1) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::endl << "Hash2 ";
    for (const auto& byte : hash2) {
        std::cout << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(byte);
    }
    std::cout << std::endl;
    assert(hash1 == hash2);

    libff::leave_block("Test SHA512");
}

int main()
{
    libff::start_profiling();
    test_sha512(100);
    test_sha256(100);
}
#else // NDEBUG
int main()
{
    printf("All tests here depend on assert() which is disabled by -DNDEBUG. Please recompile and run again.\n");
}
#endif // NDEBUG
