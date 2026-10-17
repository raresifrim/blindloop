/** @file
 *****************************************************************************
 *  Interface of digest functions
 *
 *  digest_sha256: SHA256 hash function, uses openssl
 *  digest_sha512: SHA512 hash function, uses openssl
 *****************************************************************************/

#ifndef SHA_HPP
#define SHA_HPP

#include <vector>
#include <cstdint>

namespace libsnark {

std::vector<uint8_t> digest_sha256_chunks(const std::vector<std::vector<uint8_t>>& chunks);

std::vector<uint8_t> digest_sha256(const std::vector<uint8_t>& data);

std::vector<uint8_t> digest_sha512_chunks(const std::vector<std::vector<uint8_t>>& chunks);

std::vector<uint8_t> digest_sha512(const std::vector<uint8_t>& data);

}

#endif //SHA_HPP
