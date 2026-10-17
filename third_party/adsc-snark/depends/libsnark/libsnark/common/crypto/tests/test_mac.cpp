/** @file
 *****************************************************************************
 Test mac routines

 *****************************************************************************/
#include <cassert>
#include <iostream>
#include <iomanip>

#include <libff/common/profiling.hpp>
#include <libff/common/serialization.hpp>
#include <libff/common/default_types/ec_pp.hpp>

#include "libsnark/common/crypto/mac/hmac.hpp"


#ifndef NDEBUG

using namespace libsnark;

void test_hmac_sha256(size_t size, bool serialize)
{
    libff::enter_block("Test HMAC SHA256");
    std::vector<uint8_t> data;
    for (size_t i = 0; i < size; ++i){
        data.push_back((uint8_t) i);
    }

    libff::enter_block("generate keys");
    hmac_sha256_key key = hmac_sha256_generate_key();
    libff::leave_block("generate keys");

    hmac_sha256_key key2;

    if (serialize){
        key2 = libff::reserialize(key);
        assert(key2 == key);
    } else {
        key2 = key;
    }
    std::cout << "Key size: " << key2.size_in_bits() << std::endl;
    std::cout << "Key serialized size: " << libff::get_serialized_size(key2) << std::endl;

    libff::enter_block("sign");
    hmac_sha256_mac mac = hmac_sha256_compute_mac(key2, data);
    libff::leave_block("sign");

    hmac_sha256_mac mac2;
    if (serialize){
        mac2 = libff::reserialize(mac);
        assert(mac2 == mac);
    } else {
        mac2 = mac;
    }
    std::cout << "MAC size: " << mac2.size_in_bits() << std::endl;
    std::cout << "MAC serialized size: " << libff::get_serialized_size(mac2) << std::endl;

    libff::enter_block("verify");
    bool verifies = hmac_sha256_verify_mac(key2, mac2, data);
    libff::leave_block("verify");

    assert(verifies);

    libff::leave_block("Test HMAC SHA256");
}


int main()
{
    libff::start_profiling();
    test_hmac_sha256(1000, true);
}
#else // NDEBUG
int main()
{
    printf("All tests here depend on assert() which is disabled by -DNDEBUG. Please recompile and run again.\n");
}
#endif // NDEBUG
