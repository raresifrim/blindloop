#include "hmac.hpp"
#include <iostream>
#include <istream>
#include <iomanip>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <libff/common/serialization.hpp>

namespace libsnark {

    std::ostream& operator<<(std::ostream &out, const hmac_sha256_mac &mac) {
        libff::output_bytes(out, mac.mac_bytes);
        return out;
    }

    std::istream& operator>>(std::istream &in, hmac_sha256_mac &mac) {
        libff::input_bytes(in, mac.mac_bytes);
        return in;
    }

    std::ostream& operator<<(std::ostream &out, const hmac_sha256_key &key) {
        libff::output_bytes(out, key.key_bytes);
        return out;
    }

    std::istream& operator>>(std::istream &in, hmac_sha256_key &key) {
        libff::input_bytes(in, key.key_bytes);
        return in;
    }

    hmac_sha256_key hmac_sha256_generate_key(size_t key_size) {
        std::vector<uint8_t> key(key_size);
        if (RAND_bytes(key.data(), key_size) != 1) {
            throw std::runtime_error("Failed to generate random key");
        }
        return hmac_sha256_key(std::move(key));
    }

    hmac_sha256_mac hmac_sha256_compute_mac(const hmac_sha256_key &key, const std::vector<uint8_t> &msg) {
        unsigned int mac_length = EVP_MAX_MD_SIZE;
        std::vector<uint8_t> mac(mac_length);

        if (!HMAC(EVP_sha256(), key.key_bytes.data(), key.key_bytes.size(), msg.data(), msg.size(), mac.data(), &mac_length)) {
            throw std::runtime_error("Failed to compute HMAC");
        }

        mac.resize(mac_length);
        return hmac_sha256_mac(std::move(mac));
    }

    bool hmac_sha256_verify_mac(const hmac_sha256_key &key, const hmac_sha256_mac &mac, const std::vector<uint8_t> &msg) {
        hmac_sha256_mac computed_mac = hmac_sha256_compute_mac(key, msg);
        return mac == computed_mac;
    }

}
