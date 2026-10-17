/** @file
 *****************************************************************************
 *  Interface of a MAC (Message Authentication Code) using HMAC-SHA256
 *
 *  Algorithm: HMAC with SHA-256 using OpenSSL
 *****************************************************************************/

#ifndef HMAC_SHA256_HPP
#define HMAC_SHA256_HPP

#include <vector>
#include <stdexcept>
#include <openssl/evp.h>

namespace libsnark {

    class hmac_sha256_mac {
    public:
        std::vector<uint8_t> mac_bytes;

        hmac_sha256_mac() = default;
        hmac_sha256_mac(const hmac_sha256_mac &other) = default;
        hmac_sha256_mac(hmac_sha256_mac &&other) = default;
        hmac_sha256_mac& operator=(const hmac_sha256_mac &other) = default;

        explicit hmac_sha256_mac(std::vector<uint8_t> &&mac_bytes) :
                mac_bytes(std::move(mac_bytes))
        {}

        size_t size_in_bytes() const {
            return mac_bytes.size();
        }

        size_t size_in_bits() const {
            return size_in_bytes() * 8;
        }

        bool is_well_formed() const {
            return !mac_bytes.empty();
        }

        bool operator==(const hmac_sha256_mac &other) const {
            return mac_bytes == other.mac_bytes;
        }

        friend std::ostream& operator<<(std::ostream &out, const hmac_sha256_mac &mac);
        friend std::istream& operator>>(std::istream &in, hmac_sha256_mac &mac);
    };

    class hmac_sha256_key {
    public:
        std::vector<uint8_t> key_bytes;

        hmac_sha256_key() = default;
        hmac_sha256_key(const hmac_sha256_key &other) = default;
        hmac_sha256_key(hmac_sha256_key &&other) = default;
        hmac_sha256_key& operator=(const hmac_sha256_key &other) = default;

        explicit hmac_sha256_key(std::vector<uint8_t> &&key_bytes) :
                key_bytes(std::move(key_bytes))
        {}

        size_t size_in_bytes() const {
            return key_bytes.size();
        }

        size_t size_in_bits() const {
            return size_in_bytes() * 8;
        }

        bool is_well_formed() const {
            return !key_bytes.empty();
        }

        bool operator==(const hmac_sha256_key &other) const {
            return key_bytes == other.key_bytes;
        }

        friend std::ostream& operator<<(std::ostream &out, const hmac_sha256_key &key);
        friend std::istream& operator>>(std::istream &in, hmac_sha256_key &key);
    };

    hmac_sha256_key hmac_sha256_generate_key(size_t key_size = 32);
    hmac_sha256_mac hmac_sha256_compute_mac(const hmac_sha256_key &key, const std::vector<uint8_t> &msg);
    bool hmac_sha256_verify_mac(const hmac_sha256_key &key, const hmac_sha256_mac &mac, const std::vector<uint8_t> &msg);

}

#endif // HMAC_SHA256_HPP
