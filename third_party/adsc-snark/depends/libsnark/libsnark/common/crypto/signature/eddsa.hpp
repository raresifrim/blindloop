/** @file
 *****************************************************************************
 *  Interface of a digital signature
 *
 *  Algorithm: PureEdDSA by openssl
 *****************************************************************************/

#ifndef SIGNATURE_EDDSA_HPP
#define SIGNATURE_EDDSA_HPP

#include <memory>
#include <vector>
#include <stdexcept>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

namespace libsnark {

    class signature_eddsa_signature {
    public:
         std::vector<uint8_t> sig_bytes;

        signature_eddsa_signature() {};
        signature_eddsa_signature& operator=(const signature_eddsa_signature &other) = default;
        signature_eddsa_signature(const signature_eddsa_signature &other) = default;
        signature_eddsa_signature(signature_eddsa_signature &&other) = default;
        signature_eddsa_signature(std::vector<uint8_t> &&sig_bytes) :
                sig_bytes(std::move(sig_bytes))
        {};

        size_t size_in_bytes() const
        {
            return sig_bytes.size();
        }

        size_t size_in_bits() const
        {
            return size_in_bytes() * 8;
        }

        bool is_well_formed() const
        {
            return (!sig_bytes.empty());
        }

        bool operator==(const signature_eddsa_signature &other) const;
        friend std::ostream& operator<< (std::ostream &out, const signature_eddsa_signature &signature);
        friend std::istream& operator>> (std::istream &in, signature_eddsa_signature &signature);
    };

    class signature_eddsa_pubkey {
    public:
         EVP_PKEY *pkey;

        signature_eddsa_pubkey() :
             pkey(nullptr)
        {};

        ~signature_eddsa_pubkey()
        {
          if (pkey)
          {
              EVP_PKEY_free(pkey);
          }
        };

        signature_eddsa_pubkey& operator=(const signature_eddsa_pubkey& other)
        {
            if (this != &other) {
                if (pkey) {
                    EVP_PKEY_free(pkey);
                }

                if (other.pkey) {
                    pkey = EVP_PKEY_dup(other.pkey); // Duplicate the key
                    if (!pkey) {
                        throw std::runtime_error("Failed to duplicate EVP_PKEY");
                    }
                } else {
                    pkey = nullptr;
                }
            }
            return *this;
        }

        signature_eddsa_pubkey(const signature_eddsa_pubkey &other)
        {
             if (other.pkey) {
                pkey = EVP_PKEY_dup(other.pkey); // Duplicate the key
                if (!pkey) {
                    throw std::runtime_error("Failed to duplicate EVP_PKEY");
                }
             } else {
                pkey = nullptr;
             }
        }

        signature_eddsa_pubkey(signature_eddsa_pubkey &&other) noexcept : pkey(other.pkey)
        {
            other.pkey = nullptr;
        }

        signature_eddsa_pubkey(EVP_PKEY *pkey) :
                pkey(pkey)
        {};

        size_t size_in_bytes() const
        {
            return 32;
        }

        size_t size_in_bits() const
        {
            return size_in_bytes() * 8;
        }

        bool operator==(const signature_eddsa_pubkey &other) const;
        friend std::ostream& operator<< (std::ostream &out, const signature_eddsa_pubkey &pubkey);
        friend std::istream& operator>> (std::istream &in, signature_eddsa_pubkey &pubkey);
    };

    class signature_eddsa_privkey {
    public:
         EVP_PKEY *pkey;

        signature_eddsa_privkey() :
             pkey(nullptr)
        {};

        ~signature_eddsa_privkey()
        {
          if (pkey)
          {
              EVP_PKEY_free(pkey);
          }
        };

        signature_eddsa_privkey& operator=(const signature_eddsa_privkey& other)
        {
            if (this != &other) {
                if (pkey) {
                    EVP_PKEY_free(pkey);
                }

                if (other.pkey) {
                    pkey = EVP_PKEY_dup(other.pkey); // Duplicate the key
                    if (!pkey) {
                        throw std::runtime_error("Failed to duplicate EVP_PKEY");
                    }
                } else {
                    pkey = nullptr;
                }
            }
            return *this;
        }

        signature_eddsa_privkey(const signature_eddsa_privkey &other)
        {
             if (other.pkey) {
                pkey = EVP_PKEY_dup(other.pkey); // Duplicate the key
                if (!pkey) {
                    throw std::runtime_error("Failed to duplicate EVP_PKEY");
                }
             } else {
                pkey = nullptr;
             }
        }

        signature_eddsa_privkey(signature_eddsa_privkey &&other) noexcept : pkey(other.pkey)
        {
            other.pkey = nullptr;
        }

        signature_eddsa_privkey(EVP_PKEY *pkey) :
                pkey(pkey)
        {};

        size_t size_in_bytes() const
        {
            return 32;
        }

        size_t size_in_bits() const
        {
            return size_in_bytes() * 8;
        }

        bool operator==(const signature_eddsa_privkey &other) const;
        friend std::ostream& operator<< (std::ostream &out, const signature_eddsa_privkey &privkey);
        friend std::istream& operator>> (std::istream &in, signature_eddsa_privkey &privkey);
    };

    class signature_eddsa_keypair {
    public:
    	signature_eddsa_pubkey pubkey;
        signature_eddsa_privkey privkey;

        signature_eddsa_keypair() = default;
        signature_eddsa_keypair& operator=(const signature_eddsa_keypair &other) = default;
        signature_eddsa_keypair(const signature_eddsa_keypair &other) = default;
        signature_eddsa_keypair(signature_eddsa_pubkey &&pubkey, signature_eddsa_privkey &&privkey):
        	pubkey(std::move(pubkey)),
            privkey(std::move(privkey))
        {}
        signature_eddsa_keypair(signature_eddsa_keypair &&other) = default;

        size_t size_in_bytes() const
        {
            return pubkey.size_in_bytes() + privkey.size_in_bytes();
        }

        size_t size_in_bits() const
        {
            return size_in_bytes() * 8;
        }

        bool operator==(const signature_eddsa_keypair &other) const;
        friend std::ostream& operator<< (std::ostream &out, const signature_eddsa_keypair &keypair);
        friend std::istream& operator>> (std::istream &in, signature_eddsa_keypair &keypair);

    };

    signature_eddsa_keypair signature_eddsa_generate();
    signature_eddsa_signature signature_eddsa_sign(const signature_eddsa_privkey &privkey, const std::vector<uint8_t> &msg);
    bool signature_eddsa_verify(const signature_eddsa_pubkey &pubkey, const signature_eddsa_signature &signature, const std::vector<uint8_t> &msg);
}


#endif //SIGNATURE_EDDSA_HPP
