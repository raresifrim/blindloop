#include "eddsa.hpp"
#include <ostream>
#include <istream>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core_names.h>

#include <libff/common/serialization.hpp>

namespace libsnark {

bool signature_eddsa_signature::operator==(const signature_eddsa_signature &other) const
{
    return (this->sig_bytes == other.sig_bytes);
}


std::ostream& operator<<(std::ostream &out, const signature_eddsa_signature &signature)
{
    libff::output_bytes(out, signature.sig_bytes);
    return out;
}

std::istream& operator>>(std::istream &in, signature_eddsa_signature &signature)
{
    libff::input_bytes(in, signature.sig_bytes);
    return in;
}

bool signature_eddsa_pubkey::operator==(const signature_eddsa_pubkey &other) const
{
    if (this->pkey == other.pkey) {
         return true;
    }

    if (this->pkey == nullptr || other.pkey == nullptr)
    {
        return false;
    }

    int result = EVP_PKEY_eq(pkey, other.pkey);
    if (result == -1) {
        throw std::runtime_error("Error occurred during key comparison");
    }

    return result == 1;
}

std::ostream& operator<<(std::ostream &out, const signature_eddsa_pubkey &pubkey)
{
    if (!pubkey.pkey) {
        throw std::invalid_argument("EVP_PKEY is null");
    }

    // Ensure the key is Ed25519
    if (EVP_PKEY_id(pubkey.pkey) != EVP_PKEY_ED25519) {
        throw std::invalid_argument("Provided key is not Ed25519");
    }

    // Get the raw public key
    uint8_t buffer[32]; // Ed25519 public key is 32 bytes
    size_t len = sizeof(buffer);
    if (EVP_PKEY_get_raw_public_key(pubkey.pkey, buffer, &len) != 1 || len != 32) {
        throw std::runtime_error("Failed to get raw public key");
    }

    libff::output_bytes(out, std::vector<uint8_t>(std::begin(buffer), std::end(buffer)));
    return out;
}

std::istream& operator>>(std::istream &in, signature_eddsa_pubkey &pubkey)
{
 	std::vector<uint8_t> raw_pubkey;
 	libff::input_bytes(in, raw_pubkey);

    if (raw_pubkey.size() != 32) {
        throw std::invalid_argument("Invalid raw public key size for Ed25519");
    }

    // Create the EVP_PKEY from the raw public key
    pubkey.pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw_pubkey.data(), raw_pubkey.size());
    if (!pubkey.pkey) {
        throw std::runtime_error("Failed to create EVP_PKEY from raw public key");
    }
    return in;
}

bool signature_eddsa_privkey::operator==(const signature_eddsa_privkey &other) const
{
    if (this->pkey == other.pkey) {
         return true;
    }

    if (this->pkey == nullptr || other.pkey == nullptr)
    {
        return false;
    }

    int result = EVP_PKEY_eq(pkey, other.pkey);
    if (result == -1) {
        throw std::runtime_error("Error occurred during key comparison");
    }

    return result == 1;
}

std::ostream& operator<<(std::ostream &out, const signature_eddsa_privkey &privkey)
{
    if (!privkey.pkey) {
        throw std::invalid_argument("EVP_PKEY is null");
    }

    // Ensure the key is Ed25519
    if (EVP_PKEY_id(privkey.pkey) != EVP_PKEY_ED25519) {
        throw std::invalid_argument("Provided key is not Ed25519");
    }

    // Get the raw private key
    uint8_t buffer[32]; // Ed25519 private key is 32 bytes
    size_t len = sizeof(buffer);
    if (EVP_PKEY_get_raw_private_key(privkey.pkey, buffer, &len) != 1 || len != 32) {
        throw std::runtime_error("Failed to get raw private key");
    }

    libff::output_bytes(out, std::vector<uint8_t>(std::begin(buffer), std::end(buffer)));
    return out;
}

std::istream& operator>>(std::istream &in, signature_eddsa_privkey &privkey)
{
 	std::vector<uint8_t> raw_privkey;
 	libff::input_bytes(in, raw_privkey);

    if (raw_privkey.size() != 32) {
        throw std::invalid_argument("Invalid raw private key size for Ed25519");
    }

    // Create the EVP_PKEY from the raw private key
    privkey.pkey = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, raw_privkey.data(), raw_privkey.size());
    if (!privkey.pkey) {
        throw std::runtime_error("Failed to create EVP_PKEY from raw private key");
    }
    return in;
}

bool signature_eddsa_keypair::operator==(const signature_eddsa_keypair &other) const
{
    return (this->pubkey == other.pubkey
          && this->privkey == other.privkey);
}

std::ostream& operator<<(std::ostream &out, const signature_eddsa_keypair &keypair)
{
    out << keypair.pubkey << OUTPUT_NEWLINE;
    out << keypair.privkey << OUTPUT_NEWLINE;
    return out;
}

std::istream& operator>>(std::istream &in, signature_eddsa_keypair &keypair)
{
    in >> keypair.pubkey;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> keypair.privkey;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

signature_eddsa_keypair signature_eddsa_generate() {
    // Create a context for Ed25519 key generation
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
    if (!ctx) {
        throw std::runtime_error("Failed to create EVP_PKEY_CTX");
    }

    // Generate the private key
    EVP_PKEY* private_key = nullptr;
    if (EVP_PKEY_keygen_init(ctx) != 1 || EVP_PKEY_keygen(ctx, &private_key) != 1) {
        EVP_PKEY_CTX_free(ctx);
        throw std::runtime_error("Failed to generate Ed25519 private key");
    }

    EVP_PKEY_CTX_free(ctx);

    // Extract the raw public key from the private key
    unsigned char raw_pubkey[32];
    size_t raw_pubkey_len = sizeof(raw_pubkey);
    if (EVP_PKEY_get_raw_public_key(private_key, raw_pubkey, &raw_pubkey_len) != 1 || raw_pubkey_len != 32) {
        EVP_PKEY_free(private_key);
        throw std::runtime_error("Failed to extract raw public key");
    }

    // Create an EVP_PKEY object for the public key
    EVP_PKEY* public_key = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw_pubkey, raw_pubkey_len);
    if (!public_key) {
        EVP_PKEY_free(private_key);
        throw std::runtime_error("Failed to create EVP_PKEY for public key");
    }

	signature_eddsa_pubkey pubkey(public_key);
    signature_eddsa_privkey privkey(private_key);
    return	signature_eddsa_keypair(std::move(pubkey), std::move(privkey));
}

signature_eddsa_signature signature_eddsa_sign(const signature_eddsa_privkey &privkey, const std::vector<uint8_t> &msg)
{
	// Create a signing context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestSignInit(md_ctx, nullptr, nullptr, nullptr, privkey.pkey) != 1) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to initialize signing context");
    }

    // Determine the size of the signature
    size_t sig_len = 0;
    if (EVP_DigestSign(md_ctx, nullptr, &sig_len, msg.data(), msg.size()) != 1) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to determine signature size");
    }

    // Create a buffer for the signature
    std::vector<uint8_t> signature(sig_len);

    // Perform the signing operation
    if (EVP_DigestSign(md_ctx, signature.data(), &sig_len, msg.data(), msg.size()) != 1) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to sign the message");
    }

    // Resize the signature to the actual size (in case it was shorter than allocated)
    signature.resize(sig_len);

    EVP_MD_CTX_free(md_ctx);
    return signature_eddsa_signature(std::move(signature));
}

bool signature_eddsa_verify(const signature_eddsa_pubkey &pubkey, const signature_eddsa_signature &signature, const std::vector<uint8_t> &msg)
{
	// Create a verification context
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        throw std::runtime_error("Failed to create EVP_MD_CTX");
    }

    if (EVP_DigestVerifyInit(md_ctx, nullptr, nullptr, nullptr, pubkey.pkey) != 1) {
        EVP_MD_CTX_free(md_ctx);
        throw std::runtime_error("Failed to initialize verification context");
    }

    // Perform the verification operation
    bool is_valid = EVP_DigestVerify(md_ctx, signature.sig_bytes.data(), signature.sig_bytes.size(), msg.data(), msg.size()) == 1;

    EVP_MD_CTX_free(md_ctx);
    return is_valid;
}


}