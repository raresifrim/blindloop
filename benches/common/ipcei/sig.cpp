// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// sig.cpp — Ed25519 through OpenSSL EVP (one-shot EVP_DigestSign / EVP_DigestVerify).
#include "ipcei/sig.hpp"

#include <cstdio>
#include <cstdlib>

#include <openssl/evp.h>

namespace ipcei {

static void Die(const char* what) {
	std::fprintf(stderr, "Ed25519: %s failed\n", what);
	std::abort();
}

Ed25519::Ed25519() : key_(nullptr) {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr);
	EVP_PKEY* pkey = nullptr;
	if (!ctx || EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_keygen(ctx, &pkey) <= 0) Die("keygen");
	EVP_PKEY_CTX_free(ctx);
	key_ = pkey;
	size_t len = 32;
	pub_.resize(len);
	if (EVP_PKEY_get_raw_public_key(pkey, pub_.data(), &len) <= 0 || len != 32) Die("raw public key");
}

Ed25519::~Ed25519() { EVP_PKEY_free(static_cast<EVP_PKEY*>(key_)); }

std::vector<uint8_t> Ed25519::Sign(const uint8_t* msg, size_t len) const {
	std::vector<uint8_t> sig(kSignatureBytes);
	size_t siglen = sig.size();
	EVP_MD_CTX* md = EVP_MD_CTX_new();
	if (!md || EVP_DigestSignInit(md, nullptr, nullptr, nullptr, static_cast<EVP_PKEY*>(key_)) <= 0 ||
			EVP_DigestSign(md, sig.data(), &siglen, msg, len) <= 0)
		Die("sign");
	EVP_MD_CTX_free(md);
	sig.resize(siglen);
	return sig;
}

bool Ed25519::Verify(const std::vector<uint8_t>& pub, const uint8_t* msg, size_t len, const std::vector<uint8_t>& sig) {
	EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size());
	if (!pkey) return false;
	EVP_MD_CTX* md = EVP_MD_CTX_new();
	bool ok = md && EVP_DigestVerifyInit(md, nullptr, nullptr, nullptr, pkey) > 0 &&
		EVP_DigestVerify(md, sig.data(), sig.size(), msg, len) == 1;
	EVP_MD_CTX_free(md);
	EVP_PKEY_free(pkey);
	return ok;
}

}  // namespace ipcei
