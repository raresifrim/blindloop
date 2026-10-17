// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// sig.hpp — uplink / downlink signatures for the protocol benches (Ed25519, OpenSSL).
// Each node holds its own key pair and the peer's public key; sign and verify run over
// the exact message bytes that cross the link.
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace ipcei {

class Ed25519 {
public:
	Ed25519();  // generates a key pair
	~Ed25519();
	Ed25519(const Ed25519&) = delete;
	Ed25519& operator=(const Ed25519&) = delete;

	std::vector<uint8_t> Sign(const uint8_t* msg, size_t len) const;
	std::vector<uint8_t> Sign(const std::vector<uint8_t>& msg) const { return Sign(msg.data(), msg.size()); }
	const std::vector<uint8_t>& PublicKey() const { return pub_; }

	/// Verifies `sig` over `msg` with a peer's 32-byte public key.
	static bool Verify(const std::vector<uint8_t>& pub, const uint8_t* msg, size_t len, const std::vector<uint8_t>& sig);
	static bool Verify(const std::vector<uint8_t>& pub, const std::vector<uint8_t>& msg, const std::vector<uint8_t>& sig) {
		return Verify(pub, msg.data(), msg.size(), sig);
	}
	static constexpr size_t kSignatureBytes = 64;

private:
	void* key_;  // EVP_PKEY*
	std::vector<uint8_t> pub_;
};

}  // namespace ipcei
