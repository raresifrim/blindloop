// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// zk.hpp — zero-knowledge proofs of the end zones' inputs, on the vendored ADSC-SNARK
// libsnark (third_party/adsc-snark, curve BN254):
//
//   ADSC proof  one ADSC-SNARK (r1cs_gg_ppzkadscsnark, Reinhart et al.) per end zone and
//               round. The zone's sensors authenticate their raw values (scenario.hpp,
//               SensorValues); the circuit derives exactly the bits the zone encrypts:
//                 flags  passenger: button up / down, top = position >= kTop,
//                                   bot = position <= kBottom, err = OR(error flags)
//                        driver:    overwrite up / down, child-lock
//                        ign:       Klem 15
//                 raw    the raw values themselves (the position as kPositionBits bits)
//               checking every 0/1 value is boolean, the 3-position switches never report
//               both directions and the position fits its ADC width. Raw values and bits
//               stay private; the public input is the round number (and, for the
//               passenger's flags, the limits). The chained state is a round counter, so
//               a proof is only valid in its own round.
//   Schnorr     a BN254 G1 Schnorr signature (SHA-256 challenge), the alternative to
//               Ed25519 for the uplink / downlink signatures.
//
// What the proof does not do: tie the bits to the zone's FHE ciphertexts. The zone
// encrypts the bits the circuit derived (AdscProver::bits()), but nothing in the proof
// forces it to; that needs an encryption-correctness check in the circuit.
//
// The roles are split like the protocol's nodes: a *Setup object holds the keys
// (one-time, not reported), a *Prover lives in the end zone, a *Verifier in the
// central node, and an opaque message carries the proof from one to the other.
//
// No libsnark type appears here, so the C++17 benches can include this header while
// zk.cpp is compiled at C++14 (libfqfft uses std::bind1st, removed in C++17).
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

#include "ipcei/harness.hpp"  // Zone

namespace ipcei {
namespace zk {

/// Initializes the curve parameters and silences libsnark's profiling output.
/// Idempotent; every constructor below calls it.
void Init();

// ---------------------------------------------------------------- ADSC-SNARK

/// What the end zones encrypt (scenario.hpp): bits derived at the source, or raw values.
enum class Encoding { Flags, Raw };

/// One zone's proof as it crosses the uplink: the proof and the state commitment.
class AdscMessage {
public:
	AdscMessage();
	~AdscMessage();
	AdscMessage(AdscMessage&&) noexcept;
	AdscMessage& operator=(AdscMessage&&) noexcept;
	size_t proof_bytes = 0;  // proof + commitment, as serialized by libsnark
	struct Impl;
	std::unique_ptr<Impl> impl;
};

class AdscSetup {
public:
	/// Builds the zone's circuit and runs the ADSC generator (one-time).
	AdscSetup(Zone zone, Encoding encoding);
	~AdscSetup();
	Zone zone() const;
	Encoding encoding() const;
	size_t constraints() const;
	struct Impl;
	std::unique_ptr<Impl> impl;
};

/// End zone: its sensors and the device that proves.
class AdscProver {
public:
	explicit AdscProver(const AdscSetup& setup);
	~AdscProver();
	/// The zone's sensors authenticate this round's values (scenario.hpp, SensorValues).
	void Authenticate(const std::vector<uint32_t>& sensor_values);
	/// Derives the zone's bits from the authenticated values and proves it.
	AdscMessage Prove();
	/// The bits the last Prove derived (FlagBits / RawBits order): what the zone encrypts.
	const std::vector<uint8_t>& bits() const;

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

/// Central node: verifies one zone's proofs, round after round, against the previous
/// commitment (a rejected proof does not advance the chain).
class AdscVerifier {
public:
	explicit AdscVerifier(const AdscSetup& setup);
	~AdscVerifier();
	bool Verify(const AdscMessage& msg);

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

// ---------------------------------------------------------------- BN254 Schnorr

class Bn254Schnorr {
public:
	Bn254Schnorr();  // key pair
	~Bn254Schnorr();
	std::vector<uint8_t> Sign(const uint8_t* msg, size_t len) const;
	bool Verify(const uint8_t* msg, size_t len, const std::vector<uint8_t>& sig) const;  // with this key's public key

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

}  // namespace zk
}  // namespace ipcei
