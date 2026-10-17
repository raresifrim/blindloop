// zk.hpp — zero-knowledge proofs of the protocol, on the vendored ADSC-SNARK libsnark
// (third_party/adsc-snark, curve BN254):
//
//   ADSC proof  one ADSC-SNARK (r1cs_gg_ppzkadscsnark, Reinhart et al.) per round over the
//               end node's authenticated sensor data:
//                 * the 3-DOF PID controller of the fork's controller_scenario: four sensors
//                   (two command, two measurement) authenticate their samples, the circuit
//                   runs the control law, the outputs are public;
//                 * S threshold sensors authenticate one w-bit reading each, and the circuit
//                   computes flag_i = (reading_i < threshold_i) against the public thresholds.
//                   Readings and flags stay private: the proof shows the flags are honest
//                   comparisons of authenticated readings without revealing them.
//               The central node verifies against the previous round's state commitment.
//   Schnorr     a BN254 G1 Schnorr signature (SHA-256 challenge), the alternative to
//               Ed25519 for the uplink / downlink signatures.
//
// What the proof does not do: tie the private flags to the FHE ciphertexts of the uplink.
// The end node computes and encrypts the same flags (AdscProver::flags()), but nothing in
// the proof forces it to; that needs an encryption-correctness check in the circuit.
//
// The roles are split like the protocol's nodes: a *Setup object holds the keys
// (one-time, not reported), a *Prover lives in the end node, a *Verifier in the
// central node, and an opaque message carries the proof from one to the other.
//
// No libsnark type appears here, so the C++17 benches can include this header while
// zk.cpp is compiled at C++14 (libfqfft uses std::bind1st, removed in C++17).
#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace ipcei {
namespace zk {

/// Initializes the curve parameters and silences libsnark's profiling output.
/// Idempotent; every constructor below calls it.
void Init();

// ---------------------------------------------------------------- ADSC-SNARK

/// One round's proof as it crosses the uplink: the public control outputs, the proof and
/// the state commitment. The thresholds are public inputs too, but the verifier supplies
/// its own; the flags are not in the message.
class AdscMessage {
public:
	AdscMessage();
	~AdscMessage();
	AdscMessage(AdscMessage&&) noexcept;
	AdscMessage& operator=(AdscMessage&&) noexcept;
	long output[3];          // control outputs x, y, z (public)
	size_t proof_bytes = 0;  // proof + commitment, as serialized by libsnark
	struct Impl;
	std::unique_ptr<Impl> impl;
};

class AdscSetup {
public:
	/// Builds the circuit (PID + flag_sensors comparisons of width-bit readings; 0 = the
	/// PID circuit alone) and runs the ADSC generator (one-time).
	explicit AdscSetup(int flag_sensors = 0, int width = 32);
	~AdscSetup();
	int flag_sensors() const;
	int width() const;
	size_t constraints() const;
	struct Impl;
	std::unique_ptr<Impl> impl;
};

/// End node: the sensors and the controller device.
class AdscProver {
public:
	explicit AdscProver(const AdscSetup& setup);
	~AdscProver();
	/// The PID sensors take their samples of round `round` and the threshold sensors their
	/// `readings` (one each, < 2^width); every sensor authenticates its data.
	void Authenticate(int round, const std::vector<uint32_t>& readings = {});
	/// Runs the control law and the comparisons on the authenticated inputs and proves them.
	AdscMessage Prove(const std::vector<uint32_t>& thresholds = {});
	/// The flags the last Prove computed in the circuit (what the end node encrypts).
	const std::vector<uint8_t>& flags() const;

private:
	struct Impl;
	std::unique_ptr<Impl> impl_;
};

/// Central node: verifies each round's proof for its thresholds, against the previous
/// commitment (a rejected proof does not advance the chain).
class AdscVerifier {
public:
	explicit AdscVerifier(const AdscSetup& setup);
	~AdscVerifier();
	bool Verify(const AdscMessage& msg, const std::vector<uint32_t>& thresholds = {});

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
