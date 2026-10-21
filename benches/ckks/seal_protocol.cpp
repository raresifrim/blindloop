// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// seal_protocol.cpp — one round of the window-lift use case (scenario.hpp), CKKS in
// Microsoft SEAL 4.1.
//
// Threat model as in the BFV benches: the end zones (passenger, driver, ign) share key
// material provisioned into their HSEs; only the central compute (the Process APP) must
// be blind.
//
// provisioning  (not timed) one SEAL context; one CKKS secret key shared by the three end
//               zones; the MAC key (ckks_common.hpp: k secret points alpha_m and a PRF key
//               for the per-round secrets r); the relinearization key and the 13 rotation
//               keys at the central node; one Ed25519 key per node; one ADSC-SNARK setup
//               per zone.
// end zones     each zone authenticates its sensor data and proves, in its ADSC-SNARK, the
//               flag bits it derives from it; it packs its own variables from slot 0 (FlagBits
//               order, a block of B = 7k slots per variable holding its tag at the public
//               points, ckks_common.hpp), encodes them at scale 2^--scale-bits and encrypts
//               with the shared secret key: c1 = a expanded from a fresh 32-byte seed
//               (AES-256-CTR, drawn in NTT form), c0 = m + e - a s. The uplink carries the
//               seed and c0's residues bit-packed; a never travels. CKKS cannot raise a
//               ciphertext's modulus the way the BFV benches do (q' -> Q multiplies the
//               scale too), so the uplink is at the top data level: depth 3 needs all of it.
// central       verifies each zone's signature and proof, rebuilds its ciphertext from the
//               seed and c0, and evaluates the decision in SIMD lanes, as bfv_openfhe --eval
//               lanes: one product A * Bf of two sums of rotated inputs gives g, a and the
//               four products of X and Z side by side, then S = a X + Z and cmd = g S
//               (3 tensor products and relinearizations, 13 rotations, depth 3; SEAL has
//               no hoisted rotations, so each is a full key switch). The scales are tracked
//               exactly: Z joins a X after one plaintext product by 1 at the scale that makes
//               both match after the rescale. The result ends at the last level (q0);
//               compress_downlink takes it to coefficient form, rounds away --drop low bits
//               per coefficient and bit-packs c0 and c1.
// passenger     verifies the downlink signature, rebuilds and decrypts the ciphertext,
//               decodes block 0 and checks every instance's tag (TagChecker), reading the
//               command from Y(0).
//
// Steps (harness ids; the central node's first three add up over the three uplinks):
//   encode             PRF -> r, tag lines -> slot values -> CKKSEncoder::encode (FFT + NTT)
//   encrypt            seeded secret-key encryption (error NTT, a s, c0)
//   compress           seed || bit-packed c0 residues
//   adsc_authenticate, adsc_prove, sign_uplink, verify_uplink, adsc_verify   as in bfv_seal
//   decompress         unpack c0, expand a, assemble the ciphertext, per zone
//   evaluate           the lane circuit above
//   compress_downlink  inverse NTT of the 1-prime result, drop bits, bit-pack
//   sign_downlink, verify_downlink                                           as in bfv_seal
//   decrypt            unpack, NTT, decrypt, decode
//   check_result       the approximate tag check of every instance, the command from Y(0)
//
// Parameters (HE standard, 128-bit classical): N = 8192 allows log2(QP) <= 218. The chain
// is q0 (--q0-bits), three rescaling primes (--scale-bits, the scale) and SEAL's special
// prime (--special-bits). The special prime must not be much smaller than the largest data
// prime (SEAL decomposes by data prime: key-switching noise ~ q_i N / P), and q0 / scale
// bounds the decoded values (|y| < 2^(q0 - scale - 1)). Default 46 + 3 x 36 + 60 = 214, the
// chain OpenFHE generates for ckks_openfhe's defaults (same N, comparable primes): the
// decoded slots come out within ~2^-21 of the exact values. --N 16384 allows 438 bits
// (e.g. --q0-bits 60 --scale-bits 50 --special-bits 60: ~2^-27, 2.2x the evaluation).
// Every bit --drop rounds away from the downlink costs about one bit of that precision (the
// rounding error is multiplied by s and spread by the canonical embedding), so the default
// keeps them all; the tag tolerance 2^-14 leaves ~7 bits of margin above the honest error.
//
//   ckks_seal [--N 8192] [--q0-bits 46] [--scale-bits 36] [--special-bits 60] [--mac-k 3]
//             [--mac-tol T] [--drop BITS] [--rounds R] [--warmup W] [--json FILE] [--quiet]
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

#include <openssl/rand.h>

#include "ckks_common.hpp"
#include "ipcei/harness.hpp"
#include "ipcei/net.hpp"
#include "ipcei/scenario.hpp"
#include "ipcei/sig.hpp"
#include "ipcei/zk.hpp"
#include "seal/seal.h"
#include "seal/util/ntt.h"

#ifndef IPCEI_BACKEND
#define IPCEI_BACKEND "stock"
#endif

using namespace seal;
using ipcei::Zone;
namespace zk = ipcei::zk;
namespace window = ipcei::window;
namespace ck = ipcei::ckks;
using ck::Bytes;

namespace {

struct Config {
	size_t N = 8192;
	int q0_bits = 46;
	int scale_bits = 36;
	int special_bits = 60;
	int mac_k = 3;
	double mac_tol = 0x1p-14;
	int drop = 0;
	uint64_t seed = 1;
};

/// Public parameters shared by every node.
class Ckks {
public:
	explicit Ckks(const Config& c) : N(c.N), scale(std::pow(2.0, c.scale_bits)), context(MakeParms(c)) {
		if (!context.parameters_set())
			throw std::runtime_error(std::string("invalid CKKS parameters: ") + context.parameter_error_message());
		top = context.first_context_data();
		coeff = top->parms().coeff_modulus();
		L = coeff.size();
		slots = N / 2;
		B = ck::Block(c.mac_k);
		for (const auto& m : context.key_context_data()->parms().coeff_modulus()) {
			logQP += m.bit_count();
			chain += (chain.empty() ? "" : "+") + std::to_string(m.bit_count());
		}
	}

	const size_t N;
	const double scale;
	SEALContext context;
	std::shared_ptr<const SEALContext::ContextData> top;
	std::vector<Modulus> coeff;  // top data level
	size_t L = 0, slots = 0;
	int B = 1, logQP = 0;
	std::string chain;  // bits of every prime, the special prime last

private:
	static EncryptionParameters MakeParms(const Config& c) {
		EncryptionParameters parms(scheme_type::ckks);
		parms.set_poly_modulus_degree(c.N);
		parms.set_coeff_modulus(CoeffModulus::Create(c.N, {c.q0_bits, c.scale_bits, c.scale_bits, c.scale_bits, c.special_bits}));
		return parms;
	}
};

struct Provisioning {
	SecretKey sk;
	ck::MacKey mac;
};

struct EvalKeys {
	RelinKeys relin;
	GaloisKeys galois;
};

/// Rotation steps of the evaluation (SEAL: positive = left, negative = right).
std::vector<int> RotationSteps(int B) {
	std::vector<int> steps;
	for (const auto& g : ck::RotationGroups())
		for (int blocks : g)
			if (blocks && std::find(steps.begin(), steps.end(), blocks * B) == steps.end()) steps.push_back(blocks * B);
	return steps;
}

struct Uplink {
	Bytes wire;  // round | zone | FHE payload (signed)
	Bytes signature;
	zk::AdscMessage adsc;
};

struct Downlink {
	Bytes wire;  // round | drop | scale | c0, c1 (signed)
	Bytes signature;
};

// ------------------------------------------------------------------ end zones

class EndZoneNode : public ipcei::Participant {
public:
	EndZoneNode(ipcei::Recorder& rec, Zone zone, const Ckks& ck, const Provisioning& pv, const zk::AdscSetup& adsc)
		: Participant(rec, zone), ck_(ck), pv_(pv), prf_(pv.mac.prf_key), adsc_(adsc), encoder_(ck.context),
		  rng_(100 + (int)zone) {}

	const Bytes& SigningKey() const { return sig_.PublicKey(); }

	Uplink MakeUplink(uint32_t round, const window::Inputs& in) {
		Uplink up;
		timed("adsc_authenticate", [&] { adsc_.Authenticate(window::SensorValues(zone_, in)); });
		timed("adsc_prove", [&] { up.adsc = adsc_.Prove(); });
		const std::vector<uint8_t>& bits = adsc_.bits();  // what the circuit derived: the zone encrypts these
		Plaintext pt;
		timed("encode", [&] {
			const std::vector<double> v = ck::ZoneSlots(pv_.mac, prf_, round, zone_, bits);
			encoder_.encode(v, ck_.top->parms_id(), ck_.scale, pt);
		});
		uint8_t seed[ck::kSeedBytes];
		std::vector<uint64_t> c0;
		timed("encrypt", [&] {
			RAND_bytes(seed, sizeof seed);
			c0 = Encrypt(pt, seed);
		});
		timed("compress", [&] {
			ck::PutU32(up.wire, round);
			up.wire.push_back((uint8_t)zone_);
			up.wire.insert(up.wire.end(), seed, seed + ck::kSeedBytes);
			ck::BitWriter w(up.wire);
			for (size_t i = 0; i < ck_.L; ++i) ck::PackResidues(c0.data() + i * ck_.N, ck_.N, ck_.coeff[i].value(), w);
		});
		timed("sign_uplink", [&] { up.signature = sig_.Sign(up.wire); });
		return up;
	}

protected:
	// c0 = m + e - a s at every data prime of the top level (NTT form; a from the seed,
	// the error a rounded Gaussian of SEAL's width, clipped at 6 sigma)
	std::vector<uint64_t> Encrypt(const Plaintext& pt, const uint8_t* seed) {
		const size_t N = ck_.N;
		std::vector<int64_t> e(N);
		std::normal_distribution<double> g(0.0, 3.2);
		for (auto& x : e) x = std::llround(std::max(-19.2, std::min(19.2, g(rng_))));
		std::vector<uint64_t> c0(ck_.L * N), a(N);
		const util::NTTTables* ntt = ck_.top->small_ntt_tables();
		const uint64_t* s = pv_.sk.data().data();  // NTT form, key level: the data primes first
		for (size_t i = 0; i < ck_.L; ++i) {
			const Modulus& q = ck_.coeff[i];
			const uint64_t qv = q.value();
			uint64_t* c = c0.data() + i * N;
			for (size_t j = 0; j < N; ++j) c[j] = e[j] >= 0 ? (uint64_t)e[j] : qv - (uint64_t)(-e[j]);
			util::ntt_negacyclic_harvey(util::CoeffIter(c), ntt[i]);
			ck::ExpandUniform(seed, 0, (uint32_t)i, qv, a.data(), N);
			const uint64_t* m = pt.data() + i * N;
			const uint64_t* si = s + i * N;
			for (size_t j = 0; j < N; ++j) {
				const uint64_t as = util::multiply_uint_mod(a[j], si[j], q);
				c[j] = util::sub_uint_mod(util::add_uint_mod(c[j], m[j], q), as, q);
			}
		}
		return c0;
	}

	const Ckks& ck_;
	const Provisioning pv_;  // this zone's HSE copy of the shared key material
	ck::MacPrf prf_;
	zk::AdscProver adsc_;
	CKKSEncoder encoder_;
	ipcei::Ed25519 sig_;
	std::mt19937_64 rng_;
};

class PassengerNode : public EndZoneNode {
public:
	PassengerNode(ipcei::Recorder& rec, const Ckks& ck, const Provisioning& pv, const zk::AdscSetup& adsc, double tol)
		: EndZoneNode(rec, Zone::Passenger, ck, pv, adsc), dec_(ck.context, pv_.sk), checker_(pv_.mac, tol) {}

	double cmd_dev() const { return cmd_dev_; }
	double tag_dev() const { return tag_dev_; }
	const ck::TagChecker& checker() const { return checker_; }

	ck::TagCheck ReadDownlink(uint32_t round, const Downlink& dl, const Bytes& central_key, bool& sig_ok) {
		sig_ok = timed("verify_downlink", [&] {
			return ipcei::Ed25519::Verify(central_key, dl.wire, dl.signature) && ck::GetU32(dl.wire, 0) == round;
		});
		std::vector<double> y;
		timed("decrypt", [&] { y = Decrypt(dl.wire); });
		ck::TagCheck c = timed("check_result", [&] { return checker_.Check(round, y); });
		cmd_dev_ = std::max(cmd_dev_, c.cmd_dev);
		tag_dev_ = std::max(tag_dev_, c.tag_dev);
		return c;
	}

	/// Untimed: signature + decrypt + check, for the tamper test.
	bool AcceptsUntimed(uint32_t round, const Downlink& dl, const Bytes& central_key) {
		if (!ipcei::Ed25519::Verify(central_key, dl.wire, dl.signature) || ck::GetU32(dl.wire, 0) != round) return false;
		return checker_.Check(round, Decrypt(dl.wire)).ok;
	}

private:
	// Inverse of CentralNode::CompressDownlink.
	std::vector<double> Decrypt(const Bytes& wire) {
		const int drop = (int)ck::GetU32(wire, ck::kDownlinkHeader);
		const double scale = ck::GetF64(wire, ck::kDownlinkHeader + 4);
		auto last = ck_.context.last_context_data();
		const Modulus& q = last->parms().coeff_modulus()[0];
		const size_t N = ck_.N;
		Ciphertext ct;
		ct.resize(ck_.context, last->parms_id(), 2);
		ck::BitReader r(wire, ck::kDownlinkHeader + 12);
		for (size_t e = 0; e < 2; ++e) {
			uint64_t* c = ct.data(e);
			ck::UnpackRounded(r, c, N, q.value(), drop);
			util::ntt_negacyclic_harvey(util::CoeffIter(c), last->small_ntt_tables()[0]);
		}
		ct.is_ntt_form() = true;
		ct.scale() = scale;
		Plaintext pt;
		dec_.decrypt(ct, pt);
		std::vector<double> y;
		encoder_.decode(pt, y);
		return y;
	}

	Decryptor dec_;
	ck::TagChecker checker_;
	double cmd_dev_ = 0, tag_dev_ = 0;
};

class DriverNode : public EndZoneNode {
public:
	DriverNode(ipcei::Recorder& rec, const Ckks& ck, const Provisioning& pv, const zk::AdscSetup& adsc)
		: EndZoneNode(rec, Zone::Driver, ck, pv, adsc) {}
};

class IgnNode : public EndZoneNode {
public:
	IgnNode(ipcei::Recorder& rec, const Ckks& ck, const Provisioning& pv, const zk::AdscSetup& adsc)
		: EndZoneNode(rec, Zone::Ign, ck, pv, adsc) {}
};

// ------------------------------------------------------------------ central node

class CentralNode : public ipcei::Participant {
public:
	CentralNode(ipcei::Recorder& rec, const Ckks& ck, const Config& cfg, EvalKeys keys,
			const std::map<Zone, const zk::AdscSetup*>& adsc, const std::map<Zone, Bytes>& zone_keys)
		: Participant(rec, Zone::Central), ck_(ck), cfg_(cfg), keys_(std::move(keys)), ev_(ck.context),
		  encoder_(ck.context), zone_keys_(zone_keys) {
		for (const auto& z : adsc) adsc_[z.first].reset(new zk::AdscVerifier(*z.second));
		const int B = ck_.B;
		encoder_.encode(ck::Ones({ck::kLaneA}, B), ck_.top->parms_id(), ck_.scale, one_a_);
		encoder_.encode(ck::Ones({ck::kLaneG, ck::kLaneA, ck::kLaneX, ck::kLaneX + 1, ck::kLaneZ, ck::kLaneZ + 1}, B),
				ck_.top->parms_id(), ck_.scale, one_b_);
	}
	const Bytes& SigningKey() const { return sig_.PublicKey(); }
	size_t seal_downlink_bytes() const { return seal_downlink_bytes_; }

	bool Receive(uint32_t round, Zone z, const Uplink& up) {
		bool sig = false, adsc = false;
		timed("verify_uplink", [&] {
			sig = ipcei::Ed25519::Verify(zone_keys_.at(z), up.wire, up.signature) && ck::GetU32(up.wire, 0) == round &&
				up.wire.at(4) == (uint8_t)z;
		});
		timed("adsc_verify", [&] { adsc = adsc_.at(z)->Verify(up.adsc); });
		timed("decompress", [&] { in_[z] = Decompress(up.wire); });
		return sig && adsc;
	}

	Downlink Process(uint32_t round, bool tamper = false) {
		Ciphertext y;
		Downlink dl;
		if (tamper) {  // untimed: a dishonest central node adds 1 at every slot (Off -> Motor+)
			y = Evaluate();
			Plaintext one;
			encoder_.encode(1.0, y.parms_id(), y.scale(), one);
			ev_.add_plain_inplace(y, one);
			dl.wire = CompressDownlink(round, y);
			dl.signature = sig_.Sign(dl.wire);
			return dl;
		}
		timed("evaluate", [&] { y = Evaluate(); });
		timed("compress_downlink", [&] { dl.wire = CompressDownlink(round, y); });
		timed("sign_downlink", [&] { dl.signature = sig_.Sign(dl.wire); });
		if (seal_downlink_bytes_ == 0) seal_downlink_bytes_ = (size_t)y.save_size(compr_mode_type::none);  // reference, untimed
		return dl;
	}

private:
	Ciphertext Decompress(const Bytes& wire) {
		const size_t N = ck_.N;
		const uint8_t* seed = wire.data() + ck::kUplinkHeader;
		ck::BitReader r(wire, ck::kUplinkHeader + ck::kSeedBytes);
		Ciphertext ct;
		ct.resize(ck_.context, ck_.top->parms_id(), 2);
		for (size_t i = 0; i < ck_.L; ++i) {
			const uint64_t q = ck_.coeff[i].value();
			ck::UnpackResidues(r, ct.data(0) + i * N, N, q);
			ck::ExpandUniform(seed, 0, (uint32_t)i, q, ct.data(1) + i * N, N);
		}
		ct.is_ntt_form() = true;
		ct.scale() = ck_.scale;
		return ct;
	}

	Ciphertext Rot(const Ciphertext& c, int blocks) {
		if (blocks == 0) return c;
		Ciphertext r;
		ev_.rotate_vector(c, blocks * ck_.B, keys_.galois, r);
		return r;
	}

	Ciphertext Mul(const Ciphertext& a, const Ciphertext& b) {
		Ciphertext r;
		ev_.multiply(a, b, r);
		ev_.relinearize_inplace(r, keys_.relin);
		ev_.rescale_to_next_inplace(r);
		return r;
	}

	// The lane circuit (bfv_openfhe EvaluateLanes, the lane table there):
	//   A  = k | 1 - ou - od | pu pd | ou od,   Bf = 1 - err | 1 - cl | 1 - top 1 - bot | 1 - top 1 - bot
	//   Q  = A Bf: g | a | X's products | Z's products
	//   S  = Q[a] (Q[X] - Q[X+1]) + Q[Z] - Q[Z+1],  cmd = Q[g] S
	Ciphertext Evaluate() {
		using namespace window;
		using namespace ipcei::ckks;
		const Ciphertext &P = in_.at(Zone::Passenger), &D = in_.at(Zone::Driver), &K = in_.at(Zone::Ign);
		auto p = [&](int var, int lane) { return Rot(P, var - lane); };  // passenger variable -> lane
		auto d = [&](int var, int lane) { return Rot(D, var - lane); };  // driver variable -> lane
		Ciphertext A;
		ev_.add_plain(K, one_a_, A);  // k at kLaneG = kK
		ev_.add_inplace(A, p(kPu, kLaneX));
		ev_.add_inplace(A, d(kOu, kLaneZ));
		ev_.sub_inplace(A, d(kOu, kLaneA));
		ev_.sub_inplace(A, d(kOd, kLaneA));
		Ciphertext Bf = p(kErr, kLaneG);
		ev_.add_inplace(Bf, d(kCl, kLaneA));
		ev_.add_inplace(Bf, p(kTopFlag, kLaneX));
		ev_.add_inplace(Bf, p(kTopFlag, kLaneZ));
		ev_.negate_inplace(Bf);
		ev_.add_plain_inplace(Bf, one_b_);  // 1 - err, 1 - cl, 1 - top, 1 - bot
		const Ciphertext Q = Mul(A, Bf);
		Ciphertext X = Rot(Q, kLaneX), Z = Rot(Q, kLaneZ);
		ev_.sub_inplace(X, Rot(Q, kLaneX + 1));
		ev_.sub_inplace(Z, Rot(Q, kLaneZ + 1));
		Ciphertext S = Mul(Rot(Q, kLaneA), X);
		// Z to S's level and exact scale: Z * 1 at scale(S) q / scale(Z), q the prime the
		// rescale drops; then Z's scale is scale(S) to the last bit
		{
			const double qd = (double)ck_.context.get_context_data(Z.parms_id())->parms().coeff_modulus().back().value();
			Plaintext one;
			encoder_.encode(1.0, Z.parms_id(), S.scale() * qd / Z.scale(), one);
			ev_.multiply_plain_inplace(Z, one);
			ev_.rescale_to_next_inplace(Z);
			Z.scale() = S.scale();
		}
		ev_.add_inplace(S, Z);
		Ciphertext G = Q;
		ev_.mod_switch_to_inplace(G, S.parms_id());
		return Mul(G, S);
	}

	// Downlink wire: u32 round | u32 drop | f64 scale | c0, c1 at the last level (q0), in
	// coefficient form, each coefficient as round(x / 2^drop), bit-packed.
	Bytes CompressDownlink(uint32_t round, Ciphertext y) {
		auto last = ck_.context.last_context_data();
		if (y.parms_id() != last->parms_id()) ev_.mod_switch_to_inplace(y, last->parms_id());
		const uint64_t q = last->parms().coeff_modulus()[0].value();
		Bytes w;
		ck::PutU32(w, round);
		ck::PutU32(w, (uint32_t)cfg_.drop);
		ck::PutF64(w, y.scale());
		ck::BitWriter bw(w);
		for (size_t e = 0; e < 2; ++e) {
			uint64_t* c = y.data(e);
			util::inverse_ntt_negacyclic_harvey(util::CoeffIter(c), last->small_ntt_tables()[0]);
			ck::PackRounded(c, ck_.N, q, cfg_.drop, bw);
		}
		return w;
	}

	const Ckks& ck_;
	Config cfg_;
	EvalKeys keys_;
	Evaluator ev_;
	CKKSEncoder encoder_;
	std::map<Zone, Bytes> zone_keys_;
	std::map<Zone, std::unique_ptr<zk::AdscVerifier>> adsc_;
	std::map<Zone, Ciphertext> in_;  // this round's decompressed uplinks
	Plaintext one_a_, one_b_;
	ipcei::Ed25519 sig_;
	size_t seal_downlink_bytes_ = 0;
};

int Usage() {
	std::fprintf(stderr,
			"usage: ckks_seal [--N 8192] [--q0-bits 46] [--scale-bits 36] [--special-bits 60] [--mac-k 3]\n"
			"                 [--mac-tol T] [--drop BITS] [--seed N] [--rounds R] [--warmup W] [--json FILE] [--quiet]\n");
	return 2;
}

}  // namespace

int main(int argc, char** argv) {
	const ipcei::Options opts = ipcei::Options::Parse(argc, argv, window::Rounds::kCases);
	ipcei::net::Network net(opts);  // first: it forks its peer processes
	Config cfg;
	for (size_t i = 0; i < opts.rest.size(); ++i) {
		const std::string& a = opts.rest[i];
		if (i + 1 >= opts.rest.size()) return Usage();
		const char* v = opts.rest[++i].c_str();
		if (a == "--N") cfg.N = (size_t)std::atol(v);
		else if (a == "--q0-bits") cfg.q0_bits = std::atoi(v);
		else if (a == "--scale-bits") cfg.scale_bits = std::atoi(v);
		else if (a == "--special-bits") cfg.special_bits = std::atoi(v);
		else if (a == "--mac-k") cfg.mac_k = std::atoi(v);
		else if (a == "--mac-tol") cfg.mac_tol = std::atof(v);
		else if (a == "--drop") cfg.drop = std::atoi(v);
		else if (a == "--seed") cfg.seed = std::strtoull(v, nullptr, 10);
		else return Usage();
	}
	if (cfg.mac_k < 0 || cfg.mac_k > 16 || cfg.drop < 0 || cfg.drop >= cfg.q0_bits) return Usage();

	// ---- provisioning (not reported)
	Ckks ck(cfg);
	if ((size_t)(ck::kLanesUsed * ck.B) > ck.slots) {
		std::fprintf(stderr, "too many MAC instances for N = %zu\n", ck.N);
		return 2;
	}
	KeyGenerator keygen(ck.context);
	Provisioning pv;
	pv.sk = keygen.secret_key();
	EvalKeys eval_keys;
	keygen.create_relin_keys(eval_keys.relin);
	keygen.create_galois_keys(RotationSteps(ck.B), eval_keys.galois);
	{
		std::mt19937_64 rng(cfg.seed ^ 0x5eed5eedULL);
		std::uniform_real_distribution<double> pick(0.5, 1.0);
		pv.mac.k = cfg.mac_k;
		for (int m = 0; m < cfg.mac_k; ++m) pv.mac.alpha.push_back(pick(rng));
		for (size_t i = 0; i < ck::kMacKeyBytes; ++i) pv.mac.prf_key[i] = (uint8_t)rng();
	}

	ipcei::Recorder rec(opts.warmup);
	std::map<Zone, std::unique_ptr<zk::AdscSetup>> adsc_setup;
	for (Zone z : ipcei::kEndZones) adsc_setup[z].reset(new zk::AdscSetup(z, zk::Encoding::Flags));
	PassengerNode passenger(rec, ck, pv, *adsc_setup[Zone::Passenger], cfg.mac_tol);
	DriverNode driver(rec, ck, pv, *adsc_setup[Zone::Driver]);
	IgnNode ign(rec, ck, pv, *adsc_setup[Zone::Ign]);
	EndZoneNode* const zones[] = {&passenger, &driver, &ign};
	std::map<Zone, const zk::AdscSetup*> adsc_ptr;
	std::map<Zone, Bytes> zone_keys;
	for (EndZoneNode* z : zones) {
		adsc_ptr[z->zone()] = adsc_setup[z->zone()].get();
		zone_keys[z->zone()] = z->SigningKey();
	}
	CentralNode central(rec, ck, cfg, std::move(eval_keys), adsc_ptr, zone_keys);

	// ---- rounds: the warm-up has its own generator, so the measured rounds are the cases
	window::Rounds warm(~cfg.seed), cases;
	const int total = opts.warmup + opts.rounds;
	std::map<Zone, size_t> up_bytes, adsc_bytes;
	size_t dl_bytes = 0;
	int tamper = -1;  // -1: not run, 0: forged result accepted, 1: rejected
	for (int r = 0; r < total; ++r) {
		const uint32_t round = (uint32_t)r;
		const window::Inputs in = r < opts.warmup ? warm.Next() : cases.Next();
		const window::Cmd expected = window::Decide(in);
		rec.BeginRound();
		bool verified = true;
		for (EndZoneNode* z : zones) {
			Uplink up = z->MakeUplink(round, in);
			verified = net.Uplink(rec, z->zone(), up.wire, up.signature, up.adsc.proof_bytes) && verified;
			verified = central.Receive(round, z->zone(), up) && verified;
			up_bytes[z->zone()] = up.wire.size() - ck::kUplinkHeader;
			adsc_bytes[z->zone()] = up.adsc.proof_bytes;
		}
		Downlink dl = central.Process(round);
		const bool delivered = net.Downlink(rec, dl.wire, dl.signature);
		bool sig_ok = false;
		const ck::TagCheck c = passenger.ReadDownlink(round, dl, central.SigningKey(), sig_ok);
		const bool ok = verified && delivered && sig_ok && c.ok && c.cmd == expected;
		rec.RoundResult(ok);
		dl_bytes = dl.wire.size() - ck::kDownlinkHeader;
		if (!opts.quiet)
			std::printf("round %2d%s  %-30s  cmd %-6s expected %-6s  |dY0| %.1e  |dtag| %.1e  MAC %s%s\n", r,
					r < opts.warmup ? "w" : " ", in.label.c_str(), window::CmdName(c.cmd), window::CmdName(expected),
					c.cmd_dev, c.tag_dev, c.ok ? "ok" : "FAIL", ok ? "" : "  WRONG");
		if (expected == window::Cmd::Off && tamper < 0 && cfg.mac_k > 0)
			tamper = passenger.AcceptsUntimed(round, central.Process(round, true), central.SigningKey()) ? 0 : 1;
	}

	rec.Param("backend", IPCEI_BACKEND);
	net.Describe(rec);
	rec.Param("ring dimension N", (double)ck.N);
	rec.Param("log2 QP", (double)ck.logQP);
	rec.Param("coeff modulus (bits)", ck.chain + " (special prime last)");
	rec.Param("scale", "2^" + std::to_string(cfg.scale_bits));
	rec.Param("security", "HE standard 128-bit classical (SEAL default)");
	rec.Param("multiplicative depth", 3);
	rec.Param("key switching", "SEAL hybrid, one special prime, digits = data primes");
	rec.Param("encoding", "CKKS packed (SIMD), flags, " + std::to_string(ck.B) + " slot(s) per variable");
	rec.Param("evaluation", "lanes g (Z + a X): 3 tensor products, 3 relins, 13 rotations (not hoisted), depth 3");
	rec.Param("encryption", "secret key, seeded (AES-256-CTR), top level");
	rec.Param("MAC instances k", cfg.mac_k);
	if (cfg.mac_k > 0) {
		rec.Param("MAC", "approximate (real-valued tag at x_j = j/6, alpha in [0.5, 1)): no soundness bound claimed");
		rec.Param("MAC tolerance", cfg.mac_tol);
		rec.Param("MAC max sum |L_j(alpha)|", passenger.checker().lebesgue());
		rec.Param("max honest tag deviation", passenger.tag_dev());
		rec.Param("tag margin (bits)", std::log2(cfg.mac_tol / std::max(passenger.tag_dev(), 1e-300)));
	}
	rec.Param("max |Y(0) - cmd|", passenger.cmd_dev());
	rec.Param("command precision (bits)", -std::log2(std::max(passenger.cmd_dev(), 1e-300)));
	rec.Param("downlink dropped bits", cfg.drop);
	rec.Param("signature", "Ed25519");
	for (Zone z : ipcei::kEndZones)
		rec.Param(std::string("adsc_constraints_") + ipcei::ZoneName(z), (double)adsc_setup[z]->constraints());
	for (Zone z : ipcei::kEndZones)
		rec.Size(std::string("uplink ") + ipcei::ZoneName(z) + " (FHE payload)", (double)up_bytes[z]);
	rec.Size("downlink (FHE payload)", (double)dl_bytes);
	rec.Size("downlink (SEAL serialized, 1 prime)", (double)central.seal_downlink_bytes());
	for (Zone z : ipcei::kEndZones) rec.Size(std::string("ADSC proof ") + ipcei::ZoneName(z), (double)adsc_bytes[z]);
	rec.Size("signature (each link)", (double)ipcei::Ed25519::kSignatureBytes);
	rec.Note("the end zones share the CKKS secret key and the MAC key (trusted, provisioned into their HSEs); the "
			"central node holds only the relinearization and rotation keys");
	rec.Note("no global slot layout: each zone packs its own variables from slot 0, the central node aligns them "
			"with rotations");
	rec.Note("the ADSC proofs show each zone's bits are derived from authenticated sensor data, but do not bind "
			"them to the zone's ciphertext");
	rec.Note("the encryption error is a rounded Gaussian from mt19937_64 (benchmark PRNG)");
	if (cfg.mac_k > 0)
		rec.Note(std::string("tamper test (central node adds 1 to every slot in an Off round): ") +
				(tamper < 0 ? "not run (no Off round)" : tamper ? "rejected" : "ACCEPTED (BUG)"));

	ipcei::Report report(rec, "ckks_seal", "SEAL " SEAL_VERSION, "CKKS");
	report.Print();
	if (!opts.json.empty()) report.WriteJson(opts.json);
	int correct = 0;
	for (bool b : rec.correct()) correct += b;
	return (correct == (int)rec.correct().size() && tamper != 0) ? 0 : 1;
}
