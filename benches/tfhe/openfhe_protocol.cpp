// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// openfhe_protocol.cpp — the IPCEI secure-actuation round trip in TFHE (OpenFHE binfhe,
// GINX bootstrapping), with the per-step breakdown of benches/common/ipcei/harness.hpp.
//
// Two variants of the end node's uplink (--mode):
//   stress  the end node sends its S raw w-bit sensor readings, bit by bit; the central
//           node compares each to a public threshold with a bit-serial comparator and ANDs
//           the S predicates into the 1-bit actuation command
//   flags   the end node compares at the source and sends S one-bit flags; the central
//           node only ANDs them. The threshold sensors authenticate their readings and the
//           ADSC proof covers the comparisons too, with readings and flags private
//
// Round, by node and step id:
//   end      encrypt (one LWE ciphertext per bit, secret key; there is no separate encode),
//            compress (seeded LWE: the bodies are rewritten to masks derived from a shared
//            seed, the wire carries the seed and the bodies; --no-compress sends full
//            serialized ciphertexts), adsc_authenticate + adsc_prove (ADSC-SNARK of the PID
//            control law, + the flag comparisons in flags mode), sign_uplink (Ed25519 over
//            the wire bytes)
//   central  verify_uplink, adsc_verify, decompress (regenerate the
//            masks, rebuild the ciphertexts), evaluate (comparators and/or AND gates),
//            compress_downlink (serialize the command ciphertext; no compression), sign_downlink
//   end      verify_downlink, decrypt (deserialize + decrypt the command bit)
// There is no MAC in this design (no check_result step).
//
// The readings are steered so the oracle mixes outcomes: every third round inhibits.
//
//   tfhe_openfhe [--mode stress|flags] [--sensors S] [--width w] [--paramset STD128|STD128_4|MEDIUM|TOY]
//                [--no-compress] [--seed N] [--rounds R] [--warmup W] [--json FILE]
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include <omp.h>

#include "binfhe/binfhecontext-ser.h"
#include "binfhe/binfhecontext.h"

#include "ipcei/harness.hpp"
#include "ipcei/sig.hpp"
#include "ipcei/zk.hpp"

using namespace lbcrypto;

#ifndef IPCEI_BACKEND
#define IPCEI_BACKEND "stock"
#endif
#ifndef IPCEI_OPENFHE_VERSION
#define IPCEI_OPENFHE_VERSION "unknown"
#endif

namespace {

using Bytes = std::vector<uint8_t>;

template <class T>
Bytes Serialize(const T& obj) {
	std::stringstream ss;
	Serial::Serialize(obj, ss, SerType::BINARY);
	const std::string s = ss.str();
	return Bytes(s.begin(), s.end());
}

template <class T>
void Deserialize(T& obj, const Bytes& b) {
	std::stringstream ss(std::string(b.begin(), b.end()));
	Serial::Deserialize(obj, ss, SerType::BINARY);
}

// ---- bit-serial comparator: encrypted a < PUBLIC constant c ----
// a is an LSB-first vector of encrypted bits, c a public w-bit threshold (a safety limit
// the central node knows). Recurrence, LSB to MSB (higher bits override):
//   c_i = 1:  lt = OR(NOT a_i, AND(a_i, lt))       c_i = 0:  lt = AND(NOT a_i, lt)
// Below the lowest set bit of c, lt is identically false, so it is seeded there as
// NOT a_low (free) and the lower bits are skipped. EvalNOT is free; AND / OR bootstrap.
LWECiphertext LessThanPublic(BinFHEContext& cc, const std::vector<LWECiphertext>& a, uint32_t c, long& gates) {
	const size_t w = a.size();
	int low = -1;
	for (size_t i = 0; i < w; ++i) {
		if ((c >> i) & 1u) {
			low = (int)i;
			break;
		}
	}
	LWECiphertext lt;
	size_t start;
	if (low < 0) {  // c == 0: a < c is false, an encrypted 0 = a0 AND NOT a0
		lt = cc.EvalBinGate(AND, a[0], cc.EvalNOT(a[0]));
		gates++;
		start = 1;
	} else {
		lt = cc.EvalNOT(a[low]);
		start = (size_t)low + 1;
	}
	for (size_t i = start; i < w; ++i) {
		if ((c >> i) & 1u) {
			LWECiphertext t = cc.EvalBinGate(AND, a[i], lt);
			lt = cc.EvalBinGate(OR, cc.EvalNOT(a[i]), t);
			gates += 2;
		} else {
			lt = cc.EvalBinGate(AND, cc.EvalNOT(a[i]), lt);
			gates++;
		}
	}
	return lt;
}

// ---- seeded LWE ----
// An LWE ciphertext is (a, b), b = <a, s> + e + m. The mask a is uniform, so if both
// sides derive it from a shared seed only b travels. The end node (holder of s) rewrites
// each body to match the seed-derived mask: b' = b + <a_seed - a, s> (noise and message
// unchanged); the central node regenerates the masks and rebuilds the ciphertexts.
// (mt19937_64 stands in for the seed-expanding PRF: same work shape, not secure.)
// The wire carries a 32-byte seed field, the size a real PRF seed would take.
constexpr size_t kSeedBytes = 32;
std::vector<NativeVector> SeedMasks(uint64_t seed, size_t count, uint32_t n, const NativeInteger& q) {
	std::mt19937_64 g(seed);
	const uint64_t qq = q.ConvertToInt();
	std::vector<NativeVector> masks;
	masks.reserve(count);
	for (size_t c = 0; c < count; ++c) {
		NativeVector a(n, q);
		for (uint32_t i = 0; i < n; ++i) a[i] = NativeInteger(g() % qq);
		masks.push_back(std::move(a));
	}
	return masks;
}

// The uplink as it crosses the link: the FHE payload (signed), the proofs.
struct Uplink {
	Bytes wire;
	Bytes signature;
	ipcei::zk::AdscMessage adsc;  // PID (+ in flags mode the flag comparisons; the flags stay private)
};

struct Downlink {
	Bytes wire;  // serialized command ciphertext
	Bytes signature;
};

struct Config {
	bool flags = false;
	bool compress = true;
	int sensors = 5;
	int width = 32;
	int bits_per_sensor() const { return flags ? 1 : width; }
};

class EndNode : public ipcei::Participant {
public:
	EndNode(ipcei::Recorder& rec, BinFHEContext& cc, LWEPrivateKey sk, const Config& cfg, const ipcei::zk::AdscSetup& adsc)
		: Participant(rec), cc_(cc), sk_(std::move(sk)), cfg_(cfg), adsc_(adsc) {
		const auto probe = cc_.Encrypt(sk_, 0);
		n_ = probe->GetA().GetLength();
		q_ = probe->GetModulus();
		uint64_t qq = q_.ConvertToInt();
		while (qbits_ < 64 && (uint64_t(1) << qbits_) < qq) ++qbits_;
	}
	const Bytes& PublicKey() const { return key_.PublicKey(); }
	uint32_t lwe_n() const { return n_; }
	NativeInteger lwe_q() const { return q_; }
	size_t full_uplink_bytes() const { return full_bytes_; }

	Uplink MakeUplink(int round, const std::vector<uint32_t>& readings, const std::vector<uint32_t>& thresholds,
			uint64_t seed) {
		const int S = cfg_.sensors, wb = cfg_.bits_per_sensor();
		std::vector<uint8_t> flags(S);
		for (int s = 0; s < S; ++s) flags[s] = readings[s] < thresholds[s];

		std::vector<LWECiphertext> cts;
		timed("encrypt", [&] {
			cts.reserve((size_t)S * wb);
			for (int s = 0; s < S; ++s) {
				for (int j = 0; j < wb; ++j) {
					const uint32_t bit = cfg_.flags ? flags[s] : ((readings[s] >> j) & 1u);
					cts.push_back(cc_.Encrypt(sk_, bit));
				}
			}
		});
		full_bytes_ = 0;
		for (const auto& c : cts) full_bytes_ += Serialize(c).size();

		Uplink up;
		timed("compress", [&] {
			if (!cfg_.compress) {
				for (const auto& c : cts) {
					const Bytes b = Serialize(c);
					up.wire.insert(up.wire.end(), b.begin(), b.end());
				}
				return;
			}
			const auto masks = SeedMasks(seed, cts.size(), n_, q_);
			const NativeVector& sv = sk_->GetElement();
			const int body_bytes = (qbits_ + 7) / 8;
			up.wire.assign(kSeedBytes + cts.size() * body_bytes, 0);
			std::memcpy(up.wire.data(), &seed, sizeof(seed));
			uint8_t* out = up.wire.data() + kSeedBytes;
			for (size_t c = 0; c < cts.size(); ++c) {
				const NativeVector& a = cts[c]->GetA();
				NativeInteger inner((uint64_t)0);
				for (uint32_t i = 0; i < n_; ++i) inner = inner.ModAdd(masks[c][i].ModSub(a[i], q_).ModMul(sv[i], q_), q_);
				const uint64_t b = cts[c]->GetB().ModAdd(inner, q_).ConvertToInt();
				std::memcpy(out + c * body_bytes, &b, body_bytes);  // little-endian
			}
		});
		// flags mode: the threshold sensors authenticate their readings and the proof covers
		// the comparisons too; stress mode: the PID circuit alone
		timed("adsc_authenticate", [&] {
			adsc_.Authenticate(round, cfg_.flags ? readings : std::vector<uint32_t>());
		});
		up.adsc = timed("adsc_prove", [&] { return adsc_.Prove(cfg_.flags ? thresholds : std::vector<uint32_t>()); });
		up.signature = timed("sign_uplink", [&] { return key_.Sign(up.wire); });
		return up;
	}

	bool ReadDownlink(const Downlink& dn, const Bytes& central_key, bool& command) {
		const bool ok = timed("verify_downlink", [&] { return ipcei::Ed25519::Verify(central_key, dn.wire, dn.signature); });
		if (!ok) return false;
		timed("decrypt", [&] {
			LWECiphertext ct;
			Deserialize(ct, dn.wire);
			LWEPlaintext out;
			cc_.Decrypt(sk_, ct, &out);
			command = (out & 1) != 0;
		});
		return true;
	}

private:
	BinFHEContext& cc_;
	LWEPrivateKey sk_;
	Config cfg_;
	ipcei::zk::AdscProver adsc_;
	ipcei::Ed25519 key_;
	uint32_t n_ = 0;
	NativeInteger q_;
	int qbits_ = 0;
	size_t full_bytes_ = 0;
};

class CentralNode : public ipcei::Participant {
public:
	CentralNode(ipcei::Recorder& rec, BinFHEContext& cc, const Config& cfg, const ipcei::zk::AdscSetup& adsc,
			uint32_t lwe_n, NativeInteger lwe_q)
		: Participant(rec), cc_(cc), cfg_(cfg), adsc_(adsc), n_(lwe_n), q_(lwe_q) {
		uint64_t qq = q_.ConvertToInt();
		while (qbits_ < 64 && (uint64_t(1) << qbits_) < qq) ++qbits_;
	}
	const Bytes& PublicKey() const { return key_.PublicKey(); }
	long gates() const { return gates_; }

	/// Returns false (and stops the round) when a signature or a proof is rejected.
	bool Process(const Uplink& up, const Bytes& end_key, const std::vector<uint32_t>& thresholds, Downlink& dn) {
		if (!timed("verify_uplink", [&] { return ipcei::Ed25519::Verify(end_key, up.wire, up.signature); })) return false;
		if (!timed("adsc_verify", [&] {
				return adsc_.Verify(up.adsc, cfg_.flags ? thresholds : std::vector<uint32_t>());
			}))
			return false;

		const int S = cfg_.sensors, wb = cfg_.bits_per_sensor();
		const size_t count = (size_t)S * wb;
		std::vector<LWECiphertext> cts(count);
		timed("decompress", [&] {
			if (!cfg_.compress) {
				std::stringstream ss(std::string(up.wire.begin(), up.wire.end()));
				for (auto& c : cts) Serial::Deserialize(c, ss, SerType::BINARY);
				return;
			}
			uint64_t seed;
			std::memcpy(&seed, up.wire.data(), sizeof(seed));
			const int body_bytes = (qbits_ + 7) / 8;
			const uint8_t* in = up.wire.data() + kSeedBytes;
			auto masks = SeedMasks(seed, count, n_, q_);
			for (size_t c = 0; c < count; ++c) {
				uint64_t b = 0;
				std::memcpy(&b, in + c * body_bytes, body_bytes);
				cts[c] = std::make_shared<LWECiphertextImpl>(std::move(masks[c]), NativeInteger(b), NativeInteger(4));
			}
		});

		LWECiphertext command;
		timed("evaluate", [&] {
			long gates = 0;
			std::vector<LWECiphertext> predicate(S);
			for (int s = 0; s < S; ++s) {
				if (cfg_.flags) {
					predicate[s] = cts[s];
				} else {
					std::vector<LWECiphertext> bits(cts.begin() + (size_t)s * wb, cts.begin() + (size_t)(s + 1) * wb);
					predicate[s] = LessThanPublic(cc_, bits, thresholds[s], gates);
				}
			}
			command = predicate[0];
			for (int s = 1; s < S; ++s) {
				command = cc_.EvalBinGate(AND, predicate[s], command);
				gates++;
			}
			gates_ = gates;
		});
		dn.wire = timed("compress_downlink", [&] { return Serialize(command); });
		dn.signature = timed("sign_downlink", [&] { return key_.Sign(dn.wire); });
		return true;
	}

private:
	BinFHEContext& cc_;
	Config cfg_;
	ipcei::zk::AdscVerifier adsc_;
	ipcei::Ed25519 key_;
	uint32_t n_;
	NativeInteger q_;
	int qbits_ = 0;
	long gates_ = 0;
};

}  // namespace

int main(int argc, char** argv) {
	// one thread unless OMP_NUM_THREADS says otherwise (all cores slow binfhe's small loops
	// down: n32 flags evaluate 72 ms single-threaded vs 115 ms on the 18 cores of an M5 Pro)
	ipcei::SingleThreadByDefault(argv);
	const ipcei::Options opts = ipcei::Options::Parse(argc, argv, 3);
	Config cfg;
	std::string paramset = "STD128";
	unsigned seed = 12345;
	for (size_t i = 0; i < opts.rest.size(); ++i) {
		const std::string& a = opts.rest[i];
		auto next = [&]() -> std::string {
			if (i + 1 >= opts.rest.size()) {
				std::fprintf(stderr, "missing value for %s\n", a.c_str());
				std::exit(2);
			}
			return opts.rest[++i];
		};
		if (a == "--mode") cfg.flags = next() == "flags";
		else if (a == "--sensors") cfg.sensors = std::atoi(next().c_str());
		else if (a == "--width") cfg.width = std::atoi(next().c_str());
		else if (a == "--paramset") paramset = next();
		else if (a == "--no-compress") cfg.compress = false;
		else if (a == "--seed") seed = (unsigned)std::atoi(next().c_str());
		else {
			std::fprintf(stderr, "unknown option %s\n", a.c_str());
			return 2;
		}
	}
	if (cfg.width < 1 || cfg.width > 32 || cfg.sensors < 1) {
		std::fprintf(stderr, "need 1 <= width <= 32 and sensors >= 1\n");
		return 2;
	}
	const int S = cfg.sensors, w = cfg.width;

	// ---- one-time setup (not reported): FHE keys, ZK keys, signature keys ----
	BINFHE_PARAMSET ps = STD128;
	if (paramset == "TOY") ps = TOY;
	else if (paramset == "STD128_4") ps = STD128_4;
	else if (paramset == "MEDIUM") ps = MEDIUM;
	BinFHEContext cc;
	cc.GenerateBinFHEContext(ps, GINX);
	LWEPrivateKey sk = cc.KeyGen();
	cc.BTKeyGen(sk);  // bootstrapping and key-switching keys: central-node material

	const ipcei::zk::AdscSetup adsc_setup(cfg.flags ? S : 0, w);

	ipcei::Recorder rec(opts.warmup);
	EndNode end(rec, cc, sk, cfg, adsc_setup);
	CentralNode central(rec, cc, cfg, adsc_setup, end.lwe_n(), end.lwe_q());

	rec.Param("mode", cfg.flags ? "flags" : "stress");
	rec.Param("paramset", paramset + " (GINX)");
	rec.Param("sensors", S);
	rec.Param("width", cfg.flags ? 1 : w);
	rec.Param("native_size", NATIVEINT);
	rec.Param("lwe_n", end.lwe_n());
	rec.Param("lwe_q", (double)end.lwe_q().ConvertToInt());
	rec.Param("uplink", cfg.compress ? "seeded LWE" : "full ciphertexts");
	rec.Param("signature", "Ed25519");
	rec.Param("backend", IPCEI_BACKEND);
	rec.Param("threads", std::to_string(omp_get_max_threads()));
	rec.Param("adsc_circuit", cfg.flags ? "PID + " + std::to_string(S) + " x " + std::to_string(w) + "-bit comparisons"
			: std::string("PID"));
	rec.Param("adsc_constraints", (double)adsc_setup.constraints());
	rec.Note("TFHE encrypts each bit directly: no separate encode step");
	rec.Note("no MAC in this design: no result check after decryption");
	rec.Note("downlink compress = serialization of the command ciphertext only");

	// ---- rounds ----
	std::mt19937 rng(seed), orng(seed ^ 0x5EED0ACEu);
	std::uniform_int_distribution<uint32_t> dist(0, w >= 32 ? 0xFFFFFFFFu : ((1u << w) - 1));
	size_t up_bytes = 0, dn_bytes = 0, adsc_bytes = 0;
	const int total = opts.warmup + opts.rounds;
	for (int r = 0; r < total; ++r) {
		// readings steered so every third round inhibits: one culprit at or above its threshold
		std::vector<uint32_t> reading(S), threshold(S);
		for (int s = 0; s < S; ++s) threshold[s] = dist(rng);
		const bool fire = ((r + 1) % 3) != 0;
		const int culprit = r % S;
		const uint64_t span_all = uint64_t(1) << w;
		for (int s = 0; s < S; ++s) {
			uint64_t t = threshold[s];
			if (!fire && s == culprit) {
				reading[s] = (uint32_t)(t + orng() % (span_all - t));
			} else {
				if (t == 0) threshold[s] = (uint32_t)(t = 1);
				reading[s] = (uint32_t)(orng() % t);
			}
		}
		bool expected = true;
		for (int s = 0; s < S; ++s) expected = expected && reading[s] < threshold[s];

		rec.BeginRound();
		Uplink up = end.MakeUplink(r, reading, threshold, 0x9E3779B97F4A7C15ull ^ (uint64_t)(seed + r));
		Downlink dn;
		bool ok = central.Process(up, end.PublicKey(), threshold, dn);
		bool command = false;
		ok = ok && end.ReadDownlink(dn, central.PublicKey(), command);
		rec.RoundResult(ok && command == expected);
		if (!opts.quiet)
			std::printf("round %2d  command %d (expected %d)%s  gates %ld\n", r, (int)command, (int)expected,
					r < opts.warmup ? "  [warm-up]" : "", central.gates());
		up_bytes = up.wire.size();
		dn_bytes = dn.wire.size();
		adsc_bytes = up.adsc.proof_bytes;
	}
	rec.Param("bootstrapped_gates", (double)central.gates());
	rec.Size("uplink (FHE payload)", (double)up_bytes);
	if (cfg.compress) rec.Size("uplink uncompressed", (double)end.full_uplink_bytes());
	rec.Size("downlink (FHE payload)", (double)dn_bytes);
	rec.Size("ADSC proof + commitment", (double)adsc_bytes);
	rec.Size("signature (each link)", (double)ipcei::Ed25519::kSignatureBytes);

	const std::string bench = std::string("tfhe_openfhe_") + (cfg.flags ? "flags" : "stress");
	ipcei::Report report(rec, bench, "OpenFHE " IPCEI_OPENFHE_VERSION, "TFHE");
	report.Print();
	if (!opts.json.empty()) report.WriteJson(opts.json);
	int correct = 0;
	for (bool b : rec.correct()) correct += b;
	return correct == (int)rec.correct().size() ? 0 : 1;
}
