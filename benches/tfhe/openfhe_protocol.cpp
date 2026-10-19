// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// openfhe_protocol.cpp — the window-lift round trip (scenario.hpp) in TFHE (OpenFHE binfhe,
// GINX bootstrapping), with the per-step breakdown of benches/common/ipcei/harness.hpp.
//
// Threat model: the end zones are trusted with their own data and share the key material;
// only the central compute (the Process APP) must be blind. One-time provisioning (not
// timed): one BinFHE context and one LWE secret key, provisioned into the HSEs of the three
// end zones; the bootstrapping keys at the central node; one Ed25519 key per node; one
// ADSC-SNARK setup per end zone.
//
// Round, by zone and step id (each end zone knows only its own message layout: its bits,
// in its own order):
//   passenger, driver, ign
//            adsc_authenticate (the zone's sensors authenticate SensorValues), adsc_prove
//            (ADSC-SNARK deriving the zone's bits from them), encrypt (one LWE ciphertext per
//            bit of AdscProver::bits(), secret key; no separate encode), compress (seeded LWE:
//            the bodies are rewritten to masks derived from the zone's fresh per-round seed,
//            the wire carries the seed and the bodies; --no-compress sends full serialized
//            ciphertexts), sign_uplink (Ed25519 over round || zone id || FHE payload)
//   central  per uplink: verify_uplink (signature + round), adsc_verify, decompress
//            (regenerate the masks, rebuild the ciphertexts); then evaluate (the gate
//            circuit below), compress_downlink (serialize the Motor+ and Motor- ciphertexts;
//            no compression), sign_downlink (Ed25519 over round || zone id || payload)
//   passenger
//            verify_downlink, decrypt (deserialize + decrypt both command bits)
// There is no MAC in this design (no check_result step).
//
// Two modes (--mode):
//   flags   the zones encrypt FlagBits (passenger pu, pd, top, bot, err; driver ou, od, cl;
//           ign k). Central gate circuit (EvalNOT is free, every other gate bootstraps):
//             ovr = OR(ou, od)      a = NOR(ovr, cl)
//             up = OR(ou, AND(a, pu))      dn = OR(od, AND(a, pd))
//             g = AND(k, NOT err)   T = AND(NOT top, g)   B = AND(NOT bot, g)
//             Motor+ = AND(up, T)   Motor- = AND(dn, B)                  11 bootstraps
//   stress  the zones encrypt RawBits (the passenger's 12 position bits and 4 error flags
//           instead of top, bot, err). The central node derives top = NOT(position < kTop)
//           and bot = position < kBottom + 1 with bit-serial comparators against the public
//           limits and err = OR of the four flags, then runs the same circuit: 6 + 6
//           comparator bootstraps (one per position bit above the limit's lowest set bit),
//           3 for the error OR, 11 for the decision = 26 bootstraps.
// The first Rounds::kCases measured rounds cover every case of the decision; the warm-up
// rounds draw from a separate generator so they do not shift them.
//
//   tfhe_openfhe [--mode flags|stress] [--paramset STD128|STD128_4|MEDIUM|TOY] [--no-compress]
//                [--seed N] [--rounds R] [--warmup W] [--json FILE] [--quiet]
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
#include "ipcei/net.hpp"
#include "comparator.hpp"
#include "ipcei/scenario.hpp"
#include "ipcei/sig.hpp"
#include "ipcei/zk.hpp"

using namespace lbcrypto;
using ipcei::Zone;
namespace window = ipcei::window;
namespace zk = ipcei::zk;

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

int ZoneIndex(Zone z) { return (int)z; }  // passenger 0, driver 1, ign 2


// ---- seeded LWE ----
// An LWE ciphertext is (a, b), b = <a, s> + e + m. The mask a is uniform, so if both
// sides derive it from a shared seed only b travels. The end zone (holder of s) rewrites
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

/// The LWE ciphertext shape every node agrees on (from the shared context).
struct LweShape {
	uint32_t n = 0;
	NativeInteger q;
	int qbits = 0;
	int body_bytes() const { return (qbits + 7) / 8; }
};

/// What a link signature covers: round || zone id || FHE payload.
Bytes LinkMessage(int round, Zone zone, const Bytes& payload) {
	Bytes m(5 + payload.size());
	const uint32_t r = (uint32_t)round;
	std::memcpy(m.data(), &r, 4);  // little-endian
	m[4] = (uint8_t)zone;
	if (!payload.empty()) std::memcpy(m.data() + 5, payload.data(), payload.size());
	return m;
}

struct Config {
	bool flags = true;
	bool compress = true;
	zk::Encoding encoding() const { return flags ? zk::Encoding::Flags : zk::Encoding::Raw; }
	std::vector<uint8_t> Bits(Zone z, const window::Inputs& in) const {
		return flags ? window::FlagBits(z, in) : window::RawBits(z, in);
	}
	/// The number of bits (ciphertexts) in a zone's uplink: the central node's view of the layouts.
	size_t BitCount(Zone z) const { return Bits(z, window::Inputs()).size(); }
};

// One zone's uplink as it crosses the link: header (round, zone), FHE payload, signature, proof.
struct Uplink {
	int round = 0;
	Zone zone = Zone::Passenger;
	Bytes wire;
	Bytes signature;
	zk::AdscMessage adsc;
};

struct Downlink {
	int round = 0;
	Bytes wire;  // serialized Motor+ and Motor- ciphertexts
	Bytes signature;
};

// ---- end zones ----
class EndZone : public ipcei::Participant {
public:
	EndZone(ipcei::Recorder& rec, Zone zone, BinFHEContext& cc, LWEPrivateKey sk, const LweShape& shape,
			const Config& cfg, const zk::AdscSetup& adsc, uint64_t seed)
		: Participant(rec, zone), cc_(cc), sk_(std::move(sk)), shape_(shape), cfg_(cfg), adsc_(adsc),
		  seeds_(seed ^ (0x9E3779B97F4A7C15ull * (uint64_t)(ZoneIndex(zone) + 1))) {}
	const Bytes& PublicKey() const { return key_.PublicKey(); }
	size_t full_uplink_bytes() const { return full_bytes_; }

	/// bits_ok: the bits the ADSC circuit derived equal the scenario's encoding of `in`.
	Uplink MakeUplink(int round, const window::Inputs& in, bool& bits_ok) {
		Uplink up;
		up.round = round;
		up.zone = zone_;
		timed("adsc_authenticate", [&] { adsc_.Authenticate(window::SensorValues(zone_, in)); });
		up.adsc = timed("adsc_prove", [&] { return adsc_.Prove(); });
		const std::vector<uint8_t>& bits = adsc_.bits();
		bits_ok = bits == cfg_.Bits(zone_, in);
		if (!bits_ok) std::fprintf(stderr, "round %d: %s ADSC bits differ from the scenario's\n", round, ZoneName(zone_));

		std::vector<LWECiphertext> cts;
		timed("encrypt", [&] {
			cts.reserve(bits.size());
			for (uint8_t b : bits) cts.push_back(cc_.Encrypt(sk_, b));
		});
		full_bytes_ = 0;
		for (const auto& c : cts) full_bytes_ += Serialize(c).size();

		const uint64_t seed = seeds_();  // this zone's fresh seed for this round
		timed("compress", [&] {
			if (!cfg_.compress) {
				for (const auto& c : cts) {
					const Bytes b = Serialize(c);
					up.wire.insert(up.wire.end(), b.begin(), b.end());
				}
				return;
			}
			const uint32_t n = shape_.n;
			const NativeInteger& q = shape_.q;
			const auto masks = SeedMasks(seed, cts.size(), n, q);
			const NativeVector& sv = sk_->GetElement();
			const int body_bytes = shape_.body_bytes();
			up.wire.assign(kSeedBytes + cts.size() * body_bytes, 0);
			std::memcpy(up.wire.data(), &seed, sizeof(seed));
			uint8_t* out = up.wire.data() + kSeedBytes;
			for (size_t c = 0; c < cts.size(); ++c) {
				const NativeVector& a = cts[c]->GetA();
				NativeInteger inner((uint64_t)0);
				for (uint32_t i = 0; i < n; ++i) inner = inner.ModAdd(masks[c][i].ModSub(a[i], q).ModMul(sv[i], q), q);
				const uint64_t b = cts[c]->GetB().ModAdd(inner, q).ConvertToInt();
				std::memcpy(out + c * body_bytes, &b, body_bytes);  // little-endian
			}
		});
		up.signature = timed("sign_uplink", [&] { return key_.Sign(LinkMessage(round, zone_, up.wire)); });
		return up;
	}

protected:
	BinFHEContext& cc_;
	LWEPrivateKey sk_;  // shared by the three end zones (provisioned)
	LweShape shape_;
	Config cfg_;
	zk::AdscProver adsc_;
	ipcei::Ed25519 key_;
	std::mt19937_64 seeds_;  // per-round compression seeds (stands in for the HSE's RNG)
	size_t full_bytes_ = 0;
};

/// The actuator: also receives the downlink.
class PassengerNode : public EndZone {
public:
	PassengerNode(ipcei::Recorder& rec, BinFHEContext& cc, LWEPrivateKey sk, const LweShape& shape, const Config& cfg,
			const zk::AdscSetup& adsc, uint64_t seed)
		: EndZone(rec, Zone::Passenger, cc, std::move(sk), shape, cfg, adsc, seed) {}

	/// motor[0] = Motor+, motor[1] = Motor-. False when the downlink signature or round is rejected.
	bool ReadDownlink(const Downlink& dn, int round, const Bytes& central_key, int motor[2]) {
		const bool ok = timed("verify_downlink", [&] {
			return dn.round == round &&
				ipcei::Ed25519::Verify(central_key, LinkMessage(dn.round, Zone::Central, dn.wire), dn.signature);
		});
		if (!ok) return false;
		timed("decrypt", [&] {
			std::stringstream ss(std::string(dn.wire.begin(), dn.wire.end()));
			for (int j = 0; j < 2; ++j) {
				LWECiphertext ct;
				Serial::Deserialize(ct, ss, SerType::BINARY);
				LWEPlaintext out;
				cc_.Decrypt(sk_, ct, &out);
				motor[j] = (int)(out & 1);
			}
		});
		return true;
	}
};

class DriverNode : public EndZone {
public:
	DriverNode(ipcei::Recorder& rec, BinFHEContext& cc, LWEPrivateKey sk, const LweShape& shape, const Config& cfg,
			const zk::AdscSetup& adsc, uint64_t seed)
		: EndZone(rec, Zone::Driver, cc, std::move(sk), shape, cfg, adsc, seed) {}
};

class IgnNode : public EndZone {
public:
	IgnNode(ipcei::Recorder& rec, BinFHEContext& cc, LWEPrivateKey sk, const LweShape& shape, const Config& cfg,
			const zk::AdscSetup& adsc, uint64_t seed)
		: EndZone(rec, Zone::Ign, cc, std::move(sk), shape, cfg, adsc, seed) {}
};

// ---- central compute: holds the bootstrapping keys (in cc), never the secret key ----
class CentralNode : public ipcei::Participant {
public:
	CentralNode(ipcei::Recorder& rec, BinFHEContext& cc, const LweShape& shape, const Config& cfg,
			const zk::AdscSetup* const adsc[3], const Bytes* const zone_keys[3])
		: Participant(rec, Zone::Central), cc_(cc), shape_(shape), cfg_(cfg) {
		for (int z = 0; z < 3; ++z) {
			adsc_[z].reset(new zk::AdscVerifier(*adsc[z]));
			zone_keys_[z] = *zone_keys[z];
		}
	}
	const Bytes& PublicKey() const { return key_.PublicKey(); }
	long gates() const { return gates_; }

	/// One zone's uplink: signature + round, proof, decompression. False when rejected.
	bool Receive(const Uplink& up, int round) {
		const int zi = ZoneIndex(up.zone);
		if (!timed("verify_uplink", [&] {
				return up.round == round &&
					ipcei::Ed25519::Verify(zone_keys_[zi], LinkMessage(up.round, up.zone, up.wire), up.signature);
			}))
			return false;
		if (!timed("adsc_verify", [&] { return adsc_[zi]->Verify(up.adsc); })) return false;

		const size_t count = cfg_.BitCount(up.zone);
		std::vector<LWECiphertext>& cts = cts_[zi];
		cts.assign(count, nullptr);
		return timed("decompress", [&] {
			if (!cfg_.compress) {
				std::stringstream ss(std::string(up.wire.begin(), up.wire.end()));
				for (auto& c : cts) Serial::Deserialize(c, ss, SerType::BINARY);
				return true;
			}
			const int body_bytes = shape_.body_bytes();
			if (up.wire.size() != kSeedBytes + count * body_bytes) return false;
			uint64_t seed;
			std::memcpy(&seed, up.wire.data(), sizeof(seed));
			const uint8_t* in = up.wire.data() + kSeedBytes;
			auto masks = SeedMasks(seed, count, shape_.n, shape_.q);
			for (size_t c = 0; c < count; ++c) {
				uint64_t b = 0;
				std::memcpy(&b, in + c * body_bytes, body_bytes);
				cts[c] = std::make_shared<LWECiphertextImpl>(std::move(masks[c]), NativeInteger(b), NativeInteger(4));
			}
			return true;
		});
	}

	/// The motor command over the three received uplinks, then the signed downlink.
	void Evaluate(int round, Downlink& dn) {
		LWECiphertext motor_up, motor_down;
		timed("evaluate", [&] {
			long gates = 0;
			auto gate = [&](BINGATE g, const LWECiphertext& x, const LWECiphertext& y) {
				gates++;
				return cc_.EvalBinGate(g, x, y);
			};
			auto NOT = [&](const LWECiphertext& x) { return cc_.EvalNOT(x); };
			const auto& P = cts_[ZoneIndex(Zone::Passenger)];
			const auto& D = cts_[ZoneIndex(Zone::Driver)];
			const auto& I = cts_[ZoneIndex(Zone::Ign)];
			LWECiphertext pu, pd, top, bot, err;
			if (cfg_.flags) {
				pu = P[window::kPu];
				pd = P[window::kPd];
				top = P[window::kTopFlag];
				bot = P[window::kBotFlag];
				err = P[window::kErr];
			} else {
				pu = P[window::kRawUp];
				pd = P[window::kRawDown];
				const std::vector<LWECiphertext> pos(P.begin() + window::kRawPos,
						P.begin() + window::kRawPos + window::kPositionBits);
				top = NOT(ipcei::LessThanPublic(cc_, pos, window::kTop, gates));        // position >= kTop
				bot = ipcei::LessThanPublic(cc_, pos, window::kBottom + 1, gates);      // position <= kBottom
				err = P[window::kRawErr];
				for (int j = 1; j < window::kErrorFlags; ++j) err = gate(OR, err, P[window::kRawErr + j]);
			}
			const LWECiphertext& ou = D[window::kOu];
			const LWECiphertext& od = D[window::kOd];
			const LWECiphertext& cl = D[window::kCl];
			const LWECiphertext& k = I[window::kK];

			const LWECiphertext ovr = gate(OR, ou, od);
			const LWECiphertext a = gate(NOR, ovr, cl);  // AND(NOT ovr, NOT cl): the passenger's button is allowed
			const LWECiphertext up = gate(OR, ou, gate(AND, a, pu));
			const LWECiphertext dn = gate(OR, od, gate(AND, a, pd));
			const LWECiphertext g = gate(AND, k, NOT(err));
			const LWECiphertext T = gate(AND, NOT(top), g);
			const LWECiphertext B = gate(AND, NOT(bot), g);
			motor_up = gate(AND, up, T);
			motor_down = gate(AND, dn, B);
			gates_ = gates;
		});
		dn.round = round;
		dn.wire = timed("compress_downlink", [&] {
			std::stringstream ss;
			Serial::Serialize(motor_up, ss, SerType::BINARY);
			Serial::Serialize(motor_down, ss, SerType::BINARY);
			const std::string s = ss.str();
			return Bytes(s.begin(), s.end());
		});
		dn.signature = timed("sign_downlink", [&] { return key_.Sign(LinkMessage(round, Zone::Central, dn.wire)); });
	}

private:
	BinFHEContext& cc_;
	LweShape shape_;
	Config cfg_;
	std::unique_ptr<zk::AdscVerifier> adsc_[3];
	Bytes zone_keys_[3];
	std::vector<LWECiphertext> cts_[3];  // this round's decompressed uplinks, by zone
	ipcei::Ed25519 key_;
	long gates_ = 0;
};

window::Cmd DecodeCmd(const int motor[2]) {
	return motor[0] ? window::Cmd::MotorUp : motor[1] ? window::Cmd::MotorDown : window::Cmd::Off;
}

}  // namespace

int main(int argc, char** argv) {
	// one thread unless OMP_NUM_THREADS says otherwise (all cores slow binfhe's small loops
	// down: n32 flags evaluate 72 ms single-threaded vs 115 ms on the 18 cores of an M5 Pro)
	ipcei::SingleThreadByDefault(argv);
	const ipcei::Options opts = ipcei::Options::Parse(argc, argv, window::Rounds::kCases);
	ipcei::net::Network net(opts);  // first: it forks its peer processes
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
		if (a == "--mode") {
			const std::string m = next();
			if (m != "flags" && m != "stress") {
				std::fprintf(stderr, "--mode flags|stress\n");
				return 2;
			}
			cfg.flags = m == "flags";
		} else if (a == "--paramset") paramset = next();
		else if (a == "--no-compress") cfg.compress = false;
		else if (a == "--seed") seed = (unsigned)std::atoi(next().c_str());
		else {
			std::fprintf(stderr, "unknown option %s\n", a.c_str());
			return 2;
		}
	}

	// ---- one-time provisioning (not reported) ----
	BINFHE_PARAMSET ps = STD128;
	if (paramset == "TOY") ps = TOY;
	else if (paramset == "STD128_4") ps = STD128_4;
	else if (paramset == "MEDIUM") ps = MEDIUM;
	BinFHEContext cc;
	cc.GenerateBinFHEContext(ps, GINX);
	LWEPrivateKey sk = cc.KeyGen();  // into the HSEs of the three end zones
	cc.BTKeyGen(sk);                 // bootstrapping and key-switching keys: central-node material

	LweShape shape;
	{
		const auto probe = cc.Encrypt(sk, 0);
		shape.n = probe->GetA().GetLength();
		shape.q = probe->GetModulus();
		const uint64_t qq = shape.q.ConvertToInt();
		while (shape.qbits < 64 && (uint64_t(1) << shape.qbits) < qq) ++shape.qbits;
	}

	const zk::AdscSetup adsc_p(Zone::Passenger, cfg.encoding());
	const zk::AdscSetup adsc_d(Zone::Driver, cfg.encoding());
	const zk::AdscSetup adsc_i(Zone::Ign, cfg.encoding());

	ipcei::Recorder rec(opts.warmup);
	PassengerNode passenger(rec, cc, sk, shape, cfg, adsc_p, seed);
	DriverNode driver(rec, cc, sk, shape, cfg, adsc_d, seed);
	IgnNode ign(rec, cc, sk, shape, cfg, adsc_i, seed);
	EndZone* const zones[3] = {&passenger, &driver, &ign};
	const zk::AdscSetup* const setups[3] = {&adsc_p, &adsc_d, &adsc_i};
	const Bytes* const zone_keys[3] = {&passenger.PublicKey(), &driver.PublicKey(), &ign.PublicKey()};
	CentralNode central(rec, cc, shape, cfg, setups, zone_keys);

	rec.Param("mode", cfg.flags ? "flags" : "stress");
	rec.Param("paramset", paramset + " (GINX)");
	rec.Param("native_size", NATIVEINT);
	rec.Param("lwe_n", shape.n);
	rec.Param("lwe_q", (double)shape.q.ConvertToInt());
	rec.Param("uplink", cfg.compress ? "seeded LWE" : "full ciphertexts");
	rec.Param("signature", "Ed25519");
	rec.Param("backend", IPCEI_BACKEND);
	rec.Param("threads", std::to_string(omp_get_max_threads()));
	for (int z = 0; z < 3; ++z)
		rec.Param(std::string("adsc_constraints_") + ZoneName(ipcei::kEndZones[z]), (double)setups[z]->constraints());
	net.Describe(rec);
	rec.Note("TFHE encrypts each bit directly: no separate encode step");
	rec.Note("no MAC in TFHE: no result check after decryption");
	rec.Note("the ADSC proofs show each zone's bits are derived from authenticated sensor data, "
			"but they are not bound to the ciphertexts");
	rec.Note("the end zones share the LWE secret key (trusted, provisioned into their HSEs)");
	rec.Note("downlink compress = serialization of the two command ciphertexts only");

	// ---- rounds ----
	window::Rounds rounds;                 // the measured rounds: first the kCases cases
	window::Rounds warm_rounds(0x5EED);    // the warm-up rounds, separately
	size_t up_bytes[3] = {0, 0, 0}, up_full[3] = {0, 0, 0}, adsc_bytes[3] = {0, 0, 0}, dn_bytes = 0;
	const int total = opts.warmup + opts.rounds;
	for (int r = 0; r < total; ++r) {
		const window::Inputs in = r < opts.warmup ? warm_rounds.Next() : rounds.Next();
		const window::Cmd expected = window::Decide(in);

		rec.BeginRound();
		bool ok = true;
		Uplink up[3];
		for (int z = 0; z < 3; ++z) {
			bool bits_ok = false;
			up[z] = zones[z]->MakeUplink(r, in, bits_ok);
			ok = ok && bits_ok;
		}
		for (int z = 0; z < 3; ++z)
			ok = net.Uplink(rec, ipcei::kEndZones[z], up[z].wire, up[z].signature, up[z].adsc.proof_bytes) && ok;
		for (int z = 0; z < 3; ++z) ok = central.Receive(up[z], r) && ok;  // every uplink is checked
		int motor[2] = {0, 0};
		Downlink dn;
		if (ok) {
			central.Evaluate(r, dn);
			ok = net.Downlink(rec, dn.wire, dn.signature);
			ok = ok && passenger.ReadDownlink(dn, r, central.PublicKey(), motor);
		}
		const bool valid = !(motor[0] && motor[1]);  // never both directions
		const window::Cmd got = DecodeCmd(motor);
		rec.RoundResult(ok && valid && got == expected);
		if (!opts.quiet)
			std::printf("round %2d  %-30s command %-6s (expected %-6s)%s%s  gates %ld\n", r, in.label.c_str(),
					!ok ? "reject" : valid ? window::CmdName(got) : "(1,1)", window::CmdName(expected),
					ok && valid && got == expected ? "" : "  WRONG", r < opts.warmup ? "  [warm-up]" : "",
					central.gates());
		for (int z = 0; z < 3; ++z) {
			up_bytes[z] = up[z].wire.size();
			up_full[z] = zones[z]->full_uplink_bytes();
			adsc_bytes[z] = up[z].adsc.proof_bytes;
		}
		dn_bytes = dn.wire.size();
	}
	rec.Param("bootstrapped_gates", (double)central.gates());
	for (int z = 0; z < 3; ++z)
		rec.Size(std::string("uplink ") + ZoneName(ipcei::kEndZones[z]) + " (FHE payload)", (double)up_bytes[z]);
	if (cfg.compress)
		for (int z = 0; z < 3; ++z)
			rec.Size(std::string("uplink ") + ZoneName(ipcei::kEndZones[z]) + " uncompressed", (double)up_full[z]);
	rec.Size("downlink (FHE payload)", (double)dn_bytes);
	for (int z = 0; z < 3; ++z)
		rec.Size(std::string("ADSC proof ") + ZoneName(ipcei::kEndZones[z]), (double)adsc_bytes[z]);
	rec.Size("signature (each link)", (double)ipcei::Ed25519::kSignatureBytes);

	const std::string bench = std::string("tfhe_openfhe_") + (cfg.flags ? "flags" : "stress");
	ipcei::Report report(rec, bench, "OpenFHE " IPCEI_OPENFHE_VERSION, "TFHE");
	report.Print();
	if (!opts.json.empty()) report.WriteJson(opts.json);
	int correct = 0;
	for (bool b : rec.correct()) correct += b;
	return correct == (int)rec.correct().size() ? 0 : 1;
}
