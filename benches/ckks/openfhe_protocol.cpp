// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// openfhe_protocol.cpp — the blindloop window-lift round (benches/common/ipcei/scenario.hpp)
// in CKKS (OpenFHE CKKSRNS), with the per-step breakdown of benches/common/ipcei/harness.hpp.
//
// The same protocol as bfv_openfhe, with CKKS's real-valued slots in place of BFV's Z_t:
//   - provisioning (not reported): ONE CKKS secret key shared by the three end zones, the
//     MAC key (ckks_common.hpp: k secret points alpha_m and a PRF key), the relinearization
//     key and the rotation keys at the central node, Ed25519 and ADSC setups;
//   - each zone packs its own variables from slot 0 (FlagBits order, a block of B = 7k slots
//     per variable holding its approximate tag at the public points), encodes them at the
//     top level (encode) and encrypts with the shared secret key, b = e - a s + m, its
//     uniform part a expanded from a fresh 32-byte seed with AES-256-CTR (encrypt); the
//     uplink carries the seed and b's residues bit-packed (compress). CKKS has no exact
//     modulus raise (q' -> Q multiplies the scale too), so the uplink is at the top level;
//   - the central node verifies, rebuilds the ciphertexts from the seeds (decompress) and
//     evaluates in SIMD lanes, bfv_openfhe --eval lanes (EvaluateLanes there has the lane
//     table): 3 tensor products and relinearizations, 13 rotations in 3 hoisted groups,
//     depth 3. compress_downlink: OpenFHE Compress to one RNS limb (rescales included),
//     then --drop low bits of every coefficient rounded away and the rest bit-packed;
//   - the passenger rebuilds the 1-limb ciphertext, decrypts and decodes it (decrypt) and
//     checks the approximate tag of every instance, reading the command from Y(0)
//     (check_result: ckks_common.hpp, TagChecker).
//
// Parameters: HEStd_128_classic, depth 3, OpenFHE's own parameter generation for the ring
// dimension and the chain from --first-bits (q0) and --scaling-bits (each rescaling prime,
// the scale). Key switching HYBRID (OpenFHE's CKKS default; the special modulus P makes the
// key-switching noise small against the scale) with one digit per limb (--dnum 4): OpenFHE
// then needs one 60-bit P prime, 46 + 37 + 36 + 37 + 60 = 216 bits fits N = 8192, and the
// decoded slots come out within ~2^-21. OpenFHE's default dnum (2) needs P = 2 x 60 and
// N = 16384 (2.2x the evaluation), as does a 50-bit q0 with 38-bit scales. BV, the BFV
// benches' choice, has no P: its noise is ~ one digit (--digit-size bits) times N against a
// scale of only 2^36, so it needs small digits, many of them (digit size 20 decrypts wrong,
// 10 is correct at ~2^-8 and 3.6x slower than HYBRID). Scaling FLEXIBLEAUTO (exact scale
// tracking, as ckks_seal does by hand). --drop as in ckks_seal: each dropped bit costs about
// one bit of precision.
//
//   ckks_openfhe [--first-bits 46] [--scaling-bits 36] [--ks HYBRID|BV] [--dnum 4] [--digit-size B]
//                [--scaling FLEXIBLEAUTO|FLEXIBLEAUTOEXT|FIXEDAUTO] [--ring-dim N] [--mac-k 3]
//                [--mac-tol T] [--drop BITS] [--no-hoist] [--seed N] [--rounds R] [--warmup W]
//                [--json FILE] [--quiet]
#include <omp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "ciphertext-ser.h"
#include "openfhe.h"
#include "scheme/ckksrns/ckksrns-ser.h"

#include "ckks_common.hpp"
#include "ipcei/harness.hpp"
#include "ipcei/net.hpp"
#include "ipcei/scenario.hpp"
#include "ipcei/sig.hpp"
#include "ipcei/zk.hpp"

using namespace lbcrypto;
using ipcei::Zone;
namespace window = ipcei::window;
namespace zk = ipcei::zk;
namespace ck = ipcei::ckks;
using ck::Bytes;

#ifndef IPCEI_BACKEND
#define IPCEI_BACKEND "stock"
#endif
#ifndef IPCEI_OPENFHE_VERSION
#define IPCEI_OPENFHE_VERSION "unknown"
#endif

namespace {

struct Config {
	int first_bits = 46;
	int scaling_bits = 36;
	KeySwitchTechnique ks = HYBRID;
	int dnum = 4;        // HYBRID large digits (0: OpenFHE's default)
	int digit_size = 0;  // BV digit size in bits (0: OpenFHE's default, one digit per limb)
	ScalingTechnique scaling = FLEXIBLEAUTO;
	uint32_t ring_dim = 0;  // 0: the smallest N for 128-bit security
	int mac_k = 3;
	double mac_tol = 0x1p-14;
	int drop = 0;
	bool hoist = true;
	uint64_t seed = 1;
};

const char* ScalingName(ScalingTechnique s) {
	switch (s) {
		case FLEXIBLEAUTO: return "FLEXIBLEAUTO";
		case FLEXIBLEAUTOEXT: return "FLEXIBLEAUTOEXT";
		case FIXEDAUTO: return "FIXEDAUTO";
		default: return "?";
	}
}

template <class T>
Bytes Serialize(const T& obj) {
	std::stringstream ss;
	Serial::Serialize(obj, ss, SerType::BINARY);
	const std::string s = ss.str();
	return Bytes(s.begin(), s.end());
}

/// Bit-packs the RNS residues of `p` (any format), tower i at ceil(log2 q_i) bits.
void PackPoly(const DCRTPoly& p, Bytes& out) {
	ck::BitWriter w(out);
	std::vector<uint64_t> v;
	for (const auto& tower : p.GetAllElements()) {
		const auto& vals = tower.GetValues();
		v.resize(vals.GetLength());
		for (size_t j = 0; j < v.size(); ++j) v[j] = vals[j].ConvertToInt<uint64_t>();
		ck::PackResidues(v.data(), v.size(), tower.GetModulus().ConvertToInt<uint64_t>(), w);
	}
}

NativePoly MakeTower(const NativePoly& like, const std::vector<uint64_t>& v, Format format) {
	NativeVector nv(like.GetRingDimension(), like.GetModulus());
	for (size_t j = 0; j < v.size(); ++j) nv[j] = NativeInteger(v[j]);
	NativePoly t(like.GetParams(), format, true);
	t.SetValues(std::move(nv), format);
	return t;
}

/// The uniform part a of uplink ciphertext `index` from the 32-byte seed, in EVALUATION format.
DCRTPoly ExpandA(const uint8_t* seed, uint32_t index, const std::shared_ptr<DCRTPoly::Params>& params) {
	DCRTPoly a(params, Format::EVALUATION, true);
	std::vector<uint64_t> v(params->GetRingDimension());
	for (size_t i = 0; i < a.GetNumOfElements(); ++i) {
		const auto& tower = a.GetElementAtIndex(i);
		ck::ExpandUniform(seed, index, (uint32_t)i, tower.GetModulus().ConvertToInt<uint64_t>(), v.data(), v.size());
		a.SetElementAtIndex(i, MakeTower(tower, v, Format::EVALUATION));
	}
	return a;
}

struct Provisioning {
	KeyPair<DCRTPoly> keys;
	ck::MacKey mac;
};

struct Uplink {
	Bytes wire;  // round | zone | FHE payload (signed)
	Bytes signature;
	zk::AdscMessage adsc;
};

struct Downlink {
	Bytes wire;  // round | downlink header | c0, c1 (signed)
	Bytes signature;
};

// ---------------------------------------------------------------- end zones

class EndZoneNode : public ipcei::Participant {
public:
	EndZoneNode(ipcei::Recorder& rec, Zone zone, CryptoContext<DCRTPoly> cc, const Config& cfg,
			const Provisioning& prov, const zk::AdscSetup& adsc)
		: Participant(rec, zone), cc_(cc), cfg_(cfg), prov_(prov), prf_(prov.mac.prf_key), adsc_(adsc) {
		params_ = cc_->GetCryptoParameters()->GetElementParams();
	}

	const Bytes& SigningKey() const { return sig_.PublicKey(); }
	size_t full_uplink_bytes() const { return full_uplink_bytes_; }

	Uplink MakeUplink(uint32_t round, const window::Inputs& in) {
		Uplink up;
		timed("adsc_authenticate", [&] { adsc_.Authenticate(window::SensorValues(zone_, in)); });
		timed("adsc_prove", [&] { up.adsc = adsc_.Prove(); });
		const std::vector<uint8_t>& bits = adsc_.bits();  // what the circuit derived: the zone encrypts these
		Plaintext pt;
		timed("encode", [&] { pt = cc_->MakeCKKSPackedPlaintext(ck::ZoneSlots(prov_.mac, prf_, round, zone_, bits)); });
		Ciphertext<DCRTPoly> ct;
		uint8_t seed[ck::kSeedBytes] = {0};
		timed("encrypt", [&] {
			RAND_bytes(seed, sizeof seed);
			ct = Encrypt(pt, seed);
		});
		timed("compress", [&] {
			ck::PutU32(up.wire, round);
			up.wire.push_back((uint8_t)zone_);
			ck::PutU32(up.wire, (uint32_t)ct->GetElements()[0].GetNumOfElements());
			up.wire.insert(up.wire.end(), seed, seed + ck::kSeedBytes);
			PackPoly(ct->GetElements()[0], up.wire);
		});
		if (full_uplink_bytes_ == 0) full_uplink_bytes_ = Serialize(ct).size();  // reference size, untimed
		timed("sign_uplink", [&] { up.signature = sig_.Sign(up.wire); });
		return up;
	}

protected:
	// Secret-key CKKS encryption, b = e - a s + m (PKERNS::Encrypt with a expanded from the
	// seed instead of sampled), with the plaintext's metadata as CryptoContext::Encrypt sets it.
	Ciphertext<DCRTPoly> Encrypt(const Plaintext& pt, const uint8_t* seed) {
		const auto cp = std::dynamic_pointer_cast<CryptoParametersRNS>(cc_->GetCryptoParameters());
		DCRTPoly m = pt->GetElement<DCRTPoly>();
		m.SetFormat(Format::EVALUATION);
		const auto ep = m.GetParams();
		DCRTPoly sk = prov_.keys.secretKey->GetPrivateElement();
		if (sk.GetNumOfElements() > ep->GetParams().size()) sk.DropLastElements(sk.GetNumOfElements() - ep->GetParams().size());
		DCRTPoly a = ExpandA(seed, 0, ep);
		DCRTPoly b(cp->GetDiscreteGaussianGenerator(), ep, Format::EVALUATION);
		b -= a * sk;
		b += m;
		auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(prov_.keys.secretKey);
		ct->SetElements({std::move(b), std::move(a)});
		ct->SetSlots(pt->GetSlots());
		ct->SetLevel(pt->GetLevel());
		ct->SetNoiseScaleDeg(pt->GetNoiseScaleDeg());
		ct->SetScalingFactor(pt->GetScalingFactor());
		ct->SetScalingFactorInt(pt->GetScalingFactorInt());
		ct->SetEncodingType(pt->GetEncodingType());
		return ct;
	}

	CryptoContext<DCRTPoly> cc_;
	Config cfg_;
	const Provisioning& prov_;
	std::shared_ptr<DCRTPoly::Params> params_;
	ck::MacPrf prf_;
	zk::AdscProver adsc_;
	ipcei::Ed25519 sig_;
	size_t full_uplink_bytes_ = 0;
};

class DriverNode : public EndZoneNode {
public:
	DriverNode(ipcei::Recorder& rec, CryptoContext<DCRTPoly> cc, const Config& cfg, const Provisioning& prov,
			const zk::AdscSetup& adsc)
		: EndZoneNode(rec, Zone::Driver, cc, cfg, prov, adsc) {}
};

class IgnNode : public EndZoneNode {
public:
	IgnNode(ipcei::Recorder& rec, CryptoContext<DCRTPoly> cc, const Config& cfg, const Provisioning& prov,
			const zk::AdscSetup& adsc)
		: EndZoneNode(rec, Zone::Ign, cc, cfg, prov, adsc) {}
};

/// The actuator: decrypts the downlink and checks the tag of the whole decision.
class PassengerNode : public EndZoneNode {
public:
	PassengerNode(ipcei::Recorder& rec, CryptoContext<DCRTPoly> cc, const Config& cfg, const Provisioning& prov,
			const zk::AdscSetup& adsc)
		: EndZoneNode(rec, Zone::Passenger, cc, cfg, prov, adsc), checker_(prov.mac, cfg.mac_tol) {}

	double cmd_dev() const { return cmd_dev_; }
	double tag_dev() const { return tag_dev_; }
	const ck::TagChecker& checker() const { return checker_; }

	ck::TagCheck ReadDownlink(uint32_t round, const Downlink& dl, const Bytes& central_key, bool& sig_ok) {
		timed("verify_downlink", [&] {
			sig_ok = ipcei::Ed25519::Verify(central_key, dl.wire, dl.signature) && ck::GetU32(dl.wire, 0) == round;
		});
		std::vector<double> y;
		timed("decrypt", [&] { y = Decrypt(Unpack(dl.wire)); });
		ck::TagCheck c;
		timed("check_result", [&] { c = checker_.Check(round, y); });
		cmd_dev_ = std::max(cmd_dev_, c.cmd_dev);
		tag_dev_ = std::max(tag_dev_, c.tag_dev);
		return c;
	}

	bool AcceptsUntimed(uint32_t round, const Downlink& dl, const Bytes& central_key) {
		if (!ipcei::Ed25519::Verify(central_key, dl.wire, dl.signature) || ck::GetU32(dl.wire, 0) != round) return false;
		return checker_.Check(round, Decrypt(Unpack(dl.wire))).ok;
	}

private:
	// Inverse of CentralNode::CompressDownlink (wire format there).
	Ciphertext<DCRTPoly> Unpack(const Bytes& wire) {
		size_t pos = ck::kDownlinkHeader;
		const int drop = (int)ck::GetU32(wire, pos);
		const double sf = ck::GetF64(wire, pos + 4);
		const uint32_t level = ck::GetU32(wire, pos + 12);
		DCRTPoly like(params_, Format::EVALUATION, true);
		like.DropLastElements(like.GetNumOfElements() - 1);
		const auto& tower = like.GetElementAtIndex(0);
		const uint64_t q = tower.GetModulus().ConvertToInt<uint64_t>();
		ck::BitReader r(wire, pos + 16);
		std::vector<uint64_t> v(tower.GetRingDimension());
		std::vector<DCRTPoly> cv;
		for (int e = 0; e < 2; ++e) {
			ck::UnpackRounded(r, v.data(), v.size(), q, drop);
			NativePoly t = MakeTower(tower, v, Format::COEFFICIENT);
			t.SetFormat(Format::EVALUATION);
			DCRTPoly p = like;
			p.SetElementAtIndex(0, std::move(t));
			cv.push_back(std::move(p));
		}
		auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(prov_.keys.secretKey);
		ct->SetElements(std::move(cv));
		ct->SetEncodingType(CKKS_PACKED_ENCODING);
		ct->SetSlots(cc_->GetEncodingParams()->GetBatchSize());
		ct->SetLevel(level);
		ct->SetNoiseScaleDeg(1);
		ct->SetScalingFactor(sf);
		return ct;
	}

	std::vector<double> Decrypt(const Ciphertext<DCRTPoly>& ct) {
		Plaintext pt;
		cc_->Decrypt(prov_.keys.secretKey, ct, &pt);
		return pt->GetRealPackedValue();
	}

	ck::TagChecker checker_;
	double cmd_dev_ = 0, tag_dev_ = 0;
};

// ---------------------------------------------------------------- central node

class CentralNode : public ipcei::Participant {
public:
	CentralNode(ipcei::Recorder& rec, CryptoContext<DCRTPoly> cc, const Config& cfg, std::string key_tag,
			const std::map<Zone, const zk::AdscSetup*>& adsc, const std::map<Zone, Bytes>& zone_keys)
		: Participant(rec, Zone::Central), cc_(cc), cfg_(cfg), tag_(std::move(key_tag)), zone_keys_(zone_keys) {
		params_ = cc_->GetCryptoParameters()->GetElementParams();
		for (const auto& z : adsc) adsc_[z.first].reset(new zk::AdscVerifier(*z.second));
		B_ = ck::Block(cfg_.mac_k);
		one_a_ = cc_->MakeCKKSPackedPlaintext(ck::Ones({ck::kLaneA}, B_));
		one_b_ = cc_->MakeCKKSPackedPlaintext(
				ck::Ones({ck::kLaneG, ck::kLaneA, ck::kLaneX, ck::kLaneX + 1, ck::kLaneZ, ck::kLaneZ + 1}, B_));
		probe_ = cc_->MakeCKKSPackedPlaintext(std::vector<double>{0.0});
	}
	const Bytes& SigningKey() const { return sig_.PublicKey(); }
	size_t onelimb_downlink_bytes() const { return onelimb_downlink_bytes_; }

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

	Downlink Process(uint32_t round) {
		Ciphertext<DCRTPoly> y;
		timed("evaluate", [&] { y = EvaluateLanes(); });
		Downlink dl;
		timed("compress_downlink", [&] { dl.wire = CompressDownlink(round, y); });
		timed("sign_downlink", [&] { dl.signature = sig_.Sign(dl.wire); });
		if (onelimb_downlink_bytes_ == 0) onelimb_downlink_bytes_ = Serialize(cc_->Compress(y, 1)).size();  // untimed
		return dl;
	}

	/// Untimed: a dishonest central node adds 1 at every slot (Off becomes Motor+).
	Downlink ProcessTampered(uint32_t round) {
		Downlink dl;
		dl.wire = CompressDownlink(round, cc_->EvalAdd(EvaluateLanes(), 1.0));
		dl.signature = sig_.Sign(dl.wire);
		return dl;
	}

private:
	Ciphertext<DCRTPoly> Decompress(const Bytes& wire) {
		const size_t Lu = ck::GetU32(wire, ck::kUplinkHeader);
		const uint8_t* seed = wire.data() + ck::kUplinkHeader + 4;
		ck::BitReader r(wire, ck::kUplinkHeader + 4 + ck::kSeedBytes);
		DCRTPoly b(params_, Format::EVALUATION, true);
		if (b.GetNumOfElements() > Lu) b.DropLastElements(b.GetNumOfElements() - Lu);
		std::vector<uint64_t> v(b.GetRingDimension());
		for (size_t i = 0; i < Lu; ++i) {
			const auto& tower = b.GetElementAtIndex(i);
			ck::UnpackResidues(r, v.data(), v.size(), tower.GetModulus().ConvertToInt<uint64_t>());
			b.SetElementAtIndex(i, MakeTower(tower, v, Format::EVALUATION));
		}
		DCRTPoly a = ExpandA(seed, 0, b.GetParams());
		auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(cc_);
		ct->SetKeyTag(tag_);
		ct->SetElements({std::move(b), std::move(a)});
		ct->SetSlots(probe_->GetSlots());
		ct->SetLevel(probe_->GetLevel());
		ct->SetNoiseScaleDeg(probe_->GetNoiseScaleDeg());
		ct->SetScalingFactor(probe_->GetScalingFactor());
		ct->SetScalingFactorInt(probe_->GetScalingFactorInt());
		ct->SetEncodingType(CKKS_PACKED_ENCODING);
		return ct;
	}

	Ciphertext<DCRTPoly> Rot(const Ciphertext<DCRTPoly>& c, int blocks,
			const std::shared_ptr<std::vector<DCRTPoly>>& digits) const {
		if (blocks == 0) return c;
		const int idx = ck::SlotShift(blocks, B_, (int)cc_->GetEncodingParams()->GetBatchSize());
		if (digits) return cc_->EvalFastRotation(c, (uint32_t)idx, 2 * cc_->GetRingDimension(), digits);
		return cc_->EvalRotate(c, idx);
	}
	std::shared_ptr<std::vector<DCRTPoly>> Hoist(const Ciphertext<DCRTPoly>& c) const {
		return cfg_.hoist ? cc_->EvalFastRotationPrecompute(c) : nullptr;
	}

	// bfv_openfhe EvaluateLanes, on CKKS slots (the lane table is there).
	Ciphertext<DCRTPoly> EvaluateLanes() {
		using namespace window;
		using namespace ipcei::ckks;
		const auto& P = in_.at(Zone::Passenger);
		const auto& D = in_.at(Zone::Driver);
		const auto& K = in_.at(Zone::Ign);
		const auto hp = Hoist(P), hd = Hoist(D);
		auto p = [&](int var, int lane) { return Rot(P, var - lane, hp); };  // passenger variable -> lane
		auto d = [&](int var, int lane) { return Rot(D, var - lane, hd); };  // driver variable -> lane
		Ciphertext<DCRTPoly> A = cc_->EvalAdd(K, one_a_);                    // k at kLaneG = kK
		cc_->EvalAddInPlace(A, p(kPu, kLaneX));                              // pu, pd
		cc_->EvalAddInPlace(A, d(kOu, kLaneZ));                              // ou, od
		cc_->EvalSubInPlace(A, d(kOu, kLaneA));
		cc_->EvalSubInPlace(A, d(kOd, kLaneA));                              // 1 - ou - od
		Ciphertext<DCRTPoly> Bf = cc_->EvalSub(one_b_, p(kErr, kLaneG));     // 1 - err
		cc_->EvalSubInPlace(Bf, d(kCl, kLaneA));                             // 1 - cl
		cc_->EvalSubInPlace(Bf, p(kTopFlag, kLaneX));                        // 1 - top, 1 - bot
		cc_->EvalSubInPlace(Bf, p(kTopFlag, kLaneZ));                        // 1 - top, 1 - bot
		const auto Q = cc_->EvalMult(A, Bf);
		const auto hq = Hoist(Q);
		auto q = [&](int lane) { return Rot(Q, lane, hq); };  // lane -> block 0
		auto X = q(kLaneX);
		cc_->EvalSubInPlace(X, q(kLaneX + 1));
		auto Z = q(kLaneZ);
		cc_->EvalSubInPlace(Z, q(kLaneZ + 1));
		auto S = cc_->EvalMult(q(kLaneA), X);
		cc_->EvalAddInPlace(S, Z);
		return cc_->EvalMult(Q, S);
	}

	// Downlink wire: u32 round | u32 drop | f64 scaling factor | u32 level | c0, c1 at one
	// limb in COEFFICIENT format, each coefficient as round(x / 2^drop), bit-packed.
	Bytes CompressDownlink(uint32_t round, const Ciphertext<DCRTPoly>& y) {
		auto c = cc_->Compress(y, 1);
		Bytes w;
		ck::PutU32(w, round);
		ck::PutU32(w, (uint32_t)cfg_.drop);
		ck::PutF64(w, c->GetScalingFactor());
		ck::PutU32(w, (uint32_t)c->GetLevel());
		ck::BitWriter bw(w);
		std::vector<uint64_t> v;
		for (DCRTPoly p : c->GetElements()) {
			p.SetFormat(Format::COEFFICIENT);
			const auto& tower = p.GetElementAtIndex(0);
			const auto& vals = tower.GetValues();
			v.resize(vals.GetLength());
			for (size_t j = 0; j < v.size(); ++j) v[j] = vals[j].ConvertToInt<uint64_t>();
			ck::PackRounded(v.data(), v.size(), tower.GetModulus().ConvertToInt<uint64_t>(), cfg_.drop, bw);
		}
		return w;
	}

	CryptoContext<DCRTPoly> cc_;
	Config cfg_;
	std::string tag_;
	std::map<Zone, Bytes> zone_keys_;
	std::shared_ptr<DCRTPoly::Params> params_;
	std::map<Zone, std::unique_ptr<zk::AdscVerifier>> adsc_;
	std::map<Zone, Ciphertext<DCRTPoly>> in_;  // this round's decompressed uplinks
	Plaintext one_a_, one_b_, probe_;
	int B_ = 1;
	ipcei::Ed25519 sig_;
	size_t onelimb_downlink_bytes_ = 0;
};

// ---------------------------------------------------------------- driver

int Usage() {
	std::fprintf(stderr,
			"usage: ckks_openfhe [--first-bits 46] [--scaling-bits 36] [--ks HYBRID|BV] [--dnum 4] [--digit-size B]\n"
			"                    [--scaling FLEXIBLEAUTO|FLEXIBLEAUTOEXT|FIXEDAUTO] [--ring-dim N] [--mac-k 3]\n"
			"                    [--mac-tol T] [--drop BITS] [--no-hoist] [--seed N] [--rounds R] [--warmup W]\n"
			"                    [--json FILE] [--quiet]\n");
	return 2;
}

}  // namespace

int main(int argc, char** argv) {
	ipcei::SingleThreadByDefault(argv);
	ipcei::Options opts = ipcei::Options::Parse(argc, argv, window::Rounds::kCases);
	ipcei::net::Network net(opts);  // first: it forks its peer processes
	Config cfg;
	for (size_t i = 0; i < opts.rest.size(); ++i) {
		const std::string& a = opts.rest[i];
		auto next = [&]() -> std::string {
			if (i + 1 >= opts.rest.size()) {
				std::fprintf(stderr, "missing value for %s\n", a.c_str());
				std::exit(2);
			}
			return opts.rest[++i];
		};
		if (a == "--first-bits") cfg.first_bits = std::atoi(next().c_str());
		else if (a == "--scaling-bits") cfg.scaling_bits = std::atoi(next().c_str());
		else if (a == "--ks") {
			const std::string v = next();
			if (v != "BV" && v != "HYBRID") return Usage();
			cfg.ks = v == "BV" ? BV : HYBRID;
		} else if (a == "--dnum") cfg.dnum = std::atoi(next().c_str());
		else if (a == "--digit-size") cfg.digit_size = std::atoi(next().c_str());
		else if (a == "--scaling") {
			const std::string v = next();
			if (v == "FLEXIBLEAUTO") cfg.scaling = FLEXIBLEAUTO;
			else if (v == "FLEXIBLEAUTOEXT") cfg.scaling = FLEXIBLEAUTOEXT;
			else if (v == "FIXEDAUTO") cfg.scaling = FIXEDAUTO;
			else return Usage();
		} else if (a == "--ring-dim") cfg.ring_dim = (uint32_t)std::atoi(next().c_str());
		else if (a == "--mac-k") cfg.mac_k = std::atoi(next().c_str());
		else if (a == "--mac-tol") cfg.mac_tol = std::atof(next().c_str());
		else if (a == "--drop") cfg.drop = std::atoi(next().c_str());
		else if (a == "--no-hoist") cfg.hoist = false;
		else if (a == "--seed") cfg.seed = std::strtoull(next().c_str(), nullptr, 10);
		else return Usage();
	}
	if (cfg.mac_k < 0 || cfg.mac_k > 16 || cfg.drop < 0 || cfg.drop >= cfg.first_bits) return Usage();

	// ---- one-time setup and provisioning (not reported)
	CCParams<CryptoContextCKKSRNS> p;
	p.SetMultiplicativeDepth(3);
	p.SetScalingModSize(cfg.scaling_bits);
	p.SetFirstModSize(cfg.first_bits);
	p.SetScalingTechnique(cfg.scaling);
	p.SetKeySwitchTechnique(cfg.ks);
	p.SetSecurityLevel(HEStd_128_classic);
	if (cfg.dnum > 0) p.SetNumLargeDigits(cfg.dnum);
	if (cfg.digit_size > 0) p.SetDigitSize(cfg.digit_size);
	if (cfg.ring_dim > 0) p.SetRingDim(cfg.ring_dim);
	CryptoContext<DCRTPoly> cc = GenCryptoContext(p);
	cc->Enable(PKE);
	cc->Enable(KEYSWITCH);
	cc->Enable(LEVELEDSHE);

	const uint32_t N = cc->GetRingDimension();
	const int B = ck::Block(cfg.mac_k);
	const int slots = (int)cc->GetEncodingParams()->GetBatchSize();
	if (ck::kLanesUsed * B > slots) {
		std::fprintf(stderr, "too many MAC instances for %d slots\n", slots);
		return 2;
	}
	int logQ = 0, logP = 0;
	std::string limbs, plimbs;
	const auto cpr = std::dynamic_pointer_cast<CryptoParametersRNS>(cc->GetCryptoParameters());
	for (const auto& tw : cpr->GetElementParams()->GetParams()) {
		logQ += tw->GetModulus().GetMSB();
		limbs += (limbs.empty() ? "" : "+") + std::to_string(tw->GetModulus().GetMSB());
	}
	if (cfg.ks == HYBRID && cpr->GetParamsP())
		for (const auto& tw : cpr->GetParamsP()->GetParams()) {
			logP += tw->GetModulus().GetMSB();
			plimbs += (plimbs.empty() ? "" : "+") + std::to_string(tw->GetModulus().GetMSB());
		}

	Provisioning prov;
	{
		std::mt19937_64 rng(cfg.seed ^ 0x5eed5eedULL);
		prov.keys = cc->KeyGen();
		cc->EvalMultKeyGen(prov.keys.secretKey);
		std::vector<int32_t> rot;
		for (const auto& group : ck::RotationGroups())
			for (int blocks : group) {
				const int32_t idx = ck::SlotShift(blocks, B, slots);
				if (idx && std::find(rot.begin(), rot.end(), idx) == rot.end()) rot.push_back(idx);
			}
		cc->EvalRotateKeyGen(prov.keys.secretKey, rot);
		std::uniform_real_distribution<double> pick(0.5, 1.0);
		prov.mac.k = cfg.mac_k;
		for (int m = 0; m < cfg.mac_k; ++m) prov.mac.alpha.push_back(pick(rng));
		for (size_t i = 0; i < ck::kMacKeyBytes; ++i) prov.mac.prf_key[i] = (uint8_t)rng();
	}

	ipcei::Recorder rec(opts.warmup);
	std::map<Zone, std::unique_ptr<zk::AdscSetup>> adsc_setup;
	for (Zone z : ipcei::kEndZones) adsc_setup[z].reset(new zk::AdscSetup(z, zk::Encoding::Flags));
	PassengerNode passenger(rec, cc, cfg, prov, *adsc_setup[Zone::Passenger]);
	DriverNode driver(rec, cc, cfg, prov, *adsc_setup[Zone::Driver]);
	IgnNode ign(rec, cc, cfg, prov, *adsc_setup[Zone::Ign]);
	EndZoneNode* const zones[] = {&passenger, &driver, &ign};
	std::map<Zone, const zk::AdscSetup*> adsc_ptr;
	std::map<Zone, Bytes> zone_keys;
	for (EndZoneNode* z : zones) {
		adsc_ptr[z->zone()] = adsc_setup[z->zone()].get();
		zone_keys[z->zone()] = z->SigningKey();
	}
	CentralNode central(rec, cc, cfg, prov.keys.secretKey->GetKeyTag(), adsc_ptr, zone_keys);

	window::Rounds warm(~cfg.seed), cases;
	const int total = opts.warmup + opts.rounds;
	std::map<Zone, size_t> up_bytes, adsc_bytes;
	size_t dl_bytes = 0;
	int tamper = -1;
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
			tamper = passenger.AcceptsUntimed(round, central.ProcessTampered(round), central.SigningKey()) ? 0 : 1;
	}

	rec.Param("backend", IPCEI_BACKEND);
	net.Describe(rec);
	rec.Param("threads", std::to_string(omp_get_max_threads()));
	rec.Param("ring dimension N", N);
	rec.Param("log2 Q", logQ);
	rec.Param("Q chain (bits)", limbs);
	if (logP) rec.Param("P (bits)", plimbs);
	rec.Param("log2 QP", logQ + logP);
	rec.Param("scale", "2^" + std::to_string(cfg.scaling_bits) + ", first modulus " + std::to_string(cfg.first_bits) + " bits");
	rec.Param("scaling", ScalingName(cfg.scaling));
	rec.Param("multiplicative depth", 3);
	rec.Param("security", "HEStd_128_classic");
	rec.Param("key switching", cfg.ks == HYBRID ? "HYBRID, dnum " + std::to_string(cpr->GetNumPartQ())
			: "BV" + (cfg.digit_size ? ", digit size " + std::to_string(cfg.digit_size) : std::string()));
	rec.Param("encoding", "CKKS packed (SIMD), flags, " + std::to_string(B) + " slot(s) per variable, " +
			std::to_string(slots) + " slots");
	rec.Param("evaluation", std::string("lanes g (Z + a X): 3 tensor products, 3 relins, 13 rotations") +
			(cfg.hoist ? " in 3 hoisted groups" : "") + ", depth 3");
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
	rec.Size("uplink unseeded (OpenFHE serialized)", (double)passenger.full_uplink_bytes());
	rec.Size("downlink (FHE payload)", (double)dl_bytes);
	rec.Size("downlink 1 limb (OpenFHE serialized)", (double)central.onelimb_downlink_bytes());
	for (Zone z : ipcei::kEndZones) rec.Size(std::string("ADSC proof ") + ipcei::ZoneName(z), (double)adsc_bytes[z]);
	rec.Size("signature (each link)", (double)ipcei::Ed25519::kSignatureBytes);
	rec.Note("the end zones share the CKKS secret key and the MAC key (trusted, provisioned into their HSEs); the "
			"central node holds only the relinearization/rotation keys (by key tag)");
	rec.Note("no global slot layout: each zone packs its own variables from slot 0, the central node aligns them "
			"with rotations");
	rec.Note("the ADSC proofs show each zone's bits are derived from authenticated sensor data, but do not bind "
			"them to the zone's ciphertext");
	if (cfg.mac_k > 0)
		rec.Note(std::string("tamper test (central node adds 1 to every slot in an Off round): ") +
				(tamper < 0 ? "not run (no Off round)" : tamper ? "rejected" : "ACCEPTED (BUG)"));

	ipcei::Report report(rec, "ckks_openfhe", std::string("OpenFHE ") + IPCEI_OPENFHE_VERSION, "CKKS");
	report.Print();
	if (!opts.json.empty()) report.WriteJson(opts.json);
	int correct = 0;
	for (bool b : rec.correct()) correct += b;
	return (correct == (int)rec.correct().size() && tamper != 0) ? 0 : 1;
}
