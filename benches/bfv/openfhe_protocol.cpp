// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// openfhe_protocol.cpp — the IPCEI secure-actuation round trip in BFV (OpenFHE BFVRNS),
// with the per-step breakdown of benches/common/ipcei/harness.hpp.
//
// Protocol (the BFV protocol of seal_protocol.cpp, in OpenFHE's fastest configuration):
//   The end node booleanizes S = 5 sensor readings against their thresholds into flags
//   f_i = (reading_i < threshold_i) and asks the central node for the actuation decision
//   AND_i f_i = prod_i f_i (a degree-5 product), with an integrity tag it can check.
//
//   MAC (bounded-degree homomorphic MAC, Catalano-Fiore): per round the end node draws
//   fresh secret r_i and tags flag i with the line y_i(X) = f_i + s_i X, s_i = (r_i - f_i)
//   / alpha, so y_i(0) = f_i and y_i(alpha) = r_i for its long-term secret point alpha.
//   The central node computes Y(X) = prod_i y_i(X) (degree 5): Y(0) is the decision and
//   Y(alpha) must equal prod_i r_i, which only the end node knows. A wrong decision passes
//   only if the error polynomial vanishes at alpha: probability <= 5/t per instance.
//
//   Packed encoding: Y is carried in evaluation form, at the public points X = 0..5 (a
//   degree-5 polynomial is fixed by 6 values; the slot-wise product of the evaluations is
//   the evaluation of the product). The end node reads Y(0) directly and gets Y(alpha) by
//   Lagrange interpolation, sum_j Y(j) L_j(alpha). The k MAC instances (independent alpha_m,
//   r_im) sit side by side in the slots and cost nothing extra homomorphically, so a small
//   NTT-friendly t (65537) with k = 3 gives (5/t)^3 ~ 2^-41 soundness (SEAL: one instance
//   at a 32-bit t, ~2^-29.7).
//
//   Uplink layout (--layout packed, default): ONE ciphertext; sensor i occupies the block
//   of B = 6k slots starting at i*B, slot i*B + 6m + j holding y_im(j). The central node
//   multiplies the blocks together with rotations:
//       A = v * rot(v, B)      (y0 y1 | y1 y2 | ...)
//       C = A * rot(A, 2B)     (y0 y1 y2 y3 | ...)
//       P = C * rot(v, 4B)     (y0 y1 y2 y3 y4 in block 0)
//   3 multiplications (depth 3) + 3 rotations; the two rotations of v share one hoisted
//   digit decomposition. --layout split sends one ciphertext per sensor and multiplies the
//   5 in a tree (4 multiplications, no rotations): 5x the uplink and 5x the encryptions.
//
// Round, by node and step id:
//   end      encode (flags + MAC lines -> slot values -> MakePackedPlaintext at the
//            uplink level), encrypt (secret-key BFV encryption at q' = q0 q1, the first two
//            of the three RNS limbs, its uniform part a expanded from a fresh 32-byte seed
//            with AES-256-CTR: b = e - a s + round(q'/t) m), compress (the wire is the seed
//            plus b's two RNS residues bit-packed at ceil(log2 q_i) bits; a never travels),
//            adsc_authenticate + adsc_prove (one ADSC-SNARK of the PID control law and of
//            flag_i = reading_i < threshold_i over the sensors' authenticated data; readings
//            and flags stay private), sign_uplink (Ed25519, wire bytes)
//   central  verify_uplink, adsc_verify (its own thresholds), decompress (unpack b, regenerate a
//            from the seed, raise both from q' to Q exactly by multiplying with Q/q' = q2,
//            which keeps m at scale Q/t), evaluate (rotations + products above),
//            compress_downlink (OpenFHE Compress to one 60-bit RNS limb, then the low
//            --drop = 22 bits of every coefficient are rounded away and the remaining 39
//            bits packed), sign_downlink
//   end      verify_downlink, decrypt (unpack, rebuild the 1-limb ciphertext, Decrypt),
//            check_result (every instance: Y_m(0) consistent, Y_m(alpha_m) == prod_i r_im)
// Every step of the harness exists in this design.
//
// Parameter choice (OpenFHE 1.5.1, Apple M-series dev Mac, single thread; the alternatives
// are listed below): depth 3, t = 65537, HEStd_128_classic, and OpenFHE's own
// parameter generation for the rest. With BV key switching (the BFVRNS default) OpenFHE
// picks N = 8192 and Q = 3 x 60 bits = 180 bits (<= 218 for N = 8192); HYBRID adds the
// special modulus P, Q P no longer fits 8192 and N doubles to 16384 (3x slower evaluate).
// BV's relinearization/rotation noise dominates the final noise, so the uplink can travel
// at 2 of the 3 limbs at no cost in margin (1 limb fails) and the downlink can lose 22 low
// bits per coefficient. Multiplication HPSPOVERQ (as fast as HPSPOVERQLEVELED here, with
// 4 more bits of margin; HPS and BEHZ are slower and cannot encode below the top level or
// Compress). Measured downlink noise margin: ~13 bits below the decryption bound (printed
// per run as "downlink noise margin"). Not taken: OpenFHE's own choice for 50-bit limbs
// with BV (3 x 50) and t = 786433 both decrypt WRONG (its BV estimate does not see the
// rotations), so the bench keeps the measured-safe 60-bit chain and checks every round.
//
//   bfv_openfhe [--layout packed|split] [--t T] [--mac-k K] [--mult HPS|BEHZ|HPSPOVERQ|
//               HPSPOVERQLEVELED] [--ks BV|HYBRID] [--dnum D] [--digit-size B]
//               [--scaling-bits B] [--uplink-limbs L] [--drop BITS] [--no-seed] [--pk]
//               [--no-hoist] [--seed N] [--rounds R] [--warmup W] [--json FILE] [--quiet]
#include <omp.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "ciphertext-ser.h"
#include "openfhe.h"
#include "scheme/bfvrns/bfvrns-cryptoparameters.h"
#include "scheme/bfvrns/bfvrns-ser.h"

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
constexpr int kSensors = 5;
constexpr int kPoints = 6;           // evaluation points X = 0..5 of the degree-5 tag
constexpr int kReadingBits = 32;     // sensor reading width (range check in the ADSC circuit)
constexpr size_t kSeedBytes = 32;    // AES-256 key that expands the uplink's uniform part

// Measured alternatives: median ms of this bench, 10 rounds, OMP_NUM_THREADS=1, Apple M-series
// (end to end includes ~62 ms of ZK proofs and signatures common to all).
// (measured on the Mac, kept here rather than printed: the numbers are not this run's)
//   const char* const kExploration[] = {
//   	"chosen: BV, HPSPOVERQ, packed layout, seeded sk encryption at 2 limbs, downlink 1 limb - 22 bits: "
//   		"N=8192, encrypt 0.60, evaluate 14.1, e2e 80, uplink 122920 B, downlink 79880 B",
//   	"alt HYBRID key switching: OpenFHE picks N=16384 (Q*P > 218 bits): evaluate 40.9, e2e 109.6",
//   	"alt HYBRID + 30-bit limbs (N=8192, 5x30): evaluate 33.5, e2e 102.4, margin 6 bits",
//   	"alt HPSPOVERQLEVELED: evaluate 14.2, e2e 80.3, margin 8.7 bits instead of 13",
//   	"alt HPS / BEHZ: evaluate 15.6 / 17.0, e2e 82.4 / 84.0; no leveled encoding, no Compress "
//   		"(uplink 184 KB, downlink 369 KB)",
//   	"alt BV digit size 30: evaluate 20.3, e2e 86.6, margin 14.4 bits",
//   	"alt split layout (5 ciphertexts, 4 mults, no rotations): encrypt 3.0, evaluate 16.8, e2e 87.6, "
//   		"uplink 614 KB",
//   	"alt no hoisting of the two rotations of the uplink: evaluate 14.6",
//   	"alt uplink at all 3 limbs: encrypt 0.77, e2e 80.9, uplink 184 KB",
//   	"alt OpenFHE Encrypt(sk) + Serialize, no seed: encrypt 1.8, decompress 1.9, e2e 84.1, uplink 394 KB",
//   	"alt public-key encryption: encrypt 2.1, e2e 84.6, uplink 394 KB",
//   	"alt downlink without dropped bits: downlink 122888 B, same time",
//   	"fails: uplink at 1 limb; BV with 50-bit limbs (OpenFHE picks 3x50); t=786433 with BV",
//   };

// ---------------------------------------------------------------- small helpers

uint64_t MulMod(uint64_t a, uint64_t b, uint64_t m) { return (uint64_t)((unsigned __int128)a * b % m); }
uint64_t PowMod(uint64_t b, uint64_t e, uint64_t m) {
	uint64_t r = 1;
	b %= m;
	for (; e; e >>= 1, b = MulMod(b, b, m))
		if (e & 1) r = MulMod(r, b, m);
	return r;
}
uint64_t InvMod(uint64_t a, uint64_t p) { return PowMod(a, p - 2, p); }  // p prime
int BitLen(uint64_t v) {
	int b = 0;
	while (v) {
		++b;
		v >>= 1;
	}
	return b;
}

class BitWriter {
public:
	explicit BitWriter(Bytes& out) : out_(out) {}
	void Put(uint64_t v, int bits) {
		acc_ |= (unsigned __int128)v << n_;
		n_ += bits;
		while (n_ >= 8) {
			out_.push_back((uint8_t)acc_);
			acc_ >>= 8;
			n_ -= 8;
		}
	}
	void Flush() {
		if (n_ > 0) out_.push_back((uint8_t)acc_);
		acc_ = 0;
		n_ = 0;
	}

private:
	Bytes& out_;
	unsigned __int128 acc_ = 0;
	int n_ = 0;
};

class BitReader {
public:
	BitReader(const Bytes& in, size_t pos) : in_(in), pos_(pos) {}
	uint64_t Get(int bits) {
		while (n_ < bits) {
			if (pos_ >= in_.size()) throw std::runtime_error("truncated message");
			acc_ |= (unsigned __int128)in_[pos_++] << n_;
			n_ += 8;
		}
		const uint64_t v = (uint64_t)(acc_ & (((unsigned __int128)1 << bits) - 1));
		acc_ >>= bits;
		n_ -= bits;
		return v;
	}
	void Align() {
		acc_ = 0;
		n_ = 0;
	}

private:
	const Bytes& in_;
	size_t pos_;
	unsigned __int128 acc_ = 0;
	int n_ = 0;
};

/// Bit-packs the RNS residues of `p` (any format), tower i at ceil(log2 q_i) bits.
void PackResidues(const DCRTPoly& p, Bytes& out) {
	BitWriter w(out);
	for (const auto& tower : p.GetAllElements()) {
		const int bits = BitLen(tower.GetModulus().ConvertToInt<uint64_t>() - 1);
		const auto& v = tower.GetValues();
		for (size_t j = 0; j < v.GetLength(); ++j) w.Put(v[j].ConvertToInt<uint64_t>(), bits);
		w.Flush();
	}
}

/// Inverse of PackResidues into a zero polynomial `p` with the right parameters.
void UnpackResidues(BitReader& r, DCRTPoly& p, Format format) {
	for (size_t i = 0; i < p.GetNumOfElements(); ++i) {
		const auto& tower = p.GetElementAtIndex(i);
		const NativeInteger q = tower.GetModulus();
		const int bits = BitLen(q.ConvertToInt<uint64_t>() - 1);
		const uint32_t n = tower.GetRingDimension();
		NativeVector v(n, q);
		for (uint32_t j = 0; j < n; ++j) v[j] = NativeInteger(r.Get(bits));
		r.Align();
		NativePoly t(tower.GetParams(), format, true);
		t.SetValues(std::move(v), format);
		p.SetElementAtIndex(i, std::move(t));
	}
}

/// The uniform part a of uplink ciphertext `index`, expanded from the 32-byte seed with
/// AES-256-CTR (IV = ciphertext index, tower index) and rejection-sampled mod q_i. It is
/// drawn directly in EVALUATION format (uniform there too), so it needs no NTT.
DCRTPoly ExpandUniform(const uint8_t* seed, uint32_t index, const std::shared_ptr<DCRTPoly::Params>& params) {
	DCRTPoly a(params, Format::EVALUATION, true);
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	std::vector<uint64_t> zero(2048, 0), ks(2048);
	for (size_t i = 0; i < a.GetNumOfElements(); ++i) {
		const auto& tower = a.GetElementAtIndex(i);
		const uint64_t q = tower.GetModulus().ConvertToInt<uint64_t>();
		const int bits = BitLen(q - 1);
		const uint64_t mask = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
		uint8_t iv[16] = {0};
		std::memcpy(iv, &index, 4);
		const uint32_t ti = (uint32_t)i;
		std::memcpy(iv + 4, &ti, 4);
		EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, seed, iv);
		const uint32_t n = tower.GetRingDimension();
		NativeVector v(n, tower.GetModulus());
		uint32_t j = 0;
		while (j < n) {
			int len = 0;
			EVP_EncryptUpdate(ctx, (uint8_t*)ks.data(), &len, (const uint8_t*)zero.data(), (int)(ks.size() * 8));
			for (size_t k = 0; k < ks.size() && j < n; ++k) {
				const uint64_t x = ks[k] & mask;
				if (x < q) v[j++] = NativeInteger(x);
			}
		}
		NativePoly t(tower.GetParams(), Format::EVALUATION, true);
		t.SetValues(std::move(v), Format::EVALUATION);
		a.SetElementAtIndex(i, std::move(t));
	}
	EVP_CIPHER_CTX_free(ctx);
	return a;
}

template <class T>
Bytes Serialize(const T& obj) {
	std::stringstream ss;
	Serial::Serialize(obj, ss, SerType::BINARY);
	const std::string s = ss.str();
	return Bytes(s.begin(), s.end());
}

template <class T>
void Deserialize(T& obj, const Bytes& b, size_t pos, size_t len) {
	std::stringstream ss(std::string(b.begin() + pos, b.begin() + pos + len));
	Serial::Deserialize(obj, ss, SerType::BINARY);
}

void PutU32(Bytes& b, uint32_t v) {
	for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(v >> (8 * i)));
}
uint32_t GetU32(const Bytes& b, size_t pos) {
	uint32_t v = 0;
	for (int i = 0; i < 4; ++i) v |= (uint32_t)b.at(pos + i) << (8 * i);
	return v;
}

// ---------------------------------------------------------------- configuration

struct Config {
	bool split = false;       // one ciphertext per sensor instead of one packed ciphertext
	uint64_t t = 65537;       // plaintext modulus (prime, = 1 mod 2N for packing)
	int mac_k = 3;            // independent MAC instances in the slots
	MultiplicationTechnique mult = HPSPOVERQ;
	KeySwitchTechnique ks = BV;
	int dnum = 0;             // HYBRID large digits (0: OpenFHE's default)
	int digit_size = 0;       // BV digit size in bits (0: OpenFHE's default, one digit per limb)
	int scaling_bits = 0;     // RNS limb size (0: OpenFHE's default, 60)
	int drop = 22;            // downlink: low bits rounded away per coefficient
	int uplink_limbs = 2;     // uplink encrypted at the first limbs only (0: all), lifted by the central node
	bool seeded = true;       // seeded uplink (else: OpenFHE-serialized ciphertexts)
	bool pk = false;          // public-key encryption (exploration only)
	bool hoist = true;        // hoisted rotations of the uplink ciphertext
	uint64_t seed = 1;        // readings / MAC-key RNG seed
	int block() const { return kPoints * mac_k; }
	int cts() const { return split ? kSensors : 1; }
};

const char* MultName(MultiplicationTechnique m) {
	switch (m) {
		case BEHZ: return "BEHZ";
		case HPS: return "HPS";
		case HPSPOVERQ: return "HPSPOVERQ";
		case HPSPOVERQLEVELED: return "HPSPOVERQLEVELED";
		default: return "?";
	}
}

// ---------------------------------------------------------------- messages

struct Uplink {
	Bytes wire;  // FHE payload (signed)
	Bytes signature;
	ipcei::zk::AdscMessage adsc;
};

struct Downlink {
	Bytes wire;  // compressed result ciphertext (signed)
	Bytes signature;
};

struct Outcome {
	bool decision = false;
	bool tag_ok = false;
	bool sig_ok = false;
};

// ---------------------------------------------------------------- end node

class EndNode : public ipcei::Participant {
public:
	EndNode(ipcei::Recorder& rec, CryptoContext<DCRTPoly> cc, const Config& cfg, const ipcei::zk::AdscSetup& adsc)
		: Participant(rec), cc_(cc), cfg_(cfg), adsc_(adsc), rng_(cfg.seed ^ 0x5eed5eedULL) {
		// one-time setup: keys (the secret key never leaves this node), MAC points
		keys_ = cc_->KeyGen();
		cc_->EvalMultKeyGen(keys_.secretKey);
		if (!cfg_.split) {
			const int B = cfg_.block();
			cc_->EvalRotateKeyGen(keys_.secretKey, {B, 2 * B, 4 * B});
		}
		params_ = cc_->GetCryptoParameters()->GetElementParams();
		const uint64_t t = cfg_.t;
		// alpha outside the public points; rng_ (mt19937_64) stands in for the node's secret randomness
		std::uniform_int_distribution<uint64_t> pick(kPoints, t - 1);
		for (int m = 0; m < cfg_.mac_k; ++m) {
			const uint64_t alpha = pick(rng_);
			alpha_.push_back(alpha);
			std::vector<uint64_t> L(kPoints);
			for (int j = 0; j < kPoints; ++j) {  // L_j(alpha) = prod_{l != j} (alpha - l) / (j - l)
				uint64_t num = 1, den = 1;
				for (int l = 0; l < kPoints; ++l) {
					if (l == j) continue;
					num = MulMod(num, (alpha + t - l) % t, t);
					den = MulMod(den, (uint64_t)((j - l) % (int64_t)t + (int64_t)t) % t, t);
				}
				L[j] = MulMod(num, InvMod(den, t), t);
			}
			lagrange_.push_back(L);
		}
	}

	std::string KeyTag() const { return keys_.secretKey->GetKeyTag(); }
	const Bytes& SigningKey() const { return sig_.PublicKey(); }
	size_t full_uplink_bytes() const { return full_uplink_bytes_; }
	double noise_margin_bits() const { return noise_margin_; }

	Uplink MakeUplink(int round, const std::vector<uint32_t>& readings, const std::vector<uint32_t>& thresholds) {
		std::vector<uint8_t> flags(kSensors);
		for (int i = 0; i < kSensors; ++i) flags[i] = readings[i] < thresholds[i];

		std::vector<Plaintext> pts;
		timed("encode", [&] { pts = Encode(flags); });
		std::vector<Ciphertext<DCRTPoly>> cts;
		uint8_t seed[kSeedBytes] = {0};
		timed("encrypt", [&] {
			if (cfg_.seeded) RAND_bytes(seed, sizeof seed);
			for (size_t c = 0; c < pts.size(); ++c) cts.push_back(Encrypt(pts[c], seed, (uint32_t)c));
		});
		Uplink up;
		timed("compress", [&] { up.wire = Compress(cts, seed); });
		if (round == 0) {
			full_uplink_bytes_ = 0;
			for (const auto& c : cts) full_uplink_bytes_ += Serialize(c).size();
		}
		timed("adsc_authenticate", [&] { adsc_.Authenticate(round, readings); });
		timed("adsc_prove", [&] { up.adsc = adsc_.Prove(thresholds); });
		timed("sign_uplink", [&] { up.signature = sig_.Sign(up.wire); });
		return up;
	}

	Outcome ReadDownlink(const Downlink& dl, const Bytes& central_key) {
		Outcome o;
		timed("verify_downlink", [&] { o.sig_ok = ipcei::Ed25519::Verify(central_key, dl.wire, dl.signature); });
		Ciphertext<DCRTPoly> ct;
		std::vector<int64_t> y;
		timed("decrypt", [&] {
			ct = Unpack(dl.wire);
			y = Decrypt(ct);
		});
		timed("check_result", [&] { o.tag_ok = CheckTag(y, o.decision); });
		if (ct->GetElements()[0].GetNumOfElements() == 1) MeasureNoise(ct);  // diagnostic, untimed
		return o;
	}

	/// Untimed: decrypt + tag check, for the tamper test.
	bool AcceptsUntimed(const Downlink& dl, const Bytes& central_key) {
		if (!ipcei::Ed25519::Verify(central_key, dl.wire, dl.signature)) return false;
		bool decision = false;
		return CheckTag(Decrypt(Unpack(dl.wire)), decision);
	}

private:
	std::vector<Plaintext> Encode(const std::vector<uint8_t>& flags) {
		const uint64_t t = cfg_.t;
		const int B = cfg_.block();
		std::uniform_int_distribution<uint64_t> pick(1, t - 1);
		r_.assign(kSensors, std::vector<uint64_t>(cfg_.mac_k));
		std::vector<std::vector<int64_t>> slots(cfg_.cts(), std::vector<int64_t>(cfg_.split ? B : kSensors * B, 0));
		for (int i = 0; i < kSensors; ++i) {
			auto& v = slots[cfg_.split ? i : 0];
			const int base = cfg_.split ? 0 : i * B;
			for (int m = 0; m < cfg_.mac_k; ++m) {
				const uint64_t r = pick(rng_);  // stands in for PRF_K(round, i, m)
				r_[i][m] = r;
				const uint64_t s = MulMod((r + t - flags[i]) % t, InvMod(alpha_[m], t), t);
				for (int j = 0; j < kPoints; ++j) v[base + kPoints * m + j] = (int64_t)((flags[i] + MulMod(s, j, t)) % t);
			}
		}
		std::vector<Plaintext> pts;
		const size_t L = params_->GetParams().size();
		const uint32_t level = cfg_.uplink_limbs > 0 ? (uint32_t)(L - cfg_.uplink_limbs) : 0;
		for (auto& v : slots) pts.push_back(cc_->MakePackedPlaintext(v, 1, level));
		return pts;
	}

	// Secret-key BFV encryption at the plaintext's limbs q', b = e - a s + round(q'/t) m
	// (OpenFHE's STANDARD secret-key encryption, PKEBFVRNS::Encrypt, with a expanded from
	// the seed instead of sampled, and without its COEFFICIENT/EVALUATION round trip).
	Ciphertext<DCRTPoly> Encrypt(const Plaintext& pt, const uint8_t* seed, uint32_t index) {
		if (!cfg_.seeded) return cfg_.pk ? cc_->Encrypt(keys_.publicKey, pt) : cc_->Encrypt(keys_.secretKey, pt);
		const auto cp = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc_->GetCryptoParameters());
		DCRTPoly m = pt->GetElement<DCRTPoly>();
		const auto ep = m.GetParams();  // the first L - level limbs
		const size_t level = params_->GetParams().size() - ep->GetParams().size();
		m.SetFormat(Format::COEFFICIENT);
		m.TimesQovert(ep, cp->GettInvModq(), cp->GetPlaintextModulus(), cp->GetNegQModt(level),
				cp->GetNegQModtPrecon(level));
		m.SetFormat(Format::EVALUATION);
		DCRTPoly sk = keys_.secretKey->GetPrivateElement();
		if (level) sk.DropLastElements(level);
		DCRTPoly a = ExpandUniform(seed, index, ep);
		DCRTPoly b(cp->GetDiscreteGaussianGenerator(), ep, Format::EVALUATION);
		b -= a * sk;
		b += m;
		auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(keys_.secretKey);
		ct->SetElements({std::move(b), std::move(a)});
		ct->SetNoiseScaleDeg(1);
		ct->SetEncodingType(pt->GetEncodingType());
		ct->SetSlots(pt->GetSlots());
		ct->SetLevel(pt->GetLevel());
		return ct;
	}

	// Seeded wire: u32 count | u32 limbs | seed | per ciphertext b's residues, bit-packed.
	// Unseeded wire: u32 count | per ciphertext u32 length + OpenFHE serialization.
	Bytes Compress(const std::vector<Ciphertext<DCRTPoly>>& cts, const uint8_t* seed) {
		Bytes w;
		PutU32(w, (uint32_t)cts.size());
		if (cfg_.seeded) {
			PutU32(w, (uint32_t)cts[0]->GetElements()[0].GetNumOfElements());
			w.insert(w.end(), seed, seed + kSeedBytes);
			for (const auto& c : cts) PackResidues(c->GetElements()[0], w);
		} else {
			for (const auto& c : cts) {
				const Bytes b = Serialize(c);
				PutU32(w, (uint32_t)b.size());
				w.insert(w.end(), b.begin(), b.end());
			}
		}
		return w;
	}

	// Inverse of CentralNode::CompressDownlink (wire format there).
	Ciphertext<DCRTPoly> Unpack(const Bytes& wire) {
		const uint32_t limbs = GetU32(wire, 0);
		const int drop = (int)GetU32(wire, 4);
		DCRTPoly like(params_, Format::EVALUATION, true);
		like.DropLastElements(like.GetNumOfElements() - limbs);
		BitReader r(wire, 8);
		std::vector<DCRTPoly> cv;
		for (int e = 0; e < 2; ++e) {
			DCRTPoly p = like;
			if (limbs > 1) {
				UnpackResidues(r, p, Format::EVALUATION);
			} else {
				const auto& tower = like.GetElementAtIndex(0);
				const NativeInteger q = tower.GetModulus();
				const uint64_t qq = q.ConvertToInt<uint64_t>();
				const int bits = BitLen((qq + (1ULL << drop) - 1) >> drop);
				const uint32_t n = tower.GetRingDimension();
				NativeVector v(n, q);
				for (uint32_t j = 0; j < n; ++j) v[j] = NativeInteger((r.Get(bits) << drop) % qq);
				r.Align();
				NativePoly t(tower.GetParams(), Format::COEFFICIENT, true);
				t.SetValues(std::move(v), Format::COEFFICIENT);
				t.SetFormat(Format::EVALUATION);
				p.SetElementAtIndex(0, std::move(t));
			}
			cv.push_back(std::move(p));
		}
		auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(keys_.secretKey);
		ct->SetElements(std::move(cv));
		ct->SetEncodingType(PACKED_ENCODING);
		ct->SetSlots(cc_->GetRingDimension());
		ct->SetNoiseScaleDeg(1);
		return ct;
	}

	std::vector<int64_t> Decrypt(const Ciphertext<DCRTPoly>& ct) {
		Plaintext pt;
		cc_->Decrypt(keys_.secretKey, ct, &pt);
		return pt->GetPackedValue();
	}

	bool CheckTag(const std::vector<int64_t>& y, bool& decision) {
		const uint64_t t = cfg_.t;
		auto val = [&](int idx) { return (uint64_t)(((y.at(idx) % (int64_t)t) + (int64_t)t) % (int64_t)t); };
		const uint64_t d = val(0);
		bool ok = d <= 1;
		for (int m = 0; m < cfg_.mac_k; ++m) {
			uint64_t tag = 0, expect = 1;
			for (int j = 0; j < kPoints; ++j) tag = (tag + MulMod(val(kPoints * m + j), lagrange_[m][j], t)) % t;
			for (int i = 0; i < kSensors; ++i) expect = MulMod(expect, r_[i][m], t);
			ok = ok && val(kPoints * m) == d && tag == expect;
		}
		decision = d == 1;
		return ok;
	}

	// Diagnostic (untimed): the noise of the received 1-limb ciphertext, as the margin in
	// bits between its largest coefficient and the decryption bound (q/t)/2.
	void MeasureNoise(const Ciphertext<DCRTPoly>& ct) {
		DCRTPoly s = keys_.secretKey->GetPrivateElement();
		s.DropLastElements(s.GetNumOfElements() - 1);
		DCRTPoly ph = ct->GetElements()[0] + ct->GetElements()[1] * s;
		ph.SetFormat(Format::COEFFICIENT);
		const auto& v = ph.GetElementAtIndex(0).GetValues();
		const long double q = (long double)ph.GetElementAtIndex(0).GetModulus().ConvertToInt<uint64_t>();
		const long double delta = q / cfg_.t;
		long double worst = 0;
		for (size_t j = 0; j < v.GetLength(); ++j) {
			const long double x = (long double)v[j].ConvertToInt<uint64_t>();
			const long double e = x - std::round(x / delta) * delta;
			worst = std::max(worst, std::fabs(e));
		}
		const double margin = (double)(std::log2(delta / 2) - std::log2(std::max(worst, (long double)1)));
		noise_margin_ = std::min(noise_margin_, margin);
	}

	CryptoContext<DCRTPoly> cc_;
	Config cfg_;
	KeyPair<DCRTPoly> keys_;
	std::shared_ptr<DCRTPoly::Params> params_;
	ipcei::zk::AdscProver adsc_;
	ipcei::Ed25519 sig_;
	std::mt19937_64 rng_;
	std::vector<uint64_t> alpha_;
	std::vector<std::vector<uint64_t>> lagrange_;
	std::vector<std::vector<uint64_t>> r_;  // this round's MAC keys r_im
	size_t full_uplink_bytes_ = 0;
	double noise_margin_ = 1e9;
};

// ---------------------------------------------------------------- central node

class CentralNode : public ipcei::Participant {
public:
	CentralNode(ipcei::Recorder& rec, CryptoContext<DCRTPoly> cc, const Config& cfg, std::string key_tag,
			const Bytes& end_key, const ipcei::zk::AdscSetup& adsc)
		: Participant(rec), cc_(cc), cfg_(cfg), tag_(std::move(key_tag)), end_key_(end_key), adsc_(adsc) {
		params_ = cc_->GetCryptoParameters()->GetElementParams();
	}
	const Bytes& SigningKey() const { return sig_.PublicKey(); }
	size_t full_downlink_bytes() const { return full_downlink_bytes_; }
	size_t onelimb_downlink_bytes() const { return onelimb_downlink_bytes_; }

	Downlink Process(const Uplink& up, const std::vector<uint32_t>& thresholds, bool& verified) {
		bool sig = false, adsc = false;
		timed("verify_uplink", [&] { sig = ipcei::Ed25519::Verify(end_key_, up.wire, up.signature); });
		timed("adsc_verify", [&] { adsc = adsc_.Verify(up.adsc, thresholds); });
		verified = sig && adsc;
		std::vector<Ciphertext<DCRTPoly>> cts;
		timed("decompress", [&] { cts = Decompress(up.wire); });
		Ciphertext<DCRTPoly> y;
		timed("evaluate", [&] { y = Evaluate(cts); });
		Downlink dl;
		timed("compress_downlink", [&] { dl.wire = CompressDownlink(y); });
		timed("sign_downlink", [&] { dl.signature = sig_.Sign(dl.wire); });
		if (full_downlink_bytes_ == 0) {  // reference sizes, untimed
			full_downlink_bytes_ = Serialize(y).size();
			if (CanCompress()) onelimb_downlink_bytes_ = Serialize(cc_->Compress(y, 1)).size();
		}
		return dl;
	}

	/// Untimed: a dishonest central node that adds 1 to the decision slot of every MAC
	/// instance (turning a 0 decision into 1); the end node must reject the result.
	Downlink ProcessTampered(const Uplink& up) {
		Ciphertext<DCRTPoly> y = Evaluate(Decompress(up.wire));
		std::vector<int64_t> bump(cfg_.block(), 0);
		for (int m = 0; m < cfg_.mac_k; ++m) bump[kPoints * m] = 1;
		Plaintext forged = cc_->MakePackedPlaintext(bump);
		y = cc_->EvalAdd(y, forged);
		Downlink dl;
		dl.wire = CompressDownlink(y);
		dl.signature = sig_.Sign(dl.wire);
		return dl;
	}

private:
	std::vector<Ciphertext<DCRTPoly>> Decompress(const Bytes& wire) {
		const uint32_t count = GetU32(wire, 0);
		std::vector<Ciphertext<DCRTPoly>> cts;
		if (!cfg_.seeded) {
			size_t pos = 4;
			for (uint32_t c = 0; c < count; ++c) {
				const uint32_t len = GetU32(wire, pos);
				Ciphertext<DCRTPoly> ct;
				Deserialize(ct, wire, pos + 4, len);
				pos += 4 + len;
				if (ct->GetElements()[0].GetNumOfElements() < params_->GetParams().size()) {
					ct->SetElements({Lift(ct->GetElements()[0]), Lift(ct->GetElements()[1])});
					ct->SetLevel(0);
				}
				cts.push_back(ct);
			}
			return cts;
		}
		const size_t L = params_->GetParams().size();
		const size_t Lu = GetU32(wire, 4);
		const uint8_t* seed = wire.data() + 8;
		BitReader r(wire, 8 + kSeedBytes);
		const Plaintext probe = cc_->MakePackedPlaintext(std::vector<int64_t>{0});
		DCRTPoly like(params_, Format::EVALUATION, true);
		like.DropLastElements(L - Lu);
		for (uint32_t c = 0; c < count; ++c) {
			DCRTPoly b = like;
			UnpackResidues(r, b, Format::EVALUATION);
			DCRTPoly a = ExpandUniform(seed, c, like.GetParams());
			auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(cc_);
			ct->SetKeyTag(tag_);
			if (Lu < L) ct->SetElements({Lift(b), Lift(a)});
			else ct->SetElements({std::move(b), std::move(a)});
			ct->SetNoiseScaleDeg(1);
			ct->SetEncodingType(PACKED_ENCODING);
			ct->SetSlots(probe->GetSlots());
			ct->SetLevel(probe->GetLevel());
			cts.push_back(ct);
		}
		return cts;
	}

	// Exact modulus raise from q' = q_0...q_{Lu-1} to Q: x -> (Q/q') x, which is 0 on the
	// upper limbs and (Q/q' mod q_i) x on the lower ones. The phase becomes (Q/q')(round(q'/t) m
	// + e): the message scale is Q/t again, the noise keeps its size relative to q'.
	DCRTPoly Lift(const DCRTPoly& x) const {
		const auto& qs = params_->GetParams();
		const size_t Lu = x.GetNumOfElements();
		DCRTPoly y(params_, Format::EVALUATION, true);
		for (size_t i = 0; i < Lu; ++i) {
			const NativeInteger qi = qs[i]->GetModulus();
			NativeInteger f(1);
			for (size_t k = Lu; k < qs.size(); ++k) f = f.ModMul(qs[k]->GetModulus().Mod(qi), qi);
			y.SetElementAtIndex(i, x.GetElementAtIndex(i).Times(f));
		}
		return y;
	}

	Ciphertext<DCRTPoly> Evaluate(const std::vector<Ciphertext<DCRTPoly>>& cts) {
		if (cfg_.split) {  // ((y0 y1)(y2 y3)) y4
			auto p01 = cc_->EvalMult(cts[0], cts[1]);
			auto p23 = cc_->EvalMult(cts[2], cts[3]);
			return cc_->EvalMult(cc_->EvalMult(p01, p23), cts[4]);
		}
		const int B = cfg_.block();
		const auto& v = cts[0];
		Ciphertext<DCRTPoly> r1, r4;
		if (cfg_.hoist) {
			const uint32_t m = 2 * cc_->GetRingDimension();
			auto digits = cc_->EvalFastRotationPrecompute(v);
			r1 = cc_->EvalFastRotation(v, B, m, digits);
			r4 = cc_->EvalFastRotation(v, 4 * B, m, digits);
		} else {
			r1 = cc_->EvalRotate(v, B);
			r4 = cc_->EvalRotate(v, 4 * B);
		}
		auto A = cc_->EvalMult(v, r1);
		auto C = cc_->EvalMult(A, cc_->EvalRotate(A, 2 * B));
		return cc_->EvalMult(C, r4);
	}

	bool CanCompress() const { return cfg_.mult == HPSPOVERQ || cfg_.mult == HPSPOVERQLEVELED; }

	// Downlink wire: u32 limbs | u32 drop bits | c0, c1. One limb (HPSPOVERQ*): COEFFICIENT
	// format, each coefficient as round(x / 2^drop), bit-packed. Several limbs (HPS, BEHZ:
	// no OpenFHE Compress): the residues as they are, bit-packed.
	Bytes CompressDownlink(const Ciphertext<DCRTPoly>& y) {
		Bytes w;
		if (!CanCompress()) {
			PutU32(w, (uint32_t)y->GetElements()[0].GetNumOfElements());
			PutU32(w, 0);
			for (const auto& p : y->GetElements()) PackResidues(p, w);
			return w;
		}
		auto c = cc_->Compress(y, 1);
		const int drop = cfg_.drop;
		PutU32(w, 1);
		PutU32(w, (uint32_t)drop);
		BitWriter bw(w);
		for (DCRTPoly p : c->GetElements()) {
			p.SetFormat(Format::COEFFICIENT);
			const auto& tower = p.GetElementAtIndex(0);
			const uint64_t q = tower.GetModulus().ConvertToInt<uint64_t>();
			const int bits = BitLen((q + (1ULL << drop) - 1) >> drop);  // largest rounded value
			const uint64_t half = drop ? (1ULL << (drop - 1)) : 0;
			const auto& v = tower.GetValues();
			for (size_t j = 0; j < v.GetLength(); ++j) bw.Put((v[j].ConvertToInt<uint64_t>() + half) >> drop, bits);
			bw.Flush();
		}
		return w;
	}

	CryptoContext<DCRTPoly> cc_;
	Config cfg_;
	std::string tag_;
	Bytes end_key_;
	std::shared_ptr<DCRTPoly::Params> params_;
	ipcei::zk::AdscVerifier adsc_;
	ipcei::Ed25519 sig_;
	size_t full_downlink_bytes_ = 0, onelimb_downlink_bytes_ = 0;
};

// ---------------------------------------------------------------- driver

bool ParseMult(const std::string& s, MultiplicationTechnique& m) {
	if (s == "HPS") m = HPS;
	else if (s == "BEHZ") m = BEHZ;
	else if (s == "HPSPOVERQ") m = HPSPOVERQ;
	else if (s == "HPSPOVERQLEVELED") m = HPSPOVERQLEVELED;
	else return false;
	return true;
}

int Usage() {
	std::fprintf(stderr,
			"usage: bfv_openfhe [--layout packed|split] [--t T] [--mac-k K] [--mult HPS|BEHZ|HPSPOVERQ|"
			"HPSPOVERQLEVELED]\n"
			"                   [--ks BV|HYBRID] [--dnum D] [--scaling-bits B] [--drop BITS] [--no-seed] [--pk]\n"
			"                   [--no-hoist] [--seed N] [--rounds R] [--warmup W] [--json FILE] [--quiet]\n");
	return 2;
}

}  // namespace

int main(int argc, char** argv) {
	// one thread unless OMP_NUM_THREADS says otherwise (all cores slow binfhe's small loops
	// down: n32 flags evaluate 72 ms single-threaded vs 115 ms on the 18 cores of an M5 Pro)
	ipcei::SingleThreadByDefault(argv);
	ipcei::Options opts = ipcei::Options::Parse(argc, argv, 5);
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
		if (a == "--layout") {
			const std::string v = next();
			if (v != "packed" && v != "split") return Usage();
			cfg.split = v == "split";
		} else if (a == "--t") cfg.t = std::strtoull(next().c_str(), nullptr, 10);
		else if (a == "--mac-k") cfg.mac_k = std::atoi(next().c_str());
		else if (a == "--mult") {
			if (!ParseMult(next(), cfg.mult)) return Usage();
		} else if (a == "--ks") {
			const std::string v = next();
			if (v != "BV" && v != "HYBRID") return Usage();
			cfg.ks = v == "BV" ? BV : HYBRID;
		} else if (a == "--dnum") cfg.dnum = std::atoi(next().c_str());
		else if (a == "--digit-size") cfg.digit_size = std::atoi(next().c_str());
		else if (a == "--scaling-bits") cfg.scaling_bits = std::atoi(next().c_str());
		else if (a == "--drop") cfg.drop = std::atoi(next().c_str());
		else if (a == "--uplink-limbs") cfg.uplink_limbs = std::atoi(next().c_str());
		else if (a == "--no-seed") cfg.seeded = false;
		else if (a == "--pk") {
			cfg.pk = true;
			cfg.seeded = false;
		} else if (a == "--no-hoist") cfg.hoist = false;
		else if (a == "--seed") cfg.seed = std::strtoull(next().c_str(), nullptr, 10);
		else return Usage();
	}
	if (cfg.mac_k < 1 || cfg.drop < 0 || cfg.drop > 50) return Usage();
	if (cfg.mult == HPS || cfg.mult == BEHZ) {
		std::fprintf(stderr, "note: %s cannot encode below the top level nor Compress: uplink and downlink "
				"at full Q\n", MultName(cfg.mult));
		cfg.uplink_limbs = 0;
	}

	// ---- one-time setup (not reported)
	CCParams<CryptoContextBFVRNS> p;
	p.SetPlaintextModulus(cfg.t);
	p.SetMultiplicativeDepth(3);
	p.SetSecurityLevel(HEStd_128_classic);
	p.SetMultiplicationTechnique(cfg.mult);
	p.SetKeySwitchTechnique(cfg.ks);
	if (cfg.dnum > 0) p.SetNumLargeDigits(cfg.dnum);
	if (cfg.scaling_bits > 0) p.SetScalingModSize(cfg.scaling_bits);
	if (cfg.digit_size > 0) p.SetDigitSize(cfg.digit_size);
	CryptoContext<DCRTPoly> cc = GenCryptoContext(p);
	cc->Enable(PKE);
	cc->Enable(KEYSWITCH);
	cc->Enable(LEVELEDSHE);

	const uint32_t N = cc->GetRingDimension();
	if (!cfg.split && kSensors * cfg.block() > (int)N / 2) {
		std::fprintf(stderr, "too many MAC instances for N = %u\n", N);
		return 2;
	}
	const auto& towers = cc->GetCryptoParameters()->GetElementParams()->GetParams();
	if (cfg.uplink_limbs < 0 || cfg.uplink_limbs > (int)towers.size()) {
		std::fprintf(stderr, "--uplink-limbs must be 0..%zu\n", towers.size());
		return 2;
	}
	if (cfg.uplink_limbs == (int)towers.size()) cfg.uplink_limbs = 0;
	int logQ = 0;
	std::string limbs;
	for (const auto& tw : towers) {
		logQ += tw->GetModulus().GetMSB();
		limbs += (limbs.empty() ? "" : "+") + std::to_string(tw->GetModulus().GetMSB());
	}

	ipcei::Recorder rec(opts.warmup);
	const ipcei::zk::AdscSetup adsc_setup(kSensors, kReadingBits);
	EndNode end(rec, cc, cfg, adsc_setup);
	CentralNode central(rec, cc, cfg, end.KeyTag(), end.SigningKey(), adsc_setup);

	// ---- rounds: readings below threshold actuate; every third round one sensor inhibits
	std::mt19937_64 rng(cfg.seed);
	const int total = opts.warmup + opts.rounds;
	size_t up_bytes = 0, dl_bytes = 0, adsc_bytes = 0, sig_bytes = 0;
	int actuated = 0;
	int tamper = -1;  // -1: not run, 0: forged result accepted, 1: rejected
	for (int r = 0; r < total; ++r) {
		rec.BeginRound();
		std::vector<uint32_t> readings(kSensors), thresholds(kSensors);
		for (int i = 0; i < kSensors; ++i) {
			thresholds[i] = (uint32_t)(rng() % 0xF0000000u) + 0x08000000u;
			readings[i] = (uint32_t)(rng() % thresholds[i]);
		}
		if (r % 3 == 2) {
			const int i = (int)(rng() % kSensors);
			readings[i] = thresholds[i] + (uint32_t)(rng() % (0xFFFFFFFFu - thresholds[i]));
		}
		bool oracle = true;
		for (int i = 0; i < kSensors; ++i) oracle = oracle && readings[i] < thresholds[i];

		Uplink up = end.MakeUplink(r, readings, thresholds);
		bool verified = false;
		const Downlink dl = central.Process(up, thresholds, verified);
		const Outcome o = end.ReadDownlink(dl, central.SigningKey());
		const bool ok = verified && o.sig_ok && o.tag_ok && o.decision == oracle;
		rec.RoundResult(ok);
		if (!ok && !opts.quiet) {
			std::fprintf(stderr, "round %d: WRONG (verified %d, sig %d, tag %d, decision %d, oracle %d)\n", r,
					verified, o.sig_ok, o.tag_ok, o.decision, oracle);
		}
		actuated += oracle;
		up_bytes = up.wire.size();
		dl_bytes = dl.wire.size();
		adsc_bytes = up.adsc.proof_bytes;
		sig_bytes = up.signature.size();
		if (!oracle && tamper < 0) {
			// tamper test (untimed): a dishonest central node turns this inhibiting round's
			// decision into 1; the end node must reject the result
			tamper = end.AcceptsUntimed(central.ProcessTampered(up), central.SigningKey()) ? 0 : 1;
		}
	}

	// ---- tamper test (untimed): a forged decision must fail the MAC check

	rec.Param("backend", IPCEI_BACKEND);
	rec.Param("threads", std::to_string(omp_get_max_threads()));
	rec.Param("ring dimension N", N);
	rec.Param("log2 Q", logQ);
	rec.Param("RNS limbs (bits)", limbs);
	rec.Param("plaintext modulus t", (double)cfg.t);
	rec.Param("multiplicative depth", 3);
	rec.Param("security", "HEStd_128_classic");
	rec.Param("multiplication", MultName(cfg.mult));
	rec.Param("key switching", cfg.ks == HYBRID ? "HYBRID" : "BV");
	rec.Param("encoding", "packed (SIMD)");
	rec.Param("layout", cfg.split ? "split (1 ciphertext per sensor, 4 mults)"
								: "packed (1 ciphertext, 3 rotations + 3 mults)");
	rec.Param("encryption", cfg.pk ? "public key" : cfg.seeded ? "secret key, seeded (AES-256-CTR)" : "secret key");
	{
		const size_t Lu = cfg.uplink_limbs ? (size_t)cfg.uplink_limbs : towers.size();
		int bits = 0;
		for (size_t i = 0; i < Lu; ++i) bits += towers[i]->GetModulus().GetMSB();
		rec.Param("uplink modulus", std::to_string(Lu) + " limb(s), " + std::to_string(bits) + " bits" +
				(Lu < towers.size() ? ", raised to Q by the central node" : ""));
	}
	rec.Param("sensors", kSensors);
	rec.Param("MAC instances k", cfg.mac_k);
	rec.Param("MAC soundness (bits)", -cfg.mac_k * std::log2(5.0 / (double)cfg.t));
	rec.Param("downlink dropped bits", cfg.drop);
	if (end.noise_margin_bits() < 1e8) rec.Param("downlink noise margin (bits)", end.noise_margin_bits());
	else rec.Param("downlink noise margin (bits)", "n/a (multi-limb downlink)");
	rec.Param("signature", "Ed25519");
	rec.Param("adsc_circuit", "PID + " + std::to_string(kSensors) + " x " + std::to_string(kReadingBits) +
			"-bit comparisons");
	rec.Param("adsc_constraints", (double)adsc_setup.constraints());
	rec.Size("uplink FHE payload", (double)up_bytes);
	rec.Size("uplink unseeded (OpenFHE serialized)", (double)end.full_uplink_bytes());
	rec.Size("downlink FHE payload", (double)dl_bytes);
	rec.Size("downlink 1 limb (OpenFHE serialized)", (double)central.onelimb_downlink_bytes());
	rec.Size("downlink full Q (OpenFHE serialized)", (double)central.full_downlink_bytes());
	rec.Size("ADSC proof + commitment", (double)adsc_bytes);
	rec.Size("signature", (double)sig_bytes);
	rec.Note("the ADSC proof shows the flags are honest comparisons of authenticated readings, but does not tie "
			"them to the uplink ciphertext");
	rec.Note("the end and central nodes share one CryptoContext in-process; the central node holds only the "
			"relinearization/rotation keys (by key tag), never the secret key");
	rec.Note(std::string("tamper test (central node forges decision 1 in an inhibiting round): ") +
			(tamper < 0 ? "not run (no inhibiting round)" : tamper ? "rejected" : "ACCEPTED (BUG)"));
	rec.Note("rounds actuated: " + std::to_string(actuated) + "/" + std::to_string(total));

	ipcei::Report report(rec, "bfv_openfhe", std::string("OpenFHE ") + IPCEI_OPENFHE_VERSION, "BFV");
	report.Print();
	if (!opts.json.empty()) report.WriteJson(opts.json);
	int correct = 0;
	for (bool b : rec.correct()) correct += b;
	return (correct == (int)rec.correct().size() && tamper != 0) ? 0 : 1;
}
