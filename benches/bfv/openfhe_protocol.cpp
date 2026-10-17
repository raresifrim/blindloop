// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// openfhe_protocol.cpp — the blindloop window-lift round (benches/common/ipcei/scenario.hpp)
// in BFV (OpenFHE BFVRNS), with the per-step breakdown of benches/common/ipcei/harness.hpp.
//
// Threat model: the three end zones (passenger, driver, ign) are trusted with their own
// data and may share key material; only the central compute (the Process APP) must stay
// blind. Provisioning (one-time, not reported) therefore puts into the end zones' HSEs:
//   - ONE BFV secret key, shared by the three end zones (no threshold FHE needed);
//   - the MAC points alpha_m (m = 1..k) and a shared 32-byte PRF key, from which every
//     zone derives this round's MAC secrets r_i^(m) = AES-256(key, round | zone | i | m)
//     mod t, so the passenger zone can recompute the expected tag of the whole decision;
//   - one Ed25519 key per node and one ADSC-SNARK setup per zone.
// The central node holds the relinearization and rotation keys only.
//
// MAC (bounded-degree homomorphic MAC, Catalano-Fiore): every flag f_i is tagged with
// the line y_i^(m)(X) = f_i + s_i^(m) X, s_i^(m) = (r_i^(m) - f_i) / alpha_m, so y(0) = f
// and y(alpha_m) = r. The central node evaluates the decision on the lines: Y_m(X) =
// CmdArith(y_i^(m)(X)) has degree 6, Y_m(0) is the command (+1, -1 = t-1 or 0 in Z_t) and
// Y_m(alpha_m) must equal CmdArith(r_i^(m)), which only the end zones know. A wrong
// command passes only if the error polynomial (degree <= 6) vanishes at alpha_m:
// probability <= 6/t per instance, (6/65537)^3 ~ 2^-40 for k = 3.
//
// Packed encoding: Y is carried in evaluation form, at the 7 public points X = 0..6 (a
// degree-6 polynomial is fixed by 7 values; the slot-wise product of evaluations is the
// evaluation of the product). A variable occupies a block of B = 7k = 21 slots, slot 7m + j
// holding y_i^(m)(j); the constant 1 is the plaintext block of ones. The passenger reads
// Y(0) directly and gets Y_m(alpha_m) by Lagrange interpolation, sum_j Y_m(j) L_j(alpha_m).
//
// No global slot layout: each zone packs only its own variables, in its own FlagBits
// order, from slot 0 (passenger pu pd top bot err: 5 blocks, driver ou od cl: 3, ign k: 1)
// and knows nothing of the others. The central node knows each zone's message format and
// does the alignment itself, with rotations by whole blocks. It evaluates the same
// polynomial as CmdArith, factored as
//   g = k (1 - err),  a = (1 - ou - od)(1 - cl)
//   X = pu (1 - top) - pd (1 - bot),  Z = ou (1 - top) - od (1 - bot)
//   cmd = g (Z + a X)                  = g (up (1 - top) - dn (1 - bot))
// in SIMD lanes (--eval lanes, default): the blocks are lanes, and ONE product of two sums
// of rotated inputs yields g, a and the four products of X and Z side by side; the lanes
// are then rotated onto block 0 for the last two products (CentralNode::EvaluateLanes).
// 3 tensor products (the minimum at depth 3), 3 relinearizations, 13 rotations in 3
// hoisted groups (4 of the passenger's ciphertext, 4 of the driver's, 5 of the depth-1
// product); ign's ciphertext is not rotated. A tensor product (HPSPOVERQ) costs ~3.5 ms,
// a hoisted rotation a fraction of one, so this halves the evaluation against the
// block-0-only forms: --eval factored brings each variable to block 0 (variable i rotated
// by i*B: 4 + 2 hoisted rotations) and does 8 tensor products with 5 relinearizations
// (sums of products share one), --eval direct is CmdArith as written (8, 7). Only block 0
// of the result matters. --layout split sends one ciphertext per variable instead (no
// alignment rotations, 5/3/1x the uplink and the encryptions; evaluated factored).
//
// Round, by zone and step id:
//   end zones  adsc_authenticate (the zone's sensors authenticate SensorValues), adsc_prove
//              (one ADSC-SNARK deriving the zone's flag bits from them; they stay private),
//              encode (PRF -> r, MAC lines -> slot values -> MakePackedPlaintext at the uplink
//              level), encrypt (secret-key BFV encryption at q' = q0 q1, the first two of
//              the three RNS limbs, its uniform part a expanded from a fresh per-round,
//              per-zone 32-byte seed with AES-256-CTR: b = e - a s + round(q'/t) m),
//              compress (wire = round | zone | seed | b's two RNS residues bit-packed at
//              ceil(log2 q_i) bits; a never travels), sign_uplink (Ed25519 over the wire)
//   central    per zone: verify_uplink (signature, round and zone), adsc_verify, decompress
//              (unpack b, regenerate a from the seed, raise both from q' to Q exactly by
//              multiplying with Q/q' = q2, which keeps m at scale Q/t); then evaluate
//              (alignment rotations + the circuit above), compress_downlink (OpenFHE
//              Compress to one 60-bit RNS limb, then the low --drop bits of every
//              coefficient are rounded away and the rest bit-packed), sign_downlink
//   passenger  verify_downlink (signature + round), decrypt (unpack, rebuild the 1-limb
//              ciphertext, Decrypt), check_result (every instance: Y_m(0) equal and in
//              {0, 1, t-1}, Y_m(alpha_m) == CmdArith(r^(m)) mod t)
// Every step of the harness exists in this design.
//
// Parameter choice (OpenFHE 1.5.1, Apple M-series dev Mac, single thread; the alternatives
// are listed below): depth 3, t = 65537 (the smallest NTT-friendly prime for N = 8192),
// HEStd_128_classic, OpenFHE's own parameter generation for the rest. With BV key switching
// (the BFVRNS default) OpenFHE picks N = 8192 and Q = 3 x 60 bits = 180 bits (<= 218 for
// N = 8192); HYBRID adds the special modulus P, Q P no longer fits 8192 and N doubles to
// 16384 (3.5x slower evaluate). Multiplication HPSPOVERQ (HPSPOVERQLEVELED is as fast with
// 3 bits less margin; HPS and BEHZ are slower and cannot encode below the top level or
// Compress). Re-checked for the 8-multiplication circuit: the 60-bit chain still decrypts
// with ~12 bits of margin (same depth as the old 5-flag product; the extra rotations and
// additions cost about one bit); 3 x 55 bits leaves 2 bits and 3 x 50 decrypts WRONG, so
// 3 x 60 stays the cheapest safe chain. BV's relinearization/rotation noise dominates the
// final noise, so the uplink travels at 2 of the 3 limbs at no cost in margin (1 limb
// fails) and the downlink drops --drop = 24 low bits per coefficient for 0.4 bits of margin.
// Measured downlink noise margin: 11.7 bits below the decryption bound (minimum over 300
// random rounds: 11.5; printed per run as "downlink noise margin").
//
//   bfv_openfhe [--layout packed|split] [--eval lanes|factored|direct] [--t T] [--mac-k K]
//               [--mult HPS|BEHZ|HPSPOVERQ|HPSPOVERQLEVELED] [--ks BV|HYBRID] [--dnum D]
//               [--digit-size B] [--scaling-bits B] [--uplink-limbs L] [--drop BITS]
//               [--no-seed] [--pk] [--no-hoist] [--seed N] [--rounds R] [--warmup W]
//               [--json FILE] [--quiet]
#include <omp.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
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
constexpr int kDegree = 6;               // degree of the decision in its inputs (CmdArith)
constexpr int kPoints = kDegree + 1;     // evaluation points X = 0..6 of the tag
constexpr size_t kSeedBytes = 32;        // AES-256 key that expands an uplink's uniform part
constexpr size_t kMacKeyBytes = 32;      // shared PRF key of the MAC secrets
constexpr size_t kUplinkHeader = 5;      // round (u32) | zone (u8)
constexpr size_t kDownlinkHeader = 4;    // round (u32)

// Measured alternatives: median ms of this bench, 12 rounds, OMP_NUM_THREADS=1, Apple M-series
// (end to end = critical path; it includes ~22 ms of ZK proofs and signatures common to all:
// the passenger's ADSC authenticate + prove 8.4 ms, the central node's 3 ADSC verifies 12.3 ms).
// (measured on the Mac, kept here rather than printed: the numbers are not this run's)
//   const char* const kExploration[] = {
//   	"chosen: BV, HPSPOVERQ, packed per zone, lanes evaluation, seeded sk encryption at 2 limbs, downlink "
//   		"1 limb - 24 bits: N=8192, encrypt 0.61 per zone, evaluate 17.7, e2e 40.7, uplink 122920 B per zone, "
//   		"downlink 75784 B, margin 11.7 bits",
//   	"alt --eval factored (8 tensor products, 5 relins, 6 rotations): evaluate 35.3, e2e 58.7",
//   	"alt --eval direct (CmdArith as written, 8 tensor products, 7 relins): evaluate 37.4, e2e 60.9",
//   	"alt no hoisting (13 separate rotations): evaluate 22.3, e2e 45.9",
//   	"alt split layout (9 ciphertexts, factored, no rotations): passenger encrypt 3.1, evaluate 33.1, "
//   		"e2e 61.4, uplink passenger 614 KB, margin 15.4",
//   	"alt HYBRID key switching: OpenFHE picks N=16384 (Q*P > 218 bits): evaluate 63.1, e2e 89.7",
//   	"alt HYBRID + 30-bit limbs (N=8192, 5x30): decrypts WRONG (evaluate 48.0)",
//   	"alt HPSPOVERQLEVELED: evaluate 18.4, margin 8.8 bits instead of 12",
//   	"alt HPS / BEHZ: evaluate 19.3 / 21.0; no leveled encoding, no Compress (uplink 184 KB, downlink 369 KB)",
//   	"alt BV digit size 30: evaluate 27.1, e2e 50.7, margin 15.3 bits",
//   	"alt 55-bit limbs (3x55): margin 2.0 bits, too thin; 50-bit limbs (3x50): decrypts WRONG",
//   	"alt uplink at all 3 limbs: encrypt 0.83, uplink 184 KB per zone, same margin",
//   	"alt OpenFHE Encrypt(sk) + Serialize, no seed: encrypt 1.34, decompress (3) 5.5, e2e 46.7, uplink 263 KB",
//   	"alt public-key encryption: encrypt 1.61, e2e 46.9, uplink 263 KB, margin 8.8",
//   	"alt downlink drop 0 / 20 / 27 / 30 bits: 122888 / 83976 / 69640 / 63496 B, margin 12.1 / 12.2 / 9.3 / 6.4",
//   	"alt MAC k = 4: same time, 53.7-bit soundness (k = 2: 26.8 bits)",
//   	"fails: uplink at 1 limb; t = 786433",
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

/// Z_t, for CmdArith over the MAC secrets.
struct Zt {
	uint64_t v, t;
	Zt operator+(const Zt& o) const { return {(v + o.v) % t, t}; }
	Zt operator-(const Zt& o) const { return {(v + t - o.v) % t, t}; }
	Zt operator*(const Zt& o) const { return {MulMod(v, o.v, t), t}; }
};

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

/// Number of flag bits in a zone's message (scenario.hpp, FlagBits).
int ZoneVars(Zone z) {
	return z == Zone::Passenger ? window::kPassengerFlags : z == Zone::Driver ? window::kDriverFlags
		: z == Zone::Ign ? window::kIgnFlags : 0;
}

/// A rotation by `blocks` blocks of B slots as OpenFHE's left-rotation index in [0, N/2):
/// rotations are cyclic in each row of N/2 slots, so a rotation to the right is a large one
/// to the left (same automorphism, same key).
uint32_t SlotShift(int blocks, int B, uint32_t N) {
	const int64_t half = N / 2;
	return (uint32_t)((((int64_t)blocks * B) % half + half) % half);
}

// ---------------------------------------------------------------- configuration

/// How the central node evaluates the command (header comment): in SIMD lanes with 3
/// tensor products, or block 0 only with 8 (factored: 5 relinearizations, direct: 7).
enum class Eval { Lanes, Factored, Direct };

const char* EvalName(Eval e) { return e == Eval::Lanes ? "lanes" : e == Eval::Factored ? "factored" : "direct"; }

// The lanes (blocks) of --eval lanes. The command ends in block 0, so kLaneG = 0; the
// others are placed so that no rotation brings a nonzero value onto a lane in use (the
// conditions: CentralNode::EvaluateLanes).
constexpr int kLaneG = 0, kLaneA = 3, kLaneX = 6, kLaneZ = 11;
static_assert(kLaneG == 0, "the command must end in block 0");

struct Config {
	bool split = false;       // one ciphertext per variable instead of one packed ciphertext per zone
	Eval eval = Eval::Lanes;
	uint64_t t = 65537;       // plaintext modulus (prime, = 1 mod 2N for packing)
	int mac_k = 3;            // independent MAC instances in the slots
	MultiplicationTechnique mult = HPSPOVERQ;
	KeySwitchTechnique ks = BV;
	int dnum = 0;             // HYBRID large digits (0: OpenFHE's default)
	int digit_size = 0;       // BV digit size in bits (0: OpenFHE's default, one digit per limb)
	int scaling_bits = 0;     // RNS limb size (0: OpenFHE's default, 60)
	int drop = 24;            // downlink: low bits rounded away per coefficient
	int uplink_limbs = 2;     // uplink encrypted at the first limbs only (0: all), lifted by the central node
	bool seeded = true;       // seeded uplink (else: OpenFHE-serialized ciphertexts)
	bool pk = false;          // public-key encryption (exploration only)
	bool hoist = true;        // hoisted rotations of each uplink ciphertext
	uint64_t seed = 1;        // provisioning RNG seed (MAC points, PRF key)
	int block() const { return kPoints * mac_k; }
	int cts(Zone z) const { return split ? ZoneVars(z) : 1; }
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

// ---------------------------------------------------------------- provisioning

/// The end zones' shared secrets (in their HSEs) and the public key material, created
/// once before the first round.
struct Provisioning {
	KeyPair<DCRTPoly> keys;                 // the end zones' shared BFV key pair
	std::vector<uint64_t> alpha;            // MAC points, outside the public points 0..6
	uint8_t mac_key[kMacKeyBytes] = {0};    // PRF key of the MAC secrets r
};

/// r_i^(m) = AES-256(mac_key, round | zone | i | m) mod t: every end zone derives its own
/// variables' MAC secrets, the passenger zone those of all three to check the tag.
class MacPrf {
public:
	explicit MacPrf(const uint8_t* key) : ctx_(EVP_CIPHER_CTX_new()) {
		EVP_EncryptInit_ex(ctx_, EVP_aes_256_ecb(), nullptr, key, nullptr);
		EVP_CIPHER_CTX_set_padding(ctx_, 0);
	}
	~MacPrf() { EVP_CIPHER_CTX_free(ctx_); }
	MacPrf(const MacPrf&) = delete;
	MacPrf& operator=(const MacPrf&) = delete;

	/// r[i][m] for the zone's n variables and k instances in this round, uniform mod t
	/// (64 PRF bits reduced mod t: bias < 2^-47).
	std::vector<std::vector<uint64_t>> Secrets(uint32_t round, Zone z, int n, int k, uint64_t t) {
		Bytes in(16 * n * k, 0), out(in.size() + 16);
		for (int i = 0; i < n; ++i)
			for (int m = 0; m < k; ++m) {
				uint8_t* b = in.data() + 16 * (i * k + m);
				std::memcpy(b, &round, 4);
				b[4] = (uint8_t)z;
				b[5] = (uint8_t)i;
				b[6] = (uint8_t)m;
			}
		int len = 0;
		EVP_EncryptUpdate(ctx_, out.data(), &len, in.data(), (int)in.size());
		std::vector<std::vector<uint64_t>> r(n, std::vector<uint64_t>(k));
		for (int i = 0; i < n; ++i)
			for (int m = 0; m < k; ++m) {
				uint64_t x;
				std::memcpy(&x, out.data() + 16 * (i * k + m), 8);
				r[i][m] = x % t;
			}
		return r;
	}

private:
	EVP_CIPHER_CTX* ctx_;
};

// ---------------------------------------------------------------- messages

struct Uplink {
	Bytes wire;  // round | zone | FHE payload (signed)
	Bytes signature;
	zk::AdscMessage adsc;
};

struct Downlink {
	Bytes wire;  // round | compressed result ciphertext (signed)
	Bytes signature;
};

struct Outcome {
	window::Cmd cmd = window::Cmd::Off;
	bool mac_ok = false;
	bool sig_ok = false;
};

// ---------------------------------------------------------------- end zones

/// An end zone's uplink: authenticate + prove its inputs, encode its MAC lines, encrypt
/// with the shared secret key, compress and sign.
class EndZoneNode : public ipcei::Participant {
public:
	EndZoneNode(ipcei::Recorder& rec, Zone zone, CryptoContext<DCRTPoly> cc, const Config& cfg,
			const Provisioning& prov, const zk::AdscSetup& adsc)
		: Participant(rec, zone), cc_(cc), cfg_(cfg), prov_(prov), prf_(prov.mac_key), adsc_(adsc) {
		params_ = cc_->GetCryptoParameters()->GetElementParams();
	}

	const Bytes& SigningKey() const { return sig_.PublicKey(); }
	size_t full_uplink_bytes() const { return full_uplink_bytes_; }

	Uplink MakeUplink(uint32_t round, const window::Inputs& in) {
		Uplink up;
		timed("adsc_authenticate", [&] { adsc_.Authenticate(window::SensorValues(zone_, in)); });
		timed("adsc_prove", [&] { up.adsc = adsc_.Prove(); });
		const std::vector<uint8_t>& bits = adsc_.bits();  // what the circuit derived: the zone encrypts these
		std::vector<Plaintext> pts;
		timed("encode", [&] { pts = Encode(round, bits); });
		std::vector<Ciphertext<DCRTPoly>> cts;
		uint8_t seed[kSeedBytes] = {0};
		timed("encrypt", [&] {
			if (cfg_.seeded) RAND_bytes(seed, sizeof seed);
			for (size_t c = 0; c < pts.size(); ++c) cts.push_back(Encrypt(pts[c], seed, (uint32_t)c));
		});
		timed("compress", [&] { up.wire = Compress(round, cts, seed); });
		if (full_uplink_bytes_ == 0)  // reference size, untimed
			for (const auto& c : cts) full_uplink_bytes_ += Serialize(c).size();
		timed("sign_uplink", [&] { up.signature = sig_.Sign(up.wire); });
		return up;
	}

protected:
	// The zone's variables, in its FlagBits order, from slot 0: variable i in block i
	// (packed) or in its own ciphertext (split), slot 7m + j of the block = y_i^(m)(j).
	std::vector<Plaintext> Encode(uint32_t round, const std::vector<uint8_t>& bits) {
		const uint64_t t = cfg_.t;
		const int B = cfg_.block(), n = (int)bits.size(), k = cfg_.mac_k;
		const auto r = prf_.Secrets(round, zone_, n, k, t);
		std::vector<std::vector<int64_t>> slots(cfg_.split ? n : 1, std::vector<int64_t>(cfg_.split ? B : n * B, 0));
		for (int i = 0; i < n; ++i) {
			auto& v = slots[cfg_.split ? i : 0];
			const int base = cfg_.split ? 0 : i * B;
			for (int m = 0; m < k; ++m) {
				const uint64_t s = MulMod((r[i][m] + t - bits[i]) % t, InvMod(prov_.alpha[m], t), t);
				for (int j = 0; j < kPoints; ++j) v[base + kPoints * m + j] = (int64_t)((bits[i] + MulMod(s, j, t)) % t);
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
		const auto& keys = prov_.keys;
		if (!cfg_.seeded) return cfg_.pk ? cc_->Encrypt(keys.publicKey, pt) : cc_->Encrypt(keys.secretKey, pt);
		const auto cp = std::dynamic_pointer_cast<CryptoParametersBFVRNS>(cc_->GetCryptoParameters());
		DCRTPoly m = pt->GetElement<DCRTPoly>();
		const auto ep = m.GetParams();  // the first L - level limbs
		const size_t level = params_->GetParams().size() - ep->GetParams().size();
		m.SetFormat(Format::COEFFICIENT);
		m.TimesQovert(ep, cp->GettInvModq(), cp->GetPlaintextModulus(), cp->GetNegQModt(level),
				cp->GetNegQModtPrecon(level));
		m.SetFormat(Format::EVALUATION);
		DCRTPoly sk = keys.secretKey->GetPrivateElement();
		if (level) sk.DropLastElements(level);
		DCRTPoly a = ExpandUniform(seed, index, ep);
		DCRTPoly b(cp->GetDiscreteGaussianGenerator(), ep, Format::EVALUATION);
		b -= a * sk;
		b += m;
		auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(keys.secretKey);
		ct->SetElements({std::move(b), std::move(a)});
		ct->SetNoiseScaleDeg(1);
		ct->SetEncodingType(pt->GetEncodingType());
		ct->SetSlots(pt->GetSlots());
		ct->SetLevel(pt->GetLevel());
		return ct;
	}

	// Wire: u32 round | u8 zone | FHE payload.
	// Seeded payload: u32 count | u32 limbs | seed | per ciphertext b's residues, bit-packed.
	// Unseeded payload: u32 count | per ciphertext u32 length + OpenFHE serialization.
	Bytes Compress(uint32_t round, const std::vector<Ciphertext<DCRTPoly>>& cts, const uint8_t* seed) {
		Bytes w;
		PutU32(w, round);
		w.push_back((uint8_t)zone_);
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

	CryptoContext<DCRTPoly> cc_;
	Config cfg_;
	const Provisioning& prov_;
	std::shared_ptr<DCRTPoly::Params> params_;
	MacPrf prf_;
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

/// The passenger zone: an uplink like the others, and the actuator that receives the
/// downlink, decrypts it and checks the MAC tag of the whole decision.
class PassengerNode : public EndZoneNode {
public:
	PassengerNode(ipcei::Recorder& rec, CryptoContext<DCRTPoly> cc, const Config& cfg, const Provisioning& prov,
			const zk::AdscSetup& adsc)
		: EndZoneNode(rec, Zone::Passenger, cc, cfg, prov, adsc) {
		const uint64_t t = cfg_.t;
		for (uint64_t alpha : prov_.alpha) {
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

	double noise_margin_bits() const { return noise_margin_; }

	Outcome ReadDownlink(uint32_t round, const Downlink& dl, const Bytes& central_key) {
		Outcome o;
		timed("verify_downlink", [&] {
			o.sig_ok = ipcei::Ed25519::Verify(central_key, dl.wire, dl.signature) && GetU32(dl.wire, 0) == round;
		});
		Ciphertext<DCRTPoly> ct;
		std::vector<int64_t> y;
		timed("decrypt", [&] {
			ct = Unpack(dl.wire);
			y = Decrypt(ct);
		});
		timed("check_result", [&] { o.mac_ok = CheckTag(round, y, o.cmd); });
		if (ct->GetElements()[0].GetNumOfElements() == 1) MeasureNoise(ct);  // diagnostic, untimed
		return o;
	}

	/// Untimed: signature + decrypt + tag check, for the tamper test.
	bool AcceptsUntimed(uint32_t round, const Downlink& dl, const Bytes& central_key) {
		if (!ipcei::Ed25519::Verify(central_key, dl.wire, dl.signature) || GetU32(dl.wire, 0) != round) return false;
		window::Cmd cmd;
		return CheckTag(round, Decrypt(Unpack(dl.wire)), cmd);
	}

private:
	// Inverse of CentralNode::CompressDownlink (wire format there).
	Ciphertext<DCRTPoly> Unpack(const Bytes& wire) {
		const uint32_t limbs = GetU32(wire, kDownlinkHeader);
		const int drop = (int)GetU32(wire, kDownlinkHeader + 4);
		DCRTPoly like(params_, Format::EVALUATION, true);
		like.DropLastElements(like.GetNumOfElements() - limbs);
		BitReader r(wire, kDownlinkHeader + 8);
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
		auto ct = std::make_shared<CiphertextImpl<DCRTPoly>>(prov_.keys.secretKey);
		ct->SetElements(std::move(cv));
		ct->SetEncodingType(PACKED_ENCODING);
		ct->SetSlots(cc_->GetRingDimension());
		ct->SetNoiseScaleDeg(1);
		return ct;
	}

	std::vector<int64_t> Decrypt(const Ciphertext<DCRTPoly>& ct) {
		Plaintext pt;
		cc_->Decrypt(prov_.keys.secretKey, ct, &pt);
		return pt->GetPackedValue();
	}

	// Block 0 of the result: Y_m(j) at slot 7m + j. Every instance must carry the same
	// command Y_m(0) in {0, 1, t-1}, and Y_m(alpha_m) (Lagrange) must equal CmdArith over
	// the round's MAC secrets of all three zones (recomputed from the shared PRF key).
	bool CheckTag(uint32_t round, const std::vector<int64_t>& y, window::Cmd& cmd) {
		const uint64_t t = cfg_.t;
		const int k = cfg_.mac_k;
		auto val = [&](int idx) { return (uint64_t)(((y.at(idx) % (int64_t)t) + (int64_t)t) % (int64_t)t); };
		const auto rp = prf_.Secrets(round, Zone::Passenger, window::kPassengerFlags, k, t);
		const auto rd = prf_.Secrets(round, Zone::Driver, window::kDriverFlags, k, t);
		const auto ri = prf_.Secrets(round, Zone::Ign, window::kIgnFlags, k, t);
		const uint64_t d = val(0);
		bool ok = d == 0 || d == 1 || d == t - 1;
		for (int m = 0; m < k; ++m) {
			uint64_t tag = 0;
			for (int j = 0; j < kPoints; ++j) tag = (tag + MulMod(val(kPoints * m + j), lagrange_[m][j], t)) % t;
			auto z = [&](const std::vector<std::vector<uint64_t>>& r, int i) { return Zt{r[i][m], t}; };
			const Zt expect = window::CmdArith(z(rp, window::kPu), z(rp, window::kPd), z(rp, window::kTopFlag),
					z(rp, window::kBotFlag), z(rp, window::kErr), z(rd, window::kOu), z(rd, window::kOd),
					z(rd, window::kCl), z(ri, window::kK), Zt{1, t});
			ok = ok && val(kPoints * m) == d && tag == expect.v;
		}
		cmd = d == 1 ? window::Cmd::MotorUp : d == t - 1 ? window::Cmd::MotorDown : window::Cmd::Off;
		return ok;
	}

	// Diagnostic (untimed): the noise of the received 1-limb ciphertext, as the margin in
	// bits between its largest coefficient and the decryption bound (q/t)/2.
	void MeasureNoise(const Ciphertext<DCRTPoly>& ct) {
		DCRTPoly s = prov_.keys.secretKey->GetPrivateElement();
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

	std::vector<std::vector<uint64_t>> lagrange_;  // L_j(alpha_m)
	double noise_margin_ = 1e9;
};

// ---------------------------------------------------------------- central node

/// The Process APP: verifies the three uplinks, aligns the zones' variables and evaluates
/// the motor command blind. Holds the evaluation keys (by key tag), never the secret key.
class CentralNode : public ipcei::Participant {
public:
	CentralNode(ipcei::Recorder& rec, CryptoContext<DCRTPoly> cc, const Config& cfg, std::string key_tag,
			const std::map<Zone, const zk::AdscSetup*>& adsc, const std::map<Zone, Bytes>& zone_keys)
		: Participant(rec, Zone::Central), cc_(cc), cfg_(cfg), tag_(std::move(key_tag)), zone_keys_(zone_keys) {
		params_ = cc_->GetCryptoParameters()->GetElementParams();
		for (const auto& z : adsc) adsc_[z.first].reset(new zk::AdscVerifier(*z.second));
		const int B = cfg_.block();
		auto ones = [&](std::initializer_list<int> lanes) {  // the constant 1 on these blocks
			std::vector<int64_t> v((kLaneZ + 2) * B, 0);
			for (int l : lanes) std::fill(v.begin() + l * B, v.begin() + (l + 1) * B, 1);
			return cc_->MakePackedPlaintext(v);
		};
		one_ = ones({0});
		one_a_ = ones({kLaneA});
		one_b_ = ones({kLaneG, kLaneA, kLaneX, kLaneX + 1, kLaneZ, kLaneZ + 1});
	}
	const Bytes& SigningKey() const { return sig_.PublicKey(); }
	size_t full_downlink_bytes() const { return full_downlink_bytes_; }
	size_t onelimb_downlink_bytes() const { return onelimb_downlink_bytes_; }

	/// One zone's uplink: verify_uplink, adsc_verify and decompress add up over the three.
	/// Returns whether the signature (over round | zone | payload) and the proof hold.
	bool Receive(uint32_t round, Zone z, const Uplink& up) {
		bool sig = false, adsc = false;
		timed("verify_uplink", [&] {
			sig = ipcei::Ed25519::Verify(zone_keys_.at(z), up.wire, up.signature) && GetU32(up.wire, 0) == round &&
				up.wire.at(4) == (uint8_t)z;
		});
		timed("adsc_verify", [&] { adsc = adsc_.at(z)->Verify(up.adsc); });
		timed("decompress", [&] { in_[z] = Decompress(up.wire, kUplinkHeader); });
		return sig && adsc;
	}

	Downlink Process(uint32_t round) {
		Ciphertext<DCRTPoly> y;
		timed("evaluate", [&] { y = Evaluate(); });
		Downlink dl;
		timed("compress_downlink", [&] { dl.wire = CompressDownlink(round, y); });
		timed("sign_downlink", [&] { dl.signature = sig_.Sign(dl.wire); });
		if (full_downlink_bytes_ == 0) {  // reference sizes, untimed
			full_downlink_bytes_ = Serialize(y).size();
			if (CanCompress()) onelimb_downlink_bytes_ = Serialize(cc_->Compress(y, 1)).size();
		}
		return dl;
	}

	/// Untimed: a dishonest central node that adds 1 to the command, consistently at all 7
	/// points of every MAC instance (Y + 1: Off becomes Motor+); the passenger must reject it.
	Downlink ProcessTampered(uint32_t round) {
		Ciphertext<DCRTPoly> y = cc_->EvalAdd(Evaluate(), one_);
		Downlink dl;
		dl.wire = CompressDownlink(round, y);
		dl.signature = sig_.Sign(dl.wire);
		return dl;
	}

	/// The rotations Evaluate does, in blocks (negative: to the right), grouped by the
	/// ciphertext they rotate (one hoisted decomposition per group). Key generation uses it.
	static std::vector<std::vector<int>> RotationGroups(const Config& cfg) {
		using namespace window;
		if (cfg.split) return {};
		if (cfg.eval != Eval::Lanes) return {{1, 2, 3, 4}, {1, 2}};  // Align: variable i -> block 0
		return {
			{kPu - kLaneX, kTopFlag - kLaneX, kTopFlag - kLaneZ, kErr - kLaneG},  // passenger
			{kOu - kLaneZ, kOu - kLaneA, kOd - kLaneA, kCl - kLaneA},              // driver
			{kLaneA, kLaneX, kLaneX + 1, kLaneZ, kLaneZ + 1},                      // Q: lanes -> block 0
		};
	}

private:
	std::vector<Ciphertext<DCRTPoly>> Decompress(const Bytes& wire, size_t pos) {
		const uint32_t count = GetU32(wire, pos);
		std::vector<Ciphertext<DCRTPoly>> cts;
		if (!cfg_.seeded) {
			pos += 4;
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
		const size_t Lu = GetU32(wire, pos + 4);
		const uint8_t* seed = wire.data() + pos + 8;
		BitReader r(wire, pos + 8 + kSeedBytes);
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

	/// Rotation of `c` by `blocks` blocks to the left (negative: to the right; rotations are
	/// cyclic in each row of N/2 slots), with the hoisted decomposition `digits` if given.
	Ciphertext<DCRTPoly> Rot(const Ciphertext<DCRTPoly>& c, int blocks,
			const std::shared_ptr<std::vector<DCRTPoly>>& digits) const {
		if (blocks == 0) return c;
		const uint32_t idx = SlotShift(blocks, cfg_.block(), cc_->GetRingDimension());
		if (digits) return cc_->EvalFastRotation(c, idx, 2 * cc_->GetRingDimension(), digits);
		return cc_->EvalRotate(c, (int32_t)idx);
	}
	std::shared_ptr<std::vector<DCRTPoly>> Hoist(const Ciphertext<DCRTPoly>& c) const {
		return cfg_.hoist ? cc_->EvalFastRotationPrecompute(c) : nullptr;
	}

	/// A zone's variables, each with its value in block 0: variable i of the packed message
	/// rotated by i*B (the rotations of one ciphertext share one hoisted decomposition).
	std::vector<Ciphertext<DCRTPoly>> Align(Zone z) const {
		const auto& cts = in_.at(z);
		if (cfg_.split) return cts;
		const int n = ZoneVars(z);
		std::vector<Ciphertext<DCRTPoly>> v{cts[0]};
		if (n == 1) return v;
		const auto digits = Hoist(cts[0]);
		for (int i = 1; i < n; ++i) v.push_back(Rot(cts[0], i, digits));
		return v;
	}

	// --eval lanes: 3 tensor products. P, D, K are the zones' packed messages (variable i in
	// block i); the lanes are blocks. One product of two sums of rotated inputs fills
	//   A  = k        | 1 - ou - od | pu       pd       | ou       od
	//   Bf = 1 - err  | 1 - cl      | 1 - top  1 - bot  | 1 - top  1 - bot
	//   Q  = A Bf: g  | a           | pu(1-top) pd(1-bot) | ou(1-top) od(1-bot)
	//        lane     0 (kLaneG)    3 (kLaneA)  6, 7 (kLaneX)         11, 12 (kLaneZ)
	// then, everything rotated from its lane to block 0 (5 hoisted rotations of Q),
	//   S = Q[a] (Q[X] - Q[X+1]) + Q[Z] - Q[Z+1] = a X + Z,   cmd = Q[g] S = g (Z + a X).
	// Lane conditions: every term placed on a lane in use is the only nonzero one there
	// (the zones' messages are zero beyond their last block, so a rotation to the right
	// brings in zeros), and the lanes where A or Bf carry leftovers (1, 2, 4, 5, 8..10, 13,
	// the end of the row) are never rotated onto block 0. The constant 1 is the plaintext
	// block of ones on the lanes that need it.
	Ciphertext<DCRTPoly> EvaluateLanes() {
		using namespace window;
		const auto& P = in_.at(Zone::Passenger)[0];
		const auto& D = in_.at(Zone::Driver)[0];
		const auto& K = in_.at(Zone::Ign)[0];
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
		// (adding a 2-element ciphertext to a 3-element one decrypts wrong in OpenFHE 1.5.1: the
		// product is relinearized first, still one relinearization)
		auto S = cc_->EvalMult(q(kLaneA), X);
		cc_->EvalAddInPlace(S, Z);
		return cc_->EvalMult(Q, S);
	}

	Ciphertext<DCRTPoly> Evaluate() {
		using namespace window;
		if (cfg_.eval == Eval::Lanes) return EvaluateLanes();
		const auto P = Align(Zone::Passenger), D = Align(Zone::Driver), K = Align(Zone::Ign);
		auto c1 = [&](const Ciphertext<DCRTPoly>& x) { return cc_->EvalSub(one_, x); };  // 1 - x
		const auto nt = c1(P[kTopFlag]), nb = c1(P[kBotFlag]);
		const auto g = cc_->EvalMult(K[kK], c1(P[kErr]));                         // k (1 - err)
		const auto a = cc_->EvalMult(cc_->EvalSub(c1(D[kOu]), D[kOd]), c1(D[kCl]));  // (1 - ou - od)(1 - cl)
		if (cfg_.eval == Eval::Direct) {  // CmdArith as written: 8 multiplications, 7 relinearizations
			const auto up = cc_->EvalAdd(D[kOu], cc_->EvalMult(a, P[kPu]));
			const auto dn = cc_->EvalAdd(D[kOd], cc_->EvalMult(a, P[kPd]));
			const auto gt = cc_->EvalMult(nt, g), gb = cc_->EvalMult(nb, g);
			return cc_->Relinearize(cc_->EvalSub(cc_->EvalMultNoRelin(up, gt), cc_->EvalMultNoRelin(dn, gb)));
		}
		// factored: g (Z + a X), 8 multiplications, 5 relinearizations
		const auto X = cc_->Relinearize(cc_->EvalSub(cc_->EvalMultNoRelin(P[kPu], nt), cc_->EvalMultNoRelin(P[kPd], nb)));
		const auto Z = cc_->EvalSub(cc_->EvalMultNoRelin(D[kOu], nt), cc_->EvalMultNoRelin(D[kOd], nb));
		const auto S = cc_->Relinearize(cc_->EvalAdd(cc_->EvalMultNoRelin(a, X), Z));
		return cc_->EvalMult(g, S);
	}

	bool CanCompress() const { return cfg_.mult == HPSPOVERQ || cfg_.mult == HPSPOVERQLEVELED; }

	// Downlink wire: u32 round | u32 limbs | u32 drop bits | c0, c1. One limb (HPSPOVERQ*):
	// COEFFICIENT format, each coefficient as round(x / 2^drop), bit-packed. Several limbs
	// (HPS, BEHZ: no OpenFHE Compress): the residues as they are, bit-packed.
	Bytes CompressDownlink(uint32_t round, const Ciphertext<DCRTPoly>& y) {
		Bytes w;
		PutU32(w, round);
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
	std::map<Zone, Bytes> zone_keys_;
	std::shared_ptr<DCRTPoly::Params> params_;
	std::map<Zone, std::unique_ptr<zk::AdscVerifier>> adsc_;
	std::map<Zone, std::vector<Ciphertext<DCRTPoly>>> in_;  // this round's decompressed uplinks
	Plaintext one_, one_a_, one_b_;  // the constant 1 on block 0 / lane kLaneA / Bf's lanes
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
			"usage: bfv_openfhe [--layout packed|split] [--eval lanes|factored|direct] [--t T] [--mac-k K]\n"
			"                   [--mult HPS|BEHZ|HPSPOVERQ|HPSPOVERQLEVELED] [--ks BV|HYBRID] [--dnum D]\n"
			"                   [--digit-size B] [--scaling-bits B] [--uplink-limbs L] [--drop BITS]\n"
			"                   [--no-seed] [--pk] [--no-hoist] [--seed N] [--rounds R] [--warmup W]\n"
			"                   [--json FILE] [--quiet]\n");
	return 2;
}

}  // namespace

int main(int argc, char** argv) {
	// one thread unless OMP_NUM_THREADS says otherwise (the suite measures single-core nodes)
	ipcei::SingleThreadByDefault(argv);
	ipcei::Options opts = ipcei::Options::Parse(argc, argv, window::Rounds::kCases);
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
		} else if (a == "--eval") {
			const std::string v = next();
			if (v == "lanes") cfg.eval = Eval::Lanes;
			else if (v == "factored") cfg.eval = Eval::Factored;
			else if (v == "direct") cfg.eval = Eval::Direct;
			else return Usage();
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
	if (cfg.mac_k < 1 || cfg.mac_k > 255 || cfg.drop < 0 || cfg.drop > 50) return Usage();
	if (cfg.split && cfg.eval == Eval::Lanes) cfg.eval = Eval::Factored;  // lanes need the packed messages
	if (cfg.mult == HPS || cfg.mult == BEHZ) {
		std::fprintf(stderr, "note: %s cannot encode below the top level nor Compress: uplink and downlink "
				"at full Q\n", MultName(cfg.mult));
		cfg.uplink_limbs = 0;
	}

	// ---- one-time setup and provisioning (not reported)
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
	const int B = cfg.block();
	if ((kLaneZ + 2 + window::kPassengerFlags) * B > (int)N / 2) {
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

	// the end zones' shared BFV key, MAC points and PRF key; mt19937_64 stands in for the
	// provisioning HSM's randomness. The central node gets the evaluation keys only.
	Provisioning prov;
	{
		std::mt19937_64 rng(cfg.seed ^ 0x5eed5eedULL);
		prov.keys = cc->KeyGen();
		cc->EvalMultKeyGen(prov.keys.secretKey);
		std::vector<int32_t> rot;
		for (const auto& group : CentralNode::RotationGroups(cfg))
			for (int blocks : group) {
				const int32_t idx = (int32_t)SlotShift(blocks, B, N);
				if (idx && std::find(rot.begin(), rot.end(), idx) == rot.end()) rot.push_back(idx);
			}
		if (!rot.empty()) cc->EvalRotateKeyGen(prov.keys.secretKey, rot);
		std::uniform_int_distribution<uint64_t> pick(kPoints, cfg.t - 1);
		for (int m = 0; m < cfg.mac_k; ++m) prov.alpha.push_back(pick(rng));
		for (size_t i = 0; i < kMacKeyBytes; ++i) prov.mac_key[i] = (uint8_t)rng();
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

	// ---- rounds: the warm-up draws from its own generator, so the measured rounds are
	// exactly the scenario's cases (the first Rounds::kCases), then random inputs
	window::Rounds warm(~cfg.seed), cases;
	const int total = opts.warmup + opts.rounds;
	std::map<Zone, size_t> up_bytes, adsc_bytes;
	size_t dl_bytes = 0, sig_bytes = 0;
	int commands[3] = {0, 0, 0};
	int tamper = -1;  // -1: not run, 0: forged result accepted, 1: rejected
	for (int r = 0; r < total; ++r) {
		const uint32_t round = (uint32_t)r;
		const window::Inputs in = r < opts.warmup ? warm.Next() : cases.Next();
		const window::Cmd expected = window::Decide(in);
		rec.BeginRound();
		bool verified = true;
		for (EndZoneNode* z : zones) {
			const Uplink up = z->MakeUplink(round, in);
			verified = central.Receive(round, z->zone(), up) && verified;
			up_bytes[z->zone()] = up.wire.size() - kUplinkHeader;
			adsc_bytes[z->zone()] = up.adsc.proof_bytes;
			sig_bytes = up.signature.size();
		}
		const Downlink dl = central.Process(round);
		const Outcome o = passenger.ReadDownlink(round, dl, central.SigningKey());
		const bool ok = verified && o.sig_ok && o.mac_ok && o.cmd == expected;
		rec.RoundResult(ok);
		dl_bytes = dl.wire.size() - kDownlinkHeader;
		++commands[(int)expected];
		if (!opts.quiet)
			std::printf("round %2d%s  %-30s  cmd %-6s expected %-6s  MAC %s%s\n", r, r < opts.warmup ? "w" : " ",
					in.label.c_str(), window::CmdName(o.cmd), window::CmdName(expected), o.mac_ok ? "ok" : "FAIL",
					ok ? "" : "  WRONG");
		if (!ok)
			std::fprintf(stderr, "round %d: WRONG (verified %d, downlink sig %d, MAC %d, cmd %s, expected %s)\n", r,
					verified, o.sig_ok, o.mac_ok, window::CmdName(o.cmd), window::CmdName(expected));
		if (expected == window::Cmd::Off && tamper < 0) {
			// tamper test (untimed): a dishonest central node turns this round's Off into
			// Motor+; the passenger must reject the result
			tamper = passenger.AcceptsUntimed(round, central.ProcessTampered(round), central.SigningKey()) ? 0 : 1;
		}
	}

	rec.Param("backend", IPCEI_BACKEND);
	rec.Param("threads", std::to_string(omp_get_max_threads()));
	rec.Param("ring dimension N", N);
	rec.Param("log2 Q", logQ);
	rec.Param("Q chain (bits)", limbs);
	rec.Param("plaintext modulus t", (double)cfg.t);
	rec.Param("multiplicative depth", 3);
	rec.Param("security", "HEStd_128_classic");
	rec.Param("multiplication", MultName(cfg.mult));
	rec.Param("key switching", cfg.ks == HYBRID ? "HYBRID" : "BV");
	rec.Param("encoding", "packed (SIMD), flags");
	rec.Param("layout", cfg.split ? "split (1 ciphertext per variable, no rotations)"
								: "packed (1 ciphertext per zone, variables from slot 0, aligned by the central node)");
	{
		int rots = 0;
		const auto groups = CentralNode::RotationGroups(cfg);
		for (const auto& g : groups) rots += (int)g.size();
		const char* what = cfg.eval == Eval::Lanes ? "lanes g (Z + a X): 3 tensor products, 3 relins"
			: cfg.eval == Eval::Factored ? "factored g (Z + a X): 8 tensor products, 5 relins"
			: "direct CmdArith: 8 tensor products, 7 relins";
		rec.Param("evaluation", std::string(what) + ", depth 3, " + std::to_string(rots) + " rotations" +
				(rots && cfg.hoist ? " in " + std::to_string(groups.size()) + " hoisted groups" : ""));
	}
	rec.Param("encryption", cfg.pk ? "public key" : cfg.seeded ? "secret key, seeded (AES-256-CTR)" : "secret key");
	{
		const size_t Lu = cfg.uplink_limbs ? (size_t)cfg.uplink_limbs : towers.size();
		int bits = 0;
		for (size_t i = 0; i < Lu; ++i) bits += towers[i]->GetModulus().GetMSB();
		rec.Param("uplink modulus", std::to_string(Lu) + " limb(s), " + std::to_string(bits) + " bits" +
				(Lu < towers.size() ? ", raised to Q by the central node" : ""));
	}
	rec.Param("MAC instances k", cfg.mac_k);
	rec.Param("MAC points", std::to_string(kPoints) + " (X = 0.." + std::to_string(kDegree) + "), block of " +
			std::to_string(B) + " slots per variable");
	rec.Param("MAC soundness (bits)", -cfg.mac_k * std::log2((double)kDegree / (double)cfg.t));
	rec.Param("downlink dropped bits", cfg.drop);
	if (passenger.noise_margin_bits() < 1e8) rec.Param("downlink noise margin (bits)", passenger.noise_margin_bits());
	else rec.Param("downlink noise margin (bits)", "n/a (multi-limb downlink)");
	rec.Param("signature", "Ed25519");
	for (Zone z : ipcei::kEndZones)
		rec.Param(std::string("adsc_constraints_") + ipcei::ZoneName(z), (double)adsc_setup[z]->constraints());
	for (Zone z : ipcei::kEndZones)
		rec.Size(std::string("uplink ") + ipcei::ZoneName(z) + " (FHE payload)", (double)up_bytes[z]);
	rec.Size("uplink unseeded (OpenFHE serialized)", (double)passenger.full_uplink_bytes());
	rec.Size("downlink (FHE payload)", (double)dl_bytes);
	rec.Size("downlink 1 limb (OpenFHE serialized)", (double)central.onelimb_downlink_bytes());
	rec.Size("downlink full Q (OpenFHE serialized)", (double)central.full_downlink_bytes());
	for (Zone z : ipcei::kEndZones)
		rec.Size(std::string("ADSC proof ") + ipcei::ZoneName(z), (double)adsc_bytes[z]);
	rec.Size("signature (each link)", (double)sig_bytes);
	rec.Note("the end zones share the BFV secret key and the MAC key (trusted for their own data, provisioned "
			"into their HSEs); the central node holds only the relinearization/rotation keys (by key tag)");
	rec.Note("no global slot layout: each zone packs its own variables from slot 0, the central node aligns "
			"them with rotations");
	rec.Note("the ADSC proofs show each zone's bits are derived from authenticated sensor data, but do not bind "
			"them to the zone's ciphertext");
	rec.Note(std::string("tamper test (central node forges Motor+ in an Off round): ") +
			(tamper < 0 ? "not run (no Off round)" : tamper ? "rejected" : "ACCEPTED (BUG)"));
	rec.Note("commands (warm-up included): Motor+ " + std::to_string(commands[(int)window::Cmd::MotorUp]) +
			", Motor- " + std::to_string(commands[(int)window::Cmd::MotorDown]) + ", Off " +
			std::to_string(commands[(int)window::Cmd::Off]));

	ipcei::Report report(rec, "bfv_openfhe", std::string("OpenFHE ") + IPCEI_OPENFHE_VERSION, "BFV");
	report.Print();
	if (!opts.json.empty()) report.WriteJson(opts.json);
	int correct = 0;
	for (bool b : rec.correct()) correct += b;
	return (correct == (int)rec.correct().size() && tamper != 0) ? 0 : 1;
}
