// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// ckks_common.hpp — what the two CKKS protocol benches (ckks_seal, ckks_openfhe) share:
// the approximate MAC, the slot layout and lane plan of the central evaluation, the seeded
// uniform expansion of the uplinks and the bit packing of the wire formats.
//
// Approximate MAC (CKKS computes over the reals, so the Z_t tag of the BFV benches becomes
// a real-valued one). Every flag f_i is tagged, per instance m = 1..k, with the line
//   y_i^(m)(X) = f_i + s_i^(m) X,  s_i^(m) = (r_i^(m) - f_i) / alpha_m
// where alpha_m in [0.5, 1) is a secret MAC point provisioned to the end zones and
// r_i^(m) in [-1, 1) a per-round secret, AES-256(key, round | zone | i | m). So y(0) = f
// and y(alpha_m) = r. The tag is carried in evaluation form at the 7 public points
// x_j = j / 6 (a degree-6 polynomial is fixed by 7 values, and the slot-wise product of
// evaluations is the evaluation of the product): variable i occupies a block of B = 7k
// slots, slot 7m + j holding y_i^(m)(x_j). The central node evaluates the decision on the
// blocks; block 0 of the result holds Y_m(x_j). The passenger reads the command from
// Y_m(0) (rounded to +1, -1 or 0) and checks, per instance,
//   | sum_j Y_m(x_j) L_j(alpha_m) - CmdArith(r^(m)) | <= tol
// (L_j the Lagrange basis of the points), recomputing the r of all three zones from the
// shared key. Unlike the BFV tag (forgery <= 6/t per instance, exact), this check has a
// tolerance: a forged result that adds E(X) (E(0) = +-1, to change the command) passes an
// instance when |E(alpha_m)| <= tol, which an E with a root near a guessed alpha_m does
// for alpha_m within ~tol / |E'| of the guess. Its soundness is therefore ~ the number of
// bits the tolerance resolves, per instance; no bound is claimed here, the benches record
// the tolerance, the largest honest deviation measured, and a tamper test (Y + 1 at
// every point of every instance must be rejected). --mac-k 0 turns the MAC off (block of
// one slot, the bare flag; check_result then only rounds the command).
//
// Points in [0, 1] and alpha in [0.5, 1) keep the honest slot values small (|y| <= 5) and
// the Lagrange weights at alpha modest (sum |L_j| < 5), so the precision the tag check
// needs stays within what one 40-50-bit CKKS scale gives at depth 3.
//
// Lane plan (the same as bfv_openfhe --eval lanes; slot blocks are lanes): see
// RotationGroups and the benches' EvaluateLanes.
#pragma once

#include <openssl/evp.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <vector>

#include "ipcei/harness.hpp"
#include "ipcei/scenario.hpp"

namespace ipcei {
namespace ckks {

using Bytes = std::vector<uint8_t>;

constexpr int kDegree = 6;            // degree of the decision in its inputs (CmdArith)
constexpr int kPoints = kDegree + 1;  // public evaluation points x_j = j / kDegree
constexpr size_t kSeedBytes = 32;     // AES-256 key that expands an uplink's uniform part
constexpr size_t kMacKeyBytes = 32;   // shared PRF key of the MAC secrets
constexpr size_t kUplinkHeader = 5;   // round (u32) | zone (u8)
constexpr size_t kDownlinkHeader = 4; // round (u32)

inline double Point(int j) { return (double)j / kDegree; }

/// Number of flag bits in a zone's message (scenario.hpp, FlagBits).
inline int ZoneVars(Zone z) {
	return z == Zone::Passenger ? window::kPassengerFlags : z == Zone::Driver ? window::kDriverFlags
		: z == Zone::Ign ? window::kIgnFlags : 0;
}

/// Slots per variable: 7 points per MAC instance, or the bare flag without a MAC.
inline int Block(int mac_k) { return mac_k > 0 ? kPoints * mac_k : 1; }

// The lanes (blocks) of the evaluation: the command ends in block 0 (kLaneG). The others
// are placed so that no rotation brings a nonzero value onto a lane in use (bfv_openfhe).
constexpr int kLaneG = 0, kLaneA = 3, kLaneX = 6, kLaneZ = 11;
/// Blocks in use: the lanes, and the passenger's message rotated right up to kLaneZ.
constexpr int kLanesUsed = kLaneZ + 2 + window::kPassengerFlags;

/// The rotations of the evaluation, in blocks (negative: to the right), grouped by the
/// ciphertext they rotate (one hoisted decomposition per group where the library has it).
inline std::vector<std::vector<int>> RotationGroups() {
	using namespace window;
	return {
		{kPu - kLaneX, kTopFlag - kLaneX, kTopFlag - kLaneZ, kErr - kLaneG},  // passenger
		{kOu - kLaneZ, kOu - kLaneA, kOd - kLaneA, kCl - kLaneA},              // driver
		{kLaneA, kLaneX, kLaneX + 1, kLaneZ, kLaneZ + 1},                      // Q: lanes -> block 0
	};
}

/// A rotation by `blocks` blocks of B slots as a left-rotation index in [0, slots): the
/// rotations are cyclic over the slots, so a rotation to the right is a large one to the left.
inline int SlotShift(int blocks, int B, int slots) {
	return (int)((((int64_t)blocks * B) % slots + slots) % slots);
}

// ---------------------------------------------------------------- MAC

/// The end zones' shared MAC material (in their HSEs).
struct MacKey {
	int k = 0;
	std::vector<double> alpha;            // secret points, [0.5, 1)
	uint8_t prf_key[kMacKeyBytes] = {0};  // PRF key of the per-round secrets r
};

/// r_i^(m) = AES-256(key, round | zone | i | m), mapped to [-1, 1) (53 bits).
class MacPrf {
public:
	explicit MacPrf(const uint8_t* key) : ctx_(EVP_CIPHER_CTX_new()) {
		EVP_EncryptInit_ex(ctx_, EVP_aes_256_ecb(), nullptr, key, nullptr);
		EVP_CIPHER_CTX_set_padding(ctx_, 0);
	}
	~MacPrf() { EVP_CIPHER_CTX_free(ctx_); }
	MacPrf(const MacPrf&) = delete;
	MacPrf& operator=(const MacPrf&) = delete;

	/// r[i][m] for the zone's n variables and k instances in this round.
	std::vector<std::vector<double>> Secrets(uint32_t round, Zone z, int n, int k) {
		std::vector<std::vector<double>> r(n, std::vector<double>(k));
		if (k == 0) return r;
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
		for (int i = 0; i < n; ++i)
			for (int m = 0; m < k; ++m) {
				uint64_t x;
				std::memcpy(&x, out.data() + 16 * (i * k + m), 8);
				r[i][m] = (double)(x >> 11) * 0x1p-52 - 1.0;
			}
		return r;
	}

private:
	EVP_CIPHER_CTX* ctx_;
};

/// A zone's slot values: variable i (FlagBits order) in block i from slot 0, slot 7m + j of
/// the block = y_i^(m)(x_j) (with the MAC), or the flag itself (without).
inline std::vector<double> ZoneSlots(const MacKey& mk, MacPrf& prf, uint32_t round, Zone z,
		const std::vector<uint8_t>& bits) {
	const int n = (int)bits.size(), k = mk.k, B = Block(k);
	std::vector<double> v((size_t)n * B, 0.0);
	if (k == 0) {
		for (int i = 0; i < n; ++i) v[i] = bits[i];
		return v;
	}
	const auto r = prf.Secrets(round, z, n, k);
	for (int i = 0; i < n; ++i)
		for (int m = 0; m < k; ++m) {
			const double s = (r[i][m] - bits[i]) / mk.alpha[m];
			for (int j = 0; j < kPoints; ++j) v[(size_t)i * B + kPoints * m + j] = bits[i] + s * Point(j);
		}
	return v;
}

/// The constant 1 on the given blocks (the plaintext operand of the lane sums).
inline std::vector<double> Ones(std::initializer_list<int> lanes, int B) {
	std::vector<double> v((size_t)(kLaneZ + 2) * B, 0.0);
	for (int l : lanes) std::fill(v.begin() + (size_t)l * B, v.begin() + (size_t)(l + 1) * B, 1.0);
	return v;
}

/// What the passenger reads from block 0 of the result.
struct TagCheck {
	window::Cmd cmd = window::Cmd::Off;
	bool ok = false;          // command valid and consistent, every instance's tag within tol
	double cmd_dev = 0;       // largest |Y_m(0) - round(Y_m(0))|
	double tag_dev = 0;       // largest |Y_m(alpha_m) - CmdArith(r^(m))|
};

/// The passenger's check (also the end zones' view of the MAC: Lagrange weights at alpha).
class TagChecker {
public:
	TagChecker(const MacKey& mk, double tol) : mk_(mk), prf_(mk.prf_key), tol_(tol) {
		for (double a : mk.alpha) {
			std::vector<double> L(kPoints);
			for (int j = 0; j < kPoints; ++j) {  // L_j(alpha) = prod_{l != j} (alpha - x_l) / (x_j - x_l)
				double num = 1, den = 1;
				for (int l = 0; l < kPoints; ++l) {
					if (l == j) continue;
					num *= a - Point(l);
					den *= Point(j) - Point(l);
				}
				L[j] = num / den;
			}
			lagrange_.push_back(L);
		}
	}

	/// y: the decoded slots (block 0 first).
	TagCheck Check(uint32_t round, const std::vector<double>& y) {
		TagCheck c;
		const int k = mk_.k;
		const double y0 = y.at(0);
		const long cmd = std::lround(y0);
		c.cmd_dev = std::fabs(y0 - (double)cmd);
		bool ok = cmd >= -1 && cmd <= 1 && c.cmd_dev < 0.25;
		c.cmd = cmd == 1 ? window::Cmd::MotorUp : cmd == -1 ? window::Cmd::MotorDown : window::Cmd::Off;
		if (k > 0) {
			const auto rp = prf_.Secrets(round, Zone::Passenger, window::kPassengerFlags, k);
			const auto rd = prf_.Secrets(round, Zone::Driver, window::kDriverFlags, k);
			const auto ri = prf_.Secrets(round, Zone::Ign, window::kIgnFlags, k);
			for (int m = 0; m < k; ++m) {
				const double ym0 = y.at((size_t)kPoints * m);
				c.cmd_dev = std::max(c.cmd_dev, std::fabs(ym0 - (double)cmd));
				ok = ok && std::lround(ym0) == cmd;
				double tag = 0;
				for (int j = 0; j < kPoints; ++j) tag += y.at((size_t)kPoints * m + j) * lagrange_[m][j];
				using namespace window;
				const double expect = CmdArith(rp[kPu][m], rp[kPd][m], rp[kTopFlag][m], rp[kBotFlag][m], rp[kErr][m],
						rd[kOu][m], rd[kOd][m], rd[kCl][m], ri[kK][m], 1.0);
				const double dev = std::fabs(tag - expect);
				c.tag_dev = std::max(c.tag_dev, dev);
				ok = ok && dev <= tol_;
			}
		}
		c.ok = ok;
		return c;
	}

	double lebesgue() const {  // max_m sum_j |L_j(alpha_m)|: how the slot error grows in the tag
		double w = 0;
		for (const auto& L : lagrange_) {
			double s = 0;
			for (double l : L) s += std::fabs(l);
			w = std::max(w, s);
		}
		return w;
	}

private:
	const MacKey& mk_;
	MacPrf prf_;
	double tol_;
	std::vector<std::vector<double>> lagrange_;  // L_j(alpha_m)
};

// ---------------------------------------------------------------- wire helpers

inline int BitLen(uint64_t v) {
	int b = 0;
	while (v) {
		++b;
		v >>= 1;
	}
	return b;
}

inline void PutU32(Bytes& b, uint32_t v) {
	for (int i = 0; i < 4; ++i) b.push_back((uint8_t)(v >> (8 * i)));
}
inline uint32_t GetU32(const Bytes& b, size_t pos) {
	uint32_t v = 0;
	for (int i = 0; i < 4; ++i) v |= (uint32_t)b.at(pos + i) << (8 * i);
	return v;
}
inline void PutF64(Bytes& b, double d) {
	uint64_t v;
	std::memcpy(&v, &d, 8);
	for (int i = 0; i < 8; ++i) b.push_back((uint8_t)(v >> (8 * i)));
}
inline double GetF64(const Bytes& b, size_t pos) {
	uint64_t v = 0;
	for (int i = 0; i < 8; ++i) v |= (uint64_t)b.at(pos + i) << (8 * i);
	double d;
	std::memcpy(&d, &v, 8);
	return d;
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

/// One residue vector mod q at ceil(log2 q) bits per value.
inline void PackResidues(const uint64_t* v, size_t n, uint64_t q, BitWriter& w) {
	const int bits = BitLen(q - 1);
	for (size_t j = 0; j < n; ++j) w.Put(v[j], bits);
	w.Flush();
}
inline void UnpackResidues(BitReader& r, uint64_t* v, size_t n, uint64_t q) {
	const int bits = BitLen(q - 1);
	for (size_t j = 0; j < n; ++j) v[j] = r.Get(bits);
	r.Align();
}

/// A 1-limb downlink polynomial in coefficient form, each coefficient as round(x / 2^drop).
inline void PackRounded(const uint64_t* v, size_t n, uint64_t q, int drop, BitWriter& w) {
	const int bits = BitLen((q + (1ULL << drop) - 1) >> drop);  // largest rounded value
	const uint64_t half = drop ? (1ULL << (drop - 1)) : 0;
	for (size_t j = 0; j < n; ++j) w.Put((v[j] + half) >> drop, bits);
	w.Flush();
}
inline void UnpackRounded(BitReader& r, uint64_t* v, size_t n, uint64_t q, int drop) {
	const int bits = BitLen((q + (1ULL << drop) - 1) >> drop);
	for (size_t j = 0; j < n; ++j) v[j] = (r.Get(bits) << drop) % q;
	r.Align();
}

/// The uniform part of uplink ciphertext `index`, limb `limb`: n values mod q expanded from
/// the 32-byte seed with AES-256-CTR (IV = index, limb) and rejection-sampled. It is used
/// directly as the NTT (evaluation) form, uniform there too.
inline void ExpandUniform(const uint8_t* seed, uint32_t index, uint32_t limb, uint64_t q, uint64_t* out, size_t n) {
	EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
	const int bits = BitLen(q - 1);
	const uint64_t mask = bits >= 64 ? ~0ULL : ((1ULL << bits) - 1);
	uint8_t iv[16] = {0};
	std::memcpy(iv, &index, 4);
	std::memcpy(iv + 4, &limb, 4);
	EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, seed, iv);
	std::vector<uint64_t> zero(1024, 0), ks(1024);
	size_t j = 0;
	while (j < n) {
		int len = 0;
		EVP_EncryptUpdate(ctx, (uint8_t*)ks.data(), &len, (const uint8_t*)zero.data(), (int)(ks.size() * 8));
		for (size_t k = 0; k < ks.size() && j < n; ++k) {
			const uint64_t x = ks[k] & mask;
			if (x < q) out[j++] = x;
		}
	}
	EVP_CIPHER_CTX_free(ctx);
}

}  // namespace ckks
}  // namespace ipcei
