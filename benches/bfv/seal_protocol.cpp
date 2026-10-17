// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// seal_protocol.cpp — one round of the window-lift use case (scenario.hpp), BFV in
// Microsoft SEAL 4.1.
//
// Threat model: the end zones (passenger, driver, ign) are trusted with their own data and
// share key material provisioned into their HSEs; only the central compute (the Process
// APP) must be blind.
//
// provisioning  (not timed) one SEAL context; one BFV secret key shared by the three end
//               zones; the secret MAC point(s) alpha (--kmac 2 adds a second one) and a
//               shared PRF key from which every zone derives its per-round MAC secrets
//               r = PRF(key, round, point, zone, index); the Galois and relin keys at the
//               central node; one Ed25519 key per node; one ADSC-SNARK setup per zone.
// end zones     each zone authenticates its sensor data and proves, in its ADSC-SNARK,
//               the flag bits it derives from it (FlagBits order: passenger pu pd top bot
//               err, driver ou od cl, ign k). For each bit f_i it encrypts m_i = f_i and
//               its MAC slope s_i = (r_i - f_i) / alpha (one per MAC point) as seeded LWE
//               ciphertexts (a, b) under the coefficient vector of the BFV secret key, at a
//               carrying modulus q' = the first --qprimes primes of Q (q' > 2 t^2). Every
//               'a' of the zone is expanded from the zone's own fresh 32 B seed, so its
//               uplink carries the seed and the bit-packed b residues only. No zone knows
//               anything of the others: 10 + 6 + 2 = 18 LWE values per round at kmac 1.
// central       verifies each zone's signature and proof, re-expands its 'a' vectors,
//               mod-switches each LWE ciphertext from q' up to Q (exact, q' | Q), embeds it
//               as an RLWE ciphertext and promotes it with EvalTrace (depth 0) and the N^-1
//               scaling. The MAC tags y_i(X) = m_i + s_i X are polynomials in X with
//               ciphertext coefficients; the central node evaluates the decision on them,
//                 Y = CmdArith(y_pu, .., y_k)   (scenario.hpp: depth 3, 8 tag products)
//               with the constant 1 as the plaintext polynomial [1]. Y has degree 6:
//               Y(0) = cmd in {+1, -1, 0} (Motor+, Motor-, Off) and Y(alpha) =
//               CmdArith(r_pu, .., r_k), which only the end zones can compute. The 7
//               coefficients are packed into one ciphertext (Y_j X^j), mod-switched down to
//               --rprimes primes, serialized and signed.
// passenger     verifies the downlink signature, decrypts, recomputes the r values from the
//               PRF key, checks Y(alpha) and reads the motor command Y(0).
//
// Steps (harness ids; every end zone runs the uplink steps, the central node's first three
// add up over the three uplinks):
//   encode             not recorded: the scaling by floor(q'/t) is fused into encrypt
//   encrypt            derive the MAC secrets and slopes, seeded-LWE encrypt bits*(1+kmac) values
//   compress           seed || bit-packed b residues -> uplink FHE payload
//   adsc_authenticate  zk::AdscProver::Authenticate(SensorValues): every sensor signs its data
//   adsc_prove         zk::AdscProver::Prove(): the zone's flag bits from the authenticated data
//   sign_uplink        Ed25519 over round || FHE payload
//   verify_uplink      Ed25519 + round number (replay), per zone
//   adsc_verify        the zone's zk::AdscVerifier (chained state commitment), per zone
//   decompress         unpack b, expand a, mod-switch up, embed, EvalTrace promote, N^-1, per zone
//   evaluate           CmdArith on the polynomial tags (each MAC point)
//   compress_downlink  pack the tag coefficients, mod-switch to --rprimes, serialize
//   sign_downlink      Ed25519 over round || downlink ciphertext
//   verify_downlink    Ed25519 + round number
//   decrypt            deserialize + BFV decrypt
//   check_result       Y(alpha) == CmdArith(r) (each MAC point), read the command Y(0)
//
// Parameters: N = 16384 with SEAL's BFVDefault chain (8 data primes + the special prime),
// t a 32-bit batching prime (MAC forgery <= 6/t ~ 2^-29.4 per point). The noise is set by
// the lift: after the mod-switch q' -> Q the invariant noise is ~ t^2 / q' (the slopes are
// full Z_t values), the trace adds log2 N bits and the N^-1 scaling ~ log2 t; each of the
// three product levels then costs ~ log2 t + log2 N. The old degree-5 tree at --qprimes 5
// left ~2 bits; the CmdArith circuit sums more products per coefficient and has a
// depth-2 x depth-2 last level, and at --qprimes 5 it leaves 0 bits (it still decrypts,
// with no margin). The default is --qprimes 6, one more prime of the carrying modulus
// (+6 B per LWE value): 48 bits measured. The downlink stays at --rprimes 2, whose
// mod-switch rounding caps the budget at ~55 bits (above the circuit's 48; --qprimes 7
// reaches that cap). --rprimes 1 halves the downlink but caps the budget at ~7 bits. The
// measured budget is recorded as downlink_noise_budget_bits (minimum over the rounds).
//
//   bfv_seal [--rounds R] [--warmup W] [--json FILE] [--quiet]
//            [--N 16384] [--pbits 32] [--qprimes 6] [--rprimes 2] [--kmac 1|2] [--limbbits 0]
// The defaults are the deployable configuration; --limbbits 0 is SEAL's BFVDefault chain.
// The 12 measured rounds of the default run are exactly the 12 cases of the scenario (the
// warm-up rounds draw from a separate generator).
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <random>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "ipcei/harness.hpp"
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

namespace {

constexpr int kTagDegree = 6;  // degree of CmdArith in the inputs: of Y(X)
constexpr size_t kSeedBytes = 32;
constexpr size_t kUplinkHeader = 4;  // round

using u128 = unsigned __int128;

uint64_t MulMod(uint64_t a, uint64_t b, uint64_t m) { return (uint64_t)((u128)a * b % m); }
uint64_t PowMod(uint64_t b, uint64_t e, uint64_t m) {
	uint64_t r = 1;
	b %= m;
	for (; e; e >>= 1) {
		if (e & 1) r = MulMod(r, b, m);
		b = MulMod(b, b, m);
	}
	return r;
}
uint64_t InvMod(uint64_t a, uint64_t p) { return PowMod(a, p - 2, p); }  // p prime

void PutU32(std::vector<uint8_t>& o, uint32_t v) {
	for (int i = 0; i < 4; ++i) o.push_back((uint8_t)(v >> (8 * i)));
}
uint32_t GetU32(const uint8_t* p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

/// SplitMix64 finalizer: the mixing of the benchmark PRF below.
uint64_t Mix(uint64_t x) {
	x += 0x9e3779b97f4a7c15ULL;
	x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
	x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
	return x ^ (x >> 31);
}

/// The flag bits a zone sends (FlagBits order).
size_t ZoneBits(Zone z) {
	return z == Zone::Passenger ? window::kPassengerFlags : z == Zone::Driver ? window::kDriverFlags : window::kIgnFlags;
}
size_t ZoneIndex(Zone z) { return z == Zone::Passenger ? 0 : z == Zone::Driver ? 1 : 2; }

struct Config {
	size_t N = 16384;
	int pbits = 32;
	int qprimes = 6;
	int rprimes = 2;
	int kmac = 1;
	int limb_bits = 0;
};

/// Public parameters shared by every node: the BFV context, the carrying modulus q'
/// and the seed expander of the seeded-LWE uplinks.
class Bfv {
public:
	explicit Bfv(const Config& c) : N(c.N), kmac(c.kmac), rprimes((size_t)c.rprimes), context(MakeParms(c)) {
		if (!context.parameters_set()) throw std::runtime_error("invalid BFV parameters");
		coeff = context.first_context_data()->parms().coeff_modulus();
		L = coeff.size();
		t = context.first_context_data()->parms().plain_modulus().value();
		Ninv = InvMod(N % t, t);
		if (rprimes < 1 || rprimes > L) throw std::runtime_error("--rprimes out of range");

		// q' = first Lp primes with q' > 2 t^2 (BFV decryption bound), at least --qprimes
		const double need = 1 + 2 * std::log2((double)t);
		double lg = 0;
		Lp = 0;
		while (lg <= need && Lp < L) lg += std::log2((double)coeff[Lp++].value());
		while ((int)Lp < c.qprimes && Lp < L - 1) lg += std::log2((double)coeff[Lp++].value());
		if (Lp >= L) throw std::runtime_error("plaintext too large for this Q");
		qp_bits = (size_t)lg + 1;
		double lq = 0;
		for (const auto& m : coeff) lq += std::log2((double)m.value());
		Q_bits = (size_t)lq + 1;

		// per low prime: M_hi = Q / q' and Delta' = floor(q' / t), reduced mod q_i. With
		// r = q' mod t, Delta' = (q' - r) / t = -r * t^-1 (mod q_i), since q_i | q'.
		uint64_t r = 1;
		for (size_t i = 0; i < Lp; ++i) r = MulMod(r, coeff[i].value() % t, t);
		for (size_t i = 0; i < Lp; ++i) {
			const uint64_t qi = coeff[i].value();
			uint64_t mh = 1;
			for (size_t j = Lp; j < L; ++j) mh = MulMod(mh, coeff[j].value() % qi, qi);
			mhi.push_back(mh);
			deltap.push_back(MulMod((qi - r % qi) % qi, InvMod(t % qi, qi), qi));
			qbits.push_back(coeff[i].bit_count());
		}
	}

	/// Folds the 32-byte wire seed into the expander key.
	static uint64_t SeedKey(const uint8_t* seed) {
		uint64_t k = 0;
		for (size_t w = 0; w < kSeedBytes / 8; ++w) {
			uint64_t v = 0;
			for (int i = 0; i < 8; ++i) v |= (uint64_t)seed[8 * w + i] << (8 * i);
			const int rot = (int)(17 * w) % 64;
			k ^= rot ? (v << rot | v >> (64 - rot)) : v;
		}
		return k;
	}
	/// The 'a' vector of value `ctr` at low prime i (mt19937_64, as the original bench).
	void ExpandA(uint64_t key, size_t ctr, size_t i, std::vector<uint64_t>& a) const {
		std::mt19937_64 g(key ^ (0x9e3779b97f4a7c15ULL * (uint64_t)ctr) ^ (0xD1B54A32D192ED03ULL * (uint64_t)i));
		const uint64_t qi = coeff[i].value();
		a.resize(N);
		for (size_t j = 0; j < N; ++j) a[j] = g() % qi;
	}
	/// LWE values of a zone: its bits m_i, then the slopes s_i of each MAC point.
	size_t Values(Zone z) const { return ZoneBits(z) * (size_t)(1 + kmac); }
	/// Downlink slot of coefficient j of the tag at MAC point p (Y_p(0) = Y_0(0) is sent once).
	size_t Slot(int p, int j) const { return j == 0 ? 0 : (size_t)p * kTagDegree + (size_t)j; }

	const size_t N;
	const int kmac;
	const size_t rprimes;
	SEALContext context;
	std::vector<Modulus> coeff;  // data-level chain
	size_t L = 0, Lp = 0, qp_bits = 0, Q_bits = 0;
	uint64_t t = 0, Ninv = 0;
	std::vector<uint64_t> mhi, deltap;
	std::vector<int> qbits;

private:
	static EncryptionParameters MakeParms(const Config& c) {
		EncryptionParameters parms(scheme_type::bfv);
		parms.set_poly_modulus_degree(c.N);
		if (c.limb_bits > 0) {
			const size_t nl = (size_t)CoeffModulus::MaxBitCount(c.N) / (size_t)c.limb_bits;
			parms.set_coeff_modulus(CoeffModulus::Create(c.N, std::vector<int>(nl, c.limb_bits)));
		} else {
			parms.set_coeff_modulus(CoeffModulus::BFVDefault(c.N));
		}
		parms.set_plain_modulus(PlainModulus::Batching(c.N, c.pbits));
		return parms;
	}
};

/// What the end zones' HSEs hold (shared by the three zones, provisioned once).
struct Provisioning {
	SecretKey sk;
	std::vector<int> s;                 // ternary coefficient vector of sk: the LWE key
	std::vector<uint64_t> alpha, alpha_inv;  // the MAC points
	uint64_t prf_key = 0;

	/// The MAC secret of variable (zone, i) at point p in this round, in [1, t).
	uint64_t MacSecret(uint64_t t, uint32_t round, int p, Zone z, size_t i) const {
		const uint64_t h = Mix(Mix(prf_key ^ Mix(round)) ^ ((uint64_t)p << 16 | (uint64_t)ZoneIndex(z) << 8 | i));
		return 1 + h % (t - 1);
	}
};

struct EvalKeys {
	RelinKeys relin;
	GaloisKeys galois;
};

/// One-time setup: the shared secret key and MAC key of the end zones, and the
/// evaluation keys of the central node.
Provisioning Provision(const Bfv& bfv, KeyGenerator& keygen, EvalKeys& keys) {
	Provisioning pv;
	pv.sk = keygen.secret_key();
	// ternary secret s from data prime 0 (the LWE uplink key)
	const size_t N = bfv.N;
	std::vector<uint64_t> s0(pv.sk.data().data(), pv.sk.data().data() + N);
	util::inverse_ntt_negacyclic_harvey(s0.data(), bfv.context.key_context_data()->small_ntt_tables()[0]);
	const uint64_t q0 = bfv.coeff[0].value();
	pv.s.resize(N);
	for (size_t j = 0; j < N; ++j) pv.s[j] = s0[j] == 1 ? 1 : (s0[j] == q0 - 1 ? -1 : 0);
	std::mt19937_64 rng(7);
	for (int p = 0; p < bfv.kmac; ++p) {
		pv.alpha.push_back(rng() % (bfv.t - 1) + 1);
		pv.alpha_inv.push_back(InvMod(pv.alpha.back(), bfv.t));
	}
	pv.prf_key = rng();

	keygen.create_relin_keys(keys.relin);
	std::vector<uint32_t> elts;
	for (size_t n = bfv.N; n >= 2; n /= 2) elts.push_back((uint32_t)(n + 1));
	keygen.create_galois_keys(elts, keys.galois);
	return pv;
}

/// Z_t, for the MAC check: CmdArith over the r values.
struct Zt {
	uint64_t v, t;
};
Zt operator+(const Zt& a, const Zt& b) { return {(a.v + b.v) % a.t, a.t}; }
Zt operator-(const Zt& a, const Zt& b) { return {(a.v + a.t - b.v) % a.t, a.t}; }
Zt operator*(const Zt& a, const Zt& b) { return {MulMod(a.v, b.v, a.t), a.t}; }

struct UplinkMsg {
	std::vector<uint8_t> bytes;  // signed: round || FHE payload (seed || packed b)
	std::vector<uint8_t> sig;
	zk::AdscMessage adsc;
	size_t payload_bytes = 0;
};

struct DownlinkMsg {
	std::vector<uint8_t> bytes;  // signed: round || serialized ciphertext
	std::vector<uint8_t> sig;
};

struct RoundOutcome {
	bool sig_ok = false, mac_ok = false, valid = false;  // valid: Y(0) is +1, -1 or 0
	window::Cmd cmd = window::Cmd::Off;
};

// ------------------------------------------------------------------ end zones

/// An end zone: authenticates and proves its bits, encrypts them with their MAC slopes
/// as seeded LWE under the shared key, and signs its uplink.
class EndZoneNode : public ipcei::Participant {
public:
	EndZoneNode(ipcei::Recorder& rec, Zone zone, const Bfv& bfv, const Provisioning& pv, const zk::AdscSetup& adsc)
		: Participant(rec, zone), bfv_(bfv), pv_(pv), adsc_(adsc), rng_(100 + ZoneIndex(zone)) {}

	const std::vector<uint8_t>& SigPublicKey() const { return sig_.PublicKey(); }

	/// One round: this zone sees only its own sensor values.
	UplinkMsg Send(int round, const window::Inputs& in) {
		const uint64_t t = bfv_.t;
		const size_t nb = ZoneBits(zone_), nv = bfv_.Values(zone_);
		UplinkMsg up;
		timed("adsc_authenticate", [&] { adsc_.Authenticate(window::SensorValues(zone_, in)); });
		up.adsc = timed("adsc_prove", [&] { return adsc_.Prove(); });
		const std::vector<uint8_t>& bits = adsc_.bits();  // what the circuit derived: what the zone encrypts
		if (bits.size() != nb) throw std::runtime_error("ADSC bits do not match the zone's flags");

		uint8_t seed[kSeedBytes];
		std::vector<std::vector<uint64_t>> b(nv);
		timed("encrypt", [&] {
			std::vector<uint64_t> val(nv);
			for (size_t i = 0; i < nb; ++i) val[i] = bits[i];
			for (int p = 0; p < bfv_.kmac; ++p)
				for (size_t i = 0; i < nb; ++i) {
					const uint64_t r = pv_.MacSecret(t, (uint32_t)round, p, zone_, i);
					val[(size_t)(1 + p) * nb + i] = MulMod((r + t - val[i]) % t, pv_.alpha_inv[p], t);
				}
			for (size_t w = 0; w < kSeedBytes; w += 8) {
				const uint64_t v = rng_();
				for (int i = 0; i < 8; ++i) seed[w + i] = (uint8_t)(v >> (8 * i));
			}
			const uint64_t key = Bfv::SeedKey(seed);
			for (size_t v = 0; v < nv; ++v) LweEncrypt(val[v], key, v, b[v]);
		});

		std::vector<uint8_t> payload;
		timed("compress", [&] {
			payload.assign(seed, seed + kSeedBytes);
			u128 acc = 0;
			int nbits = 0;
			for (const auto& bv : b)
				for (size_t i = 0; i < bfv_.Lp; ++i) {
					acc |= (u128)bv[i] << nbits;
					nbits += bfv_.qbits[i];
					for (; nbits >= 8; nbits -= 8, acc >>= 8) payload.push_back((uint8_t)acc);
				}
			if (nbits) payload.push_back((uint8_t)acc);
		});

		timed("sign_uplink", [&] {
			up.bytes.reserve(kUplinkHeader + payload.size());
			PutU32(up.bytes, (uint32_t)round);
			up.bytes.insert(up.bytes.end(), payload.begin(), payload.end());
			up.sig = sig_.Sign(up.bytes);
		});
		up.payload_bytes = payload.size();
		return up;
	}

protected:
	// b = Delta' m + e - <a, s>  (mod q_i), one error e in [-8, 8] shared by all primes
	void LweEncrypt(uint64_t m, uint64_t key, size_t ctr, std::vector<uint64_t>& b) {
		b.assign(bfv_.Lp, 0);
		const long e = (long)(rng_() % 17) - 8;
		for (size_t i = 0; i < bfv_.Lp; ++i) {
			const uint64_t qi = bfv_.coeff[i].value();
			bfv_.ExpandA(key, ctr, i, a_);
			uint64_t dot = 0;
			for (size_t j = 0; j < bfv_.N; ++j) {
				if (pv_.s[j] == 0) continue;
				dot = pv_.s[j] == 1 ? (dot + a_[j]) % qi : (dot + (qi - a_[j])) % qi;
			}
			const uint64_t emod = e >= 0 ? (uint64_t)e % qi : qi - (uint64_t)(-e) % qi;
			const uint64_t dm = MulMod(bfv_.deltap[i], m % qi, qi);
			b[i] = (uint64_t)(((u128)dm + emod + qi - dot) % qi);
		}
	}

	const Bfv& bfv_;
	const Provisioning pv_;  // this zone's HSE copy of the shared key material
	zk::AdscProver adsc_;
	ipcei::Ed25519 sig_;
	std::mt19937_64 rng_;
	std::vector<uint64_t> a_;
};

/// The actuator: also receives, verifies and checks the downlink.
class PassengerNode : public EndZoneNode {
public:
	PassengerNode(ipcei::Recorder& rec, const Bfv& bfv, const Provisioning& pv, const zk::AdscSetup& adsc)
		: EndZoneNode(rec, Zone::Passenger, bfv, pv, adsc), dec_(bfv.context, pv_.sk) {}
	void SetPeer(const std::vector<uint8_t>& central_pub) { peer_ = central_pub; }

	RoundOutcome Receive(int round, const DownlinkMsg& dl) {
		RoundOutcome out;
		out.sig_ok = timed("verify_downlink", [&] {
			return dl.bytes.size() > 4 && GetU32(dl.bytes.data()) == (uint32_t)round &&
				ipcei::Ed25519::Verify(peer_, dl.bytes, dl.sig);
		});
		Ciphertext ct;
		Plaintext pt;
		timed("decrypt", [&] {
			ct.load(bfv_.context, reinterpret_cast<const seal_byte*>(dl.bytes.data() + 4), dl.bytes.size() - 4);
			dec_.decrypt(ct, pt);
		});
		const int budget = dec_.invariant_noise_budget(ct);
		noise_bits_ = noise_bits_ < 0 ? budget : std::min(noise_bits_, budget);
		timed("check_result", [&] {
			const uint64_t t = bfv_.t;
			auto coef = [&](size_t k) { return k < pt.coeff_count() ? pt[k] : 0; };
			auto r = [&](int p, Zone z, size_t i) { return Zt{pv_.MacSecret(t, (uint32_t)round, p, z, i), t}; };
			out.mac_ok = true;
			for (int p = 0; p < bfv_.kmac; ++p) {
				using namespace window;
				const Zt tag = CmdArith(r(p, Zone::Passenger, kPu), r(p, Zone::Passenger, kPd),
						r(p, Zone::Passenger, kTopFlag), r(p, Zone::Passenger, kBotFlag), r(p, Zone::Passenger, kErr),
						r(p, Zone::Driver, kOu), r(p, Zone::Driver, kOd), r(p, Zone::Driver, kCl), r(p, Zone::Ign, kK),
						Zt{1, t});
				uint64_t y = 0, ap = 1;  // Y_p(alpha_p) = sum_j Y_j alpha_p^j
				for (int j = 0; j <= kTagDegree; ++j) {
					y = (y + MulMod(coef(bfv_.Slot(p, j)), ap, t)) % t;
					ap = MulMod(ap, pv_.alpha[p], t);
				}
				out.mac_ok = out.mac_ok && y == tag.v;
			}
			const uint64_t y0 = coef(0);
			out.valid = y0 == 0 || y0 == 1 || y0 == t - 1;
			out.cmd = y0 == 1 ? window::Cmd::MotorUp : y0 == t - 1 ? window::Cmd::MotorDown : window::Cmd::Off;
		});
		return out;
	}

	int noise_bits() const { return noise_bits_; }

private:
	Decryptor dec_;
	std::vector<uint8_t> peer_;
	int noise_bits_ = -1;
};

class DriverNode : public EndZoneNode {
public:
	DriverNode(ipcei::Recorder& rec, const Bfv& bfv, const Provisioning& pv, const zk::AdscSetup& adsc)
		: EndZoneNode(rec, Zone::Driver, bfv, pv, adsc) {}
};

class IgnNode : public EndZoneNode {
public:
	IgnNode(ipcei::Recorder& rec, const Bfv& bfv, const Provisioning& pv, const zk::AdscSetup& adsc)
		: EndZoneNode(rec, Zone::Ign, bfv, pv, adsc) {}
};

// ------------------------------------------------------------------ central node

class TagArith;

/// A MAC tag: a polynomial in X with ciphertext coefficients (X^0 first), or the
/// plaintext polynomial [1].
struct Tag {
	TagArith* ar = nullptr;
	std::vector<Ciphertext> c;
	bool one = false;
};

/// Polynomial arithmetic on tags. The products of one output coefficient are summed
/// before a single relinearization.
class TagArith {
public:
	TagArith(Evaluator& ev, const RelinKeys& relin) : ev_(ev), relin_(relin), one_(1) { one_[0] = 1; }

	Tag One() { return Tag{this, {}, true}; }

	Tag Add(const Tag& a, const Tag& b, bool sub) {
		if (a.one && b.one) throw std::logic_error("tag: 1 +- 1");
		if (b.one) {  // a +- 1
			Tag r = a;
			if (sub) ev_.sub_plain_inplace(r.c[0], one_);
			else ev_.add_plain_inplace(r.c[0], one_);
			return r;
		}
		if (a.one) {  // 1 +- b
			Tag r = b;
			if (sub)
				for (auto& x : r.c) ev_.negate_inplace(x);
			ev_.add_plain_inplace(r.c[0], one_);
			return r;
		}
		Tag r{this, std::vector<Ciphertext>(std::max(a.c.size(), b.c.size())), false};
		for (size_t j = 0; j < r.c.size(); ++j) {
			if (j < a.c.size() && j < b.c.size()) {
				if (sub) ev_.sub(a.c[j], b.c[j], r.c[j]);
				else ev_.add(a.c[j], b.c[j], r.c[j]);
			} else if (j < a.c.size()) {
				r.c[j] = a.c[j];
			} else {
				r.c[j] = b.c[j];
				if (sub) ev_.negate_inplace(r.c[j]);
			}
		}
		return r;
	}

	Tag Mul(const Tag& a, const Tag& b) {
		if (a.one) return b;
		if (b.one) return a;
		Tag r{this, std::vector<Ciphertext>(a.c.size() + b.c.size() - 1), false};
		std::vector<bool> init(r.c.size(), false);
		for (size_t i = 0; i < a.c.size(); ++i)
			for (size_t j = 0; j < b.c.size(); ++j) {
				Ciphertext t;
				ev_.multiply(a.c[i], b.c[j], t);
				++mults_;
				if (!init[i + j]) {
					r.c[i + j] = std::move(t);
					init[i + j] = true;
				} else {
					ev_.add_inplace(r.c[i + j], t);
				}
			}
		for (auto& x : r.c) {
			ev_.relinearize_inplace(x, relin_);
			++relins_;
		}
		return r;
	}

	long mults() const { return mults_; }
	long relins() const { return relins_; }

private:
	Evaluator& ev_;
	const RelinKeys& relin_;
	Plaintext one_;
	long mults_ = 0, relins_ = 0;
};

Tag operator+(const Tag& a, const Tag& b) { return a.ar->Add(a, b, false); }
Tag operator-(const Tag& a, const Tag& b) { return a.ar->Add(a, b, true); }
Tag operator*(const Tag& a, const Tag& b) { return a.ar->Mul(a, b); }

/// The Process APP: blind evaluation of the motor command on the three uplinks.
class CentralNode : public ipcei::Participant {
public:
	CentralNode(ipcei::Recorder& rec, const Bfv& bfv, EvalKeys keys, const zk::AdscSetup& adsc_p,
			const zk::AdscSetup& adsc_d, const zk::AdscSetup& adsc_i)
		: Participant(rec, Zone::Central), bfv_(bfv), keys_(std::move(keys)), ev_(bfv.context),
		  ar_(ev_, keys_.relin) {
		adsc_[0].reset(new zk::AdscVerifier(adsc_p));
		adsc_[1].reset(new zk::AdscVerifier(adsc_d));
		adsc_[2].reset(new zk::AdscVerifier(adsc_i));
		ninv_.resize(1);
		ninv_[0] = bfv_.Ninv;
		const size_t slots = bfv_.Slot(bfv_.kmac - 1, kTagDegree) + 1;
		mono_.resize(slots);
		for (size_t k = 1; k < slots; ++k) {
			mono_[k].resize(k + 1);
			mono_[k][k] = 1;
		}
	}
	const std::vector<uint8_t>& SigPublicKey() const { return sig_.PublicKey(); }
	void SetPeer(Zone z, const std::vector<uint8_t>& pub) { peer_[ZoneIndex(z)] = pub; }
	/// Every uplink of the last round passed its signature and proof check.
	bool accepted() const { return accepted_[0] && accepted_[1] && accepted_[2]; }
	const TagArith& arith() const { return ar_; }

	/// One zone's uplink: verify, then lift its LWE values into promoted ciphertexts.
	void Receive(Zone z, const UplinkMsg& up) {
		const size_t zi = ZoneIndex(z), nb = ZoneBits(z), nv = bfv_.Values(z);
		const size_t want = kUplinkHeader + kSeedBytes + (nv * bfv_.qp_bits + 7) / 8;
		const bool sig_ok = timed("verify_uplink", [&] {
			return up.bytes.size() >= want && GetU32(up.bytes.data()) == round_ &&
				ipcei::Ed25519::Verify(peer_[zi], up.bytes, up.sig);
		});
		const bool adsc_ok = timed("adsc_verify", [&] { return adsc_[zi]->Verify(up.adsc); });
		accepted_[zi] = sig_ok && adsc_ok;

		std::vector<Ciphertext> y(nv);
		timed("decompress", [&] {
			const size_t N = bfv_.N;
			const uint8_t* p = up.bytes.data() + kUplinkHeader;
			const uint64_t key = Bfv::SeedKey(p);
			p += kSeedBytes;
			u128 acc = 0;
			int nbits = 0;
			std::vector<uint64_t> b(bfv_.Lp);
			Ciphertext ct;
			for (size_t v = 0; v < nv; ++v) {
				for (size_t i = 0; i < bfv_.Lp; ++i) {
					for (; nbits < bfv_.qbits[i]; nbits += 8) acc |= (u128)*p++ << nbits;
					b[i] = (uint64_t)(acc & (((u128)1 << bfv_.qbits[i]) - 1));
					acc >>= bfv_.qbits[i];
					nbits -= bfv_.qbits[i];
				}
				Embed(b, key, v, N, ct);
				ev_.multiply_plain(EvalTrace(ct), ninv_, y[v]);
			}
		});
		// y_i(X) = m_i + s_i X, per MAC point
		tags_[zi].assign(bfv_.kmac, {});
		for (int pt = 0; pt < bfv_.kmac; ++pt)
			for (size_t i = 0; i < nb; ++i) tags_[zi][pt].push_back(Tag{&ar_, {y[i], y[(size_t)(1 + pt) * nb + i]}, false});
	}

	/// After the three uplinks: evaluate, compress and sign the downlink.
	DownlinkMsg Respond() {
		std::vector<Tag> Y(bfv_.kmac);
		timed("evaluate", [&] {
			for (int p = 0; p < bfv_.kmac; ++p) {
				using namespace window;
				const std::vector<Tag>&ps = tags_[0][p], &dr = tags_[1][p], &ig = tags_[2][p];
				Y[p] = CmdArith(ps[kPu], ps[kPd], ps[kTopFlag], ps[kBotFlag], ps[kErr], dr[kOu], dr[kOd], dr[kCl],
						ig[kK], ar_.One());
				if (Y[p].c.size() != kTagDegree + 1) throw std::logic_error("unexpected tag degree");
			}
		});

		DownlinkMsg dl;
		timed("compress_downlink", [&] {
			Ciphertext packed = Y[0].c[0];
			for (int p = 0; p < bfv_.kmac; ++p)
				for (int j = 1; j <= kTagDegree; ++j) {
					Ciphertext sh;
					ev_.multiply_plain(Y[p].c[j], mono_[bfv_.Slot(p, j)], sh);
					ev_.add_inplace(packed, sh);
				}
			while (bfv_.context.get_context_data(packed.parms_id())->parms().coeff_modulus().size() > bfv_.rprimes)
				ev_.mod_switch_to_next_inplace(packed);
			const size_t cap = (size_t)packed.save_size(compr_mode_type::none);
			PutU32(dl.bytes, round_);
			dl.bytes.resize(4 + cap);
			const size_t n =
				(size_t)packed.save(reinterpret_cast<seal_byte*>(dl.bytes.data() + 4), cap, compr_mode_type::none);
			dl.bytes.resize(4 + n);
		});
		timed("sign_downlink", [&] { dl.sig = sig_.Sign(dl.bytes); });
		++round_;
		return dl;
	}

private:
	// exact mod-switch q' -> Q (multiply by M_hi = Q/q'; zero on the high primes) and
	// embed (a, b) as the RLWE ciphertext (b, a') with c0 + c1 s = b + <a, s> in coeff 0
	void Embed(const std::vector<uint64_t>& b, uint64_t key, size_t ctr, size_t N, Ciphertext& ct) {
		ct.resize(bfv_.context, bfv_.context.first_parms_id(), 2);
		ct.is_ntt_form() = false;
		std::fill(ct.data(), ct.data() + 2 * bfv_.L * N, 0);
		uint64_t *c0 = ct.data(0), *c1 = ct.data(1);
		for (size_t i = 0; i < bfv_.Lp; ++i) {
			const uint64_t qi = bfv_.coeff[i].value(), mh = bfv_.mhi[i];
			bfv_.ExpandA(key, ctr, i, a_);
			uint64_t *C0 = c0 + i * N, *C1 = c1 + i * N;
			C0[0] = MulMod(b[i], mh, qi);
			C1[0] = MulMod(a_[0], mh, qi);
			for (size_t j = 1; j < N; ++j) C1[j] = (qi - MulMod(a_[N - j], mh, qi)) % qi;
		}
	}
	// EvalTrace: log2(N) automorphisms + adds kill the non-constant coefficients -> N*m in coeff 0
	Ciphertext EvalTrace(const Ciphertext& in) {
		Ciphertext acc = in;
		for (size_t k = bfv_.N; k >= 2; k /= 2) {
			Ciphertext t;
			ev_.apply_galois(acc, (uint32_t)(k + 1), keys_.galois, t);
			ev_.add_inplace(acc, t);
		}
		return acc;
	}

	const Bfv& bfv_;
	EvalKeys keys_;
	Evaluator ev_;
	TagArith ar_;
	std::unique_ptr<zk::AdscVerifier> adsc_[3];
	ipcei::Ed25519 sig_;
	std::vector<uint8_t> peer_[3];
	std::vector<std::vector<Tag>> tags_[3];  // per zone, per MAC point: the zone's tags in FlagBits order
	Plaintext ninv_;
	std::vector<Plaintext> mono_;  // X^k, k = 1 .. last downlink slot
	std::vector<uint64_t> a_;
	uint32_t round_ = 0;
	bool accepted_[3] = {false, false, false};
};

Config ParseConfig(const std::vector<std::string>& args) {
	Config c;
	for (size_t i = 0; i < args.size(); ++i) {
		const std::string& a = args[i];
		if (i + 1 >= args.size()) {
			std::fprintf(stderr, "unknown or incomplete option %s\n", a.c_str());
			std::exit(2);
		}
		const char* v = args[++i].c_str();
		if (a == "--N") c.N = (size_t)std::atol(v);
		else if (a == "--pbits") c.pbits = std::atoi(v);
		else if (a == "--qprimes") c.qprimes = std::atoi(v);
		else if (a == "--rprimes") c.rprimes = std::atoi(v);
		else if (a == "--kmac") c.kmac = std::atoi(v);
		else if (a == "--limbbits") c.limb_bits = std::atoi(v);
		else {
			std::fprintf(stderr, "unknown option %s\n", a.c_str());
			std::exit(2);
		}
	}
	if (c.kmac < 1 || c.kmac > 2) {
		std::fprintf(stderr, "--kmac must be 1 or 2\n");
		std::exit(2);
	}
	return c;
}

}  // namespace

int main(int argc, char** argv) {
	const ipcei::Options opts = ipcei::Options::Parse(argc, argv, window::Rounds::kCases);
	const Config cfg = ParseConfig(opts.rest);
	ipcei::Recorder rec(opts.warmup);

	// provisioning (not reported): parameters, the end zones' shared keys, evaluation keys,
	// signature keys, the ADSC proving / verification keys of every zone
	Bfv bfv(cfg);
	KeyGenerator keygen(bfv.context);
	EvalKeys eval_keys;
	const Provisioning pv = Provision(bfv, keygen, eval_keys);
	const zk::AdscSetup adsc_p(Zone::Passenger, zk::Encoding::Flags), adsc_d(Zone::Driver, zk::Encoding::Flags),
		adsc_i(Zone::Ign, zk::Encoding::Flags);
	PassengerNode passenger(rec, bfv, pv, adsc_p);
	DriverNode driver(rec, bfv, pv, adsc_d);
	IgnNode ign(rec, bfv, pv, adsc_i);
	CentralNode central(rec, bfv, std::move(eval_keys), adsc_p, adsc_d, adsc_i);
	passenger.SetPeer(central.SigPublicKey());
	central.SetPeer(Zone::Passenger, passenger.SigPublicKey());
	central.SetPeer(Zone::Driver, driver.SigPublicKey());
	central.SetPeer(Zone::Ign, ign.SigPublicKey());

	// the measured rounds start with the scenario's cases; the warm-up has its own generator
	window::Rounds warmup_rounds(7), rounds;
	UplinkMsg up_p, up_d, up_i;
	DownlinkMsg dl;
	const int total = opts.warmup + opts.rounds;
	for (int r = 0; r < total; ++r) {
		const window::Inputs in = r < opts.warmup ? warmup_rounds.Next() : rounds.Next();
		const window::Cmd expect = window::Decide(in);

		rec.BeginRound();
		up_p = passenger.Send(r, in);
		up_d = driver.Send(r, in);
		up_i = ign.Send(r, in);
		central.Receive(Zone::Passenger, up_p);
		central.Receive(Zone::Driver, up_d);
		central.Receive(Zone::Ign, up_i);
		dl = central.Respond();
		const RoundOutcome got = passenger.Receive(r, dl);
		const bool ok = central.accepted() && got.sig_ok && got.mac_ok && got.valid && got.cmd == expect;
		rec.RoundResult(ok);
		if (!opts.quiet)
			std::printf("round %d%s %-30s command %-6s (expected %-6s), uplinks %s, downlink sig %s, MAC %s -> %s\n", r,
					r < opts.warmup ? " (warm-up)" : "", in.label.c_str(),
					got.valid ? window::CmdName(got.cmd) : "INVALID", window::CmdName(expect),
					central.accepted() ? "accepted" : "REJECTED", got.sig_ok ? "ok" : "BAD", got.mac_ok ? "ok" : "BAD",
					ok ? "correct" : "WRONG");
	}

	const long rounds_run = std::max(total, 1);
	rec.Param("N", (double)bfv.N);
	rec.Param("plaintext_bits", (double)cfg.pbits);
	rec.Param("t", (double)bfv.t);
	rec.Param("Q", std::to_string(bfv.L) + " primes, " + std::to_string(bfv.Q_bits) + " bits");
	rec.Param("q_primes", std::to_string(bfv.Lp) + " (q' " + std::to_string(bfv.qp_bits) + " bits)");
	rec.Param("downlink_primes", (double)bfv.rprimes);
	rec.Param("limb_bits", cfg.limb_bits > 0 ? std::to_string(cfg.limb_bits) : std::string("BFVDefault"));
	rec.Param("kmac", (double)bfv.kmac);
	rec.Param("uplink_values_passenger", (double)bfv.Values(Zone::Passenger));
	rec.Param("uplink_values_driver", (double)bfv.Values(Zone::Driver));
	rec.Param("uplink_values_ign", (double)bfv.Values(Zone::Ign));
	rec.Param("circuit", "CmdArith on degree-1 tags: depth 3, 8 tag products, degree " + std::to_string(kTagDegree) +
			", " + std::to_string(central.arith().mults() / rounds_run) + " ciphertext products + " +
			std::to_string(central.arith().relins() / rounds_run) + " relinearizations per round");
	rec.Param("signature", "Ed25519");
	rec.Param("backend", IPCEI_BACKEND);
	rec.Param("adsc_constraints_passenger", (double)adsc_p.constraints());
	rec.Param("adsc_constraints_driver", (double)adsc_d.constraints());
	rec.Param("adsc_constraints_ign", (double)adsc_i.constraints());
	rec.Param("downlink_noise_budget_bits", (double)passenger.noise_bits());
	rec.Size("uplink passenger (FHE payload)", (double)up_p.payload_bytes);
	rec.Size("uplink driver (FHE payload)", (double)up_d.payload_bytes);
	rec.Size("uplink ign (FHE payload)", (double)up_i.payload_bytes);
	rec.Size("downlink (FHE payload)", (double)(dl.bytes.size() - 4));
	rec.Size("ADSC proof passenger", (double)up_p.adsc.proof_bytes);
	rec.Size("ADSC proof driver", (double)up_d.adsc.proof_bytes);
	rec.Size("ADSC proof ign", (double)up_i.adsc.proof_bytes);
	rec.Size("signature (each link)", (double)ipcei::Ed25519::kSignatureBytes);
	rec.Note("the end zones share the BFV secret key and the MAC key (alpha, PRF key): trusted, provisioned into "
			"their HSEs; only the central node is blind");
	rec.Note("encode is fused into encrypt: each value is scaled by floor(q'/t) inside the seeded-LWE encryption");
	rec.Note("the ADSC proofs show each zone's bits are derived from its authenticated sensor data, but do not bind "
			"them to the uplink ciphertexts");
	rec.Note("seeded 'a' vectors are expanded with mt19937_64 and the MAC secrets r = PRF(key, round, point, zone, "
			"index) use a SplitMix64 mix (benchmark PRNG / PRF, not a XOF / cryptographic PRF)");

	ipcei::Report report(rec, "bfv_seal", "SEAL " SEAL_VERSION, "BFV");
	report.Print();
	if (!opts.json.empty()) report.WriteJson(opts.json);
	return 0;
}
