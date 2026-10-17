// seal_protocol.cpp — one IPCEI secure-actuation round, BFV in Microsoft SEAL 4.1.
//
// end node   S = 5 sensor readings are booleanized at the source, flag_i = reading_i <
//            threshold_i. Each flag m_i and its MAC slope s_i = (r_i - m_i) / alpha (fresh
//            round keys r_i, secret point alpha; --kmac 2 adds a second point) is encrypted
//            as a seeded LWE ciphertext (a, b) under the coefficient vector of the BFV secret
//            key, at a carrying modulus q' = the first --qprimes primes of Q (q' > 2 t^2).
//            Every 'a' is expanded from one 32 B seed, so the uplink carries the seed and the
//            b residues only. The node proves its PID control law and the flag comparisons in
//            one ADSC-SNARK over the sensors' authenticated data (readings and flags stay
//            private), and signs the uplink.
// central    verifies the signature and the proof (against its own thresholds), re-expands the 'a' vectors, mod-switches
//            each LWE ciphertext from q' up to Q (exact, q' | Q) and embeds it as an RLWE
//            ciphertext, promotes it with EvalTrace (depth 0) and evaluates the degree-5 tag
//            Y(X) = prod_i (m_i + s_i X): Y(0) = AND of the flags (the decision), Y(alpha) =
//            prod_i r_i (the MAC tag). The tag coefficients are packed into one ciphertext
//            (Y_j * X^j), mod-switched down to --rprimes primes, serialized and signed.
// end node   verifies the downlink signature, decrypts, checks Y(alpha) and reads Y(0).
//
// Steps (harness ids):
//   encode             not recorded: the scaling by floor(q'/t) is fused into encrypt
//   encrypt            booleanize, draw MAC keys and slopes, seeded-LWE encrypt S*(1+kmac) values
//   compress           seed || bit-packed b residues -> uplink FHE payload
//   adsc_authenticate  zk::AdscProver::Authenticate(round, readings): every sensor signs its data
//   adsc_prove         zk::AdscProver::Prove(thresholds): PID control law + flag comparisons
//   sign_uplink        Ed25519 over round || PID outputs || FHE payload
//   verify_uplink      Ed25519 + round number (replay)
//   adsc_verify        zk::AdscVerifier for the central node's thresholds (chained state commitment)
//   decompress         unpack b, expand a from the seed, mod-switch up and embed into RLWE
//   evaluate           EvalTrace promote, N^-1 scaling, degree-5 tag(s)
//   compress_downlink  pack the tag coefficients, mod-switch to --rprimes, serialize
//   sign_downlink      Ed25519 over round || downlink ciphertext
//   verify_downlink    Ed25519 + round number
//   decrypt            deserialize + BFV decrypt
//   check_result       Y(alpha) == prod r_i (each MAC point), read the decision Y(0)
//
//   bfv_seal [--rounds R] [--warmup W] [--json FILE] [--quiet]
//            [--N 16384] [--pbits 32] [--qprimes 5] [--rprimes 2] [--kmac 1|2] [--limbbits 0]
// The defaults are the deployable configuration; --limbbits 0 is SEAL's BFVDefault chain.
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
#include "ipcei/sig.hpp"
#include "ipcei/zk.hpp"
#include "seal/seal.h"
#include "seal/util/ntt.h"

#ifndef IPCEI_BACKEND
#define IPCEI_BACKEND "stock"
#endif

using namespace seal;
namespace zk = ipcei::zk;

namespace {

constexpr int kSensors = 5;      // S: one flag per sensor, degree-5 decision
constexpr int kReadingBits = 32;  // the readings' range check in the ADSC circuit
constexpr size_t kSeedBytes = 32;
constexpr size_t kUplinkHeader = 4 + 3 * 8;  // round, PID outputs

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
void PutU64(std::vector<uint8_t>& o, uint64_t v) {
	for (int i = 0; i < 8; ++i) o.push_back((uint8_t)(v >> (8 * i)));
}
uint32_t GetU32(const uint8_t* p) { return p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24; }

struct Config {
	size_t N = 16384;
	int pbits = 32;
	int qprimes = 5;
	int rprimes = 2;
	int kmac = 1;
	int limb_bits = 0;
};

/// Public parameters shared by both nodes: the BFV context, the carrying modulus q'
/// and the seed expander of the seeded-LWE uplink.
class Bfv {
public:
	explicit Bfv(const Config& c)
		: N(c.N), kmac(c.kmac), rprimes((size_t)c.rprimes), nvals((size_t)kSensors * (1 + c.kmac)),
		  context(MakeParms(c)) {
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
	/// Downlink slot of coefficient j of the tag at MAC point p (Y_p(0) = Y_0(0) is sent once).
	size_t Slot(int p, int j) const { return j == 0 ? 0 : (size_t)p * kSensors + (size_t)j; }

	const size_t N;
	const int kmac;
	const size_t rprimes;
	const size_t nvals;  // S flags + S slopes per MAC point
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

struct EvalKeys {
	RelinKeys relin;
	GaloisKeys galois;
};

struct UplinkMsg {
	std::vector<uint8_t> bytes;  // signed: header || FHE payload (seed || packed b)
	std::vector<uint8_t> sig;
	zk::AdscMessage adsc;
	size_t payload_bytes = 0;
};

struct DownlinkMsg {
	std::vector<uint8_t> bytes;  // signed: round || serialized ciphertext
	std::vector<uint8_t> sig;
};

struct RoundOutcome {
	bool sig_ok = false, mac_ok = false;
	uint64_t decision = 0;
};

// ------------------------------------------------------------------ end node

class EndNode : public ipcei::Participant {
public:
	EndNode(ipcei::Recorder& rec, const Bfv& bfv, const zk::AdscSetup& adsc)
		: Participant(rec), bfv_(bfv), keygen_(bfv.context), sk_(keygen_.secret_key()), dec_(bfv.context, sk_),
		  adsc_(adsc), rng_(7) {
		// ternary secret s from data prime 0 (the LWE uplink key)
		const size_t N = bfv_.N;
		std::vector<uint64_t> s0(sk_.data().data(), sk_.data().data() + N);
		util::inverse_ntt_negacyclic_harvey(s0.data(), bfv.context.key_context_data()->small_ntt_tables()[0]);
		const uint64_t q0 = bfv_.coeff[0].value();
		s_.resize(N);
		for (size_t j = 0; j < N; ++j) s_[j] = s0[j] == 1 ? 1 : (s0[j] == q0 - 1 ? -1 : 0);
		for (int p = 0; p < bfv_.kmac; ++p) {
			alpha_.push_back(rng_() % (bfv_.t - 1) + 1);
			alpha_inv_.push_back(InvMod(alpha_.back(), bfv_.t));
		}
		r_.assign(bfv_.kmac, std::vector<uint64_t>(kSensors));
	}

	/// One-time setup: the evaluation keys the central node needs.
	EvalKeys MakeEvalKeys() {
		EvalKeys k;
		keygen_.create_relin_keys(k.relin);
		std::vector<uint32_t> elts;
		for (size_t n = bfv_.N; n >= 2; n /= 2) elts.push_back((uint32_t)(n + 1));
		keygen_.create_galois_keys(elts, k.galois);
		return k;
	}
	const std::vector<uint8_t>& SigPublicKey() const { return sig_.PublicKey(); }
	void SetPeer(const std::vector<uint8_t>& central_pub) { peer_ = central_pub; }

	UplinkMsg Send(int round, const std::vector<uint32_t>& readings, const std::vector<uint32_t>& thresholds) {
		const uint64_t t = bfv_.t;
		std::vector<uint8_t> flags(kSensors);
		uint8_t seed[kSeedBytes];
		std::vector<std::vector<uint64_t>> b(bfv_.nvals);
		timed("encrypt", [&] {
			std::vector<uint64_t> val(bfv_.nvals);
			for (int i = 0; i < kSensors; ++i) {
				flags[i] = readings[i] < thresholds[i];
				val[i] = flags[i];
			}
			for (int p = 0; p < bfv_.kmac; ++p)
				for (int i = 0; i < kSensors; ++i) {
					r_[p][i] = rng_() % (t - 1) + 1;
					val[(size_t)(1 + p) * kSensors + i] = MulMod((r_[p][i] + t - val[i]) % t, alpha_inv_[p], t);
				}
			for (size_t w = 0; w < kSeedBytes; w += 8) {
				const uint64_t v = rng_();
				for (int i = 0; i < 8; ++i) seed[w + i] = (uint8_t)(v >> (8 * i));
			}
			const uint64_t key = Bfv::SeedKey(seed);
			for (size_t v = 0; v < bfv_.nvals; ++v) LweEncrypt(val[v], key, v, b[v]);
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

		UplinkMsg up;
		timed("adsc_authenticate", [&] { adsc_.Authenticate(round, readings); });
		up.adsc = timed("adsc_prove", [&] { return adsc_.Prove(thresholds); });
		timed("sign_uplink", [&] {
			up.bytes.reserve(kUplinkHeader + payload.size());
			PutU32(up.bytes, (uint32_t)round);
			for (long o : up.adsc.output) PutU64(up.bytes, (uint64_t)o);
			up.bytes.insert(up.bytes.end(), payload.begin(), payload.end());
			up.sig = sig_.Sign(up.bytes);
		});
		up.payload_bytes = payload.size();
		round_ = (uint32_t)round;
		return up;
	}

	RoundOutcome Receive(const DownlinkMsg& dl) {
		RoundOutcome out;
		out.sig_ok = timed("verify_downlink", [&] {
			return dl.bytes.size() > 4 && GetU32(dl.bytes.data()) == round_ &&
				ipcei::Ed25519::Verify(peer_, dl.bytes, dl.sig);
		});
		Ciphertext ct;
		Plaintext pt;
		timed("decrypt", [&] {
			ct.load(bfv_.context, reinterpret_cast<const seal_byte*>(dl.bytes.data() + 4), dl.bytes.size() - 4);
			dec_.decrypt(ct, pt);
		});
		if (noise_bits_ < 0) noise_bits_ = dec_.invariant_noise_budget(ct);
		timed("check_result", [&] {
			const uint64_t t = bfv_.t;
			auto coef = [&](size_t k) { return k < pt.coeff_count() ? pt[k] : 0; };
			out.mac_ok = true;
			for (int p = 0; p < bfv_.kmac; ++p) {
				uint64_t tag = 1, y = 0, ap = 1;  // Y_p(alpha_p) = sum_j c_j alpha_p^j
				for (int i = 0; i < kSensors; ++i) tag = MulMod(tag, r_[p][i], t);
				for (int j = 0; j <= kSensors; ++j) {
					y = (y + MulMod(coef(bfv_.Slot(p, j)), ap, t)) % t;
					ap = MulMod(ap, alpha_[p], t);
				}
				out.mac_ok = out.mac_ok && y == tag;
			}
			out.decision = coef(0);
		});
		return out;
	}

	int noise_bits() const { return noise_bits_; }

private:
	// b = Delta' m + e - <a, s>  (mod q_i), one error e in [-8, 8] shared by all primes
	void LweEncrypt(uint64_t m, uint64_t key, size_t ctr, std::vector<uint64_t>& b) {
		b.assign(bfv_.Lp, 0);
		const long e = (long)(rng_() % 17) - 8;
		for (size_t i = 0; i < bfv_.Lp; ++i) {
			const uint64_t qi = bfv_.coeff[i].value();
			bfv_.ExpandA(key, ctr, i, a_);
			uint64_t dot = 0;
			for (size_t j = 0; j < bfv_.N; ++j) {
				if (s_[j] == 0) continue;
				dot = s_[j] == 1 ? (dot + a_[j]) % qi : (dot + (qi - a_[j])) % qi;
			}
			const uint64_t emod = e >= 0 ? (uint64_t)e % qi : qi - (uint64_t)(-e) % qi;
			const uint64_t dm = MulMod(bfv_.deltap[i], m % qi, qi);
			b[i] = (uint64_t)(((u128)dm + emod + qi - dot) % qi);
		}
	}

	const Bfv& bfv_;
	KeyGenerator keygen_;
	SecretKey sk_;
	Decryptor dec_;
	std::vector<int> s_;
	zk::AdscProver adsc_;
	ipcei::Ed25519 sig_;
	std::vector<uint8_t> peer_;
	std::mt19937_64 rng_;
	std::vector<uint64_t> alpha_, alpha_inv_;
	std::vector<std::vector<uint64_t>> r_;  // this round's MAC keys, per MAC point
	std::vector<uint64_t> a_;
	uint32_t round_ = 0;
	int noise_bits_ = -1;
};

// ------------------------------------------------------------------ central node

class CentralNode : public ipcei::Participant {
public:
	CentralNode(ipcei::Recorder& rec, const Bfv& bfv, EvalKeys keys, const zk::AdscSetup& adsc)
		: Participant(rec), bfv_(bfv), keys_(std::move(keys)), ev_(bfv.context), adsc_(adsc) {
		ninv_.resize(1);
		ninv_[0] = bfv_.Ninv;
		const size_t slots = bfv_.Slot(bfv_.kmac - 1, kSensors) + 1;
		mono_.resize(slots);
		for (size_t k = 1; k < slots; ++k) {
			mono_[k].resize(k + 1);
			mono_[k][k] = 1;
		}
	}
	const std::vector<uint8_t>& SigPublicKey() const { return sig_.PublicKey(); }
	void SetPeer(const std::vector<uint8_t>& end_pub) { peer_ = end_pub; }
	bool accepted() const { return accepted_; }

	DownlinkMsg Process(const UplinkMsg& up, const std::vector<uint32_t>& thresholds) {
		const size_t N = bfv_.N;
		const bool sig_ok = timed("verify_uplink", [&] {
			return up.bytes.size() > kUplinkHeader && GetU32(up.bytes.data()) == round_ &&
				ipcei::Ed25519::Verify(peer_, up.bytes, up.sig);
		});
		const bool adsc_ok = timed("adsc_verify", [&] { return adsc_.Verify(up.adsc, thresholds); });
		accepted_ = sig_ok && adsc_ok;

		std::vector<Ciphertext> ct(bfv_.nvals);
		timed("decompress", [&] {
			const uint8_t* p = up.bytes.data() + kUplinkHeader;
			const uint64_t key = Bfv::SeedKey(p);
			p += kSeedBytes;
			u128 acc = 0;
			int nbits = 0;
			std::vector<uint64_t> b(bfv_.Lp);
			for (size_t v = 0; v < bfv_.nvals; ++v) {
				for (size_t i = 0; i < bfv_.Lp; ++i) {
					for (; nbits < bfv_.qbits[i]; nbits += 8) acc |= (u128)*p++ << nbits;
					b[i] = (uint64_t)(acc & (((u128)1 << bfv_.qbits[i]) - 1));
					acc >>= bfv_.qbits[i];
					nbits -= bfv_.qbits[i];
				}
				Embed(b, key, v, N, ct[v]);
			}
		});

		std::vector<std::vector<Ciphertext>> Y(bfv_.kmac);
		timed("evaluate", [&] {
			std::vector<Ciphertext> y(bfv_.nvals);
			for (size_t v = 0; v < bfv_.nvals; ++v) {
				Ciphertext prom = EvalTrace(ct[v]);
				ev_.multiply_plain(prom, ninv_, y[v]);
			}
			for (int p = 0; p < bfv_.kmac; ++p) {
				// y_i(X) = m_i + s_i X;  Y = ((y0 y1)(y2 y3)) y4
				std::vector<std::vector<Ciphertext>> f(kSensors);
				for (int i = 0; i < kSensors; ++i) f[i] = {y[i], y[(size_t)(1 + p) * kSensors + i]};
				Y[p] = PolyMul(PolyMul(PolyMul(f[0], f[1]), PolyMul(f[2], f[3])), f[4]);
			}
		});

		DownlinkMsg dl;
		timed("compress_downlink", [&] {
			Ciphertext packed = Y[0][0];
			for (int p = 0; p < bfv_.kmac; ++p)
				for (int j = 1; j <= kSensors; ++j) {
					Ciphertext sh;
					ev_.multiply_plain(Y[p][j], mono_[bfv_.Slot(p, j)], sh);
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
	// product of two encrypted polynomials in X (coefficient vectors of ciphertexts)
	std::vector<Ciphertext> PolyMul(const std::vector<Ciphertext>& a, const std::vector<Ciphertext>& b) {
		std::vector<Ciphertext> out(a.size() + b.size() - 1);
		std::vector<bool> init(out.size(), false);
		for (size_t i = 0; i < a.size(); ++i)
			for (size_t j = 0; j < b.size(); ++j) {
				Ciphertext t;
				ev_.multiply(a[i], b[j], t);
				ev_.relinearize_inplace(t, keys_.relin);
				if (!init[i + j]) {
					out[i + j] = std::move(t);
					init[i + j] = true;
				} else {
					ev_.add_inplace(out[i + j], t);
				}
			}
		return out;
	}

	const Bfv& bfv_;
	EvalKeys keys_;
	Evaluator ev_;
	zk::AdscVerifier adsc_;
	ipcei::Ed25519 sig_;
	std::vector<uint8_t> peer_;
	Plaintext ninv_;
	std::vector<Plaintext> mono_;  // X^k, k = 1 .. last downlink slot
	std::vector<uint64_t> a_;
	uint32_t round_ = 0;
	bool accepted_ = false;
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
	const ipcei::Options opts = ipcei::Options::Parse(argc, argv, 8);
	const Config cfg = ParseConfig(opts.rest);
	ipcei::Recorder rec(opts.warmup);

	// one-time setup (not reported): parameters, keys, proving / verification keys
	Bfv bfv(cfg);
	const zk::AdscSetup adsc_setup(kSensors, kReadingBits);
	EndNode end(rec, bfv, adsc_setup);
	CentralNode central(rec, bfv, end.MakeEvalKeys(), adsc_setup);
	end.SetPeer(central.SigPublicKey());
	central.SetPeer(end.SigPublicKey());

	// sensors: thresholds in [2^31, 2^32); every third round one reading exceeds its threshold
	std::mt19937_64 sensors(2024);
	UplinkMsg up;
	DownlinkMsg dl;
	const int total = opts.warmup + opts.rounds;
	for (int r = 0; r < total; ++r) {
		std::vector<uint32_t> readings(kSensors), thresholds(kSensors);
		for (int i = 0; i < kSensors; ++i) {
			thresholds[i] = (uint32_t)(0x80000000ULL + sensors() % 0x80000000ULL);
			readings[i] = (uint32_t)(sensors() % thresholds[i]);
		}
		if (r % 3 == 2) {
			const int k = (int)(sensors() % kSensors);
			readings[k] = (uint32_t)(thresholds[k] + sensors() % (0x100000000ULL - thresholds[k]));
		}
		uint64_t oracle = 1;
		for (int i = 0; i < kSensors; ++i) oracle &= readings[i] < thresholds[i];

		rec.BeginRound();
		up = end.Send(r, readings, thresholds);
		dl = central.Process(up, thresholds);  // the central node's policy, not the uplink's
		const RoundOutcome got = end.Receive(dl);
		const bool ok = central.accepted() && got.sig_ok && got.mac_ok && got.decision == oracle;
		rec.RoundResult(ok);
		if (!opts.quiet)
			std::printf("round %d%s: decision %llu (oracle %llu), uplink %s, downlink sig %s, MAC %s -> %s\n", r,
					r < opts.warmup ? " (warm-up)" : "", (unsigned long long)got.decision,
					(unsigned long long)oracle, central.accepted() ? "accepted" : "REJECTED",
					got.sig_ok ? "ok" : "BAD", got.mac_ok ? "ok" : "BAD", ok ? "correct" : "WRONG");
	}

	rec.Param("N", (double)bfv.N);
	rec.Param("plaintext_bits", (double)cfg.pbits);
	rec.Param("t", (double)bfv.t);
	rec.Param("Q", std::to_string(bfv.L) + " primes, " + std::to_string(bfv.Q_bits) + " bits");
	rec.Param("q_primes", std::to_string(bfv.Lp) + " (q' " + std::to_string(bfv.qp_bits) + " bits)");
	rec.Param("downlink_primes", (double)bfv.rprimes);
	rec.Param("limb_bits", cfg.limb_bits > 0 ? std::to_string(cfg.limb_bits) : std::string("BFVDefault"));
	rec.Param("kmac", (double)bfv.kmac);
	rec.Param("sensors", (double)kSensors);
	rec.Param("uplink_values", (double)bfv.nvals);
	rec.Param("signature", "Ed25519");
	rec.Param("backend", IPCEI_BACKEND);
	rec.Param("adsc_circuit", "PID + " + std::to_string(kSensors) + " x " + std::to_string(kReadingBits) +
			"-bit comparisons");
	rec.Param("adsc_constraints", (double)adsc_setup.constraints());
	rec.Param("downlink_noise_budget_bits", (double)end.noise_bits());
	rec.Size("uplink (FHE payload)", (double)up.payload_bytes);
	rec.Size("uplink signed message", (double)up.bytes.size());
	rec.Size("downlink (FHE payload)", (double)(dl.bytes.size() - 4));
	rec.Size("ADSC proof + commitment", (double)up.adsc.proof_bytes);
	rec.Size("signature (each link)", (double)ipcei::Ed25519::kSignatureBytes);
	rec.Note("encode is fused into encrypt: each value is scaled by floor(q'/t) inside the seeded-LWE encryption");
	rec.Note("the uplink signature covers round, PID outputs and the FHE payload; the ADSC proof is bound by its "
			"chained state commitment");
	rec.Note("the ADSC proof shows the flags are honest comparisons of authenticated readings, but does not tie them "
			"to the uplink ciphertexts");
	rec.Note("seeded 'a' vectors are expanded with mt19937_64 (benchmark PRNG, not a XOF)");

	ipcei::Report report(rec, "bfv_seal", "SEAL " SEAL_VERSION, "BFV");
	report.Print();
	if (!opts.json.empty()) report.WriteJson(opts.json);
	return 0;
}
