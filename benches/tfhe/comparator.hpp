// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// comparator.hpp — the boolean gates and the bit-serial comparator of the TFHE benches
// (openfhe_protocol.cpp, openfhe_lut_compare.cpp), on OpenFHE binfhe.
//
// Gates (Gates below), 2 or 3 inputs:
//   arity 2  EvalBinGate(AND / OR, x, y) at plaintext modulus p = 4 (STD128), one bootstrap
//            per 2-input gate
//   arity 3  OpenFHE's multi-input gates AND3 / OR3 at p = 6 (STD128_3): the inputs are
//            added and bootstrapped once, so up to three inputs cost one bootstrap. Every
//            ciphertext of the circuit is then at p = 6: a gate with fewer inputs is padded
//            with trivial constants (a = 0, b = m floor(q/p): no key, no noise), and NOT is
//            computed for p (EvalNOT hardcodes p = 4): NOT x = (-a, floor(q/p) - b).
// STD128_3 has a slightly larger LWE dimension (595 vs 556; same q = 2048 and ring), so a
// bootstrap costs a little more, but the circuits need far fewer of them.
#pragma once

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

#include "binfhe/binfhecontext.h"

namespace ipcei {

/// The plaintext modulus of a circuit built from gates with `arity` inputs.
inline int GatePlaintextModulus(int arity) { return arity == 2 ? 4 : 2 * arity; }
/// The OpenFHE parameter set of those gates.
inline lbcrypto::BINFHE_PARAMSET GateParamSet(int arity) { return arity == 2 ? lbcrypto::STD128 : lbcrypto::STD128_3; }

/// AND / OR of any number of inputs, NOT and constants, counting bootstraps, at the
/// plaintext modulus of 2-input or 3-input gates.
class Gates {
public:
	Gates(lbcrypto::BinFHEContext& cc, int arity, uint32_t n, lbcrypto::NativeInteger q, long& count)
		: cc_(cc), arity_(arity), p_(GatePlaintextModulus(arity)), n_(n), q_(q), count_(count) {}

	int arity() const { return arity_; }
	int p() const { return p_; }

	lbcrypto::LWECiphertext Not(const lbcrypto::LWECiphertext& x) const {
		if (p_ == 4) return cc_.EvalNOT(x);
		lbcrypto::NativeVector a(x->GetA());
		const lbcrypto::NativeInteger q = x->GetModulus();
		for (uint32_t i = 0; i < a.GetLength(); ++i)
			if (a[i] != 0) a[i] = q - a[i];
		const lbcrypto::NativeInteger unit(q.ConvertToInt() / (uint64_t)p_);
		return std::make_shared<lbcrypto::LWECiphertextImpl>(std::move(a), unit.ModSub(x->GetB(), q),
				lbcrypto::NativeInteger(p_));
	}
	/// A trivial encryption of v (no key, no noise).
	lbcrypto::LWECiphertext Const(bool v) const {
		lbcrypto::NativeVector a(n_, q_);
		const lbcrypto::NativeInteger b(v ? q_.ConvertToInt() / (uint64_t)p_ : 0);
		return std::make_shared<lbcrypto::LWECiphertextImpl>(std::move(a), b, lbcrypto::NativeInteger(p_));
	}
	/// AND of all inputs: ceil((k - 1) / (arity - 1)) bootstraps for k inputs.
	lbcrypto::LWECiphertext And(std::vector<lbcrypto::LWECiphertext> in) const { return Reduce(true, std::move(in)); }
	lbcrypto::LWECiphertext Or(std::vector<lbcrypto::LWECiphertext> in) const { return Reduce(false, std::move(in)); }

private:
	lbcrypto::LWECiphertext Gate(bool is_and, std::vector<lbcrypto::LWECiphertext> in) const {
		using namespace lbcrypto;
		count_++;
		if (arity_ == 2) return cc_.EvalBinGate(is_and ? AND : OR, in[0], in[1]);
		while ((int)in.size() < arity_) in.push_back(Const(is_and));  // fresh constants: distinct inputs
		return cc_.EvalBinGate(is_and ? AND3 : OR3, in);
	}
	lbcrypto::LWECiphertext Reduce(bool is_and, std::vector<lbcrypto::LWECiphertext> in) const {
		while (in.size() > 1) {  // fold from the left, arity inputs per bootstrap
			const size_t take = std::min(in.size(), (size_t)arity_);
			std::vector<lbcrypto::LWECiphertext> head(in.begin(), in.begin() + take);
			std::vector<lbcrypto::LWECiphertext> rest{Gate(is_and, std::move(head))};
			rest.insert(rest.end(), in.begin() + take, in.end());
			in.swap(rest);
		}
		return in[0];
	}

	lbcrypto::BinFHEContext& cc_;
	const int arity_, p_;
	const uint32_t n_;
	const lbcrypto::NativeInteger q_;
	long& count_;
};

// ---- bit-serial comparator: encrypted a < PUBLIC constant c ----
// a is an LSB-first vector of encrypted bits, c a public w-bit threshold (a limit the
// central node knows). Recurrence, LSB to MSB (higher bits override):
//   c_i = 1:  lt = OR(NOT a_i, lt)                 c_i = 0:  lt = AND(NOT a_i, lt)
// For c_i = 1, a < c on bits i.. holds when a_i = 0, or when a_i = 1 and a < c below it:
// NOT a_i OR (a_i AND lt), which absorbs to NOT a_i OR lt. Consecutive bits with the same
// threshold bit share one gate: OR(NOT a_i, NOT a_i+1, lt) with 3-input gates, so a run of
// r equal bits costs ceil(r / (arity - 1)) bootstraps (one per bit with 2-input gates).
// Below the lowest set bit of c, lt is identically false, so it is seeded there as
// NOT a_low (free) and the lower bits are skipped.
inline lbcrypto::LWECiphertext LessThanPublic(const Gates& g, const std::vector<lbcrypto::LWECiphertext>& a, uint32_t c) {
	const size_t w = a.size();
	int low = -1;
	for (size_t i = 0; i < w; ++i) {
		if ((c >> i) & 1u) {
			low = (int)i;
			break;
		}
	}
	if (low < 0) return g.Const(false);  // c == 0: a < c is false
	lbcrypto::LWECiphertext lt = g.Not(a[low]);
	for (size_t i = (size_t)low + 1; i < w;) {
		const bool set = (c >> i) & 1u;
		std::vector<lbcrypto::LWECiphertext> in{lt};
		while (i < w && (int)in.size() < g.arity() && (bool)((c >> i) & 1u) == set) in.push_back(g.Not(a[i++]));
		lt = set ? g.Or(std::move(in)) : g.And(std::move(in));
	}
	return lt;
}

}  // namespace ipcei
