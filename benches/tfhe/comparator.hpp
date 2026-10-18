// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// comparator.hpp — the bit-serial comparator of the TFHE benches (openfhe_protocol.cpp,
// openfhe_lut_compare.cpp), on OpenFHE binfhe gates.
#pragma once

#include <cstdint>
#include <vector>

#include "binfhe/binfhecontext.h"

namespace ipcei {

// ---- bit-serial comparator: encrypted a < PUBLIC constant c ----
// a is an LSB-first vector of encrypted bits, c a public w-bit threshold (a limit the
// central node knows). Recurrence, LSB to MSB (higher bits override):
//   c_i = 1:  lt = OR(NOT a_i, AND(a_i, lt))       c_i = 0:  lt = AND(NOT a_i, lt)
// Below the lowest set bit of c, lt is identically false, so it is seeded there as
// NOT a_low (free) and the lower bits are skipped. EvalNOT is free; AND / OR bootstrap.
inline lbcrypto::LWECiphertext LessThanPublic(lbcrypto::BinFHEContext& cc, const std::vector<lbcrypto::LWECiphertext>& a, uint32_t c, long& gates) {
	const size_t w = a.size();
	int low = -1;
	for (size_t i = 0; i < w; ++i) {
		if ((c >> i) & 1u) {
			low = (int)i;
			break;
		}
	}
	using namespace lbcrypto;
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

}  // namespace ipcei
