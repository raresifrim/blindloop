// zk_selftest.cpp — checks that the ADSC proof (PID alone, and PID + flag comparisons) and
// both signature schemes verify (and that tampering is rejected), and times each operation.
//   zk_selftest [--rounds R]
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

#include "ipcei/harness.hpp"
#include "ipcei/sig.hpp"
#include "ipcei/zk.hpp"

using ipcei::Clock;
using ipcei::MsSince;

int main(int argc, char** argv) {
	int rounds = 20;
	for (int i = 1; i + 1 < argc; ++i)
		if (std::string(argv[i]) == "--rounds") rounds = std::atoi(argv[i + 1]);
	int failures = 0;
	auto check = [&](bool ok, const char* what) {
		if (!ok) {
			std::printf("FAIL  %s\n", what);
			++failures;
		}
	};

	// ---- ADSC-SNARK: the PID circuit alone, then PID + S flag comparisons ----
	const int S = 5, w = 32;
	std::mt19937 rng(7);
	for (int sensors : {0, S}) {
		ipcei::zk::AdscSetup setup(sensors, w);
		ipcei::zk::AdscProver prover(setup);
		ipcei::zk::AdscVerifier verifier(setup);
		std::vector<double> auth, prove, verify;
		size_t bytes = 0;
		for (int r = 0; r < rounds; ++r) {
			std::vector<uint32_t> reading(sensors), threshold(sensors);
			for (int i = 0; i < sensors; ++i) {
				reading[i] = rng();
				threshold[i] = rng();
			}
			auto t = Clock::now();
			prover.Authenticate(r, reading);
			auth.push_back(MsSince(t));
			t = Clock::now();
			ipcei::zk::AdscMessage m = prover.Prove(threshold);
			prove.push_back(MsSince(t));
			bytes = m.proof_bytes;
			bool flags_ok = true;
			for (int i = 0; i < sensors; ++i) flags_ok &= prover.flags()[i] == (reading[i] < threshold[i]);
			check(flags_ok, "the circuit's flags are the comparisons");
			t = Clock::now();
			const bool ok = verifier.Verify(m, threshold);
			verify.push_back(MsSince(t));
			check(ok, "ADSC proof verifies");
		}
		{
			// a proof replayed in the next round must be rejected (the commitment chain moved on)
			ipcei::zk::AdscProver p2(setup);
			ipcei::zk::AdscVerifier v2(setup);
			std::vector<uint32_t> reading(sensors, 100), threshold(sensors, 200);
			p2.Authenticate(0, reading);
			auto m0 = p2.Prove(threshold);
			check(v2.Verify(m0, threshold), "ADSC round 0 verifies");
			p2.Authenticate(1, reading);
			auto m1 = p2.Prove(threshold);
			(void)m1;
			check(!v2.Verify(m0, threshold), "ADSC replayed proof is rejected");
		}
		if (sensors) {
			// the proof only holds for the thresholds it was made for
			ipcei::zk::AdscProver p3(setup);
			ipcei::zk::AdscVerifier v3(setup);
			std::vector<uint32_t> reading(sensors, 100), threshold(sensors, 200);
			p3.Authenticate(0, reading);
			auto m = p3.Prove(threshold);
			threshold[0] = 50;  // would flip flag 0
			check(!v3.Verify(m, threshold), "ADSC proof rejects other thresholds");
		}
		if (sensors)
			std::printf("ADSC-SNARK, PID + %d x %d-bit flag comparisons  (%zu constraints, proof+commitment %zu B)\n",
					sensors, w, setup.constraints(), bytes);
		else
			std::printf("ADSC-SNARK, PID only  (%zu constraints, proof+commitment %zu B)\n", setup.constraints(), bytes);
		std::printf("  authenticate inputs  median %8.3f ms\n", ipcei::Summarize(auth).median);
		std::printf("  prove                median %8.3f ms\n", ipcei::Summarize(prove).median);
		std::printf("  verify               median %8.3f ms\n", ipcei::Summarize(verify).median);
	}

	// ---- signatures: Ed25519 vs BN254 Schnorr, over an uplink-sized message ----
	std::vector<uint8_t> msg(4096);
	for (auto& b : msg) b = (uint8_t)rng();
	ipcei::Ed25519 ed;
	ipcei::zk::Bn254Schnorr bn;
	std::vector<double> eds, edv, bns, bnv;
	for (int r = 0; r < rounds * 5; ++r) {
		auto t = Clock::now();
		auto s1 = ed.Sign(msg);
		eds.push_back(MsSince(t));
		t = Clock::now();
		check(ipcei::Ed25519::Verify(ed.PublicKey(), msg, s1), "Ed25519 verifies");
		edv.push_back(MsSince(t));
		t = Clock::now();
		auto s2 = bn.Sign(msg.data(), msg.size());
		bns.push_back(MsSince(t));
		t = Clock::now();
		check(bn.Verify(msg.data(), msg.size(), s2), "BN254 Schnorr verifies");
		bnv.push_back(MsSince(t));
		msg[r % msg.size()] ^= 1;
		check(!ipcei::Ed25519::Verify(ed.PublicKey(), msg, s1), "Ed25519 rejects a changed message");
		check(!bn.Verify(msg.data(), msg.size(), s2), "BN254 Schnorr rejects a changed message");
	}
	std::printf("signatures over 4096 B   sign median   verify median\n");
	std::printf("  Ed25519 (OpenSSL)      %8.4f ms   %8.4f ms\n", ipcei::Summarize(eds).median, ipcei::Summarize(edv).median);
	std::printf("  BN254 Schnorr (libff)  %8.4f ms   %8.4f ms\n", ipcei::Summarize(bns).median, ipcei::Summarize(bnv).median);

	std::printf("%s (%d failure%s)\n", failures ? "FAILED" : "all checks passed", failures, failures == 1 ? "" : "s");
	return failures ? 1 : 0;
}
