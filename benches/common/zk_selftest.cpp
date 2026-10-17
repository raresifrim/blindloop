// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// zk_selftest.cpp — checks that every end zone's ADSC proof (flags and raw encodings) and
// both signature schemes verify (and that replays and tampering are rejected), and times
// each operation.
//   zk_selftest [--rounds R]
#include <cstdio>
#include <cstdlib>
#include <random>
#include <string>
#include <vector>

#include "ipcei/harness.hpp"
#include "ipcei/scenario.hpp"
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

	// ---- ADSC-SNARK: one circuit per end zone and encoding, on the scenario's rounds ----
	std::mt19937 rng(7);
	for (ipcei::zk::Encoding enc : {ipcei::zk::Encoding::Flags, ipcei::zk::Encoding::Raw}) {
		for (ipcei::Zone zone : ipcei::kEndZones) {
			ipcei::zk::AdscSetup setup(zone, enc);
			ipcei::zk::AdscProver prover(setup);
			ipcei::zk::AdscVerifier verifier(setup);
			ipcei::window::Rounds scenario;
			std::vector<double> auth, prove, verify;
			size_t bytes = 0;
			for (int r = 0; r < rounds; ++r) {
				const ipcei::window::Inputs in = scenario.Next();
				auto t = Clock::now();
				prover.Authenticate(ipcei::window::SensorValues(zone, in));
				auth.push_back(MsSince(t));
				t = Clock::now();
				ipcei::zk::AdscMessage m = prover.Prove();
				prove.push_back(MsSince(t));
				bytes = m.proof_bytes;
				const auto expect = enc == ipcei::zk::Encoding::Flags ? ipcei::window::FlagBits(zone, in)
																		 : ipcei::window::RawBits(zone, in);
				check(prover.bits() == expect, "the circuit derives the bits the zone encrypts");
				t = Clock::now();
				const bool ok = verifier.Verify(m);
				verify.push_back(MsSince(t));
				check(ok, "ADSC proof verifies");
			}
			{
				// a proof replayed in the next round must be rejected (the round counter moved on)
				ipcei::zk::AdscProver p2(setup);
				ipcei::zk::AdscVerifier v2(setup);
				ipcei::window::Rounds sc;
				const auto in = sc.Next();
				p2.Authenticate(ipcei::window::SensorValues(zone, in));
				auto m0 = p2.Prove();
				check(v2.Verify(m0), "ADSC round 1 verifies");
				check(!v2.Verify(m0), "ADSC replayed proof is rejected");
			}
			std::printf("ADSC-SNARK %-9s %-5s (%zu constraints, proof+commitment %zu B)\n", ipcei::ZoneName(zone),
					enc == ipcei::zk::Encoding::Flags ? "flags" : "raw", setup.constraints(), bytes);
			std::printf("  authenticate inputs  median %8.3f ms\n", ipcei::Summarize(auth).median);
			std::printf("  prove                median %8.3f ms\n", ipcei::Summarize(prove).median);
			std::printf("  verify               median %8.3f ms\n", ipcei::Summarize(verify).median);
		}
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
