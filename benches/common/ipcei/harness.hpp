// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// harness.hpp — shared protocol harness for the blindloop benches.
//
// Every protocol bench (BFV in SEAL and OpenFHE, TFHE in OpenFHE) models the same round
// of the window-lift use case (scenario.hpp) between three END ZONES and the CENTRAL
// compute:
//
//   uplink    each end zone (passenger, driver, ign) encodes, encrypts and compresses its
//             signals, authenticates its sensor data and proves its inputs in an
//             ADSC-SNARK, and signs its uplink
//   central   the Process APP verifies every uplink signature and proof, decompresses,
//             evaluates the motor command blind, compresses and signs the downlink
//   downlink  the passenger zone (the actuator) verifies the downlink signature,
//             decrypts and checks the result
//
// A bench implements one Participant per zone (PassengerNode, DriverNode, IgnNode,
// CentralNode) whose methods wrap each step in timed("<step id>", ...); the zone comes
// from the Participant. The Recorder collects one value per (zone, step) and round;
// Report prints the per-step breakdown, the zone totals, the critical path (the end
// zones work in parallel: the slowest uplink, then the central node, then the
// passenger's downlink) and the sequential sum, and writes the same numbers as JSON.
// One-time setup (key generation, provisioning) is not reported.
#pragma once

#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace ipcei {

enum class Zone { Passenger, Driver, Ign, Central };
enum class Phase { Uplink, Central, Downlink };
constexpr Zone kEndZones[] = {Zone::Passenger, Zone::Driver, Zone::Ign};

inline const char* ZoneName(Zone z) {
	switch (z) {
		case Zone::Passenger: return "passenger";
		case Zone::Driver: return "driver";
		case Zone::Ign: return "ign";
		case Zone::Central: return "central";
	}
	return "?";
}
inline const char* PhaseName(Phase p) {
	return p == Phase::Uplink ? "uplink" : p == Phase::Central ? "central" : "downlink";
}

/// A protocol step: stable id, owning zone and phase, human label. The JSON key of a
/// step is "<zone>.<id>".
struct StepDef {
	const char* id;
	Zone zone;
	Phase phase;
	const char* label;
	std::string key() const { return std::string(ZoneName(zone)) + "." + id; }
};

/// The protocol steps in protocol order. A bench records the steps its scheme has;
/// the others are reported as "n/a" (e.g. the MAC check in TFHE). The central node's
/// verify_uplink / adsc_verify / decompress add up over the three uplinks.
inline const std::vector<StepDef>& Steps() {
	static const std::vector<StepDef> steps = [] {
		std::vector<StepDef> s;
		for (Zone z : kEndZones) {
			s.push_back({"encode", z, Phase::Uplink, "FHE encode"});
			s.push_back({"encrypt", z, Phase::Uplink, "FHE encrypt"});
			s.push_back({"compress", z, Phase::Uplink, "uplink compress"});
			s.push_back({"adsc_authenticate", z, Phase::Uplink, "sensor data authenticate (ADSC)"});
			s.push_back({"adsc_prove", z, Phase::Uplink, "ADSC-SNARK proof of the inputs"});
			s.push_back({"sign_uplink", z, Phase::Uplink, "uplink sign"});
		}
		s.push_back({"verify_uplink", Zone::Central, Phase::Central, "uplink signatures verify (3)"});
		s.push_back({"adsc_verify", Zone::Central, Phase::Central, "ADSC-SNARK verify (3)"});
		s.push_back({"decompress", Zone::Central, Phase::Central, "uplinks decompress (3)"});
		s.push_back({"evaluate", Zone::Central, Phase::Central, "FHE evaluate (motor command)"});
		s.push_back({"compress_downlink", Zone::Central, Phase::Central, "downlink compress"});
		s.push_back({"sign_downlink", Zone::Central, Phase::Central, "downlink sign"});
		s.push_back({"verify_downlink", Zone::Passenger, Phase::Downlink, "downlink signature verify"});
		s.push_back({"decrypt", Zone::Passenger, Phase::Downlink, "FHE decrypt"});
		s.push_back({"check_result", Zone::Passenger, Phase::Downlink, "result check (MAC tag)"});
		return s;
	}();
	return steps;
}

inline const StepDef* FindStep(Zone z, const std::string& id) {
	for (const auto& s : Steps())
		if (s.zone == z && id == s.id) return &s;
	return nullptr;
}
inline const StepDef* FindStep(const std::string& key) {
	for (const auto& s : Steps())
		if (key == s.key()) return &s;
	return nullptr;
}

using Clock = std::chrono::steady_clock;

inline double MsSince(Clock::time_point t0) {
	return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

/// One value per (round, zone, step); warm-up rounds are recorded but left out of the
/// statistics. Also carries the bench's description (parameters, sizes, notes).
class Recorder {
public:
	explicit Recorder(int warmup = 1) : warmup_(warmup) {}

	void BeginRound() { rounds_.emplace_back(); }
	void Add(Zone z, const char* id, double ms) {
		const StepDef* s = FindStep(z, id);
		if (!s) {
			std::fprintf(stderr, "harness: unknown step '%s' for zone %s\n", id, ZoneName(z));
			std::abort();
		}
		if (rounds_.empty()) BeginRound();
		rounds_.back()[s->key()] += ms;
	}
	void RoundResult(bool correct) { correct_.push_back(correct); }

	void Param(const std::string& k, const std::string& v) { params_.emplace_back(k, v); }
	void Param(const std::string& k, double v) { params_.emplace_back(k, Num(v)); }
	void Size(const std::string& k, double bytes) { sizes_.emplace_back(k, bytes); }
	void Note(const std::string& n) { notes_.push_back(n); }

	int warmup() const { return warmup_; }
	const std::vector<std::map<std::string, double>>& rounds() const { return rounds_; }
	const std::vector<bool>& correct() const { return correct_; }
	const std::vector<std::pair<std::string, std::string>>& params() const { return params_; }
	const std::vector<std::pair<std::string, double>>& sizes() const { return sizes_; }
	const std::vector<std::string>& notes() const { return notes_; }

	static std::string Num(double v) {
		std::ostringstream os;
		os.precision(10);
		os << v;
		return os.str();
	}

private:
	int warmup_;
	std::vector<std::map<std::string, double>> rounds_;
	std::vector<bool> correct_;
	std::vector<std::pair<std::string, std::string>> params_;
	std::vector<std::pair<std::string, double>> sizes_;
	std::vector<std::string> notes_;
};

/// Base of a bench's zone nodes: timed() records one protocol step of this zone.
class Participant {
public:
	Participant(Recorder& rec, Zone zone) : rec_(rec), zone_(zone) {}
	virtual ~Participant() = default;
	Zone zone() const { return zone_; }

protected:
	/// Runs f() and adds its wall time to step `id` of this zone in the current round.
	template <class F>
	auto timed(const char* id, F&& f) -> decltype(f()) {
		struct Stop {
			Recorder& r;
			Zone z;
			const char* id;
			Clock::time_point t0;
			~Stop() { r.Add(z, id, MsSince(t0)); }
		} stop{rec_, zone_, id, Clock::now()};
		return f();
	}
	Recorder& rec_;
	Zone zone_;
};

/// Summary of one series (one step, or one total, over the measured rounds).
struct Stats {
	int n = 0;
	double median = 0, mean = 0, min = 0, max = 0;
};

inline Stats Summarize(std::vector<double> v) {
	Stats s;
	s.n = (int)v.size();
	if (v.empty()) return s;
	std::sort(v.begin(), v.end());
	s.min = v.front();
	s.max = v.back();
	s.median = (v.size() % 2) ? v[v.size() / 2] : 0.5 * (v[v.size() / 2 - 1] + v[v.size() / 2]);
	double sum = 0;
	for (double x : v) sum += x;
	s.mean = sum / v.size();
	return s;
}


/// Prints the breakdown and writes it as JSON.
class Report {
public:
	Report(const Recorder& rec, std::string bench, std::string library, std::string scheme)
		: rec_(rec), bench_(std::move(bench)), library_(std::move(library)), scheme_(std::move(scheme)) {}

	void Print(FILE* out = stdout) const {
		const auto m = Measured();
		std::fprintf(out, "\n=== %s  (%s, %s) ===\n", bench_.c_str(), library_.c_str(), scheme_.c_str());
		for (const auto& p : rec_.params()) std::fprintf(out, "  %-28s %s\n", p.first.c_str(), p.second.c_str());
		std::fprintf(out, "  %-28s %d measured (+%d warm-up), correct %d/%d (warm-up included)\n", "rounds", (int)m.size(),
				std::min(rec_.warmup(), (int)rec_.rounds().size()), CorrectCount(), (int)rec_.correct().size());
		std::fprintf(out, "\n  %-10s %-36s %11s %11s %11s %11s\n", "zone", "step", "median ms", "mean ms", "min ms",
				"max ms");
		auto line = [&](const char* zone, const std::string& label, const Stats& st) {
			if (st.n == 0)
				std::fprintf(out, "  %-10s %-36s %11s\n", zone, label.c_str(), "n/a");
			else
				std::fprintf(out, "  %-10s %-36s %11.3f %11.3f %11.3f %11.3f\n", zone, label.c_str(), st.median,
						st.mean, st.min, st.max);
		};
		for (Zone z : {Zone::Passenger, Zone::Driver, Zone::Ign, Zone::Central}) {
			for (const auto& s : Steps())
				if (s.zone == z) line(ZoneName(z), std::string(s.phase == Phase::Downlink ? "[downlink] " : "") + s.label,
						StepStats(s.key()));
			line(ZoneName(z), std::string("= ") + ZoneName(z) + " total", TotalStats(Total::OfZone, z));
		}
		line("all", "= critical path (zones in parallel)", TotalStats(Total::Critical));
		line("all", "= sequential sum", TotalStats(Total::Sequential));
		if (!rec_.sizes().empty()) {
			std::fprintf(out, "\n");
			for (const auto& s : rec_.sizes()) std::fprintf(out, "  %-40s %12.0f B\n", s.first.c_str(), s.second);
		}
		for (const auto& n : rec_.notes()) std::fprintf(out, "  note: %s\n", n.c_str());
	}

	void WriteJson(const std::string& path) const {
		std::ofstream f(path);
		if (!f) {
			std::fprintf(stderr, "harness: cannot write %s\n", path.c_str());
			return;
		}
		auto q = [](const std::string& s) {
			std::string o = "\"";
			for (char c : s) {
				if (c == '"' || c == '\\') o += '\\';
				o += c;
			}
			return o + "\"";
		};
		auto stats = [&](const Stats& s) {
			return "{\"n\": " + std::to_string(s.n) + ", \"median_ms\": " + Recorder::Num(s.median) +
				", \"mean_ms\": " + Recorder::Num(s.mean) + ", \"min_ms\": " + Recorder::Num(s.min) +
				", \"max_ms\": " + Recorder::Num(s.max) + "}";
		};
		f << "{\n  \"bench\": " << q(bench_) << ",\n  \"library\": " << q(library_) << ",\n  \"scheme\": "
		  << q(scheme_) << ",\n  \"rounds_measured\": " << Measured().size() << ",\n  \"warmup\": "
		  << rec_.warmup() << ",\n  \"correct\": " << CorrectCount() << ",\n  \"checked\": "
		  << rec_.correct().size() << ",\n  \"params\": {";
		for (size_t i = 0; i < rec_.params().size(); ++i)
			f << (i ? ", " : "") << q(rec_.params()[i].first) << ": " << q(rec_.params()[i].second);
		f << "},\n  \"steps\": [\n";
		bool first = true;
		for (const auto& s : Steps()) {
			const Stats st = StepStats(s.key());
			f << (first ? "" : ",\n") << "    {\"id\": " << q(s.id) << ", \"zone\": " << q(ZoneName(s.zone))
			  << ", \"phase\": " << q(PhaseName(s.phase)) << ", \"label\": " << q(s.label)
			  << ", \"applicable\": " << (st.n ? "true" : "false");
			if (st.n) f << ", \"stats\": " << stats(st);
			f << "}";
			first = false;
		}
		f << "\n  ],\n  \"totals\": {";
		for (Zone z : {Zone::Passenger, Zone::Driver, Zone::Ign, Zone::Central})
			f << q(ZoneName(z)) << ": " << stats(TotalStats(Total::OfZone, z)) << ", ";
		f << "\"critical_path\": " << stats(TotalStats(Total::Critical))
		  << ", \"sequential\": " << stats(TotalStats(Total::Sequential)) << "},\n  \"sizes_bytes\": {";
		for (size_t i = 0; i < rec_.sizes().size(); ++i)
			f << (i ? ", " : "") << q(rec_.sizes()[i].first) << ": " << Recorder::Num(rec_.sizes()[i].second);
		f << "},\n  \"notes\": [";
		for (size_t i = 0; i < rec_.notes().size(); ++i) f << (i ? ", " : "") << q(rec_.notes()[i]);
		f << "]\n}\n";
	}

private:
	enum class Total { OfZone, Critical, Sequential };

	std::vector<std::map<std::string, double>> Measured() const {
		const auto& r = rec_.rounds();
		const size_t skip = std::min<size_t>(rec_.warmup(), r.size());
		return {r.begin() + skip, r.end()};
	}
	int CorrectCount() const {
		int c = 0;
		for (bool b : rec_.correct()) c += b;
		return c;
	}
	Stats StepStats(const std::string& key) const {
		std::vector<double> v;
		for (const auto& r : Measured()) {
			auto it = r.find(key);
			if (it != r.end()) v.push_back(it->second);
		}
		return Summarize(v);
	}
	/// Per round: one zone's steps, the critical path (max over the end zones' uplinks,
	/// plus the central node, plus the passenger's downlink) or the plain sum.
	Stats TotalStats(Total which, Zone zone = Zone::Central) const {
		std::vector<double> v;
		for (const auto& r : Measured()) {
			double t = 0, central = 0, downlink = 0;
			std::map<Zone, double> uplink;
			for (const auto& kv : r) {
				const StepDef* s = FindStep(kv.first);
				if (which == Total::OfZone && s->zone == zone) t += kv.second;
				if (which == Total::Sequential) t += kv.second;
				if (s->phase == Phase::Uplink) uplink[s->zone] += kv.second;
				if (s->phase == Phase::Central) central += kv.second;
				if (s->phase == Phase::Downlink) downlink += kv.second;
			}
			if (which == Total::Critical) {
				double slowest = 0;
				for (const auto& u : uplink) slowest = std::max(slowest, u.second);
				t = slowest + central + downlink;
			}
			v.push_back(t);
		}
		return Summarize(v);
	}

	const Recorder& rec_;
	std::string bench_, library_, scheme_;
};

/// One OpenMP thread unless the caller set OMP_NUM_THREADS: the suite measures single-core
/// nodes. OpenFHE reads the thread count once, when it is loaded, and passes it as an
/// explicit num_threads to its loops, so omp_set_num_threads() in main() is too late; the
/// bench re-executes itself with the variable set instead. Call first thing in main().
inline void SingleThreadByDefault(char** argv) {
	if (std::getenv("OMP_NUM_THREADS")) return;
	setenv("OMP_NUM_THREADS", "1", 1);
	execv(argv[0], argv);  // returns only on failure: keep going with OpenFHE's default
	std::fprintf(stderr, "harness: could not re-execute %s with OMP_NUM_THREADS=1\n", argv[0]);
}

/// Common command-line options: --rounds R --warmup W --json FILE --quiet.
/// Leaves every other argument in `rest` for the bench to parse.
struct Options {
	int rounds = 5;
	int warmup = 1;
	std::string json;
	bool quiet = false;
	std::vector<std::string> rest;

	static Options Parse(int argc, char** argv, int default_rounds = 5) {
		Options o;
		o.rounds = default_rounds;
		for (int i = 1; i < argc; ++i) {
			std::string a = argv[i];
			auto next = [&]() -> std::string {
				if (i + 1 >= argc) {
					std::fprintf(stderr, "missing value for %s\n", a.c_str());
					std::exit(2);
				}
				return argv[++i];
			};
			if (a == "--rounds") o.rounds = std::atoi(next().c_str());
			else if (a == "--warmup") o.warmup = std::atoi(next().c_str());
			else if (a == "--json") o.json = next();
			else if (a == "--quiet") o.quiet = true;
			else o.rest.push_back(a);
		}
		return o;
	}
};

}  // namespace ipcei
