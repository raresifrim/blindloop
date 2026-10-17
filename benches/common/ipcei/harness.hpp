// harness.hpp — shared protocol harness for the IPCEI secure-actuation benches.
//
// Every protocol bench (BFV in SEAL and OpenFHE, TFHE in OpenFHE) models the same
// round trip between an END NODE (sensor side) and a CENTRAL NODE:
//
//   end node      encode, encrypt and compress the readings or flags, authenticate the
//                 sensor data, prove the PID control law and (with flags) the flag
//                 comparisons in one ADSC-SNARK, sign the uplink
//   central node  verify the uplink signature and the proofs, decompress, evaluate
//                 homomorphically, compress and sign the downlink
//   end node      verify the downlink signature, decrypt, check the result
//
// A bench implements one EndNode and one CentralNode class (derived from
// Participant) whose methods wrap each step in timed("<step id>", ...). The Recorder
// collects one value per step and round; Report prints the per-step breakdown,
// the node totals and the end-to-end total, and writes the same numbers as JSON.
// One-time setup (key generation) is not reported.
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

enum class Node { End, Central };

/// A protocol step: stable id (JSON key), owning node, human label.
struct StepDef {
	const char* id;
	Node node;
	const char* label;
};

/// The protocol steps in protocol order. A bench records the steps its scheme has;
/// the others are reported as "n/a" (e.g. the MAC check in TFHE).
inline const std::vector<StepDef>& Steps() {
	static const std::vector<StepDef> steps = {
		// end node, uplink
		{"encode", Node::End, "FHE encode"},
		{"encrypt", Node::End, "FHE encrypt"},
		{"compress", Node::End, "uplink compress"},
		{"adsc_authenticate", Node::End, "sensor data authenticate (ADSC)"},
		{"adsc_prove", Node::End, "ADSC-SNARK proof (PID + flags)"},
		{"sign_uplink", Node::End, "uplink sign"},
		// central node
		{"verify_uplink", Node::Central, "uplink signature verify"},
		{"adsc_verify", Node::Central, "ADSC-SNARK verify"},
		{"decompress", Node::Central, "uplink decompress"},
		{"evaluate", Node::Central, "FHE evaluate"},
		{"compress_downlink", Node::Central, "downlink compress"},
		{"sign_downlink", Node::Central, "downlink sign"},
		// end node, downlink
		{"verify_downlink", Node::End, "downlink signature verify"},
		{"decrypt", Node::End, "FHE decrypt"},
		{"check_result", Node::End, "result check (MAC tag)"},
	};
	return steps;
}

inline const StepDef* FindStep(const std::string& id) {
	for (const auto& s : Steps())
		if (id == s.id) return &s;
	return nullptr;
}

using Clock = std::chrono::steady_clock;

inline double MsSince(Clock::time_point t0) {
	return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

/// One value per (round, step); warm-up rounds are recorded but left out of the
/// statistics. Also carries the bench's description (parameters, sizes, notes).
class Recorder {
public:
	explicit Recorder(int warmup = 1) : warmup_(warmup) {}

	void BeginRound() { rounds_.emplace_back(); }
	void Add(const char* id, double ms) {
		if (!FindStep(id)) {
			std::fprintf(stderr, "harness: unknown step id '%s'\n", id);
			std::abort();
		}
		if (rounds_.empty()) BeginRound();
		rounds_.back()[id] += ms;
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

/// Base of a bench's EndNode / CentralNode: timed() records one protocol step.
class Participant {
public:
	explicit Participant(Recorder& rec) : rec_(rec) {}
	virtual ~Participant() = default;

protected:
	/// Runs f() and adds its wall time to step `id` of the current round.
	template <class F>
	auto timed(const char* id, F&& f) -> decltype(f()) {
		struct Stop {
			Recorder& r;
			const char* id;
			Clock::time_point t0;
			~Stop() { r.Add(id, MsSince(t0)); }
		} stop{rec_, id, Clock::now()};
		return f();
	}
	Recorder& rec_;
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
		std::fprintf(out, "\n  %-8s %-34s %11s %11s %11s %11s\n", "node", "step", "median ms", "mean ms", "min ms",
				"max ms");
		for (Node node : {Node::End, Node::Central}) {
			for (const auto& s : Steps()) {
				if (s.node != node) continue;
				const Stats st = StepStats(s.id);
				if (st.n == 0) {
					std::fprintf(out, "  %-8s %-34s %11s\n", NodeName(node), s.label, "n/a");
				} else {
					std::fprintf(out, "  %-8s %-34s %11.3f %11.3f %11.3f %11.3f\n", NodeName(node), s.label,
							st.median, st.mean, st.min, st.max);
				}
			}
			const Stats t = TotalStats(node == Node::End ? "end" : "central");
			std::fprintf(out, "  %-8s %-34s %11.3f %11.3f %11.3f %11.3f\n", NodeName(node),
					node == Node::End ? "= end-node total" : "= central-node total", t.median, t.mean, t.min,
					t.max);
		}
		const Stats e = TotalStats("e2e");
		std::fprintf(out, "  %-8s %-34s %11.3f %11.3f %11.3f %11.3f\n", "both", "= end to end (round trip)", e.median,
				e.mean, e.min, e.max);
		if (!rec_.sizes().empty()) {
			std::fprintf(out, "\n");
			for (const auto& s : rec_.sizes()) std::fprintf(out, "  %-34s %12.0f B\n", s.first.c_str(), s.second);
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
			const Stats st = StepStats(s.id);
			f << (first ? "" : ",\n") << "    {\"id\": " << q(s.id) << ", \"node\": " << q(NodeName(s.node))
			  << ", \"label\": " << q(s.label) << ", \"applicable\": " << (st.n ? "true" : "false");
			if (st.n) f << ", \"stats\": " << stats(st);
			f << "}";
			first = false;
		}
		f << "\n  ],\n  \"totals\": {\"end_node\": " << stats(TotalStats("end"))
		  << ", \"central_node\": " << stats(TotalStats("central")) << ", \"end_to_end\": " << stats(TotalStats("e2e"))
		  << "},\n  \"sizes_bytes\": {";
		for (size_t i = 0; i < rec_.sizes().size(); ++i)
			f << (i ? ", " : "") << q(rec_.sizes()[i].first) << ": " << Recorder::Num(rec_.sizes()[i].second);
		f << "},\n  \"notes\": [";
		for (size_t i = 0; i < rec_.notes().size(); ++i) f << (i ? ", " : "") << q(rec_.notes()[i]);
		f << "]\n}\n";
	}

private:
	static const char* NodeName(Node n) { return n == Node::End ? "end" : "central"; }

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
	Stats StepStats(const char* id) const {
		std::vector<double> v;
		for (const auto& r : Measured()) {
			auto it = r.find(id);
			if (it != r.end()) v.push_back(it->second);
		}
		return Summarize(v);
	}
	Stats TotalStats(const std::string& which) const {
		std::vector<double> v;
		for (const auto& r : Measured()) {
			double t = 0;
			for (const auto& kv : r) {
				const StepDef* s = FindStep(kv.first);
				if (which == "e2e" || (which == "end") == (s->node == Node::End)) t += kv.second;
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
