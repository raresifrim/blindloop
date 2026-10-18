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
//             ADSC-SNARK, signs its uplink and sends it
//   central   the Process APP receives every uplink, verifies its signature and proof,
//             decompresses, evaluates the motor command blind, compresses, signs and
//             sends the downlink
//   downlink  the passenger zone (the actuator) receives the downlink, verifies its
//             signature, decrypts and checks the result
//
// The transfers run over emulated automotive Ethernet (net.hpp): the end zones through
// lwIP (an MCU-class stack), the central node through the OS's TCP stack. Their CPU
// cost is a step of each node; the time on the wire is modelled per link (EthernetWire)
// and reported separately, at 100BASE-T1 and 1000BASE-T1.
//
// A bench implements one Participant per zone (PassengerNode, DriverNode, IgnNode,
// CentralNode) whose methods wrap each step in timed("<step id>", ...); the zone comes
// from the Participant. The Recorder collects one value per (zone, step) and round;
// Report prints the per-step breakdown, the zone totals, the critical path (the end
// zones work in parallel: the slowest uplink, then the central node, then the
// passenger's downlink) and the sequential sum, and writes the same numbers as JSON.
// One-time setup (key generation, provisioning) is not reported.
#pragma once

#include <fcntl.h>
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
			s.push_back({"send_uplink", z, Phase::Uplink, "uplink send (lwIP, Ethernet)"});
		}
		s.push_back({"recv_uplink", Zone::Central, Phase::Central, "uplinks receive (3, OS TCP)"});
		s.push_back({"verify_uplink", Zone::Central, Phase::Central, "uplink signatures verify (3)"});
		s.push_back({"adsc_verify", Zone::Central, Phase::Central, "ADSC-SNARK verify (3)"});
		s.push_back({"decompress", Zone::Central, Phase::Central, "uplinks decompress (3)"});
		s.push_back({"evaluate", Zone::Central, Phase::Central, "FHE evaluate (motor command)"});
		s.push_back({"compress_downlink", Zone::Central, Phase::Central, "downlink compress"});
		s.push_back({"sign_downlink", Zone::Central, Phase::Central, "downlink sign"});
		s.push_back({"send_downlink", Zone::Central, Phase::Central, "downlink send (OS TCP)"});
		s.push_back({"recv_downlink", Zone::Passenger, Phase::Downlink, "downlink receive (lwIP, Ethernet)"});
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

/// One message on a switched automotive Ethernet link: TCP over IPv4 (no options, MSS
/// 1460 for the 1500-byte MTU), each segment in its own frame (14-byte header, 4-byte FCS,
/// 64-byte minimum) plus preamble and inter-frame gap (20 bytes). The latency at a link
/// rate is the serialization of every frame plus one switch hop (store-and-forward of the
/// last frame). Not modelled: the reverse-direction ACKs (full duplex), TCP slow start,
/// queueing behind other traffic, propagation delay (ns over in-vehicle distances).
struct WireStats {
	size_t bytes = 0, frames = 0, wire_bytes = 0;
	double ms_100m = 0, ms_1g = 0;
};

inline WireStats EthernetWire(size_t bytes) {
	constexpr size_t kMss = 1460, kTcpIp = 40, kEth = 18, kMinFrame = 64, kPhy = 20;
	WireStats w;
	w.bytes = bytes;
	w.frames = bytes == 0 ? 1 : (bytes + kMss - 1) / kMss;
	size_t last = 0;
	for (size_t f = 0; f < w.frames; ++f) {
		const size_t seg = std::min(kMss, bytes - std::min(bytes, f * kMss));
		last = std::max(kMinFrame, kEth + kTcpIp + seg);
		w.wire_bytes += last + kPhy;
	}
	auto ms = [&](double bps) { return (8.0 * w.wire_bytes + 8.0 * last) / bps * 1e3; };
	w.ms_100m = ms(100e6);
	w.ms_1g = ms(1e9);
	return w;
}

inline double MsSince(Clock::time_point t0) {
	return std::chrono::duration<double, std::milli>(Clock::now() - t0).count();
}

/// One value per (round, zone, step); warm-up rounds are recorded but left out of the
/// statistics. Also carries the bench's description (parameters, sizes, notes).
class Recorder {
public:
	explicit Recorder(int warmup = 1) : warmup_(warmup) {}

	void BeginRound() { rounds_.emplace_back(); }
	/// True once the warm-up rounds are over.
	bool measuring() const { return (int)rounds_.size() > warmup_; }
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
	/// A message crossing a link (whole message: header, payload, signature, proof); the
	/// last round's size is kept (the sizes do not change between rounds).
	void Link(const std::string& name, size_t bytes) {
		for (auto& l : links_)
			if (l.first == name) {
				l.second = bytes;
				return;
			}
		links_.emplace_back(name, bytes);
	}
	void Note(const std::string& n) { notes_.push_back(n); }

	int warmup() const { return warmup_; }
	const std::vector<std::map<std::string, double>>& rounds() const { return rounds_; }
	const std::vector<bool>& correct() const { return correct_; }
	const std::vector<std::pair<std::string, std::string>>& params() const { return params_; }
	const std::vector<std::pair<std::string, double>>& sizes() const { return sizes_; }
	const std::vector<std::pair<std::string, size_t>>& links() const { return links_; }
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
	std::vector<std::pair<std::string, size_t>> links_;
	std::vector<std::string> notes_;
};

/// Optional profiling of the central node alone: with BLINDLOOP_PERF_CTL=<ctl fifo>,<ack fifo>
/// (perf record --control fifo:<ctl>,<ack> -D -1 ...), perf counts only while a central-node
/// step of a measured round runs; setup, warm-up and the end zones stay out of the profile.
class PerfControl {
public:
	static PerfControl& Get() {
		static PerfControl pc;
		return pc;
	}
	bool active() const { return ctl_ >= 0; }
	void Set(bool on) {
		const char* cmd = on ? "enable\n" : "disable\n";
		if (write(ctl_, cmd, std::strlen(cmd)) < 0) return;
		char ack[8];
		if (read(ack_, ack, sizeof ack) < 0) return;
	}

private:
	PerfControl() {
		const char* v = std::getenv("BLINDLOOP_PERF_CTL");
		if (!v) return;
		const std::string s(v);
		const size_t c = s.find(',');
		if (c == std::string::npos) return;
		ctl_ = open(s.substr(0, c).c_str(), O_WRONLY);
		ack_ = open(s.substr(c + 1).c_str(), O_RDONLY);
		if (ctl_ < 0 || ack_ < 0) ctl_ = -1;
	}
	int ctl_ = -1, ack_ = -1;
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
		const bool prof = zone_ == Zone::Central && PerfControl::Get().active() && rec_.measuring();
		if (prof) PerfControl::Get().Set(true);
		struct Stop {
			Recorder& r;
			Zone z;
			const char* id;
			bool prof;
			Clock::time_point t0;
			~Stop() {
				r.Add(z, id, MsSince(t0));
				if (prof) PerfControl::Get().Set(false);
			}
		} stop{rec_, zone_, id, prof, Clock::now()};
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
		if (!rec_.links().empty()) {
			std::fprintf(out, "\n  %-24s %10s %7s %11s %13s %13s\n", "link (TCP/IPv4/Ethernet)", "message B",
					"frames", "on wire B", "100BASE-T1 ms", "1000BASE-T1 ms");
			for (const auto& l : rec_.links()) {
				const WireStats w = EthernetWire(l.second);
				std::fprintf(out, "  %-24s %10zu %7zu %11zu %13.3f %13.3f\n", l.first.c_str(), w.bytes, w.frames,
						w.wire_bytes, w.ms_100m, w.ms_1g);
			}
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
		f << "},\n  \"links\": {";
		for (size_t i = 0; i < rec_.links().size(); ++i) {
			const WireStats w = EthernetWire(rec_.links()[i].second);
			f << (i ? ", " : "") << q(rec_.links()[i].first) << ": {\"bytes\": " << w.bytes << ", \"frames\": "
			  << w.frames << ", \"wire_bytes\": " << w.wire_bytes << ", \"ms_100base_t1\": " << Recorder::Num(w.ms_100m)
			  << ", \"ms_1000base_t1\": " << Recorder::Num(w.ms_1g) << "}";
		}
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

/// Common command-line options: --rounds R --warmup W --json FILE --quiet, and for the
/// emulated Ethernet (net.hpp) --no-net (no transfers) and --eth-offload (the end zones'
/// MAC computes the TCP/IP checksums). Leaves every other argument in `rest`.
struct Options {
	int rounds = 5;
	int warmup = 1;
	std::string json;
	bool quiet = false;
	bool net = true;
	bool eth_offload = false;
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
		else if (a == "--no-net") o.net = false;
		else if (a == "--eth-offload") o.eth_offload = true;
			else o.rest.push_back(a);
		}
		return o;
	}
};

}  // namespace ipcei
