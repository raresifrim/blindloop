// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// scenario.hpp — the window-lift use case every bench evaluates (NXP IPCEI A14, slide 5,
// with the driver-side overwrite).
//
// Three end zones encrypt their own signals; the central compute (the Process APP)
// evaluates the motor command blind and returns it to the passenger zone:
//
//   passenger  the actuator: window button (UP / OFF / DOWN), window position sensor,
//              motor error flags (OvC, OvT, S2G, S2Vcc); receives the command
//   driver     the driver-side overwrite of the passenger window (UP / OFF / DOWN) and
//              the child-lock
//   ign        the ignition control ECU: Klem 15
//
// Decision (the overwrite wins; the child-lock blocks only the passenger's own button):
//   dir    = overwrite != OFF ? overwrite : (child_lock ? OFF : button)
//   Motor+ : dir = UP   and not Full Up   and Klem and no motor error
//   Motor- : dir = DOWN and not Full Down and Klem and no motor error
//   else Off
//
// Two encodings of what a zone encrypts:
//   flags  each zone derives its bits at the source (FlagBits):
//            passenger pu, pd, top (position >= kTop), bot (position <= kBottom),
//                      err (OR of the four error flags)
//            driver    ou, od, cl
//            ign       k
//   raw    each zone sends its raw signals bit by bit (RawBits) and the central node
//          derives everything, including the two 12-bit position comparisons:
//            passenger up, down, position (kPositionBits, LSB first), ovc, ovt, s2g, s2vcc
//            driver    up, down, cl
//            ign       k
//
// Arithmetic form of the decision over Z_t (BFV), on the flag bits:
//   a   = (1 - ou - od) (1 - cl)          the passenger's own button is allowed
//   up  = ou + a pu,  dn = od + a pd       the effective direction
//   g   = k (1 - err)
//   cmd = up (1 - top) g  -  dn (1 - bot) g   in {+1 (Motor+), -1 (Motor-), 0 (Off)}
// depth 3, 8 multiplications, degree 6 in the inputs (CmdArith).
#pragma once

#include <cstdint>
#include <random>
#include <string>
#include <vector>

#include "ipcei/harness.hpp"  // Zone

namespace ipcei {
namespace window {

enum class Dir : uint8_t { Off = 0, Up = 1, Down = 2 };
enum class Cmd : uint8_t { Off = 0, MotorUp = 1, MotorDown = 2 };

constexpr int kPositionBits = 12;    // position sensor ADC: 0 (fully down) .. 4095 (fully up)
constexpr uint32_t kTop = 4000;      // Full Up:   position >= kTop
constexpr uint32_t kBottom = 95;     // Full Down: position <= kBottom
constexpr int kErrorFlags = 4;       // OvC, OvT, S2G, S2Vcc

struct Passenger {
	Dir button = Dir::Off;
	uint32_t position = 2000;
	uint8_t err[kErrorFlags] = {0, 0, 0, 0};
};
struct Driver {
	Dir overwrite = Dir::Off;
	bool child_lock = false;
};
struct Ign {
	bool klem = true;
};
struct Inputs {
	Passenger p;
	Driver d;
	Ign i;
	std::string label;  // which case of the scenario this round exercises
};

inline Cmd Decide(const Inputs& in) {
	const Dir dir = in.d.overwrite != Dir::Off ? in.d.overwrite : (in.d.child_lock ? Dir::Off : in.p.button);
	bool err = false;
	for (int j = 0; j < kErrorFlags; ++j) err = err || in.p.err[j];
	const bool enabled = in.i.klem && !err;
	if (dir == Dir::Up && in.p.position < kTop && enabled) return Cmd::MotorUp;
	if (dir == Dir::Down && in.p.position > kBottom && enabled) return Cmd::MotorDown;
	return Cmd::Off;
}

inline const char* CmdName(Cmd c) {
	return c == Cmd::MotorUp ? "Motor+" : c == Cmd::MotorDown ? "Motor-" : "Off";
}
/// +1 / -1 / 0: the value of the arithmetic form.
inline int CmdValue(Cmd c) { return c == Cmd::MotorUp ? 1 : c == Cmd::MotorDown ? -1 : 0; }

// ---------------------------------------------------------------- encodings

/// Flags mode: the bits a zone derives at the source and encrypts, in its message order.
inline std::vector<uint8_t> FlagBits(Zone z, const Inputs& in) {
	switch (z) {
		case Zone::Passenger: {
			uint8_t err = 0;
			for (int j = 0; j < kErrorFlags; ++j) err |= in.p.err[j];
			return {uint8_t(in.p.button == Dir::Up), uint8_t(in.p.button == Dir::Down),
					uint8_t(in.p.position >= kTop), uint8_t(in.p.position <= kBottom), err};
		}
		case Zone::Driver:
			return {uint8_t(in.d.overwrite == Dir::Up), uint8_t(in.d.overwrite == Dir::Down),
					uint8_t(in.d.child_lock)};
		case Zone::Ign:
			return {uint8_t(in.i.klem)};
		case Zone::Central:
			break;
	}
	return {};
}
/// Positions of the flag bits in each zone's message.
enum PassengerFlag { kPu = 0, kPd, kTopFlag, kBotFlag, kErr, kPassengerFlags };
enum DriverFlag { kOu = 0, kOd, kCl, kDriverFlags };
enum IgnFlag { kK = 0, kIgnFlags };

/// Raw mode: a zone's raw signals bit by bit, in its message order.
inline std::vector<uint8_t> RawBits(Zone z, const Inputs& in) {
	std::vector<uint8_t> b;
	switch (z) {
		case Zone::Passenger:
			b.push_back(in.p.button == Dir::Up);
			b.push_back(in.p.button == Dir::Down);
			for (int j = 0; j < kPositionBits; ++j) b.push_back((in.p.position >> j) & 1u);
			for (int j = 0; j < kErrorFlags; ++j) b.push_back(in.p.err[j]);
			break;
		case Zone::Driver:
			b = {uint8_t(in.d.overwrite == Dir::Up), uint8_t(in.d.overwrite == Dir::Down), uint8_t(in.d.child_lock)};
			break;
		case Zone::Ign:
			b = {uint8_t(in.i.klem)};
			break;
		case Zone::Central:
			break;
	}
	return b;
}
/// Raw passenger message: up, down, position bits [kRawPos, kRawPos + kPositionBits), error flags.
enum { kRawUp = 0, kRawDown = 1, kRawPos = 2, kRawErr = 2 + kPositionBits, kPassengerRaw = 2 + kPositionBits + kErrorFlags };

/// The raw values each zone's sensors authenticate (ADSC), grouped by sensor:
///   passenger  {button up, button down} {position} {ovc, ovt, s2g, s2vcc}
///   driver     {overwrite up, overwrite down} {child-lock}
///   ign        {klem}
inline std::vector<uint32_t> SensorValues(Zone z, const Inputs& in) {
	switch (z) {
		case Zone::Passenger:
			return {uint32_t(in.p.button == Dir::Up), uint32_t(in.p.button == Dir::Down), in.p.position,
					in.p.err[0], in.p.err[1], in.p.err[2], in.p.err[3]};
		case Zone::Driver:
			return {uint32_t(in.d.overwrite == Dir::Up), uint32_t(in.d.overwrite == Dir::Down),
					uint32_t(in.d.child_lock)};
		case Zone::Ign:
			return {uint32_t(in.i.klem)};
		case Zone::Central:
			break;
	}
	return {};
}

/// The decision in arithmetic form, over any ring T with +, - and * (Z_t values for the
/// MAC check, plain ints for a self-test). Flag bits in FlagBits order.
template <class T>
T CmdArith(const T& pu, const T& pd, const T& top, const T& bot, const T& err, const T& ou, const T& od,
		const T& cl, const T& k, const T& one) {
	const T a = (one - ou - od) * (one - cl);
	const T up = ou + a * pu;
	const T dn = od + a * pd;
	const T g = k * (one - err);
	return up * ((one - top) * g) - dn * ((one - bot) * g);
}

// ---------------------------------------------------------------- rounds

/// The rounds: first one of each case of the decision (kCases), then random inputs.
class Rounds {
public:
	static constexpr int kCases = 12;
	explicit Rounds(uint64_t seed = 2026) : rng_(seed) {}

	Inputs Next() {
		const int i = n_++;
		Inputs in;
		in.p.position = 1000 + (uint32_t)(rng_() % 2000);  // somewhere in the middle
		switch (i < kCases ? i : -1) {
			case 0: in.p.button = Dir::Up; in.label = "passenger up"; break;
			case 1: in.p.button = Dir::Down; in.label = "passenger down"; break;
			case 2: in.p.button = Dir::Up; in.p.position = kTop + (uint32_t)(rng_() % 96); in.label = "up at Full Up"; break;
			case 3: in.p.button = Dir::Down; in.p.position = (uint32_t)(rng_() % (kBottom + 1)); in.label = "down at Full Down"; break;
			case 4: in.p.button = Dir::Up; in.i.klem = false; in.label = "Klem off"; break;
			case 5: in.p.button = Dir::Down; in.p.err[1] = 1; in.label = "motor error (OvT)"; break;
			case 6: in.p.button = Dir::Up; in.d.child_lock = true; in.label = "child-lock blocks passenger"; break;
			case 7: in.label = "no button"; break;
			case 8: in.d.overwrite = Dir::Up; in.label = "driver overwrite up"; break;
			case 9: in.p.button = Dir::Up; in.d.overwrite = Dir::Down; in.label = "overwrite beats passenger"; break;
			case 10: in.d.overwrite = Dir::Down; in.d.child_lock = true; in.label = "overwrite despite child-lock"; break;
			case 11: in.d.overwrite = Dir::Up; in.p.position = kTop + (uint32_t)(rng_() % 96); in.label = "overwrite at Full Up"; break;
			default: {
				in.p.button = (Dir)(rng_() % 3);
				in.d.overwrite = (rng_() % 4 == 0) ? (Dir)(1 + rng_() % 2) : Dir::Off;
				in.d.child_lock = rng_() % 4 == 0;
				in.i.klem = rng_() % 8 != 0;
				in.p.position = (uint32_t)(rng_() % (1u << kPositionBits));
				if (rng_() % 8 == 0) in.p.err[rng_() % kErrorFlags] = 1;
				in.label = "random";
			}
		}
		return in;
	}

private:
	std::mt19937_64 rng_;
	int n_ = 0;
};

}  // namespace window
}  // namespace ipcei
