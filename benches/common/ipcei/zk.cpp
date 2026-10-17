// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// zk.cpp — the end zones' ADSC-SNARKs (one circuit per zone of the window-lift scenario)
// and BN254 Schnorr, on the vendored libsnark (third_party/adsc-snark). Compiled at
// C++14. Interface: zk.hpp.
#include "ipcei/zk.hpp"
#include "ipcei/scenario.hpp"

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <openssl/sha.h>

#include "libff/common/default_types/ec_pp.hpp"
#include "libff/common/profiling.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/gadgetlib1/protoboard_structured.hpp"
#include "libsnark/gadgetlib1/state_structured.hpp"
#include "libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.hpp"
#include "libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppzkadscsnark/r1cs_gg_ppzkadscsnark.hpp"

using namespace libsnark;
typedef libff::default_ec_pp EcPP;
typedef libff::Fr<EcPP> SFieldT;

namespace ipcei {
namespace zk {

void Init() {
	static bool done = false;
	if (done) return;
	EcPP::init_public_params();
	EC_Inner<EcPP>::init_public_params();  // inner curve of the sensors' snark-friendly signatures
	libff::inhibit_profiling_info = true;
	libff::inhibit_profiling_counters = true;
	done = true;
}

// ---------------------------------------------------------------- zone circuits

// One end zone's circuit. Layout (the ADSC transformation needs the blocks in this order):
//   IO              round, then (passenger, flags) kTop and kBottom          public
//   PRIVATE_INPUTS  the zone's sensor values, in SensorValues order          authenticated
//   STATE_IN / OUT  the round counter                                         chained
//   free            bits of the position, comparisons, OR of the error flags
// Constraints:
//   state_out = state_in + 1 = round          (one proof per round, in order)
//   every 0/1 sensor value is boolean; up * down = 0 for a 3-position switch
//   passenger: position = sum of kPositionBits boolean bits (range check), and in flags
//   mode top = (position >= kTop), bot = (position <= kBottom), err = OR(error flags)
// The derived bits (Bits(): what the zone encrypts) are private wires; nothing about the
// raw values or the bits is public.
class ZoneCircuit {
public:
	static const int ID_BLOCK_IO = 0;
	static const int ID_BLOCK_PRIVATE_INPUTS = 1;
	static const int ID_BLOCK_STATE_IN = 2;
	static const int ID_BLOCK_STATE_OUT = 3;
	static const int NUM_STATES = 1;

	const Zone zone;
	const Encoding encoding;
	structured_protoboard<SFieldT> pb;
	state_manager<SFieldT> s_manager;
	r1cs_gg_ppzkadscsnark_constraint_system<EcPP> constraint_system;

	ZoneCircuit(Zone z, Encoding e) : zone(z), encoding(e), pb(), s_manager(pb, ID_BLOCK_STATE_IN, ID_BLOCK_STATE_OUT) {
		limits_ = zone == Zone::Passenger && encoding == Encoding::Flags;
		const int nio = 1 + (limits_ ? 2 : 0);
		const int ninputs = NumInputs(zone);
		pb.reserve_block(ID_BLOCK_IO, nio);
		pb.reserve_block(ID_BLOCK_PRIVATE_INPUTS, ninputs);
		pb.reserve_block(ID_BLOCK_STATE_IN, NUM_STATES);
		pb.reserve_block(ID_BLOCK_STATE_OUT, NUM_STATES);

		inputs_.resize(ninputs);
		for (auto& v : inputs_) v.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "input");
		round_.allocate_from_block(pb, ID_BLOCK_IO, "round");
		if (limits_) {
			top_limit_.allocate_from_block(pb, ID_BLOCK_IO, "top_limit");
			bottom_limit_.allocate_from_block(pb, ID_BLOCK_IO, "bottom_limit");
		}
		counter_.reset(new pb_state_structured<SFieldT>(pb, ID_BLOCK_STATE_IN, ID_BLOCK_STATE_OUT, SFieldT::zero(),
				"counter"));
		s_manager.add_state(*counter_);
		pb.set_input_sizes(nio);

		// round counter
		pb.add_r1cs_constraint(r1cs_constraint<SFieldT>(1, counter_->in + 1, counter_->out), "counter");
		pb.add_r1cs_constraint(r1cs_constraint<SFieldT>(1, round_, counter_->out), "round");

		// 0/1 values and 3-position switches
		for (int i = 0; i < ninputs; ++i)
			if (!(zone == Zone::Passenger && i == kSensorPosition)) generate_boolean_r1cs_constraint<SFieldT>(pb, inputs_[i]);
		if (zone != Zone::Ign) pb.add_r1cs_constraint(r1cs_constraint<SFieldT>(inputs_[0], inputs_[1], 0), "switch");

		if (zone == Zone::Passenger) {
			pos_bits_.allocate(pb, window::kPositionBits, "position_bits");
			pos_pack_.reset(new packing_gadget<SFieldT>(pb, pos_bits_, inputs_[kSensorPosition], "position_pack"));
			pos_pack_->generate_r1cs_constraints(true);  // and every bit boolean
			if (encoding == Encoding::Flags) {
				less_top_.allocate(pb, "less_top");
				leq_top_.allocate(pb, "leq_top");
				less_bot_.allocate(pb, "less_bot");
				bot_.allocate(pb, "bot");
				top_.allocate(pb, "top");
				cmp_top_.reset(new comparison_gadget<SFieldT>(pb, window::kPositionBits, inputs_[kSensorPosition], top_limit_,
						less_top_, leq_top_, "cmp_top"));
				cmp_bot_.reset(new comparison_gadget<SFieldT>(pb, window::kPositionBits, inputs_[kSensorPosition],
						bottom_limit_, less_bot_, bot_, "cmp_bot"));
				cmp_top_->generate_r1cs_constraints();
				cmp_bot_->generate_r1cs_constraints();
				pb.add_r1cs_constraint(r1cs_constraint<SFieldT>(1, 1 - less_top_, top_), "top");
				// err = 1 - prod_j (1 - e_j)
				none_.allocate(pb, window::kErrorFlags - 1, "no_error");
				pb_linear_combination<SFieldT> acc;
				acc.assign(pb, 1 - inputs_[kSensorErrors]);
				for (int j = 1; j < window::kErrorFlags; ++j) {
					pb.add_r1cs_constraint(r1cs_constraint<SFieldT>(acc, 1 - inputs_[kSensorErrors + j], none_[j - 1]),
							"no_error");
					acc.assign(pb, pb_linear_combination<SFieldT>(none_[j - 1]));
				}
				err_.allocate(pb, "err");
				pb.add_r1cs_constraint(r1cs_constraint<SFieldT>(1, 1 - none_[window::kErrorFlags - 2], err_), "err");
			}
		}
		assert(pb.blocks_fully_allocated());
		constraint_system = r1cs_to_r1cs_adsc(pb.get_constraint_system(), ninputs, NUM_STATES);
	}

	/// The sensors' values grouped as the sensors authenticate them.
	static std::vector<size_t> SensorGroups(Zone z) {
		switch (z) {
			case Zone::Passenger: return {2, 1, (size_t)window::kErrorFlags};  // button, position, motor driver
			case Zone::Driver: return {2, 1};                                     // overwrite button, child-lock
			case Zone::Ign: return {1};                                           // Klem 15
			case Zone::Central: break;
		}
		return {};
	}
	static int NumInputs(Zone z) {
		int n = 0;
		for (size_t g : SensorGroups(z)) n += (int)g;
		return n;
	}

	/// Fills the witness for round counter+1 from the zone's authenticated values.
	void Witness(const std::vector<SFieldT>& values) {
		for (size_t i = 0; i < inputs_.size(); ++i) pb.val(inputs_[i]) = values[i];
		pb.val(counter_->out) = pb.val(counter_->in) + SFieldT::one();
		pb.val(round_) = pb.val(counter_->out);
		if (limits_) {
			pb.val(top_limit_) = SFieldT((long)window::kTop);
			pb.val(bottom_limit_) = SFieldT((long)window::kBottom);
		}
		if (zone == Zone::Passenger) {
			pos_bits_.fill_with_bits_of_field_element(pb, pb.val(inputs_[kSensorPosition]));
			pos_pack_->generate_r1cs_witness_from_bits();
			if (encoding == Encoding::Flags) {
				cmp_top_->generate_r1cs_witness();
				cmp_bot_->generate_r1cs_witness();
				pb.val(top_) = SFieldT::one() - pb.val(less_top_);
				SFieldT acc = SFieldT::one() - pb.val(inputs_[kSensorErrors]);
				for (int j = 1; j < window::kErrorFlags; ++j) {
					acc = acc * (SFieldT::one() - pb.val(inputs_[kSensorErrors + j]));
					pb.val(none_[j - 1]) = acc;
				}
				pb.val(err_) = SFieldT::one() - acc;
			}
		}
	}

	/// The bits this zone encrypts, as the circuit derived them (FlagBits / RawBits order).
	std::vector<uint8_t> Bits() const {
		auto bit = [&](const pb_variable<SFieldT>& v) { return (uint8_t)(pb.val(v) == SFieldT::one()); };
		std::vector<uint8_t> b;
		if (zone != Zone::Passenger) {
			for (const auto& v : inputs_) b.push_back(bit(v));
			return b;
		}
		b = {bit(inputs_[0]), bit(inputs_[1])};
		if (encoding == Encoding::Flags) {
			b.push_back(bit(top_));
			b.push_back(bit(bot_));
			b.push_back(bit(err_));
		} else {
			for (size_t j = 0; j < pos_bits_.size(); ++j) b.push_back(bit(pos_bits_[j]));
			for (int j = 0; j < window::kErrorFlags; ++j) b.push_back(bit(inputs_[kSensorErrors + j]));
		}
		return b;
	}

	/// The public input the verifier expects for round `round` (1-based).
	r1cs_gg_ppzkadscsnark_primary_input<EcPP> PublicInput(size_t round) const {
		r1cs_gg_ppzkadscsnark_primary_input<EcPP> in = {SFieldT((long)round)};
		if (limits_) {
			in.push_back(SFieldT((long)window::kTop));
			in.push_back(SFieldT((long)window::kBottom));
		}
		return in;
	}

private:
	enum { kSensorPosition = 2, kSensorErrors = 3 };  // passenger: up, down, position, errors
	bool limits_ = false;  // passenger, flags: kTop and kBottom are public inputs
	std::vector<pb_variable<SFieldT>> inputs_;
	pb_variable<SFieldT> round_, top_limit_, bottom_limit_;
	std::unique_ptr<pb_state_structured<SFieldT>> counter_;
	pb_variable_array<SFieldT> pos_bits_, none_;
	std::shared_ptr<packing_gadget<SFieldT>> pos_pack_;
	pb_variable<SFieldT> less_top_, leq_top_, less_bot_, top_, bot_, err_;
	std::shared_ptr<comparison_gadget<SFieldT>> cmp_top_, cmp_bot_;
};

// ---------------------------------------------------------------- ADSC-SNARK per zone

struct AdscMessage::Impl {
	r1cs_gg_ppzkadscsnark_proof<EcPP> proof;
	r1cs_gg_ppzkadscsnark_commitment<EcPP> commitment;
};
AdscMessage::AdscMessage() : impl(new Impl) {}
AdscMessage::~AdscMessage() = default;
AdscMessage::AdscMessage(AdscMessage&&) noexcept = default;
AdscMessage& AdscMessage::operator=(AdscMessage&&) noexcept = default;

static r1cs_gg_ppzkadscsnark_keypair<EcPP> AdscGenerate(ZoneCircuit& c) {
	c.s_manager.init();
	return r1cs_gg_ppzkadscsnark_generator<EcPP>(c.constraint_system, c.pb.get_block_assignment(c.ID_BLOCK_STATE_IN),
			ZoneCircuit::SensorGroups(c.zone));
}

struct AdscSetup::Impl {
	ZoneCircuit circuit;
	r1cs_gg_ppzkadscsnark_keypair<EcPP> keypair;
	Impl(Zone z, Encoding e) : circuit(z, e), keypair(AdscGenerate(circuit)) {}
};
AdscSetup::AdscSetup(Zone zone, Encoding encoding) {
	Init();
	if (zone == Zone::Central) {
		std::fprintf(stderr, "ADSC: the central node has no inputs to prove\n");
		std::abort();
	}
	impl.reset(new Impl(zone, encoding));
}
AdscSetup::~AdscSetup() = default;
Zone AdscSetup::zone() const { return impl->circuit.zone; }
Encoding AdscSetup::encoding() const { return impl->circuit.encoding; }
size_t AdscSetup::constraints() const { return impl->circuit.constraint_system.num_constraints(); }

struct AdscProver::Impl {
	const AdscSetup::Impl& setup;
	ZoneCircuit circuit;  // the zone's own protoboard
	r1cs_gg_ppzkadscsnark_prover_state<EcPP> prover_state;
	size_t message_count = 0;
	std::vector<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>> inputs;  // one per sensor
	std::vector<uint8_t> bits;
	explicit Impl(const AdscSetup::Impl& s) : setup(s), circuit(s.circuit.zone, s.circuit.encoding) {
		circuit.s_manager.init();
	}
};
AdscProver::AdscProver(const AdscSetup& setup) : impl_(new Impl(*setup.impl)) {}
AdscProver::~AdscProver() = default;

void AdscProver::Authenticate(const std::vector<uint32_t>& values) {
	const auto groups = ZoneCircuit::SensorGroups(impl_->circuit.zone);
	if ((int)values.size() != ZoneCircuit::NumInputs(impl_->circuit.zone)) {
		std::fprintf(stderr, "ADSC: %zu sensor values for zone %s\n", values.size(), ZoneName(impl_->circuit.zone));
		std::abort();
	}
	const size_t mc = impl_->message_count++;
	const auto& aks = impl_->setup.keypair.aks;
	impl_->inputs.clear();
	size_t k = 0;
	for (size_t g = 0; g < groups.size(); ++g) {
		std::vector<SFieldT> v;
		for (size_t i = 0; i < groups[g]; ++i) v.push_back(SFieldT((long)values[k++]));
		impl_->inputs.push_back(r1cs_gg_ppzkadscsnark_authenticate(aks[g], mc, v));
	}
}

AdscMessage AdscProver::Prove() {
	ZoneCircuit& c = impl_->circuit;
	std::vector<SFieldT> values;
	for (const auto& a : impl_->inputs)
		for (const auto& v : a.values) values.push_back(v);
	c.Witness(values);
	impl_->bits = c.Bits();
	const auto primary = c.pb.primary_input();
	auto proof = r1cs_gg_ppzkadscsnark_prover<EcPP>(impl_->setup.keypair.pk, c.constraint_system, primary,
			impl_->inputs, c.pb.get_block_assignment(c.ID_BLOCK_STATE_IN), c.pb.get_block_assignment(c.ID_BLOCK_STATE_OUT),
			c.pb.get_free_assignment(), impl_->prover_state);
	AdscMessage m;
	m.impl->proof = proof.first;
	m.impl->commitment = proof.second;
	m.proof_bytes = (m.impl->proof.size_in_bits() + m.impl->commitment.size_in_bits() + 7) / 8;
	c.s_manager.update();
	return m;
}

const std::vector<uint8_t>& AdscProver::bits() const { return impl_->bits; }

struct AdscVerifier::Impl {
	const AdscSetup::Impl& setup;
	r1cs_gg_ppzkadscsnark_processed_verification_key<EcPP> pvk;
	r1cs_gg_ppzkadscsnark_commitment<EcPP> previous_commitment;
	uint16_t message_count = 0;
	explicit Impl(const AdscSetup::Impl& s) : setup(s) {}
};
AdscVerifier::AdscVerifier(const AdscSetup& setup) : impl_(new Impl(*setup.impl)) {
	impl_->pvk = r1cs_gg_ppzkadscsnark_verifier_process_vk(setup.impl->keypair.vk);
	impl_->previous_commitment = setup.impl->keypair.initial_commitment;
}
AdscVerifier::~AdscVerifier() = default;

bool AdscVerifier::Verify(const AdscMessage& m) {
	const uint16_t mc = impl_->message_count++;
	const bool ok = r1cs_gg_ppzkadscsnark_online_verifier_strong_IC<EcPP>(impl_->pvk,
			impl_->setup.circuit.PublicInput(mc + 1), m.impl->proof, m.impl->commitment, impl_->previous_commitment, mc);
	if (ok) impl_->previous_commitment = m.impl->commitment;
	return ok;
}

// ---------------------------------------------------------------- BN254 Schnorr

static libff::Fr<EcPP> HashToFr(const std::string& m) {
	unsigned char d[SHA256_DIGEST_LENGTH];
	SHA256(reinterpret_cast<const unsigned char*>(m.data()), m.size(), d);
	libff::Fr<EcPP> acc = libff::Fr<EcPP>::zero(), base = libff::Fr<EcPP>::one();
	const libff::Fr<EcPP> b256 = libff::Fr<EcPP>(256);
	for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
		acc += base * libff::Fr<EcPP>((long)d[i]);
		base *= b256;
	}
	return acc;
}

struct Bn254Schnorr::Impl {
	libff::Fr<EcPP> sk;
	libff::G1<EcPP> pk;
};
Bn254Schnorr::Bn254Schnorr() : impl_(new Impl) {
	Init();
	impl_->sk = libff::Fr<EcPP>::random_element();
	impl_->pk = impl_->sk * libff::G1<EcPP>::one();
}
Bn254Schnorr::~Bn254Schnorr() = default;

// Signature: R (affine G1) and s = k + e*sk with e = H(R || msg); serialized as text.
std::vector<uint8_t> Bn254Schnorr::Sign(const uint8_t* msg, size_t len) const {
	const libff::Fr<EcPP> k = libff::Fr<EcPP>::random_element();
	libff::G1<EcPP> R = k * libff::G1<EcPP>::one();
	R.to_affine_coordinates();
	std::ostringstream rs;
	rs << R;
	const libff::Fr<EcPP> e = HashToFr(rs.str() + std::string(reinterpret_cast<const char*>(msg), len));
	const libff::Fr<EcPP> s = k + e * impl_->sk;
	std::ostringstream out;
	out << R << s;
	const std::string str = out.str();
	return std::vector<uint8_t>(str.begin(), str.end());
}

bool Bn254Schnorr::Verify(const uint8_t* msg, size_t len, const std::vector<uint8_t>& sig) const {
	std::istringstream in(std::string(sig.begin(), sig.end()));
	libff::G1<EcPP> R;
	libff::Fr<EcPP> s;
	in >> R >> s;
	std::ostringstream rs;
	rs << R;
	const libff::Fr<EcPP> e = HashToFr(rs.str() + std::string(reinterpret_cast<const char*>(msg), len));
	return s * libff::G1<EcPP>::one() == R + e * impl_->pk;
}

}  // namespace zk
}  // namespace ipcei
