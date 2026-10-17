// zk.cpp — the ADSC-SNARK of the end node (PID control law + flag comparisons) and BN254
// Schnorr on the vendored libsnark (third_party/adsc-snark). Compiled at C++14. Interface: zk.hpp.
//
// The PID circuit (controller_gadget) is copied verbatim from
// third_party/adsc-snark/application/controller/controller_scenario.cpp (MIT, Johannes
// Reinhart), between the "verbatim" markers. ProtoboardSetup follows that scenario's and
// adds the threshold sensors and their comparisons; the sensor sample generators, the
// device and the verifier follow the scenario's Sensor / Device / Verifier classes.
#include "ipcei/zk.hpp"

#include <cassert>
#include <cmath>
#include <cstdio>
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
#include "libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.hpp"
#include "libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp"
#include "libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppzkadscsnark/r1cs_gg_ppzkadscsnark.hpp"
#include "libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp"

#include "application/gadgets/duplex_voter_gadget.hpp"  // before control_gadgets_structured.hpp, as in the scenario
#include "application/gadgets/control_gadgets_structured.hpp"
#include "application/gadgets/utils.h"

using namespace libsnark;
typedef libff::default_ec_pp EcPP;
typedef libff::Fr<EcPP> SFieldT;

// ======================= verbatim from controller_scenario.cpp (begin) =======================
template<typename FieldT>
class controller_gadget : public gadget<FieldT> {
private:
    std::shared_ptr<duplex_voter_gadget<FieldT>> vote_cmd_x_gadget;
    std::shared_ptr<duplex_voter_gadget<FieldT>> vote_cmd_y_gadget;
    std::shared_ptr<duplex_voter_gadget<FieldT>> vote_cmd_z_gadget;
    std::shared_ptr<duplex_voter_gadget<FieldT>> vote_measured_x_gadget;
    std::shared_ptr<duplex_voter_gadget<FieldT>> vote_measured_y_gadget;
    std::shared_ptr<duplex_voter_gadget<FieldT>> vote_measured_z_gadget;
    std::shared_ptr<pt1_structured_gadget<FieldT>> filter_cmd_x_gadget;
    std::shared_ptr<pt1_structured_gadget<FieldT>> filter_cmd_y_gadget;
    std::shared_ptr<pt1_structured_gadget<FieldT>> filter_cmd_z_gadget;
    std::shared_ptr<limit_gadget<FieldT>> limit_cmd_x_gadget;
    std::shared_ptr<limit_gadget<FieldT>> limit_cmd_y_gadget;
    std::shared_ptr<limit_gadget<FieldT>> limit_cmd_z_gadget;
    std::shared_ptr<pid_structured_gadget<FieldT>> pid_x_gadget;
    std::shared_ptr<pid_structured_gadget<FieldT>> pid_y_gadget;
    std::shared_ptr<pid_structured_gadget<FieldT>> pid_z_gadget;

    pb_variable<FieldT> cmd_x_voted;
    pb_variable<FieldT> cmd_y_voted;
    pb_variable<FieldT> cmd_z_voted;
    pb_variable<FieldT> cmd_x_filtered;
    pb_variable<FieldT> cmd_y_filtered;
    pb_variable<FieldT> cmd_z_filtered;
    pb_variable<FieldT> cmd_x_limited;
    pb_variable<FieldT> cmd_y_limited;
    pb_variable<FieldT> cmd_z_limited;
    pb_variable<FieldT> measured_x_voted;
    pb_variable<FieldT> measured_y_voted;
    pb_variable<FieldT> measured_z_voted;

public:
    const pb_variable<FieldT> &cmd_x_1;
    const pb_variable<FieldT> &cmd_x_2;
    const pb_variable<FieldT> &cmd_y_1;
    const pb_variable<FieldT> &cmd_y_2;
    const pb_variable<FieldT> &cmd_z_1;
    const pb_variable<FieldT> &cmd_z_2;

    const pb_variable<FieldT> &measured_x_1;
    const pb_variable<FieldT> &measured_x_2;
    const pb_variable<FieldT> &measured_y_1;
    const pb_variable<FieldT> &measured_y_2;
    const pb_variable<FieldT> &measured_z_1;
    const pb_variable<FieldT> &measured_z_2;

    const pb_variable<FieldT> &output_x;
    const pb_variable<FieldT> &output_y;
    const pb_variable<FieldT> &output_z;

    controller_gadget(structured_protoboard<FieldT>& pb,
                          ::state_manager<FieldT> &s_manager,
                    const pb_variable<FieldT> &cmd_x_1,
                    const pb_variable<FieldT> &cmd_x_2,
                    const pb_variable<FieldT> &cmd_y_1,
                    const pb_variable<FieldT> &cmd_y_2,
                    const pb_variable<FieldT> &cmd_z_1,
                    const pb_variable<FieldT> &cmd_z_2,

                    const pb_variable<FieldT> &measured_x_1,
                    const pb_variable<FieldT> &measured_x_2,
                    const pb_variable<FieldT> &measured_y_1,
                    const pb_variable<FieldT> &measured_y_2,
                    const pb_variable<FieldT> &measured_z_1,
                    const pb_variable<FieldT> &measured_z_2,

                    const pb_variable<FieldT> &output_x,
                    const pb_variable<FieldT> &output_y,
                    const pb_variable<FieldT> &output_z,
                          const std::string &annotation_prefix="") :
            gadget<FieldT>(pb, annotation_prefix),
            cmd_x_1(cmd_x_1), cmd_x_2(cmd_x_2), cmd_y_1(cmd_y_1), cmd_y_2(cmd_y_2), cmd_z_1(cmd_z_1), cmd_z_2(cmd_z_2),
            measured_x_1(measured_x_1), measured_x_2(measured_x_2), measured_y_1(measured_y_1), measured_y_2(measured_y_2),
            measured_z_1(measured_z_1), measured_z_2(measured_z_2),
            output_x(output_x), output_y(output_y), output_z(output_z)
    {
        const size_t word_size = 30;
        const double sampling_time = 0.05;
        const int voting_limit = 20;
        const double filter_time = 0.5;
        const double filter_amplification = 1.0;
        const unsigned int filter_precision = 16;
        const int input_limit_min = -10000;
        const int input_limit_max = 10000;
        const double controller_p_gain = 0.2;
        const double controller_i_gain = 0.5;
        const double controller_d_gain = 0.05;
        const double controller_filter_time = 0.1;
        const unsigned int controller_precision = 16;

        cmd_x_voted.allocate(pb, "cmd_x_voted");
        cmd_y_voted.allocate(pb, "cmd_y_voted");
        cmd_z_voted.allocate(pb, "cmd_z_voted");
        vote_cmd_x_gadget.reset(new duplex_voter_gadget<FieldT>(pb, cmd_x_1, cmd_x_2, cmd_x_voted, word_size, voting_limit, FMT(this->annotation_prefix, ".vote_cmd_x")));
        vote_cmd_y_gadget.reset(new duplex_voter_gadget<FieldT>(pb, cmd_y_1, cmd_y_2, cmd_y_voted, word_size, voting_limit, FMT(this->annotation_prefix, ".vote_cmd_y")));
        vote_cmd_z_gadget.reset(new duplex_voter_gadget<FieldT>(pb, cmd_z_1, cmd_z_2, cmd_z_voted, word_size, voting_limit, FMT(this->annotation_prefix, ".vote_cmd_z")));

        measured_x_voted.allocate(pb, "measured_x_voted");
        measured_y_voted.allocate(pb, "measured_y_voted");
        measured_z_voted.allocate(pb, "measured_z_voted");
        vote_measured_x_gadget.reset(new duplex_voter_gadget<FieldT>(pb, measured_x_1, measured_x_2, measured_x_voted, word_size, voting_limit, FMT(this->annotation_prefix, ".vote_measured_x")));
        vote_measured_y_gadget.reset(new duplex_voter_gadget<FieldT>(pb, measured_y_1, measured_y_2, measured_y_voted, word_size, voting_limit, FMT(this->annotation_prefix, ".vote_measured_y")));
        vote_measured_z_gadget.reset(new duplex_voter_gadget<FieldT>(pb, measured_z_1, measured_z_2, measured_z_voted, word_size, voting_limit, FMT(this->annotation_prefix, ".vote_measured_z")));

        cmd_x_filtered.allocate(pb, "cmd_x_filtered");
        cmd_y_filtered.allocate(pb, "cmd_y_filtered");
        cmd_z_filtered.allocate(pb, "cmd_z_filtered");
        filter_cmd_x_gadget.reset(new pt1_structured_gadget<FieldT>(pb, s_manager, cmd_x_voted, cmd_x_filtered, filter_amplification, filter_time, sampling_time, filter_precision, word_size, FMT(this->annotation_prefix, ".pt1_x")));
        filter_cmd_y_gadget.reset(new pt1_structured_gadget<FieldT>(pb, s_manager, cmd_y_voted, cmd_y_filtered, filter_amplification, filter_time, sampling_time, filter_precision, word_size, FMT(this->annotation_prefix, ".pt1_y")));
        filter_cmd_z_gadget.reset(new pt1_structured_gadget<FieldT>(pb, s_manager, cmd_z_voted, cmd_z_filtered, filter_amplification, filter_time, sampling_time, filter_precision, word_size, FMT(this->annotation_prefix, ".pt1_z")));

        cmd_x_limited.allocate(pb, "cmd_x_limited");
        cmd_y_limited.allocate(pb, "cmd_y_limited");
        cmd_z_limited.allocate(pb, "cmd_z_limited");
        limit_cmd_x_gadget.reset(new limit_gadget<FieldT>(pb, word_size, input_limit_min, input_limit_max, cmd_x_filtered, cmd_x_limited, FMT(this->annotation_prefix, ".limit_x")));
        limit_cmd_y_gadget.reset(new limit_gadget<FieldT>(pb, word_size, input_limit_min, input_limit_max, cmd_y_filtered, cmd_y_limited, FMT(this->annotation_prefix, ".limit_y")));
        limit_cmd_z_gadget.reset(new limit_gadget<FieldT>(pb, word_size, input_limit_min, input_limit_max, cmd_z_filtered, cmd_z_limited, FMT(this->annotation_prefix, ".limit_z")));

        pid_x_gadget.reset(new pid_structured_gadget<FieldT>(pb, s_manager, cmd_x_limited - measured_x_voted, output_x, controller_p_gain, controller_i_gain, controller_d_gain, controller_filter_time, sampling_time, controller_precision, word_size, FMT(this->annotation_prefix, ".pid_x")));
        pid_y_gadget.reset(new pid_structured_gadget<FieldT>(pb, s_manager, cmd_y_limited - measured_y_voted, output_y, controller_p_gain, controller_i_gain, controller_d_gain, controller_filter_time, sampling_time, controller_precision, word_size, FMT(this->annotation_prefix, ".pid_y")));
        pid_z_gadget.reset(new pid_structured_gadget<FieldT>(pb, s_manager, cmd_z_limited - measured_z_voted, output_z, controller_p_gain, controller_i_gain, controller_d_gain, controller_filter_time, sampling_time, controller_precision, word_size, FMT(this->annotation_prefix, ".pid_z")));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
void controller_gadget<FieldT>::generate_r1cs_constraints(){
    vote_cmd_x_gadget->generate_r1cs_constraints();
    vote_cmd_y_gadget->generate_r1cs_constraints();
    vote_cmd_z_gadget->generate_r1cs_constraints();
    vote_measured_x_gadget->generate_r1cs_constraints();
    vote_measured_y_gadget->generate_r1cs_constraints();
    vote_measured_z_gadget->generate_r1cs_constraints();
    filter_cmd_x_gadget->generate_r1cs_constraints();
    filter_cmd_y_gadget->generate_r1cs_constraints();
    filter_cmd_z_gadget->generate_r1cs_constraints();
    limit_cmd_x_gadget->generate_r1cs_constraints();
    limit_cmd_y_gadget->generate_r1cs_constraints();
    limit_cmd_z_gadget->generate_r1cs_constraints();
    pid_x_gadget->generate_r1cs_constraints();
    pid_y_gadget->generate_r1cs_constraints();
    pid_z_gadget->generate_r1cs_constraints();
}

template<typename FieldT>
void controller_gadget<FieldT>::generate_r1cs_witness(){
    vote_cmd_x_gadget->generate_r1cs_witness();
    vote_cmd_y_gadget->generate_r1cs_witness();
    vote_cmd_z_gadget->generate_r1cs_witness();
    vote_measured_x_gadget->generate_r1cs_witness();
    vote_measured_y_gadget->generate_r1cs_witness();
    vote_measured_z_gadget->generate_r1cs_witness();
    filter_cmd_x_gadget->generate_r1cs_witness();
    filter_cmd_y_gadget->generate_r1cs_witness();
    filter_cmd_z_gadget->generate_r1cs_witness();
    limit_cmd_x_gadget->generate_r1cs_witness();
    limit_cmd_y_gadget->generate_r1cs_witness();
    limit_cmd_z_gadget->generate_r1cs_witness();
    pid_x_gadget->generate_r1cs_witness();
    pid_y_gadget->generate_r1cs_witness();
    pid_z_gadget->generate_r1cs_witness();

}
// ======================= verbatim from controller_scenario.cpp (end) =========================

// The scenario's ProtoboardSetup, extended with the flag comparisons. On top of the four
// PID sensors (two command, two measurement, three values each), S threshold sensors
// each authenticate one w-bit reading, and the circuit computes
//     flag_i = (reading_i < threshold_i)
// as private wires. The thresholds are public inputs (the central node's policy); the
// readings and the flags never leave the end node. S = 0 is the scenario's circuit.
//
// Layout (the ADSC transformation needs the blocks in this order):
//   IO             output_x/y/z, then threshold_0..S-1                 (public)
//   PRIVATE_INPUTS cmd_{x,y,z}_1, cmd_{x,y,z}_2, measured_{x,y,z}_1, measured_{x,y,z}_2,
//                  reading_0..S-1                                       (authenticated)
//   STATE_IN/OUT   the 9 controller states
//   free           the controller's wires, then per sensor: reading bits, flag, reading <= threshold
class ProtoboardSetup {
private:
    pb_variable<SFieldT> cmd_x_1;
    pb_variable<SFieldT> cmd_x_2;
    pb_variable<SFieldT> cmd_y_1;
    pb_variable<SFieldT> cmd_y_2;
    pb_variable<SFieldT> cmd_z_1;
    pb_variable<SFieldT> cmd_z_2;

    pb_variable<SFieldT> measured_x_1;
    pb_variable<SFieldT> measured_x_2;
    pb_variable<SFieldT> measured_y_1;
    pb_variable<SFieldT> measured_y_2;
    pb_variable<SFieldT> measured_z_1;
    pb_variable<SFieldT> measured_z_2;

    pb_variable<SFieldT> output_x;
    pb_variable<SFieldT> output_y;
    pb_variable<SFieldT> output_z;

    std::vector<pb_variable<SFieldT>> threshold, reading, flag, less_or_eq;
    std::vector<pb_variable_array<SFieldT>> reading_bits;
    std::vector<std::shared_ptr<packing_gadget<SFieldT>>> reading_pack;  // range check: w bits
    std::vector<std::shared_ptr<comparison_gadget<SFieldT>>> compare;

public:
    static const int ID_BLOCK_IO = 0;
    static const int ID_BLOCK_PRIVATE_INPUTS = 1;
    static const int ID_BLOCK_STATE_IN = 2;
    static const int ID_BLOCK_STATE_OUT = 3;

    static const int NUM_PID_OUTPUTS = 3; // output_x/y/z
    static const int NUM_PID_INPUTS = 12; // 2 * cmd_x/y/z + 2 * measured_x/y/z
    static const int NUM_STATES = 9; // 3* 1 (PT1 filter) + 3*2 (PID controller)

    typedef controller_gadget<SFieldT> ctrl_gadget;
    const int S, w;
    structured_protoboard<SFieldT> pb;
    state_manager<SFieldT> s_manager;

    std::shared_ptr<ctrl_gadget> g;
    r1cs_gg_ppzkadscsnark_constraint_system<EcPP> constraint_system;

    ProtoboardSetup(int sensors, int width, const std::string &annotation_prefix="")
            : threshold(sensors), reading(sensors), flag(sensors), less_or_eq(sensors), reading_bits(sensors),
              reading_pack(sensors), compare(sensors), S(sensors), w(width),
              pb(), s_manager(pb, ID_BLOCK_STATE_IN, ID_BLOCK_STATE_OUT)
    {
        pb.reserve_block(ID_BLOCK_IO, NUM_PID_OUTPUTS + S);
        pb.reserve_block(ID_BLOCK_PRIVATE_INPUTS, NUM_PID_INPUTS + S);
        pb.reserve_block(ID_BLOCK_STATE_IN, NUM_STATES);
        pb.reserve_block(ID_BLOCK_STATE_OUT, NUM_STATES);

        cmd_x_1.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "cmd_x_1");
        cmd_y_1.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "cmd_y_1");
        cmd_z_1.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "cmd_z_1");
        cmd_x_2.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "cmd_x_2");
        cmd_y_2.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "cmd_y_2");
        cmd_z_2.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "cmd_z_2");

        measured_x_1.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "measured_x_1");
        measured_y_1.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "measured_y_1");
        measured_z_1.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "measured_z_1");
        measured_x_2.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "measured_x_2");
        measured_y_2.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "measured_y_2");
        measured_z_2.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "measured_z_2");
        for (int i = 0; i < S; ++i)
            reading[i].allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "reading");

        output_x.allocate_from_block(pb, ID_BLOCK_IO, "output_x");
        output_y.allocate_from_block(pb, ID_BLOCK_IO, "output_y");
        output_z.allocate_from_block(pb, ID_BLOCK_IO, "output_z");
        for (int i = 0; i < S; ++i)
            threshold[i].allocate_from_block(pb, ID_BLOCK_IO, "threshold");
        g.reset(new ctrl_gadget(pb, s_manager,
                                cmd_x_1, cmd_x_2, cmd_y_1, cmd_y_2, cmd_z_1, cmd_z_2,
                                measured_x_1, measured_x_2, measured_y_1, measured_y_2, measured_z_1, measured_z_2,
                                output_x, output_y, output_z, annotation_prefix));
        for (int i = 0; i < S; ++i) {
            flag[i].allocate(pb, "flag");
            less_or_eq[i].allocate(pb, "less_or_eq");
            reading_bits[i].allocate(pb, w, "reading_bits");
            reading_pack[i].reset(new packing_gadget<SFieldT>(pb, reading_bits[i], reading[i], "reading_pack"));
            compare[i].reset(new comparison_gadget<SFieldT>(pb, w, reading[i], threshold[i], flag[i], less_or_eq[i],
                                                            "compare"));
        }

        pb.set_input_sizes(NUM_PID_OUTPUTS + S);
        g->generate_r1cs_constraints();
        for (int i = 0; i < S; ++i) {
            reading_pack[i]->generate_r1cs_constraints(true);  // and every bit boolean
            compare[i]->generate_r1cs_constraints();
        }
        assert(pb.blocks_fully_allocated());
        constraint_system = r1cs_to_r1cs_adsc(pb.get_constraint_system(), NUM_PID_INPUTS + S, NUM_STATES);
    }

    // The authenticated inputs in block order; the thresholds of this round.
    void generate_r1cs_witness(const std::vector<SFieldT> &inputs, const std::vector<uint32_t> &thresholds) {
        assert((int)inputs.size() == NUM_PID_INPUTS + S && (int)thresholds.size() == S);
        const pb_variable<SFieldT>* in[NUM_PID_INPUTS] = {
            &cmd_x_1, &cmd_y_1, &cmd_z_1, &cmd_x_2, &cmd_y_2, &cmd_z_2,
            &measured_x_1, &measured_y_1, &measured_z_1, &measured_x_2, &measured_y_2, &measured_z_2};
        for (int i = 0; i < NUM_PID_INPUTS; ++i) pb.val(*in[i]) = inputs[i];
        for (int i = 0; i < S; ++i) {
            pb.val(reading[i]) = inputs[NUM_PID_INPUTS + i];
            pb.val(threshold[i]) = SFieldT((long)thresholds[i]);
        }
        g->generate_r1cs_witness();
        for (int i = 0; i < S; ++i) {
            reading_bits[i].fill_with_bits_of_field_element(pb, pb.val(reading[i]));
            reading_pack[i]->generate_r1cs_witness_from_bits();
            compare[i]->generate_r1cs_witness();
        }
    }

    bool flag_value(int i) const { return pb.val(flag[i]) == SFieldT::one(); }
};

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

// ---------------------------------------------------------------- ADSC-SNARK (PID + flags)

struct AdscMessage::Impl {
	r1cs_gg_ppzkadscsnark_primary_input<EcPP> primary_input;  // outputs, then thresholds
	r1cs_gg_ppzkadscsnark_proof<EcPP> proof;
	r1cs_gg_ppzkadscsnark_commitment<EcPP> commitment;
};
AdscMessage::AdscMessage() : output{0, 0, 0}, impl(new Impl) {}
AdscMessage::~AdscMessage() = default;
AdscMessage::AdscMessage(AdscMessage&&) noexcept = default;
AdscMessage& AdscMessage::operator=(AdscMessage&&) noexcept = default;

static r1cs_gg_ppzkadscsnark_keypair<EcPP> AdscGenerate(ProtoboardSetup& ps) {
	ps.s_manager.init();
	// the 4 PID sensors provide 3 values each, every threshold sensor 1
	std::vector<size_t> sizes = {3, 3, 3, 3};
	sizes.insert(sizes.end(), ps.S, 1);
	return r1cs_gg_ppzkadscsnark_generator<EcPP>(ps.constraint_system,
			ps.pb.get_block_assignment(ps.ID_BLOCK_STATE_IN), sizes);
}

struct AdscSetup::Impl {
	ProtoboardSetup ps;
	r1cs_gg_ppzkadscsnark_keypair<EcPP> keypair;
	Impl(int S, int w) : ps(S, w, "g"), keypair(AdscGenerate(ps)) {}
};
AdscSetup::AdscSetup(int flag_sensors, int width) {
	Init();
	impl.reset(new Impl(flag_sensors, width));
}
AdscSetup::~AdscSetup() = default;
int AdscSetup::flag_sensors() const { return impl->ps.S; }
int AdscSetup::width() const { return impl->ps.w; }
size_t AdscSetup::constraints() const { return impl->ps.constraint_system.num_constraints(); }

// The scenario's sensor sample generators (SensorInputCmd, SensorMeasurement).
static void CmdSample(int k, long v[3]) {
	v[0] = sin(2.0 * M_PI / 50.0 * (double)k) * 5000.0;
	v[1] = sin(2.0 * M_PI / 100.0 * (double)k + 0.25 * 2.0 * M_PI) * 5000.0;
	v[2] = sin(2.0 * M_PI / 80.0 * (double)k + 0.333 * 2.0 * M_PI) * 5000.0;
}
static void MeasuredSample(int k, long v[3]) {
	v[0] = sin(2.0 * M_PI / 8.0 * (double)k) * 190.0;
	v[1] = sin(2.0 * M_PI / 4.0 * (double)k) * 210.0;
	v[2] = sin(2.0 * M_PI / 3.0 * (double)k) * 100.0;
}

struct AdscProver::Impl {
	const AdscSetup::Impl& setup;
	ProtoboardSetup ps;  // the device's own protoboard
	r1cs_gg_ppzkadscsnark_prover_state<EcPP> prover_state;
	size_t message_count = 0;
	// cmd1, cmd2, measured1, measured2, then one per threshold sensor
	std::vector<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>> inputs;
	std::vector<uint8_t> flags;
	explicit Impl(const AdscSetup::Impl& s) : setup(s), ps(s.ps.S, s.ps.w, "g") { ps.s_manager.init(); }
};
AdscProver::AdscProver(const AdscSetup& setup) : impl_(new Impl(*setup.impl)) {}
AdscProver::~AdscProver() = default;

void AdscProver::Authenticate(int round, const std::vector<uint32_t>& readings) {
	const int S = impl_->ps.S;
	if ((int)readings.size() != S) {
		std::fprintf(stderr, "ADSC: %zu readings for %d threshold sensors\n", readings.size(), S);
		std::abort();
	}
	const int k = round + 1;  // the scenario's sample_count before its first sample
	long cmd[3], measured[3];
	CmdSample(k, cmd);
	MeasuredSample(k, measured);
	const size_t mc = impl_->message_count++;
	const auto& aks = impl_->setup.keypair.aks;
	impl_->inputs.clear();
	const long* sample[4] = {cmd, cmd, measured, measured};  // two redundant sensors of each kind
	for (int i = 0; i < 4; ++i) {
		impl_->inputs.push_back(r1cs_gg_ppzkadscsnark_authenticate(aks[i], mc,
				{SFieldT(sample[i][0]), SFieldT(sample[i][1]), SFieldT(sample[i][2])}));
	}
	for (int i = 0; i < S; ++i)
		impl_->inputs.push_back(r1cs_gg_ppzkadscsnark_authenticate(aks[4 + i], mc, {SFieldT((long)readings[i])}));
}

AdscMessage AdscProver::Prove(const std::vector<uint32_t>& thresholds) {
	auto& in = impl_->inputs;
	ProtoboardSetup& ps = impl_->ps;
	assert((int)in.size() == 4 + ps.S && (int)thresholds.size() == ps.S);
	// block order: cmd1 x/y/z, cmd2 x/y/z, measured1 x/y/z, measured2 x/y/z, readings
	std::vector<SFieldT> values;
	for (const auto& a : in)
		for (const auto& v : a.values) values.push_back(v);
	ps.generate_r1cs_witness(values, thresholds);
	impl_->flags.resize(ps.S);
	for (int i = 0; i < ps.S; ++i) impl_->flags[i] = ps.flag_value(i);
	AdscMessage m;
	m.impl->primary_input = ps.pb.primary_input();
	auto state_input = ps.pb.get_block_assignment(ps.ID_BLOCK_STATE_IN);
	auto state_update_input = ps.pb.get_block_assignment(ps.ID_BLOCK_STATE_OUT);
	auto witness_input = ps.pb.get_free_assignment();
	auto proof = r1cs_gg_ppzkadscsnark_prover<EcPP>(impl_->setup.keypair.pk, ps.constraint_system,
			m.impl->primary_input, in, state_input, state_update_input, witness_input, impl_->prover_state);
	m.impl->proof = proof.first;
	m.impl->commitment = proof.second;
	m.proof_bytes = (m.impl->proof.size_in_bits() + m.impl->commitment.size_in_bits() + 7) / 8;
	for (int i = 0; i < 3; ++i) m.output[i] = field_to_signed_int(m.impl->primary_input[i]);
	ps.s_manager.update();
	return m;
}

const std::vector<uint8_t>& AdscProver::flags() const { return impl_->flags; }

struct AdscVerifier::Impl {
	int S;
	r1cs_gg_ppzkadscsnark_processed_verification_key<EcPP> pvk;
	r1cs_gg_ppzkadscsnark_commitment<EcPP> previous_commitment;
	uint16_t message_count = 0;
};
AdscVerifier::AdscVerifier(const AdscSetup& setup) : impl_(new Impl) {
	impl_->S = setup.impl->ps.S;
	impl_->pvk = r1cs_gg_ppzkadscsnark_verifier_process_vk(setup.impl->keypair.vk);
	impl_->previous_commitment = setup.impl->keypair.initial_commitment;
}
AdscVerifier::~AdscVerifier() = default;

bool AdscVerifier::Verify(const AdscMessage& m, const std::vector<uint32_t>& thresholds) {
	const uint16_t mc = impl_->message_count++;
	const int S = impl_->S;
	if ((int)thresholds.size() != S || (int)m.impl->primary_input.size() != 3 + S) return false;
	// the verifier's own thresholds, not the ones the message claims
	auto input = m.impl->primary_input;
	for (int i = 0; i < S; ++i) input[3 + i] = SFieldT((long)thresholds[i]);
	const bool ok = r1cs_gg_ppzkadscsnark_online_verifier_strong_IC<EcPP>(impl_->pvk, input, m.impl->proof,
			m.impl->commitment, impl_->previous_commitment, mc);
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
