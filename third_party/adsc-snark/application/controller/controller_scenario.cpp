/** @file
 *****************************************************************************

 Demo application for a 3-DOF PID Controller

 Generator: Setup Relation and send authentication, verification and prover
 keys to other parties. Generator is assumed to be honest.

 4 Sensors: SensorInputCmd1, SensorInputCmd2, SensorMeasurement1, SensorMeasurement2,
 two of each type measure the same physical quantity for redundancy.
 Sensors authenticate their measurements and send them to the device.

 Device: Control Unit that executes a control law to compute some control outputs
 and a proof, that certifies the correctness of the control outputs

 Verifier: Verifying party, that accepts control outputs and uses proof
 to check their correctness

 *****************************************************************************/

#include <string>
#include <sstream>
#include <boost/program_options.hpp>

#include "libff/common/default_types/ec_pp.hpp"
#include "libsnark/gadgetlib1/protoboard_structured.hpp"
#include "libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppzkadscsnark/r1cs_gg_ppzkadscsnark.hpp"
#include "libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp"
#include "libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.hpp"

#include "scenario_network.h"
#include "application/gadgets/duplex_voter_gadget.hpp"
#include "application/gadgets/control_gadgets_structured.hpp"

typedef libff::default_ec_pp EcPP;
typedef libff::Fr<EcPP> SFieldT;


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

public:
    static const int ID_BLOCK_IO = 0;
    static const int ID_BLOCK_PRIVATE_INPUTS = 1;
    static const int ID_BLOCK_STATE_IN = 2;
    static const int ID_BLOCK_STATE_OUT = 3;

    static const int NUM_PUBLIC_IO = 3; // output_x/y/z
    static const int NUM_PRIVATE_INPUTS = 12; // 2 * cmd_x/y/z + 2 * measured_x/y/z
    static const int NUM_STATES = 9; // 3* 1 (PT1 filter) + 3*2 (PID controller)

    typedef controller_gadget<SFieldT> ctrl_gadget;
    structured_protoboard<SFieldT> pb;
    state_manager<SFieldT> s_manager;

    std::shared_ptr<ctrl_gadget> g;
    r1cs_gg_ppzkadscsnark_constraint_system<EcPP> constraint_system;
    size_t label_cmd_x_1;
    size_t label_cmd_x_2;
    size_t label_cmd_y_1;
    size_t label_cmd_y_2;
    size_t label_cmd_z_1;
    size_t label_cmd_z_2;
    size_t label_measured_x_1;
    size_t label_measured_x_2;
    size_t label_measured_y_1;
    size_t label_measured_y_2;
    size_t label_measured_z_1;
    size_t label_measured_z_2;

    ProtoboardSetup(const std::string &annotation_prefix="")
            : pb(), s_manager(pb, ID_BLOCK_STATE_IN, ID_BLOCK_STATE_OUT)
    {
        pb.reserve_block(ID_BLOCK_IO, NUM_PUBLIC_IO);
        pb.reserve_block(ID_BLOCK_PRIVATE_INPUTS, NUM_PRIVATE_INPUTS);
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

        label_cmd_x_1 = cmd_x_1.index;
        label_cmd_x_2 = cmd_x_2.index;
        label_cmd_y_1 = cmd_y_1.index;
        label_cmd_y_2 = cmd_y_2.index;
        label_cmd_z_1 = cmd_z_1.index;
        label_cmd_z_2 = cmd_z_2.index;

        label_measured_x_1 = measured_x_1.index;
        label_measured_x_2 = measured_x_2.index;
        label_measured_y_1 = measured_y_1.index;
        label_measured_y_2 = measured_y_2.index;
        label_measured_z_1 = measured_z_1.index;
        label_measured_z_2 = measured_z_2.index;

        output_x.allocate_from_block(pb, ID_BLOCK_IO, "output_x");
        output_y.allocate_from_block(pb, ID_BLOCK_IO, "output_y");
        output_z.allocate_from_block(pb, ID_BLOCK_IO, "output_z");
        g.reset(new ctrl_gadget(pb,
                                s_manager,
                                cmd_x_1,
       cmd_x_2,
        cmd_y_1,
        cmd_y_2,
        cmd_z_1,
        cmd_z_2,
        measured_x_1,
        measured_x_2,
        measured_y_1,
        measured_y_2,
        measured_z_1,
        measured_z_2,
        output_x,
        output_y,
        output_z,
        annotation_prefix));

        pb.set_input_sizes(NUM_PUBLIC_IO);
        g->generate_r1cs_constraints();
        assert(pb.blocks_fully_allocated());

        if (!libff::inhibit_profiling_info)
        {
            std::cout << "Number of constraints before transformation: " << pb.num_constraints() << std::endl;
        }
        constraint_system = r1cs_to_r1cs_adsc(pb.get_constraint_system(), NUM_PRIVATE_INPUTS, NUM_STATES);
        if (!libff::inhibit_profiling_info)
        {
            std::cout << "Number of constraints after transformation: " << constraint_system.num_constraints() << std::endl;
        }

    }

    void generate_r1cs_witness(SFieldT cmd_x_1_val, SFieldT cmd_x_2_val,
                               SFieldT cmd_y_1_val, SFieldT cmd_y_2_val,
                               SFieldT cmd_z_1_val, SFieldT cmd_z_2_val,
                               SFieldT measured_x_1_val, SFieldT measured_x_2_val,
                               SFieldT measured_y_1_val, SFieldT measured_y_2_val,
                               SFieldT measured_z_1_val, SFieldT measured_z_2_val){
        pb.val(this->cmd_x_1) = cmd_x_1_val;
        pb.val(this->cmd_x_2) = cmd_x_2_val;
        pb.val(this->cmd_y_1) = cmd_y_1_val;
        pb.val(this->cmd_y_2) = cmd_y_2_val;
        pb.val(this->cmd_z_1) = cmd_z_1_val;
        pb.val(this->cmd_z_2) = cmd_z_2_val;
        pb.val(this->measured_x_1) = measured_x_1_val;
        pb.val(this->measured_x_2) = measured_x_2_val;
        pb.val(this->measured_y_1) = measured_y_1_val;
        pb.val(this->measured_y_2) = measured_y_2_val;
        pb.val(this->measured_z_1) = measured_z_1_val;
        pb.val(this->measured_z_2) = measured_z_2_val;
        g->generate_r1cs_witness();
    }

};

struct longv3{
    long x;
    long y;
    long z;
};


class Sensor: NetworkParticipant {
private:
    size_t message_count;
    r1cs_gg_ppzkadscsnark_authentication_key<EcPP> authentication_key;

protected:
    int sample_count;
    virtual longv3 get_sample() = 0;
public:
    Sensor(std::string name="Sensor", Communicator &comm=default_comm) : NetworkParticipant(name, comm),
                                                                        message_count(0),  sample_count(0)
        {}
    void setup();
    void run();

};

void Sensor::setup(){
    authentication_key = this->receive_from<r1cs_gg_ppzkadscsnark_authentication_key<EcPP>>("authentication-key", "Generator");
}

void Sensor::run(){
    longv3 value = get_sample();
    size_t mc = message_count++;

    // Authenticate
    r1cs_gg_ppzkadscsnark_authenticated_input<EcPP> authenticated_input = r1cs_gg_ppzkadscsnark_authenticate(
        authentication_key, mc,
        {SFieldT(value.x),
                SFieldT(value.y),
                SFieldT(value.z)});

    this->send_to(authenticated_input, "input", "Device");
}

class SensorInputCmd: public Sensor {
protected:
    longv3 get_sample();

public:
    SensorInputCmd(std::string name="SensorInputCmd", Communicator &comm=default_comm) : Sensor(name, comm)
    {}
};

longv3 SensorInputCmd::get_sample() {
    ++sample_count;
    longv3 sample;
    sample.x = sin(2.0*M_PI / 50.0 * (double) sample_count)*5000.0;
    sample.y = sin(2.0*M_PI / 100.0 * (double) sample_count + 0.25*2.0*M_PI)*5000.0;
    sample.z = sin(2.0*M_PI / 80.0 * (double) sample_count + 0.333*2.0*M_PI)*5000.0;
    return sample;
}


class SensorMeasurement: public Sensor {
protected:
    longv3 get_sample();

public:
    SensorMeasurement(std::string name="SensorMeasurement", Communicator &comm=default_comm) : Sensor(name, comm)
    {}
};

longv3 SensorMeasurement::get_sample() {
    ++sample_count;
    longv3 sample;
    sample.x = sin(2.0*M_PI / 8.0 * (double) sample_count)*190.0;
    sample.y = sin(2.0*M_PI / 4.0 * (double) sample_count)*210.0;
    sample.z = sin(2.0*M_PI / 3.0 * (double) sample_count)*100.0;
    return sample;
}


class Device : NetworkParticipant{
private:
    r1cs_gg_ppzkadscsnark_proving_key<EcPP> pk;
    std::shared_ptr<ProtoboardSetup> ps;
    r1cs_gg_ppzkadscsnark_prover_state<EcPP> prover_state;

public:
    Device(std::string name="Device", Communicator &comm=default_comm) :
        NetworkParticipant(name, comm)
        {}
    void setup(); // Receive prover key
    void run();
};

void Device::setup(){
    pk = this->receive_from<r1cs_gg_ppzkadscsnark_proving_key<EcPP>>("pk", "Generator");
    ps.reset(new ProtoboardSetup("g"));
    ps->s_manager.init();
}

void Device::run(){
    r1cs_gg_ppzkadscsnark_primary_input<EcPP> primary_input;
    r1cs_gg_ppzkadscsnark_assignment<EcPP> state_input;
    r1cs_gg_ppzkadscsnark_assignment<EcPP> state_update_input;
    r1cs_gg_ppzkadscsnark_assignment<EcPP> witness_input;

    auto cmd_1 = this->receive_from<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>>("input", "SensorInputCmd1");
    auto cmd_2 = this->receive_from<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>>("input", "SensorInputCmd2");
    auto measured_1 = this->receive_from<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>>("input", "SensorMeasurement1");
    auto measured_2 = this->receive_from<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>>("input", "SensorMeasurement2");

    ps->generate_r1cs_witness(cmd_1.values[0], cmd_2.values[0],
                                cmd_1.values[1], cmd_2.values[1],
                                cmd_1.values[2], cmd_2.values[2],
                            measured_1.values[0], measured_2.values[0],
                            measured_1.values[1], measured_2.values[1],
                            measured_1.values[2], measured_2.values[2]);

    primary_input = ps->pb.primary_input();
    state_input = ps->pb.get_block_assignment(ps->ID_BLOCK_STATE_IN);
    state_update_input = ps->pb.get_block_assignment(ps->ID_BLOCK_STATE_OUT);
    witness_input = ps->pb.get_free_assignment();

#ifdef DEBUG
    r1cs_auxiliary_input<SFieldT> auxiliary_input;
    auxiliary_input.insert(auxiliary_input.end(), cmd_1.values.begin(), cmd_1.values.end());
    auxiliary_input.insert(auxiliary_input.end(), cmd_2.values.begin(), cmd_2.values.end());
    auxiliary_input.insert(auxiliary_input.end(), measured_1.values.begin(), measured_1.values.end());
    auxiliary_input.insert(auxiliary_input.end(), measured_2.values.begin(), measured_2.values.end());
    auxiliary_input.insert(auxiliary_input.end(), state_input.begin(), state_input.end());
    auxiliary_input.insert(auxiliary_input.end(), state_update_input.begin(), state_update_input.end());
    auxiliary_input.insert(auxiliary_input.end(), witness_input.begin(), witness_input.end());
    assert(ps->constraint_system.is_satisfied(primary_input, auxiliary_input));
#endif

    std::pair<r1cs_gg_ppzkadscsnark_proof<EcPP>,
                r1cs_gg_ppzkadscsnark_commitment<EcPP>> proof = r1cs_gg_ppzkadscsnark_prover<EcPP>(pk,
                                     ps->constraint_system,
                                     primary_input,
                                     {cmd_1, cmd_2, measured_1, measured_2},
                                     state_input,
                                     state_update_input,
                                     witness_input,
                                     prover_state);

    this->send_to(primary_input, "values", "Verifier");
    this->send_to(proof.first, "proof", "Verifier");
    this->send_to(proof.second, "commitment", "Verifier");
    ps->s_manager.update();
}

class Generator : NetworkParticipant{
public:
    Generator(std::string name="Generator", Communicator &comm=default_comm) : NetworkParticipant(name, comm) {}
    void setup();
};

void Generator::setup(){
    ProtoboardSetup ps("g");

    // Initialize state variables
    ps.s_manager.init();
    r1cs_gg_ppzkadscsnark_keypair<EcPP> keypair = r1cs_gg_ppzkadscsnark_generator<EcPP>(ps.constraint_system,
                                                                                    ps.pb.get_block_assignment(ps.ID_BLOCK_STATE_IN),
                                                                                    {3, 3, 3, 3}); // each of the 4 sensors provides 3 values
    assert(keypair.aks.size() == 4);

    this->send_to(keypair.pk, "pk", "Device");
    this->send_to(keypair.vk, "vk", "Verifier");
    this->send_to(keypair.initial_commitment, "initial_commitment", "Verifier");
    this->send_to(keypair.aks[0], "authentication-key", "SensorInputCmd1");
    this->send_to(keypair.aks[1], "authentication-key", "SensorInputCmd2");
    this->send_to(keypair.aks[2], "authentication-key", "SensorMeasurement1");
    this->send_to(keypair.aks[3], "authentication-key", "SensorMeasurement2");
}

class Verifier : NetworkParticipant{
private:
    int message_count;
    r1cs_gg_ppzkadscsnark_commitment<EcPP> previous_commitment;
    r1cs_gg_ppzkadscsnark_processed_verification_key<EcPP> pvk;
public:
    int confirmed_count;
    int error_count;
    Verifier(std::string name="Verifier", Communicator &comm=default_comm, bool silent = false) :
    NetworkParticipant(name, comm, silent), message_count(0), confirmed_count(0), error_count(0) {}
    void setup();
    void run();
};

void Verifier::setup(){
    r1cs_gg_ppzkadscsnark_verification_key<EcPP> vk = this->receive_from<r1cs_gg_ppzkadscsnark_verification_key<EcPP>>("vk", "Generator");
    pvk = r1cs_gg_ppzkadscsnark_verifier_process_vk(vk);
    previous_commitment = this->receive_from<r1cs_gg_ppzkadscsnark_commitment<EcPP>>("initial_commitment", "Generator");
}

void Verifier::run(){
    const uint16_t mc = message_count++;

    const auto primary_input = this->receive_from<r1cs_gg_ppzkadscsnark_primary_input<EcPP>>("values", "Device");
    const auto proof = this->receive_from<r1cs_gg_ppzkadscsnark_proof<EcPP>>("proof", "Device");
    const auto commitment = this->receive_from<r1cs_gg_ppzkadscsnark_commitment<EcPP>>("commitment", "Device");

    assert(primary_input.size() == 3);
    const long output_x = field_to_signed_int(primary_input[0]);
    const long output_y = field_to_signed_int(primary_input[1]);
    const long output_z = field_to_signed_int(primary_input[2]);

    const bool verified = r1cs_gg_ppzkadscsnark_online_verifier_strong_IC<EcPP>(pvk, primary_input, proof, commitment, previous_commitment, mc);
    if (!verified && !silent){
        std::cerr << "SNARK does not verify" << std::endl;
    }

    previous_commitment = commitment;
    if (!silent)
    {
        std::cout << " Outputs: x=" << output_x << " y=" << output_y << " z=" << output_z << " Verified: " << verified
                  << std::endl;
    }
    if(verified){
        confirmed_count++;
    }else{
        error_count++;
    }
}



int main(int argc, char *argv[]) {
    namespace po = boost::program_options;
    int rounds;
    std::cout << "Controller Scenario" << std::endl;
    po::options_description desc("Usage");
    po::variables_map vm;
    desc.add_options()
            ("help", "show help")
            ("generator", "Generate prover and verifier key")
            ("sensor", "Run the sensor")
            ("device", "Calculate commands and generate proof")
            ("verifier", "Check proof")
            ("all", "Run generator, sensors, device and verifier")
            ("silent", "Do not print outputs")
            ("rounds", po::value<int>(&rounds)->default_value(1), "run complete scenario with number of rounds")
            ("file", "Write outputs to a file");

    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help") || argc <= 1) {
        std::cout << desc << std::endl;
        return 1;
    }

    EcPP::init_public_params();
#ifdef SIGNATURE_SNARKFRIENDLY
    EC_Inner<EcPP>::init_public_params();
#endif

    bool silent = vm.count("silent") > 0;

    // Disable profiling
#ifndef DEBUG
    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;
#endif

    Communicator communicator;

    if (vm.count("test")){
        //return test_circuit();
        return -1;
    }

    if(vm.count("file")){
        communicator = Communicator(Communicator::CommunicationMode::File);
    } else{
        communicator = Communicator(Communicator::CommunicationMode::Ram);
    }

    Generator gen("Generator", communicator);
    Device device("Device", communicator);
    SensorInputCmd sensorInputCmd1("SensorInputCmd1", communicator);
    SensorInputCmd sensorInputCmd2("SensorInputCmd2", communicator);
    SensorMeasurement sensorMeasurement1("SensorMeasurement1", communicator);
    SensorMeasurement sensorMeasurement2("SensorMeasurement2", communicator);
    Verifier ver("Verifier", communicator, silent);

    if(vm.count("generator") || vm.count("all")) {
        std::cout << "generator ";
        gen.setup();
    }

    if (vm.count("sensor") || vm.count("all")) {
        std::cout << "sensor ";
        sensorInputCmd1.setup();
        sensorInputCmd2.setup();
        sensorMeasurement1.setup();
        sensorMeasurement2.setup();
    }

    if (vm.count("device") || vm.count("all")) {
        std::cout << "device ";
        device.setup();
    }

    if (vm.count("verifier") || vm.count("all")) {
        std::cout << "verifier ";
        ver.setup();
    }
    std::cout << std::endl;

    long long start_time, end_time;

    start_time = libff::get_nsec_time();
    for(int i = 0; i < rounds; i++) {
        if (vm.count("sensor") || vm.count("all")) {
            sensorInputCmd1.run();
            sensorInputCmd2.run();
            sensorMeasurement1.run();
            sensorMeasurement2.run();
        }
        if (vm.count("device") || vm.count("all")) {
            device.run();
        }
        if (vm.count("verifier") || vm.count("all")) {
            ver.run();
        }
        communicator.tick();
    }
    end_time = libff::get_nsec_time();

    std::cout << rounds << " rounds completed." << std::endl;
    if(vm.count("verifier") || vm.count("all")) {
        std::cout << "Verifier - Confirmed: " << ver.confirmed_count << " (Errors: " << ver.error_count << ")" << std::endl;
    }
    std::cout << "Duration: " << (end_time - start_time) / 1000 << "us, = " << (end_time - start_time) / 1000 / rounds << "us per round" << std::endl;

}