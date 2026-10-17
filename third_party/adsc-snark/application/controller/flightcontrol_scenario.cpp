/** @file
 *****************************************************************************

 Demo application for a fixed-wing flight controller, inspired by
 A320 flight control (normal law), consisting of:
    - lateral control law
    - longitudinal control law
    - bank angle protection
    - pitch attitude protection
    - high angle-of-attack protection
    - high speed protection

 Inputs are:
    From ADIRU:
    - roll rate, pitch rate, yaw rate
    - speed, angle-of-attack, sideslip
    - load factor (vertical acceleration)
    - pitch angle, roll angle
    From Pilot Controls Transducer (Sidestick):
    - pitch command
    - roll command
    - sideslip command

 Outputs are:
    - THS position command
    - elevator deflection command
    - aileron deflection command
    - rudder deflection command

 In each iteration, the flight control computer computes an ADSC-SNARK proof which
 attests for the correctness of the output.

 Generator: Setup Relation and send authentication, verification and prover
 keys to other parties. Generator is assumed to be honest.

 Sensors:
 2x ADIRU (Air Data And Inertial Reference Unit)
 2x Pilot Controls (Sidestick + Pedals) Transducer

 Actuators:
 THS (trimmable horizontal stabilizer)
 Elevator
 Aileron
 Rudder

 There are 2 Sensors for each physical quantity to protect against sensor failures (Monitoring by comparing
 difference of sensor values against a threschold)
 Sensors authenticate their measurements and send them to the device.

 Flight Control Computer: Control Unit that executes the flight control law to compute some control outputs
 and a proof which certifies the correctness of the control outputs

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
#include "application/gadgets/flightcontrol_gadgets.hpp"
#include "application/gadgets/flightcontrol_variables.hpp"

typedef libff::default_ec_pp EcPP;
typedef libff::Fr<EcPP> SFieldT;


/**
* Flight control gadget
*
* Units and expected Ranges
* ==========================
* Pilot Controls Transducers: 16 bit signed integer
* Min: -2^15 = -32768    Max: 2^15 - 1 = 32767
* Monitoring limit: 10
*
* Angular rates (p, q, r): mdeg/s, Min: -200 000 mdeg/s, Max: 200 000 mdeg/s
* Monitoring limit: 500
*
* Angles (theta/pitch, phi/bank, alpha/angle-of-attack, beta/sideslip): mdeg, Min: -179 000 mdeg, Max: 180 000 mdeg
* Monitoring limit: 500
*
* Velocity (v): mm/s, Min: 0 mm/s, Max: 400 000 mm/s (~Mach 1.2 at sea level)
* Monitoring limit: 1000
*
* Acceleration (n/load-factor): mm/s^2, Min: -100 000mm/s^2, Max: 100 000mm/s^2 (~10g)
* Monitoring limit: 1000
*
*
**/
template <typename FieldT>
class flightcontrol_gadget : public gadget<FieldT>
{
public:
    // Monitor ADIRU outputs
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_p;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_q;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_r;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_v;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_alpha;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_beta;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_n;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_theta;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_phi;

    // Monitor Sidestick+Pedals Transducer outputs
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_qc;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_pc;
    std::shared_ptr<duplex_voter_gadget<FieldT>> monitor_betac;

    // Longitudinal control
    std::shared_ptr<pitch_attitude_protection_gadget<FieldT>> pitch_attitude_protection;
    std::shared_ptr<high_speed_protection_gadget<FieldT>> high_speed_protection;
    std::shared_ptr<high_aoa_protection_gadget<FieldT>> high_aoa_protection;
    std::shared_ptr<limit_gadget<FieldT>> load_factor_limitation;
    std::shared_ptr<longitudinal_control_gadget<FieldT>> longitudinal_control;
    std::shared_ptr<trim_gadget<FieldT>> trim;

    // Lateral control
    std::shared_ptr<bank_angle_protection_gadget<FieldT>> bank_angle_protection;
    std::shared_ptr<lateral_control_gadget<FieldT>> lateral_control;

    ADIRUVars<FieldT> adiru_voted;
    PilotControlsVars<FieldT> controls_voted;
    pb_variable<FieldT> pitch_lf_limited;

public:
    const ADIRUVars<FieldT>& adiru_1;
    const ADIRUVars<FieldT>& adiru_2;
    const PilotControlsVars<FieldT>& controls_1;
    const PilotControlsVars<FieldT>& controls_2;
    const CommandVars<FieldT>& commands;

    flightcontrol_gadget(structured_protoboard<FieldT>& pb,
                         ::state_manager<FieldT>& s_manager,
                         const ADIRUVars<FieldT>& adiru_1,
                         const ADIRUVars<FieldT>& adiru_2,
                         const PilotControlsVars<FieldT>& controls_1,
                         const PilotControlsVars<FieldT>& controls_2,
                         const CommandVars<FieldT>& commands,
                         const std::string& annotation_prefix = "") :
        gadget<FieldT>(pb, annotation_prefix),
        adiru_1(adiru_1), adiru_2(adiru_2), controls_1(controls_1), controls_2(controls_2), commands(commands)
    {
        const size_t WORD_SIZE = 24;
        const double SAMPLING_TIME = 0.01;
        const size_t MONITORING_LIMIT_TRANSDUCERS = 10;
        const size_t MONITORING_LIMIT_ANGULAR_RATES = 500;
        const size_t MONITORING_LIMIT_ANGLE = 500;
        const size_t MONITORING_LIMIT_VEL = 1000;
        const size_t MONITORING_LIMIT_ACC = 1000;

        adiru_voted.allocate(pb, "adiru_voted");
        controls_voted.allocate(pb, "controls_voted");

        // Input consolidation
        monitor_p.reset(new duplex_voter_gadget<FieldT>(pb, adiru_1.p, adiru_2.p, adiru_voted.p, WORD_SIZE,
                                                        MONITORING_LIMIT_ANGULAR_RATES,
                                                        FMT(this->annotation_prefix, ".monitor_p")));
        monitor_q.reset(new duplex_voter_gadget<FieldT>(pb, adiru_1.q, adiru_2.q, adiru_voted.q, WORD_SIZE,
                                                        MONITORING_LIMIT_ANGULAR_RATES,
                                                        FMT(this->annotation_prefix, ".monitor_q")));
        monitor_r.reset(new duplex_voter_gadget<FieldT>(pb, adiru_1.r, adiru_2.r, adiru_voted.r, WORD_SIZE,
                                                        MONITORING_LIMIT_ANGULAR_RATES,
                                                        FMT(this->annotation_prefix, ".monitor_r")));
        monitor_v.reset(new duplex_voter_gadget<FieldT>(pb, adiru_1.v, adiru_2.v, adiru_voted.v, WORD_SIZE,
                                                        MONITORING_LIMIT_VEL,
                                                        FMT(this->annotation_prefix, ".monitor_r")));
        monitor_alpha.reset(new duplex_voter_gadget<FieldT>(pb, adiru_1.alpha, adiru_2.alpha, adiru_voted.alpha,
                                                            WORD_SIZE, MONITORING_LIMIT_ANGLE,
                                                            FMT(this->annotation_prefix, ".monitor_alpha")));
        monitor_beta.reset(new duplex_voter_gadget<FieldT>(pb, adiru_1.beta, adiru_2.beta, adiru_voted.beta, WORD_SIZE,
                                                           MONITORING_LIMIT_ANGLE,
                                                           FMT(this->annotation_prefix, ".monitor_beta")));
        monitor_n.reset(new duplex_voter_gadget<FieldT>(pb, adiru_1.n, adiru_2.n, adiru_voted.n, WORD_SIZE,
                                                        MONITORING_LIMIT_ACC,
                                                        FMT(this->annotation_prefix, ".monitor_n")));
        monitor_theta.reset(new duplex_voter_gadget<FieldT>(pb, adiru_1.theta, adiru_2.theta, adiru_voted.theta,
                                                            WORD_SIZE, MONITORING_LIMIT_ANGLE,
                                                            FMT(this->annotation_prefix, ".monitor_theta")));
        monitor_phi.reset(new duplex_voter_gadget<FieldT>(pb, adiru_1.phi, adiru_2.phi, adiru_voted.phi, WORD_SIZE,
                                                          MONITORING_LIMIT_ANGLE,
                                                          FMT(this->annotation_prefix, ".monitor_phi")));

        monitor_qc.reset(new duplex_voter_gadget<FieldT>(pb, controls_1.qc, controls_2.qc, controls_voted.qc, WORD_SIZE,
                                                         MONITORING_LIMIT_TRANSDUCERS,
                                                         FMT(this->annotation_prefix, ".monitor_qc")));
        monitor_pc.reset(new duplex_voter_gadget<FieldT>(pb, controls_1.pc, controls_2.pc, controls_voted.pc, WORD_SIZE,
                                                         MONITORING_LIMIT_TRANSDUCERS,
                                                         FMT(this->annotation_prefix, ".monitor_pc")));
        monitor_betac.reset(new duplex_voter_gadget<FieldT>(pb, controls_1.betac, controls_2.betac,
                                                            controls_voted.betac, WORD_SIZE,
                                                            MONITORING_LIMIT_TRANSDUCERS,
                                                            FMT(this->annotation_prefix, ".monitor_betac")));

        // Longitudinal control
        const int PITCH_ANGLE_MAX = 30000; // 30deg nose up
        const int PITCH_ANGLE_MIN = -15000; // 15deg nose down
        pitch_attitude_protection.reset(new pitch_attitude_protection_gadget<FieldT>(
            pb, controls_voted.qc, adiru_voted.theta, PITCH_ANGLE_MAX, PITCH_ANGLE_MIN, WORD_SIZE,
            FMT(this->annotation_prefix, ".pitch_attitude_protection")));

        const int VM0 = 260000; // 260m/s maximum operating velocity
        const int OVERSPEED_THRESHOLD = 3000; // 3m/s
        const double OVERSPEED_GAIN = 0.25; // for each m/s overspeed, increase pitch command by 250
        high_speed_protection.reset(new high_speed_protection_gadget<FieldT>(
            pb, s_manager, controls_voted.qc, adiru_voted.v, VM0, OVERSPEED_THRESHOLD, OVERSPEED_GAIN, 3, WORD_SIZE,
            FMT(this->annotation_prefix, ".high_speed_protection")));

        const int STICK_MAX = 32767;
        const int ALPHA_MAX = 20000; // 20deg
        const int ALPHA_PROT = 15000; // 15deg
        const double PROTECTION_DEACTIVATE_LONG_TIME = 0.5; // 0.5s
        const int PROTECTION_DEACTIVATE_LONG_THRESHOLD = -500;
        const int PROTECTION_DEACTIVATE_THRESHOLD = -8000;
        high_aoa_protection.reset(
            new high_aoa_protection_gadget<FieldT>(pb,
                                                   s_manager,
                                                   high_speed_protection->get_output(),
                                                   adiru_voted.alpha,
                                                   STICK_MAX,
                                                   ALPHA_MAX,
                                                   ALPHA_PROT,
                                                   PROTECTION_DEACTIVATE_LONG_TIME,
                                                   PROTECTION_DEACTIVATE_LONG_THRESHOLD,
                                                   PROTECTION_DEACTIVATE_THRESHOLD,
                                                   SAMPLING_TIME,
                                                   8,
                                                   WORD_SIZE,
                                                   FMT(this->annotation_prefix, ".high_aoa_protection")));

        const int LOAD_FACTOR_MAX = 25000; // 25m/s^2 (approx 2.5g)
        const int LOAD_FACTOR_MIN = -10000; // -10m/s^2 (approx -1g)
        pitch_lf_limited.allocate(pb, FMT(this->annotation_prefix, ".pitch_lf_limited"));
        load_factor_limitation.reset(new limit_gadget<FieldT>(
            pb,
            WORD_SIZE,
            LOAD_FACTOR_MIN,
            LOAD_FACTOR_MAX,
            high_aoa_protection->get_output(),
            pitch_lf_limited,
            FMT(this->annotation_prefix, ".load_factor_limitation")));

        const double K_NC = 1.25; // direct response to stick input, 20deg deflection at max load factor
        const double K_INT = 12.5; // feedback gain of integrated command deviation
        const double K_N = -0.5; // direct feedback of load factor measurement
        const double K_Q = -0.75; // feedback gain for pitch measurement
        const int INTEGRATOR_MIN = -100000;
        const int INTEGRATOR_MAX = 100000;
        longitudinal_control.reset(new longitudinal_control_gadget<FieldT>(
            pb,
            s_manager,
            pitch_lf_limited,
            adiru_voted.n,
            adiru_voted.q,
            K_NC,
            K_INT,
            K_N,
            K_Q,
            SAMPLING_TIME,
            INTEGRATOR_MIN,
            INTEGRATOR_MAX,
            8,
            WORD_SIZE,
            FMT(this->annotation_prefix, ".longitudinal_control")
        ));

        // trim = THS angle in mdeg
        const double TRIM_GAIN = 0.061;
        const int TRIM_MIN = -20000; // 20deg nose down
        const int TRIM_MAX = 35000; // 35deg nose up
        trim.reset(new trim_gadget<FieldT>(
            pb,
            s_manager,
            longitudinal_control->get_output(),
            high_speed_protection->get_is_enabled(),
            TRIM_GAIN,
            SAMPLING_TIME,
            TRIM_MIN,
            TRIM_MAX,
            16,
            WORD_SIZE,
            FMT(this->annotation_prefix, ".trim")
        ));


        // Lateral control
        const unsigned int PHI_STAB = 33000; // 33deg: stabilize bank angle above 33deg
        const unsigned int PHI_MAX = 67000; // 67: maximum bank
        bank_angle_protection.reset(new bank_angle_protection_gadget<FieldT>(
            pb,
            controls_voted.pc,
            adiru_voted.phi,
            PHI_STAB,
            PHI_MAX,
            STICK_MAX,
            8,
            WORD_SIZE,
            FMT(this->annotation_prefix, ".bank_angle_protection")
        ));

        const double K_P[] = {
            0.75, 0.25,
            0.25, 0.75
        };
        const double K_RET[] = {
            0.2, 0.125, 0.125, 0.5,
            0.25, 0.25, 0.5, 0.125
        };
        const double K_LAT = 1.25; // direct respone to stick input
        const double LAT_INT_MAX = 70000; // limit integrator to +/-70deg
        const double LAT_INT_MIN = -70000;
        lateral_control.reset(new lateral_control_gadget<FieldT>(
            pb,
            s_manager,
            bank_angle_protection->get_output(),
            controls_voted.betac,
            adiru_voted.p,
            adiru_voted.beta,
            adiru_voted.r,
            adiru_voted.phi,
            K_P,
            K_RET,
            K_LAT,
            LAT_INT_MIN,
            LAT_INT_MAX,
            SAMPLING_TIME,
            8,
            WORD_SIZE,
            FMT(this->annotation_prefix, ".lateral_control")
        ));
    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template <typename FieldT>
void flightcontrol_gadget<FieldT>::generate_r1cs_constraints()
{
    // Input consolidation
    monitor_p->generate_r1cs_constraints();
    monitor_q->generate_r1cs_constraints();
    monitor_r->generate_r1cs_constraints();
    monitor_v->generate_r1cs_constraints();
    monitor_alpha->generate_r1cs_constraints();
    monitor_beta->generate_r1cs_constraints();
    monitor_n->generate_r1cs_constraints();
    monitor_theta->generate_r1cs_constraints();
    monitor_phi->generate_r1cs_constraints();

    monitor_qc->generate_r1cs_constraints();
    monitor_pc->generate_r1cs_constraints();
    monitor_betac->generate_r1cs_constraints();

    // Longitudinal control
    pitch_attitude_protection->generate_r1cs_constraints();
    high_speed_protection->generate_r1cs_constraints();
    high_aoa_protection->generate_r1cs_constraints();
    load_factor_limitation->generate_r1cs_constraints();
    longitudinal_control->generate_r1cs_constraints();
    trim->generate_r1cs_constraints();

    // Lateral control
    bank_angle_protection->generate_r1cs_constraints();
    lateral_control->generate_r1cs_constraints();

    // Set outputs
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, commands.pitch_trim, trim->get_output()),
                                 FMT(this->annotation_prefix, ".pitch_trim"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, commands.elevator, longitudinal_control->get_output()),
                                 FMT(this->annotation_prefix, ".elevator"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, commands.aileron, lateral_control->get_aileron_command()),
                                 FMT(this->annotation_prefix, ".aileron"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, commands.rudder, lateral_control->get_rudder_command()),
                                 FMT(this->annotation_prefix, ".rudder"));
}

template <typename FieldT>
void flightcontrol_gadget<FieldT>::generate_r1cs_witness()
{
    // Input consolidation
    monitor_p->generate_r1cs_witness();
    monitor_q->generate_r1cs_witness();
    monitor_r->generate_r1cs_witness();
    monitor_v->generate_r1cs_witness();
    monitor_alpha->generate_r1cs_witness();
    monitor_beta->generate_r1cs_witness();
    monitor_n->generate_r1cs_witness();
    monitor_theta->generate_r1cs_witness();
    monitor_phi->generate_r1cs_witness();

    monitor_qc->generate_r1cs_witness();
    monitor_pc->generate_r1cs_witness();
    monitor_betac->generate_r1cs_witness();

    // Longitudinal control
    pitch_attitude_protection->generate_r1cs_witness();
    high_speed_protection->generate_r1cs_witness();
    high_aoa_protection->generate_r1cs_witness();
    load_factor_limitation->generate_r1cs_witness();
    longitudinal_control->generate_r1cs_witness();
    trim->generate_r1cs_witness();

    // Lateral control
    bank_angle_protection->generate_r1cs_witness();
    lateral_control->generate_r1cs_witness();

    // Set outputs
    this->pb.val(commands.pitch_trim) = this->pb.val(trim->get_output());
    this->pb.val(commands.elevator) = this->pb.val(longitudinal_control->get_output());
    this->pb.val(commands.aileron) = this->pb.val(lateral_control->get_aileron_command());
    this->pb.val(commands.rudder) = this->pb.val(lateral_control->get_rudder_command());

    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, commands.pitch_trim, trim->get_output()),
                                 FMT(this->annotation_prefix, ".pitch_trim"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, commands.elevator, longitudinal_control->get_output()),
                                 FMT(this->annotation_prefix, ".elevator"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, commands.aileron, lateral_control->get_aileron_command()),
                                 FMT(this->annotation_prefix, ".aileron"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, commands.rudder, lateral_control->get_rudder_command()),
                                 FMT(this->annotation_prefix, ".rudder"));
}

class ProtoboardSetup
{
private:
    ADIRUVars<SFieldT> adiru_1;
    ADIRUVars<SFieldT> adiru_2;
    PilotControlsVars<SFieldT> controls_1;
    PilotControlsVars<SFieldT> controls_2;

    CommandVars<SFieldT> commands;

public:
    static const int ID_BLOCK_IO = 0;
    static const int ID_BLOCK_PRIVATE_INPUTS = 1;
    static const int ID_BLOCK_STATE_IN = 2;
    static const int ID_BLOCK_STATE_OUT = 3;

    static const int NUM_PUBLIC_IO = 4;
    static const int NUM_PRIVATE_INPUTS = 24;
    static const int NUM_STATES = 6;
    // 1x trim, 1x integrator longitudinal control, 1x integrator lateral control, 1x timer + 1x state on high aoa protection, 1x state on high_speed_protection

    structured_protoboard<SFieldT> pb;
    state_manager<SFieldT> s_manager;

    std::shared_ptr<flightcontrol_gadget<SFieldT>> g;
    r1cs_gg_ppzkadscsnark_constraint_system<EcPP> constraint_system;

    explicit ProtoboardSetup(const std::string& annotation_prefix = "")
        : pb(), s_manager(pb, ID_BLOCK_STATE_IN, ID_BLOCK_STATE_OUT)
    {
        pb.reserve_block(ID_BLOCK_IO, NUM_PUBLIC_IO);
        pb.reserve_block(ID_BLOCK_PRIVATE_INPUTS, NUM_PRIVATE_INPUTS);
        pb.reserve_block(ID_BLOCK_STATE_IN, NUM_STATES);
        pb.reserve_block(ID_BLOCK_STATE_OUT, NUM_STATES);

        adiru_1.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "adiru_1");
        adiru_2.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "adiru_2");
        controls_1.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "controls_1");
        controls_2.allocate_from_block(pb, ID_BLOCK_PRIVATE_INPUTS, "controls_2");

        commands.allocate_from_block(pb, ID_BLOCK_IO, "commands");

        g.reset(new flightcontrol_gadget<SFieldT>(pb,
                                                  s_manager,
                                                  adiru_1,
                                                  adiru_2,
                                                  controls_1,
                                                  controls_2,
                                                  commands,
                                                  annotation_prefix));

        pb.set_input_sizes(NUM_PUBLIC_IO);
        g->generate_r1cs_constraints();
        assert(pb.blocks_fully_allocated());

        constraint_system = r1cs_adsc_constraint_system<SFieldT>(pb.get_constraint_system(), NUM_PRIVATE_INPUTS,
                                                                 NUM_STATES);
    }

    void generate_r1cs_witness(
        ADIRUVals<SFieldT> adiru_1,
        ADIRUVals<SFieldT> adiru_2,
        PilotControlsVals<SFieldT> controls_1,
        PilotControlsVals<SFieldT> controls_2)
    {
        this->adiru_1.assign(this->pb, adiru_1);
        this->adiru_2.assign(this->pb, adiru_2);
        this->controls_1.assign(this->pb, controls_1);
        this->controls_2.assign(this->pb, controls_2);
        g->generate_r1cs_witness();
    }
};

enum FlightControlScenario
{
    EQUILIBRIUM,
    PULL_UP,
    PUSH_DOWN,
    CURVE_LEFT,
    CURVE_RIGHT,
    STALL,
    OVERSPEED
};

std::istream& operator>>(std::istream& in, FlightControlScenario& scenario)
{
    std::string token;
    in >> token;
    if (token == "0")
        scenario = EQUILIBRIUM;
    else if (token == "1")
        scenario = PULL_UP;
    else if (token == "2")
        scenario = PUSH_DOWN;
    else if (token == "3")
        scenario = CURVE_LEFT;
    else if (token == "4")
        scenario = CURVE_RIGHT;
    else if (token == "5")
        scenario = STALL;
    else if (token == "6")
        scenario = OVERSPEED;
    else
        in.setstate(std::ios_base::failbit);
    return in;
}

class Adiru : NetworkParticipant
{
private:
    size_t message_count;
    r1cs_gg_ppzkadscsnark_authentication_key<EcPP> authentication_key;

    FlightControlScenario scenario;
    int sample_count;
    ADIRUVals<SFieldT> sample_vals();

public:
    Adiru(std::string name = "Adiru", Communicator& comm = default_comm, FlightControlScenario scenario = EQUILIBRIUM) :
        NetworkParticipant(name, comm),
        message_count(0), scenario(scenario), sample_count(0)
    {
    };

    void setup();
    void run();
};

ADIRUVals<SFieldT> Adiru::sample_vals()
{
    ADIRUVals<SFieldT> vals;
    vals.p = SFieldT(0); // 0 deg/s
    vals.q = SFieldT(0); // 0 deg/s
    vals.r = SFieldT(0); // 0 deg/s
    vals.v = SFieldT(200000); // 200 m/s
    vals.alpha = SFieldT(10000); // 10 deg
    vals.beta = SFieldT(0); // 0 deg
    vals.n = SFieldT(0); // 0 m/s^2
    vals.theta = SFieldT(10000); // 10 deg
    vals.phi = SFieldT(0); // 0 deg
    switch (scenario)
    {
    case EQUILIBRIUM:
        // Do not change anything
        break;
    case PULL_UP:
        vals.q = SFieldT(1000); // 1 deg/s
        vals.n = SFieldT(100); // 0.1 m/s^2
        break;
    case PUSH_DOWN:
        vals.q = SFieldT(-1000); // -1 deg/s
        vals.n = SFieldT(-100); // -0.1 m/s^2
        break;
    case CURVE_LEFT:
        {
            int phi = -100 * std::min(static_cast<int>(message_count), 1000);
            vals.phi = SFieldT(phi); // 0 to -100 deg
            vals.p = SFieldT(-100); // -0.1 deg/s
        }
        break;
    case CURVE_RIGHT:
        {
            int phi = 100 * std::min(static_cast<int>(message_count), 1000);
            vals.phi = SFieldT(phi); // 0 to 100 deg
            vals.p = SFieldT(100); // 0.1 deg/s
        }
        break;
    case STALL:
        {
            int angle;
            if (message_count < 200)
            {
                vals.q = SFieldT(50000); // 50deg/s
                angle = 6000 + 50 * std::min(static_cast<int>(message_count), 200); // 6 to 16 deg
            }else
            {
                vals.q = SFieldT(-50000); // -50deg/s
                angle = 16000 - 50 * std::min(static_cast<int>(message_count - 200), 200); // 16 to 6 deg

            }
            vals.alpha = SFieldT(angle);
            vals.theta = SFieldT(angle);
        }
        break;
    case OVERSPEED:
        {
            int speed;
            if (message_count < 500)
            {
                speed = 220000 + 100 * std::min(static_cast<int>(message_count), 500); // 220m/s to 270m/s
            }
            else
            {
                speed = 270000 - 100 * std::min(static_cast<int>(message_count - 500), 500); // 270m/s to 220m/s
            }
            vals.v = speed;
        }
        break;
    default:
        throw std::runtime_error("Unknown scenario selected");
    }

    return vals;
}

void Adiru::setup()
{
    authentication_key = this->receive_from<r1cs_gg_ppzkadscsnark_authentication_key<EcPP>>(
        "authentication-key", "Generator");
}

void Adiru::run()
{
    size_t mc = message_count++;

    ADIRUVals<SFieldT> vals = sample_vals();

    // Authenticate
    r1cs_gg_ppzkadscsnark_authenticated_input<EcPP> authenticated_input = r1cs_gg_ppzkadscsnark_authenticate(
        authentication_key, mc,
        {vals.p, vals.q, vals.r, vals.v, vals.alpha, vals.beta, vals.n, vals.theta, vals.phi});

    this->send_to(authenticated_input, "input", "Device");
}


class PilotControlsTransducer : NetworkParticipant
{
private:
    size_t message_count;
    r1cs_gg_ppzkadscsnark_authentication_key<EcPP> authentication_key;

    FlightControlScenario scenario;
    int sample_count;
    PilotControlsVals<SFieldT> sample_vals();

public:
    PilotControlsTransducer(std::string name = "PilotControls", Communicator& comm = default_comm,
                            FlightControlScenario scenario = EQUILIBRIUM) :
        NetworkParticipant(name, comm),
        message_count(0), scenario(scenario), sample_count(0)
    {
    };

    void setup();
    void run();
};

PilotControlsVals<SFieldT> PilotControlsTransducer::sample_vals()
{
    PilotControlsVals<SFieldT> vals;
    vals.qc = SFieldT(0);
    vals.pc = SFieldT(0);
    vals.betac = SFieldT(0);
    switch (scenario)
    {
    case EQUILIBRIUM:
        // Do not change anything
        break;
    case PULL_UP:
        vals.qc = SFieldT(1000);
        break;
    case PUSH_DOWN:
        vals.qc = SFieldT(-1000);
        break;
    case CURVE_LEFT:
        vals.pc = SFieldT(-10000);
        break;
    case CURVE_RIGHT:
        vals.pc = SFieldT(10000);
        break;
    case STALL:
        if (message_count < 200)
        {
            vals.qc = SFieldT(4000);
        }else
        {
            vals.qc = SFieldT(-4000);
        }
        break;
    case OVERSPEED:
        vals.qc = SFieldT(-100);
        break;
    default:
        throw std::runtime_error("Unknown scenario selected");
    }

    return vals;
}

void PilotControlsTransducer::setup()
{
    authentication_key = this->receive_from<r1cs_gg_ppzkadscsnark_authentication_key<EcPP>>(
        "authentication-key", "Generator");
}

void PilotControlsTransducer::run()
{
    size_t mc = message_count++;

    PilotControlsVals<SFieldT> vals = sample_vals();

    // Authenticate
    r1cs_gg_ppzkadscsnark_authenticated_input<EcPP> authenticated_input = r1cs_gg_ppzkadscsnark_authenticate(
        authentication_key, mc,
        {vals.qc, vals.pc, vals.betac});

    this->send_to(authenticated_input, "input", "Device");
}

class Device : NetworkParticipant
{
private:
    r1cs_gg_ppzkadscsnark_proving_key<EcPP> pk;
    std::shared_ptr<ProtoboardSetup> ps;
    r1cs_gg_ppzkadscsnark_prover_state<EcPP> prover_state;

public:
    Device(std::string name = "Device", Communicator& comm = default_comm, bool silent = false) :
        NetworkParticipant(name, comm, silent)
    {
    }

    void setup(); // Receive prover key
    void run();
};

void Device::setup()
{
    pk = this->receive_from<r1cs_gg_ppzkadscsnark_proving_key<EcPP>>("pk", "Generator");
    ps.reset(new ProtoboardSetup("g"));
    ps->s_manager.init();
}

void Device::run()
{
    r1cs_gg_ppzkadscsnark_primary_input<EcPP> primary_input;
    r1cs_gg_ppzkadscsnark_assignment<EcPP> state_input;
    r1cs_gg_ppzkadscsnark_assignment<EcPP> state_update_input;
    r1cs_gg_ppzkadscsnark_assignment<EcPP> witness_input;

    auto adiru_a_1 = this->receive_from<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>>("input", "Adiru1");
    auto adiru_a_2 = this->receive_from<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>>("input", "Adiru2");
    auto controls_a_1 = this->receive_from<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>>(
        "input", "PilotControlsTransducer1");
    auto controls_a_2 = this->receive_from<r1cs_gg_ppzkadscsnark_authenticated_input<EcPP>>(
        "input", "PilotControlsTransducer2");

    ADIRUVals<SFieldT> adiru_vals_1 = ADIRUVals<SFieldT>(adiru_a_1.values);
    ADIRUVals<SFieldT> adiru_vals_2 = ADIRUVals<SFieldT>(adiru_a_2.values);
    PilotControlsVals<SFieldT> controls_vals_1 = PilotControlsVals<SFieldT>(controls_a_1.values);
    PilotControlsVals<SFieldT> controls_vals_2 = PilotControlsVals<SFieldT>(controls_a_2.values);

    ps->generate_r1cs_witness(adiru_vals_1, adiru_vals_2, controls_vals_1, controls_vals_2);

    if (!silent)
    {
        std::cout << "Internals: " << "AOA-P = " << (ps->g->high_aoa_protection->is_aoa_enabled() ? "ON " : "OFF");
        std::cout << " HS-P = " << (ps->g->high_speed_protection->is_hsp_enabled() ? "ON " : "OFF");
        std::cout << " Bank-P = " << (ps->g->bank_angle_protection->is_bap_enabled() ? "ON " : "OFF");
        std::cout << " V = " << field_to_signed_int(ps->pb.val(ps->g->monitor_v->voted_value)) / 1000 << "m/s";
        std::cout << " Alpha = " << field_to_signed_int(ps->pb.val(ps->g->monitor_alpha->voted_value)) / 1000 << "deg";
    }

    primary_input = ps->pb.primary_input();
    state_input = ps->pb.get_block_assignment(ps->ID_BLOCK_STATE_IN);
    state_update_input = ps->pb.get_block_assignment(ps->ID_BLOCK_STATE_OUT);
    witness_input = ps->pb.get_free_assignment();

#ifdef DEBUG
    r1cs_auxiliary_input<SFieldT> auxiliary_input;
    auxiliary_input.insert(auxiliary_input.end(), adiru_a_1.values.begin(), adiru_a_1.values.end());
    auxiliary_input.insert(auxiliary_input.end(), adiru_a_2.values.begin(), adiru_a_2.values.end());
    auxiliary_input.insert(auxiliary_input.end(), controls_a_1.values.begin(), controls_a_1.values.end());
    auxiliary_input.insert(auxiliary_input.end(), controls_a_2.values.begin(), controls_a_2.values.end());
    auxiliary_input.insert(auxiliary_input.end(), state_input.begin(), state_input.end());
    auxiliary_input.insert(auxiliary_input.end(), state_update_input.begin(), state_update_input.end());
    auxiliary_input.insert(auxiliary_input.end(), witness_input.begin(), witness_input.end());
    assert(ps->constraint_system.is_satisfied(primary_input, auxiliary_input));
#endif

    std::pair<r1cs_gg_ppzkadscsnark_proof<EcPP>,
              r1cs_gg_ppzkadscsnark_commitment<EcPP>> proof = r1cs_gg_ppzkadscsnark_prover<EcPP>(pk,
        ps->constraint_system,
        primary_input,
        {adiru_a_1, adiru_a_2, controls_a_1, controls_a_2},
        state_input,
        state_update_input,
        witness_input,
        prover_state);

    this->send_to(primary_input, "values", "Verifier");
    this->send_to(proof.first, "proof", "Verifier");
    this->send_to(proof.second, "commitment", "Verifier");
    ps->s_manager.update();
}

class Generator : NetworkParticipant
{
public:
    Generator(std::string name = "Generator", Communicator& comm = default_comm) : NetworkParticipant(name, comm)
    {
    }

    void setup();
};

void Generator::setup()
{
    ProtoboardSetup ps("g");

    // Initialize state variables
    ps.s_manager.init();
    r1cs_gg_ppzkadscsnark_keypair<EcPP> keypair = r1cs_gg_ppzkadscsnark_generator<EcPP>(ps.constraint_system,
        ps.pb.get_block_assignment(ps.ID_BLOCK_STATE_IN),
        {
            ADIRUVals<SFieldT>::NUM_VALS,
            ADIRUVals<SFieldT>::NUM_VALS,
            PilotControlsVals<SFieldT>::NUM_VALS,
            PilotControlsVals<SFieldT>::NUM_VALS,
        });
    assert(keypair.aks.size() == 4);

    this->send_to(keypair.pk, "pk", "Device");
    this->send_to(keypair.vk, "vk", "Verifier");
    this->send_to(keypair.initial_commitment, "initial_commitment", "Verifier");
    this->send_to(keypair.aks[0], "authentication-key", "Adiru1");
    this->send_to(keypair.aks[1], "authentication-key", "Adiru2");
    this->send_to(keypair.aks[2], "authentication-key", "PilotControlsTransducer1");
    this->send_to(keypair.aks[3], "authentication-key", "PilotControlsTransducer2");
}

class Verifier : NetworkParticipant
{
private:
    int message_count;
    r1cs_gg_ppzkadscsnark_commitment<EcPP> previous_commitment;
    r1cs_gg_ppzkadscsnark_processed_verification_key<EcPP> pvk;

public:
    int confirmed_count;
    int error_count;

    Verifier(std::string name = "Verifier", Communicator& comm = default_comm, bool silent = false) :
        NetworkParticipant(name, comm, silent), message_count(0), confirmed_count(0), error_count(0)
    {
    }

    void setup();
    void run();
};

void Verifier::setup()
{
    r1cs_gg_ppzkadscsnark_verification_key<EcPP> vk = this->receive_from<r1cs_gg_ppzkadscsnark_verification_key<EcPP>>(
        "vk", "Generator");
    pvk = r1cs_gg_ppzkadscsnark_verifier_process_vk(vk);
    previous_commitment = this->receive_from<r1cs_gg_ppzkadscsnark_commitment<EcPP>>("initial_commitment", "Generator");
}

void Verifier::run()
{
    const uint16_t mc = message_count++;

    const auto primary_input = this->receive_from<r1cs_gg_ppzkadscsnark_primary_input<EcPP>>("values", "Device");
    const auto proof = this->receive_from<r1cs_gg_ppzkadscsnark_proof<EcPP>>("proof", "Device");
    const auto commitment = this->receive_from<r1cs_gg_ppzkadscsnark_commitment<EcPP>>("commitment", "Device");

    assert(primary_input.size() == CommandVals<SFieldT>::NUM_VALS);
    CommandVals<SFieldT> commands = CommandVals<SFieldT>(primary_input);

    const bool verified = r1cs_gg_ppzkadscsnark_online_verifier_strong_IC<EcPP>(
        pvk, primary_input, proof, commitment, previous_commitment, mc);
    if (!verified && !silent)
    {
        std::cerr << "SNARK does not verify" << std::endl;
    }

    previous_commitment = commitment;

    if (!silent)
    {
        std::cout << " Outputs: pitch trim = " << field_to_signed_int(commands.pitch_trim)
            << " elevator = " << field_to_signed_int(commands.elevator)
            << " aileron = " << field_to_signed_int(commands.aileron)
            << " rudder = " << field_to_signed_int(commands.rudder)
            << " Verified: " << verified
            << std::endl;
    }

    if (verified)
    {
        confirmed_count++;
    }
    else
    {
        error_count++;
    }
}


int main(int argc, char* argv[])
{
    namespace po = boost::program_options;
    int rounds;
    FlightControlScenario scenario;
    std::cout << "Flightcontrol Scenario" << std::endl;
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
        ("scenario", po::value<FlightControlScenario>(&scenario)->default_value(EQUILIBRIUM),
         "Select scenario: \n0) Equilibrium \n1) Pull up \n2) Push down \n3) Curve left \n4) Curve right \n5) Stall \n6) Overspeed")
        ("file", "Write outputs to a file");
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help") || argc <= 1)
    {
        std::cout << desc << std::endl;
        return 1;
    }

    std::cout << "Selected scenario: " << scenario << std::endl;

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

    if (vm.count("test"))
    {
        //return test_circuit();
        return -1;
    }

    if (vm.count("file"))
    {
        communicator = Communicator(Communicator::CommunicationMode::File);
    }
    else
    {
        communicator = Communicator(Communicator::CommunicationMode::Ram);
    }

    Generator gen("Generator", communicator);
    Device device("Device", communicator, silent);
    Adiru adiru1("Adiru1", communicator, scenario);
    Adiru adiru2("Adiru2", communicator, scenario);
    PilotControlsTransducer transducer1("PilotControlsTransducer1", communicator, scenario);
    PilotControlsTransducer transducer2("PilotControlsTransducer2", communicator, scenario);
    Verifier ver("Verifier", communicator, silent);

    if (vm.count("generator") || vm.count("all"))
    {
        std::cout << "generator ";
        gen.setup();
    }

    if (vm.count("sensor") || vm.count("all"))
    {
        std::cout << "sensor ";
        adiru1.setup();
        adiru2.setup();
        transducer1.setup();
        transducer2.setup();
    }

    if (vm.count("device") || vm.count("all"))
    {
        std::cout << "device ";
        device.setup();
    }

    if (vm.count("verifier") || vm.count("all"))
    {
        std::cout << "verifier ";
        ver.setup();
    }
    std::cout << std::endl;

    long long start_time, end_time;

    start_time = libff::get_nsec_time();
    for (int i = 0; i < rounds; i++)
    {
        if (vm.count("sensor") || vm.count("all"))
        {
            adiru1.run();
            adiru2.run();
            transducer1.run();
            transducer2.run();
        }
        if (vm.count("device") || vm.count("all"))
        {
            device.run();
        }
        if (vm.count("verifier") || vm.count("all"))
        {
            ver.run();
        }
        communicator.tick();
    }
    end_time = libff::get_nsec_time();

    std::cout << rounds << " rounds completed." << std::endl;
    if (vm.count("verifier") || vm.count("all"))
    {
        std::cout << "Verifier - Confirmed: " << ver.confirmed_count << " (Errors: " << ver.error_count << ")" <<
            std::endl;
    }
    std::cout << "Duration: " << (end_time - start_time) / 1000 << "us, = " << (end_time - start_time) / 1000 / rounds
        << "us per round" << std::endl;
}
