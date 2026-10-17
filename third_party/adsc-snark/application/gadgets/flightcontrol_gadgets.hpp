/** @file
 *****************************************************************************

 Declaration of interfaces for flight control gadgets

 Requires a structured protoboard, as gadgets are stateful

 Includes:
 trim_gadget: computes position of THS from pitch command 
 *****************************************************************************/

#ifndef _FLIGHTCONTROL_GADGETS_H
#define _FLIGHTCONTROL_GADGETS_H

#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/gadgetlib1/protoboard_structured.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/state_structured.hpp"
#include "application/gadgets/integer_arithmetic.hpp"

#include "control_gadgets_structured.hpp"
#include "comp_gadgets.hpp"

/**
 * trim gadget
 *
 * computes position of THS from elevator deflection command:
 * - Integrates elevator deflection command
 * - Freezes, if high-speed protection is enabled
 *
 *
 * K: k_gain, proportional amplification
 *  min: minimal trim value
 *  max: maximum trim value
 *
 *  ts: discretization time
 *
 *  Precision:
 *  number of bits to shift the coefficients:
 *  p = 1 << precision
 *  y(t) = (K*p*ts*u(t)) / p
*
 *  The higher the precision, the lower the rounding errors
 *
 *  Word Size:
 *  Number of bits to represent the output values
 */
template <typename FieldT>
class trim_gadget : public gadget<FieldT>
{
private:
    std::shared_ptr<limited_integrator_structured_gadget<FieldT>> integrator;
    const pb_linear_combination<FieldT> input;
    const pb_variable<FieldT> hsp_enabled;
    pb_variable<FieldT> selected_input;

public:
    trim_gadget(structured_protoboard<FieldT>& pb,
                ::state_manager<FieldT>& s_manager,
                const linear_combination<FieldT>& input,
                const pb_variable<FieldT>& hsp_enabled, // hsp_enabled is expected to be constrained to set {0, 1}
                const double k_gain,
                const double ts,
                const int min,
                const int max,
                const unsigned int precision,
                const unsigned int word_size,
                const std::string& annotation_prefix = "") :
        gadget<FieldT>(pb, annotation_prefix),
        input(pb, input), hsp_enabled(hsp_enabled)
    {
        selected_input.allocate(pb, FMT(this->annotation_prefix, ".selected_input"));

        integrator.reset(new limited_integrator_structured_gadget<FieldT>(
            pb, s_manager, selected_input, k_gain, ts, min, max, precision, word_size,
            FMT(this->annotation_prefix, ".integrator")));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_output() const;
};

/**
 * longitudinal control gadget
 *
 * inputs:
 * - commanded load factor
 * - measured load factor, pitch rate
 *
 * computation:
 * - Integrates load factor deviation
 * - Combines deviation integral, load factor and pitch rate with individual gains
 *
 * outputs:
 * - elevator deflection command
 *
 *  k_nc: gain for commanded load factor
 *  k_int: gain for deviation integral
 *  k_n: gain for measured load factor
 *  k_q: gain for pitch rate
 *  min, max: limits for integrator
 *
 *  ts: discretization time
 *
 *  precision:
 *  number of bits to shift the coefficients before division
 *  The higher the precision, the lower the rounding errors
 *
 *  Word Size:
 *  Number of bits to represent the output values
 */
template <typename FieldT>
class longitudinal_control_gadget : public gadget<FieldT>
{
private:
    std::shared_ptr<limited_integrator_structured_gadget<FieldT>> integrator;
    std::shared_ptr<gain_gadget<FieldT>> nc_gain;
    std::shared_ptr<gain_gadget<FieldT>> n_gain;
    std::shared_ptr<gain_gadget<FieldT>> q_gain;

    pb_variable<FieldT> output;

public:
    longitudinal_control_gadget(structured_protoboard<FieldT>& pb,
                                ::state_manager<FieldT>& s_manager,
                                const linear_combination<FieldT>& load_factor_command,
                                const linear_combination<FieldT>& load_factor_measurement,
                                const linear_combination<FieldT>& pitch_rate,
                                double k_nc,
                                double k_int,
                                double k_n,
                                double k_q,
                                double ts,
                                int min,
                                int max,
                                unsigned int precision,
                                unsigned int word_size,
                                const std::string& annotation_prefix = "") :
        gadget<FieldT>(pb, annotation_prefix)
    {
        output.allocate(pb, FMT(this->annotation_prefix, ".output"));
        nc_gain.reset(new gain_gadget<FieldT>(this->pb, load_factor_command, k_nc, precision, word_size,
                                              FMT(this->annotation_prefix, ".nc_gain")));
        n_gain.reset(new gain_gadget<FieldT>(this->pb, load_factor_measurement, k_n, precision, word_size,
                                             FMT(this->annotation_prefix, ".n_gain")));
        q_gain.reset(new gain_gadget<FieldT>(this->pb, pitch_rate, k_q, precision, word_size,
                                             FMT(this->annotation_prefix, ".q_gain")));

        integrator.reset(new limited_integrator_structured_gadget<FieldT>(
            pb, s_manager, load_factor_command - load_factor_measurement, k_int, ts, min, max, precision,
            word_size, FMT(this->annotation_prefix, ".integrator")));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_output() const;
};

/**
 * lateral control gadget
 *
 * inputs:
 * - commanded roll rate
 * - commanded side slip
 * - measured side slip
 * - bank angle
 * - roll rate
 * - yaw rate
 *
 * computation:
 * - Integrates roll rate command
 * - mix roll rate command and side slip command for coordinated turns using Kp-matrix
 * - decouple roll and sideslip using Kret-matrix
 *
 * outputs:
 * - asymmetric ailerons deflection command
 * - rudder deflection command
 *
 *  k: gain for direct roll command
 *  k_p: 2x2 gain matrix Kp for turn coordination
 *  k_ret: 2x4 gain matrix Kret for roll-sideslip decoupling
 *  Matrix entries k_i first fill row: i = column_idx + row_idx * row_size:
 *  Kret = [ k_0, k_1, k_2, k_3,
 *         [ k_4, k_5, k_6, k_7], with row_size = 4
 *  Rows: 0 = aileron, 1 = rudder
 *  Columns k_p: 0 = roll_command, 1 = sideslip_command
 *  Columns k_ret: 0 = roll_rate, 1 = sideslip, 2 = yaw_rate, 3 = bank_angle
 *
 *  min, max: limits for integrator
 *
 *  ts: discretization time
 *
 *  precision:
 *  number of bits to shift the coefficients before division
 *  The higher the precision, the lower the rounding errors
 *
 *  Word Size:
 *  Number of bits to represent the output values
 */
template <typename FieldT>
class lateral_control_gadget : public gadget<FieldT>
{
private:
    int coeff_kp[2 * 2];
    int coeff_kret[2 * 4];
    std::shared_ptr<limited_integrator_structured_gadget<FieldT>> integrator;
    std::shared_ptr<fixed_division_gadget<FieldT>> division_aileron;
    std::shared_ptr<fixed_division_gadget<FieldT>> division_rudder;
    std::shared_ptr<gain_gadget<FieldT>> k_gain;

    const pb_linear_combination<FieldT> roll_command;
    const pb_linear_combination<FieldT> sideslip_command;
    const pb_linear_combination<FieldT> roll_rate;
    const pb_linear_combination<FieldT> sideslip;
    const pb_linear_combination<FieldT> yaw_rate;
    const pb_linear_combination<FieldT> bank_angle;

    pb_variable<FieldT> aileron_command;
    pb_variable<FieldT> rudder_command;

public:
    lateral_control_gadget(structured_protoboard<FieldT>& pb,
                           ::state_manager<FieldT>& s_manager,
                           const pb_linear_combination<FieldT>& roll_command,
                           const pb_linear_combination<FieldT>& sideslip_command,
                           const pb_linear_combination<FieldT>& roll_rate,
                           const pb_linear_combination<FieldT>& sideslip,
                           const pb_linear_combination<FieldT>& yaw_rate,
                           const pb_linear_combination<FieldT>& bank_angle,
                           const double k_p[2 * 2],
                           const double k_ret[2 * 4],
                           const double k,
                           const int min,
                           const int max,
                           const double ts,
                           const unsigned int precision,
                           const unsigned int word_size,
                           const std::string& annotation_prefix = "") :
        gadget<FieldT>(pb, annotation_prefix),
        roll_command(roll_command), sideslip_command(sideslip_command), roll_rate(roll_rate),
        sideslip(sideslip), yaw_rate(yaw_rate), bank_angle(bank_angle)
    {
        int precision_factor = (1 << precision);
        for (int i = 0; i < 2 * 2; ++i)
        {
            coeff_kp[i] = k_p[i] * precision_factor;
        }
        for (int i = 0; i < 2 * 4; ++i)
        {
            coeff_kret[i] = k_ret[i] * precision_factor;
        }

        aileron_command.allocate(pb, FMT(this->annotation_prefix, ".aileron_command"));
        rudder_command.allocate(pb, FMT(this->annotation_prefix, ".rudder_command"));


        k_gain.reset(new gain_gadget<FieldT>(this->pb, roll_command, k, precision, word_size,
                                             FMT(this->annotation_prefix, ".k_gain")));
        integrator.reset(new limited_integrator_structured_gadget<FieldT>(
            pb, s_manager, roll_command, 1, ts, min, max, precision, word_size,
            FMT(this->annotation_prefix, ".integrator")));

        linear_combination<FieldT> roll_command_1 = k_gain->get_output() + integrator->get_output() -
            sideslip_command;
        // Sum (Kp[0, i] * [roll_command_1, sideslip_command] + Kret[0, i] * [roll_rate, sideslip, yaw_rate, bank_angle]) / precision
        division_aileron.reset(new fixed_division_gadget<FieldT>(this->pb, word_size,
                                                                 coeff_kp[0] * roll_command_1 + coeff_kp[1] *
                                                                 sideslip_command
                                                                 + coeff_kret[0] * roll_rate + coeff_kret[1] * sideslip
                                                                 + coeff_kret[2] * yaw_rate + coeff_kret[3] *
                                                                 bank_angle,
                                                                 precision_factor, aileron_command,
                                                                 FMT(this->annotation_prefix, ".division_aileron")));

        // Sum (Kp[1, i] * [roll_command_1, sideslip_command] + Kret[1, i] * [roll_rate, sideslip, yaw_rate, bank_angle]) / precision
        division_rudder.reset(new fixed_division_gadget<FieldT>(this->pb, word_size,
                                                                coeff_kp[2] * roll_command_1 + coeff_kp[2] *
                                                                sideslip_command
                                                                + coeff_kret[4] * roll_rate + coeff_kret[5] * sideslip +
                                                                coeff_kret[6] * yaw_rate + coeff_kret[7] * bank_angle,
                                                                precision_factor, rudder_command,
                                                                FMT(this->annotation_prefix, ".division_rudder")));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_aileron_command() const;
    const pb_variable<FieldT>& get_rudder_command() const;
};


/**
 * high angle of attack protection gadget
 *
 * inputs:
 * - alpha: angle of attack
 * - pitch command
 *
 * computation:
 * - activates aoa protection mode, if alpha > alpha_prot
 * - deactivates aoa protection mode, if stick_deflection_pitch < protection_deactivate_threshold
 * - or deactivates aoa protection mode, if stick_deflection_pitch < protection_deactivate_long_threshold for -protection_deactivate_long_time AND alpha < alpha_max
 * - if aoa protection mode is off, the pitch command is unmodified
 * - if aoa protection mode is on, pitch command is modified to an aoa command and aoa is limited to alpha_max
 *
 * outputs:
 * - pitch command
 *
 *  protection_deactivate_threshold: stick_deflection, for which aoa protection mode is deactivated
 *  protection_deactivate_long_threshold, protection_deactivate_long_time: parameters for deactivating aoa protection mode including timing constraint
 *  stick_max: full deflection of stick
 *  alpha_max: angle-of-attack limit
 *  alpha_prot: threshold for activating high aoa protection
 *  ts: discretization time
 *
 *  precision:
 *  number of bits to shift the coefficients before division
 *  The higher the precision, the lower the rounding errors
 *
 *  Word Size:
 *  Number of bits to represent the output values
 */
template <typename FieldT>
class high_aoa_protection_gadget : public gadget<FieldT>
{
private:
    int stick_max;
    int alpha_max;
    int alpha_prot;
    unsigned int protection_deactivate_long_iterations;
    int protection_deactivate_long_threshold;
    int protection_deactivate_threshold;
    unsigned int gain_stick_to_alpha;
    std::shared_ptr<comparison_gadget<FieldT>> comp_alpha_alpha_max;
    std::shared_ptr<comparison_gadget<FieldT>> comp_alpha_alpha_prot;
    std::shared_ptr<comparison_gadget<FieldT>> comp_stick_threshold;
    std::shared_ptr<comparison_gadget<FieldT>> comp_stick_long_threshold;
    std::shared_ptr<comparison_gadget<FieldT>> comp_timer;
    std::shared_ptr<fixed_division_gadget<FieldT>> division;

    const pb_linear_combination<FieldT> pitch_command;
    const pb_linear_combination<FieldT> alpha;

    pb_variable<FieldT> alpha_ge_alpha_max;
    pb_variable<FieldT> alpha_ge_alpha_prot;
    pb_variable<FieldT> stick_lt_deactivate_threshold;
    pb_variable<FieldT> stick_lt_deactivate_long_threshold;
    pb_variable<FieldT> timer_ge_threshold;

    pb_variable<FieldT> dum1;
    pb_variable<FieldT> dum2;
    pb_variable<FieldT> dum3;
    pb_variable<FieldT> dum4;
    pb_variable<FieldT> dum5;

    pb_variable<FieldT> increase_timer;
    pb_variable<FieldT> protection_on_1;
    pb_variable<FieldT> deactivate_protection;
    pb_variable<FieldT> pitch_command_protected;

    pb_state_structured<FieldT> timer;
    pb_state_structured<FieldT> protection_on;

    pb_variable<FieldT> output;

public:
    high_aoa_protection_gadget(structured_protoboard<FieldT>& pb,
                               ::state_manager<FieldT>& s_manager,
                               const pb_linear_combination<FieldT>& pitch_command,
                               const pb_linear_combination<FieldT>& alpha,
                               const int stick_max,
                               const int alpha_max,
                               const int alpha_prot,
                               const double protection_deactivate_long_time,
                               const int protection_deactivate_long_threshold,
                               const int protection_deactivate_threshold,
                               const double ts,
                               const unsigned int precision,
                               const unsigned int word_size,
                               const std::string& annotation_prefix = "") :
        gadget<FieldT>(pb, annotation_prefix),
        stick_max(stick_max), alpha_max(alpha_max), alpha_prot(alpha_prot),
        protection_deactivate_long_threshold(protection_deactivate_long_threshold),
        protection_deactivate_threshold(protection_deactivate_threshold),
        pitch_command(pitch_command), alpha(alpha),

        timer(pb, s_manager.id_block_in, s_manager.id_block_out, FieldT(0), FMT(annotation_prefix, ".timer")),
        protection_on(pb, s_manager.id_block_in, s_manager.id_block_out, FieldT(0),
                      FMT(annotation_prefix, ".protection_on"))
    {
        int precision_factor = (1 << precision);
        protection_deactivate_long_iterations = protection_deactivate_long_time / ts;
        gain_stick_to_alpha = (stick_max * precision_factor) / (alpha_max - alpha_prot);

        alpha_ge_alpha_max.allocate(pb, FMT(this->annotation_prefix, ".alpha_gt_alpha_max"));
        alpha_ge_alpha_prot.allocate(pb, FMT(this->annotation_prefix, ".alpha_gt_alpha_prot"));
        stick_lt_deactivate_threshold.allocate(pb, FMT(this->annotation_prefix, ".stick_lt_deactivate_threshold"));
        stick_lt_deactivate_long_threshold.allocate(pb, FMT(this->annotation_prefix,
                                                            ".stick_st_deactivate_long_threshold"));
        timer_ge_threshold.allocate(pb, FMT(this->annotation_prefix, ".timer_ge_threshold"));

        dum1.allocate(pb, FMT(this->annotation_prefix, ".dum1"));
        dum2.allocate(pb, FMT(this->annotation_prefix, ".dum2"));
        dum3.allocate(pb, FMT(this->annotation_prefix, ".dum3"));
        dum4.allocate(pb, FMT(this->annotation_prefix, ".dum4"));
        dum5.allocate(pb, FMT(this->annotation_prefix, ".dum5"));

        increase_timer.allocate(pb, FMT(this->annotation_prefix, ".increase_timer"));
        protection_on_1.allocate(pb, FMT(this->annotation_prefix, ".protection_on_1"));
        deactivate_protection.allocate(pb, FMT(this->annotation_prefix, ".deactivate_protection"));
        pitch_command_protected.allocate(pb, FMT(this->annotation_prefix, ".pitch_command_protected"));

        output.allocate(pb, FMT(this->annotation_prefix, ".output"));

        comp_alpha_alpha_max.reset(new comparison_gadget<FieldT>(
            pb, word_size, pb_linear_combination<FieldT>(pb, alpha_max), alpha, alpha_ge_alpha_max, dum1,
            FMT(this->annotation_prefix, ".comp_alpha_alpha_max")));
        comp_alpha_alpha_prot.reset(new comparison_gadget<FieldT>(
            pb, word_size, pb_linear_combination<FieldT>(pb, alpha_prot), alpha, alpha_ge_alpha_prot, dum2,
            FMT(this->annotation_prefix, ".comp_alpha_alpha_prot")));
        comp_stick_threshold.reset(new comparison_gadget<FieldT>(
            pb, word_size, pitch_command, pb_linear_combination<FieldT>(pb, protection_deactivate_threshold), stick_lt_deactivate_threshold, dum3,
            FMT(this->annotation_prefix, ".comp_stick_threshold")));
        comp_stick_long_threshold.reset(new comparison_gadget<FieldT>(
            pb, word_size, pitch_command, pb_linear_combination<FieldT>(pb, protection_deactivate_long_threshold),
            stick_lt_deactivate_long_threshold, dum4,
            FMT(this->annotation_prefix, ".comp_stick_long_threshold")));
        comp_timer.reset(new comparison_gadget<FieldT>(pb, word_size,
                                                                 pb_linear_combination<FieldT>(pb, protection_deactivate_long_iterations),
                                                                 timer.out, timer_ge_threshold, dum5,
                                                                 FMT(this->annotation_prefix, ".comp_timer")));
        division.reset(new fixed_division_gadget<FieldT>(this->pb, word_size,
                                                         pitch_command + alpha_prot * gain_stick_to_alpha - alpha *
                                                         gain_stick_to_alpha, precision_factor, pitch_command_protected,
                                                         FMT(this->annotation_prefix, ".division")));
        s_manager.add_state(timer);
        s_manager.add_state(protection_on);
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_output() const;
    bool is_aoa_enabled() const;
};


/**
 * high speed protection gadget
 *
 * inputs:
 * - velocity
 * - pitch command
 *
 * computation:
 * - activates HS protection mode, if velocity > vel_m0 + threshold
 * - deactivates HS protection mode, if velocity < vel_m0
 * - increases pitch command proportional to overspeed velocity
 *
 * outputs:
 * - pitch command
 * - is protection active
 *
 *  vel_m0: maximum operating velocity
 *  threshold: activation threshold for enabling HS protection mode
 *  k: proportional gain for pitch command increase
 *
 *  precision:
 *  number of bits to shift the coefficients before division
 *  The higher the precision, the lower the rounding errors
 *
 *  Word Size:
 *  Number of bits to represent the output values
 */
template <typename FieldT>
class high_speed_protection_gadget : public gadget<FieldT>
{
private:
    const pb_linear_combination<FieldT> pitch_command;
    const pb_linear_combination<FieldT> velocity;

    unsigned int vel_m0;
    unsigned int threshold;

    const pb_state_structured<FieldT> protection_on;
    std::shared_ptr<gain_gadget<FieldT>> k_gain;
    std::shared_ptr<comparison_gadget<FieldT>> comp_vel_over_threshold;
    std::shared_ptr<comparison_gadget<FieldT>> comp_vel_below_m0;


    pb_variable<FieldT> vel_over_threshold;
    pb_variable<FieldT> vel_below_m0;
    pb_variable<FieldT> dum1;
    pb_variable<FieldT> dum2;
    pb_variable<FieldT> protection_on_1;

    pb_variable<FieldT> output;

public:
    high_speed_protection_gadget(structured_protoboard<FieldT>& pb,
                                 ::state_manager<FieldT>& s_manager,
                                 const pb_linear_combination<FieldT>& pitch_command,
                                 const pb_linear_combination<FieldT>& velocity,
                                 const int vel_m0,
                                 const int threshold,
                                 const double k,
                                 const unsigned int precision,
                                 const unsigned int word_size,
                                 const std::string& annotation_prefix = "") :
        gadget<FieldT>(pb, annotation_prefix),
        pitch_command(pitch_command), velocity(velocity), vel_m0(vel_m0), threshold(threshold),
        protection_on(pb, s_manager.id_block_in, s_manager.id_block_out, FieldT(0),
                      FMT(annotation_prefix, ".protection_on"))
    {
        vel_over_threshold.allocate(pb, FMT(this->annotation_prefix, ".vel_over_threshold"));
        vel_below_m0.allocate(pb, FMT(this->annotation_prefix, ".vel_below_m0"));
        dum1.allocate(pb, FMT(this->annotation_prefix, ".dum1"));
        dum2.allocate(pb, FMT(this->annotation_prefix, ".dum2"));
        protection_on_1.allocate(pb, FMT(this->annotation_prefix, ".protection_on"));
        output.allocate(pb, FMT(this->annotation_prefix, ".output"));
        k_gain.reset(new gain_gadget<FieldT>(this->pb, pb_linear_combination<FieldT>(pb, velocity - vel_m0), k, precision, word_size,
                                             FMT(this->annotation_prefix, ".k_gain")));
        comp_vel_over_threshold.reset(new comparison_gadget<FieldT>(
            pb, word_size, pb_linear_combination<FieldT>(pb, threshold + vel_m0), velocity, vel_over_threshold, dum1,
            FMT(this->annotation_prefix, ".comp_vel_over_threshold")));
        comp_vel_below_m0.reset(new comparison_gadget<FieldT>(pb, word_size, velocity, pb_linear_combination<FieldT>(pb, vel_m0),
                                                                        vel_below_m0, dum2,
                                                                        FMT(this->annotation_prefix,
                                                                            ".comp_vel_below_m0")));
        s_manager.add_state(protection_on);
    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_output() const;
    const pb_variable<FieldT>& get_is_enabled() const;
    bool is_hsp_enabled() const;
};

/**
 * pitch attitude protection gadget
 *
 * inputs:
 * - pitch angle
 * - pitch command
 *
 * computation:
 * - limits pitch command to at max 0, if pitch_angle > pitch_angle_max
 * - limits pitch command to at min 0, if pitch_angle < pitch_angle_min
 *
 * outputs:
 * - pitch command
 *
 *  pitch_angle_max: maximum pitch angle
 *  pitch_angle_min: minimum pitch angle
 *
 *
 *  Word Size:
 *  Number of bits to represent the output values
 */
template <typename FieldT>
class pitch_attitude_protection_gadget : public gadget<FieldT>
{
private:
    unsigned int pitch_angle_max;
    unsigned int pitch_angle_min;

    const pb_linear_combination<FieldT> pitch_command;
    const pb_linear_combination<FieldT> pitch_angle;

    std::shared_ptr<libsnark::comparison_gadget<FieldT>> comp_pitch_max;
    std::shared_ptr<libsnark::comparison_gadget<FieldT>> comp_pitch_min;
    std::shared_ptr<limit_max_gadget<FieldT>> limit_pitch_max;
    std::shared_ptr<limit_min_gadget<FieldT>> limit_pitch_min;

    pb_variable<FieldT> pitch_ge_max;
    pb_variable<FieldT> pitch_lt_min;

    pb_variable<FieldT> pitch_limited_max;
    pb_variable<FieldT> pitch_limited_min;

    pb_variable<FieldT> dum1;
    pb_variable<FieldT> dum2;

    pb_variable<FieldT> pitch_command_1;
    pb_variable<FieldT> output;

public:
    pitch_attitude_protection_gadget(protoboard<FieldT>& pb,
                                     const pb_linear_combination<FieldT>& pitch_command,
                                     const pb_linear_combination<FieldT>& pitch_angle,
                                     const int pitch_angle_max,
                                     const int pitch_angle_min,
                                     const unsigned int word_size,
                                     const std::string& annotation_prefix = "") :
        gadget<FieldT>(pb, annotation_prefix),
        pitch_angle_max(pitch_angle_max), pitch_angle_min(pitch_angle_min),
        pitch_command(pitch_command), pitch_angle(pitch_angle)
    {
        pitch_ge_max.allocate(pb, FMT(this->annotation_prefix, ".pitch_ge_max"));
        pitch_lt_min.allocate(pb, FMT(this->annotation_prefix, ".pitch_lt_min"));
        pitch_limited_max.allocate(pb, FMT(this->annotation_prefix, ".pitch_limited_max"));
        pitch_limited_min.allocate(pb, FMT(this->annotation_prefix, ".pitch_limited_min"));
        dum1.allocate(pb, FMT(this->annotation_prefix, ".dum1"));
        dum2.allocate(pb, FMT(this->annotation_prefix, ".dum2"));
        pitch_command_1.allocate(pb, FMT(this->annotation_prefix, ".pitch_command_1"));
        output.allocate(pb, FMT(this->annotation_prefix, ".output"));

        comp_pitch_max.reset(new comparison_gadget<FieldT>(pb, word_size,
                                                           pb_linear_combination<FieldT>(
                                                               pb, pitch_angle_max), pitch_angle,
                                                           pitch_ge_max, dum1,
                                                           FMT(this->annotation_prefix, ".comp_pitch_max")));
        comp_pitch_min.reset(new comparison_gadget<FieldT>(pb, word_size, pitch_angle,
                                                            pb_linear_combination<FieldT>(pb, pitch_angle_min),
                                                           pitch_lt_min, dum2,
                                                           FMT(this->annotation_prefix, ".comp_pitch_min")));
        limit_pitch_min.reset(new limit_min_gadget<FieldT>(pb, word_size, 0, pitch_command, pitch_limited_min,
                                                           FMT(this->annotation_prefix, ".limit_min_gadget")));
        limit_pitch_max.reset(new limit_max_gadget<FieldT>(pb, word_size, 0, pitch_command, pitch_limited_max,
                                                           FMT(this->annotation_prefix, ".limit_max_gadget")));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_output() const;
};

/**
 * bank angle protection gadget
 *
 * inputs:
 * - bank angle
 * - roll command
 *
 * computation:
 * - limits roll angle to phi_max
 * - below phi_stab, roll rate is commanded, above phi_stab, roll angle is commanded
 *
 * outputs:
 * - roll command
 *
 *  phi_stab: bank angle limit for stabilizing roll command
 *  phi_max: absolute limit for bank angle
 *
 *  Word Size:
 *  Number of bits to represent the output values
 */
template <typename FieldT>
class bank_angle_protection_gadget : public gadget<FieldT>
{
private:
    unsigned int phi_stab;
    unsigned int phi_max;
    unsigned int stick_max;
    unsigned int gain_stick_to_phi;
    std::shared_ptr<comparison_gadget<FieldT>> comp_phi_stab_pos;
    std::shared_ptr<comparison_gadget<FieldT>> comp_phi_stab_neg;
    std::shared_ptr<fixed_division_gadget<FieldT>> division_pos;
    std::shared_ptr<fixed_division_gadget<FieldT>> division_neg;

    const pb_linear_combination<FieldT> roll_command;
    const pb_linear_combination<FieldT> bank_angle;

    pb_variable<FieldT> bank_ge_stab_pos;
    pb_variable<FieldT> bank_lt_stab_neg;

    pb_variable<FieldT> dum1;
    pb_variable<FieldT> dum2;

    pb_variable<FieldT> roll_command_protected_pos;
    pb_variable<FieldT> roll_command_protected_neg;
    pb_variable<FieldT> selected_command;
    pb_variable<FieldT> output;

public:
    bank_angle_protection_gadget(protoboard<FieldT>& pb,
                                 const linear_combination<FieldT>& roll_command,
                                 const linear_combination<FieldT>& bank_angle,
                                 const unsigned int phi_stab,
                                 const unsigned int phi_max,
                                 const unsigned int stick_max,
                                 const unsigned int precision,
                                 const unsigned int word_size,
                                 const std::string& annotation_prefix = "") :
        gadget<FieldT>(pb, annotation_prefix),
        phi_stab(phi_stab), phi_max(phi_max), stick_max(stick_max),
        roll_command(pb, roll_command), bank_angle(pb, bank_angle)

    {
        int precision_factor = (1 << precision);
        gain_stick_to_phi = (stick_max * precision_factor) / (phi_max - phi_stab);
        roll_command_protected_pos.allocate(pb, FMT(this->annotation_prefix, ".roll_command_protected_pos"));
        roll_command_protected_neg.allocate(pb, FMT(this->annotation_prefix, ".roll_command_protected_neg"));
        selected_command.allocate(pb, FMT(this->annotation_prefix, ".selected_command"));
        output.allocate(pb, FMT(this->annotation_prefix, ".output"));
        bank_ge_stab_pos.allocate(pb, FMT(this->annotation_prefix, ".bank_ge_stab_pos"));
        bank_lt_stab_neg.allocate(pb, FMT(this->annotation_prefix, ".bank_lt_stab_neg"));

        dum1.allocate(pb, FMT(this->annotation_prefix, ".dum1"));
        dum2.allocate(pb, FMT(this->annotation_prefix, ".dum2"));

        comp_phi_stab_pos.reset(new comparison_gadget<FieldT>(pb, word_size, pb_linear_combination<FieldT>(pb, phi_stab), this->bank_angle,
                                                                        bank_ge_stab_pos, dum1,
                                                                        FMT(this->annotation_prefix,
                                                                            ".comp_phi_stab_pos")));
        comp_phi_stab_neg.reset(new comparison_gadget<FieldT>(pb, word_size, this->bank_angle, pb_linear_combination<FieldT>(pb, -1* static_cast<int>(phi_stab)),
                                                                        bank_lt_stab_neg, dum2,
                                                                        FMT(this->annotation_prefix,
                                                                            ".comp_phi_stab_neg")));

        division_pos.reset(new fixed_division_gadget<FieldT>(this->pb, word_size,
                                                             roll_command + phi_stab * gain_stick_to_phi - bank_angle *
                                                             gain_stick_to_phi, precision_factor,
                                                             roll_command_protected_pos,
                                                             FMT(this->annotation_prefix, ".division_pos")));
        division_neg.reset(new fixed_division_gadget<FieldT>(this->pb, word_size,
                                                             roll_command - phi_stab * gain_stick_to_phi - bank_angle *
                                                             gain_stick_to_phi, precision_factor,
                                                             roll_command_protected_neg,
                                                             FMT(this->annotation_prefix, ".division_neg")));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_output() const;
    bool is_bap_enabled() const;
};


#include "flightcontrol_gadgets.tcc"

#endif //_FLIGHTCONTROL_GADGETS_H
