/** @file
 *****************************************************************************

 Implementation of interfaces for flightcontrol gadgets.

 See flightcontrol_gadgets.hpp

 *****************************************************************************/

#include "flightcontrol_gadgets.hpp"

template<typename FieldT>
void trim_gadget<FieldT>::generate_r1cs_constraints()
{
    // set input to zero (fix trim), if hsp is enabled:
    // selected_input = (1 - hsp_enabled) * input
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(input, (1 - hsp_enabled), selected_input), FMT(this->annotation_prefix, ".select_output"));
    integrator->generate_r1cs_constraints();
}

template<typename FieldT>
void trim_gadget<FieldT>::generate_r1cs_witness()
{
    input.evaluate(this->pb);

    this->pb.val(selected_input) = this->pb.val(hsp_enabled).is_zero() ? this->pb.lc_val(input) : FieldT::zero();
    integrator->generate_r1cs_witness();
}

template<typename FieldT>
const pb_variable<FieldT>& trim_gadget<FieldT>::get_output() const
{
    return integrator->get_output();
}

template<typename FieldT>
void longitudinal_control_gadget<FieldT>::generate_r1cs_constraints()
{
    integrator->generate_r1cs_constraints();
    nc_gain->generate_r1cs_constraints();
    n_gain->generate_r1cs_constraints();
    q_gain->generate_r1cs_constraints();

    // Sum up outputs
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(integrator->get_output() + nc_gain->get_output() + n_gain->get_output() + q_gain->get_output(), ONE, output), FMT(this->annotation_prefix, ".sum"));
}

template<typename FieldT>
void longitudinal_control_gadget<FieldT>::generate_r1cs_witness()
{
    integrator->generate_r1cs_witness();
    nc_gain->generate_r1cs_witness();
    n_gain->generate_r1cs_witness();
    q_gain->generate_r1cs_witness();

    this->pb.val(output) = this->pb.val(integrator->get_output())
                           + this->pb.val(nc_gain->get_output())
                           + this->pb.val(n_gain->get_output())
                           + this->pb.val(q_gain->get_output());

}

template<typename FieldT>
const pb_variable<FieldT>& longitudinal_control_gadget<FieldT>::get_output() const
{
    return output;
}

template<typename FieldT>
void lateral_control_gadget<FieldT>::generate_r1cs_constraints()
{
    integrator->generate_r1cs_constraints();
    k_gain->generate_r1cs_constraints();
    division_aileron->generate_r1cs_constraints();
    division_rudder->generate_r1cs_constraints();
}

template<typename FieldT>
void lateral_control_gadget<FieldT>::generate_r1cs_witness()
{
    roll_command.evaluate(this->pb);
    sideslip_command.evaluate(this->pb);
    roll_rate.evaluate(this->pb);
    sideslip.evaluate(this->pb);
    yaw_rate.evaluate(this->pb);
    bank_angle.evaluate(this->pb);

    integrator->generate_r1cs_witness();
    k_gain->generate_r1cs_witness();
    division_aileron->generate_r1cs_witness();
    division_rudder->generate_r1cs_witness();
}

template<typename FieldT>
const pb_variable<FieldT>& lateral_control_gadget<FieldT>::get_aileron_command() const
{
    return aileron_command;
}

template<typename FieldT>
const pb_variable<FieldT>& lateral_control_gadget<FieldT>::get_rudder_command() const
{
    return rudder_command;
}

template<typename FieldT>
void high_aoa_protection_gadget<FieldT>::generate_r1cs_constraints()
{
    comp_alpha_alpha_max->generate_r1cs_constraints();
    comp_alpha_alpha_prot->generate_r1cs_constraints();
    comp_stick_threshold->generate_r1cs_constraints();
    comp_stick_long_threshold->generate_r1cs_constraints();

    // if stick < long_threshold and alpha < alpha_max, increase timer, otherwise set to zero
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>((1 - alpha_ge_alpha_max), stick_lt_deactivate_long_threshold, increase_timer), FMT(this->annotation_prefix, ".increase_timer_condition"));
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>((timer.in + libsnark::ONE), increase_timer, timer.out), FMT(this->annotation_prefix, ".increase_timer"));

    comp_timer->generate_r1cs_constraints();

    // protection_on_1 = alpha > alpha_prot OR protection_on.in == 1
    // <=> (1 - alpha_ge_alpha_prot) * (1 - protection_on.in) == (1 - protection_on_1)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(libsnark::ONE - alpha_ge_alpha_prot, libsnark::ONE - protection_on.in, libsnark::ONE - protection_on_1), FMT(this->annotation_prefix, ".or"));

    // deactivate protection if either stick is lower than threshold or stick is lower than long threshold for enough time
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>((1 - timer_ge_threshold), (1 - stick_lt_deactivate_threshold),(1 - deactivate_protection)), FMT(this->annotation_prefix, ".deactivate_condition"));

    // if deactivate_protection, set protection_on.out = 0, otherwise, set to protection_on_1
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>((libsnark::ONE - deactivate_protection), protection_on_1, protection_on.out), FMT(this->annotation_prefix, ".apply_deactivate"));

    // if protection mode is on, modify pitch command, s.t.
    // pitch_command_protected = pitch_command + (alpha_prot - alpha) * gain_stick_to_alpha, with gain_stick_to_alpha = (stick_max/(alpha_max - alpha_prot))
    // then the maximum stick deviation commands alpha_max
    division->generate_r1cs_constraints();

    // select pitch_command_protected, if protection mode enabled, otherwise, use original pitch command:
    // output = pitch_command + protection_on.out * (pitch_command_protected - pitch_command)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(pitch_command_protected - pitch_command, protection_on.out, output - pitch_command), FMT(this->annotation_prefix, ".select_output"));
}

template<typename FieldT>
void high_aoa_protection_gadget<FieldT>::generate_r1cs_witness()
{
    pitch_command.evaluate(this->pb);
    alpha.evaluate(this->pb);

    comp_alpha_alpha_max->generate_r1cs_witness();
    comp_alpha_alpha_prot->generate_r1cs_witness();
    comp_stick_threshold->generate_r1cs_witness();
    comp_stick_long_threshold->generate_r1cs_witness();

    // if stick < long_threshold and alpha < alpha_max, increase timer, otherwise set to zero
    this->pb.val(increase_timer) = (this->pb.val(alpha_ge_alpha_max).is_zero() && !this->pb.val(stick_lt_deactivate_long_threshold).is_zero())? FieldT(1) : FieldT(0);
    this->pb.val(timer.out) = !this->pb.val(increase_timer).is_zero()? this->pb.val(timer.in) + 1 : FieldT(0);

    comp_timer->generate_r1cs_witness();

    // if alpha > alpha_prot, turn protection on
    this->pb.val(protection_on_1) = this->pb.val(alpha_ge_alpha_prot).is_zero() ? this->pb.val(protection_on.in) : FieldT(1);

    // deactivate protection if either stick is lower than threshold or stick is lower than long threshold for enough time
    this->pb.val(deactivate_protection) = (!this->pb.val(timer_ge_threshold).is_zero() || !this->pb.val(stick_lt_deactivate_threshold).is_zero())? FieldT(1): FieldT(0);

   // if deactivate_protection, set protection_on.out = 0, otherwise, set to protection_on_1
	this->pb.val(protection_on.out) = this->pb.val(deactivate_protection).is_zero() ? this->pb.val(protection_on_1) : FieldT(0);

    // if protection mode is on, modify pitch command, s.t.
    // pitch_command_protected = pitch_command + (alpha_prot - alpha) * gain_stick_to_alpha, with gain_stick_to_alpha = (stick_max/(alpha_max - alpha_prot))
    // then the maximum stick deviation commands alpha_max
    division->generate_r1cs_witness();

    // select pitch_command_protected, if protection mode enabled, otherwise, use original pitch command:
    // output = pitch_command + protection_on.out * (pitch_command_protected - pitch_command)
    this->pb.val(output) = this->pb.val(protection_on.out).is_zero()? this->pb.lc_val(pitch_command) : this->pb.val(pitch_command_protected);
}

template<typename FieldT>
const pb_variable<FieldT>& high_aoa_protection_gadget<FieldT>::get_output() const
{
    return output;
}

template<typename FieldT>
bool high_aoa_protection_gadget<FieldT>::is_aoa_enabled() const
{
    return !this->pb.val(protection_on.out).is_zero();
}



template<typename FieldT>
void high_speed_protection_gadget<FieldT>::generate_r1cs_constraints()
{
    k_gain->generate_r1cs_constraints();
    comp_vel_over_threshold->generate_r1cs_constraints();
    comp_vel_below_m0->generate_r1cs_constraints();


    // if velocity > vel_m0 + threshold, activate hs_protection
    // protection_on_1 = protection_on.in + vel_over_threshold * (1 - protection_on.in)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(vel_over_threshold, libsnark::ONE - protection_on.in, protection_on_1 - protection_on.in), FMT(this->annotation_prefix, ".vel>vel_m0+thresh?"));

    // if velocity < vel_m0, deactivate hs_protection
    // protection_on.out = protection_on_1 * (1 - vel_below_m0)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(protection_on_1, (libsnark::ONE - vel_below_m0), protection_on.out), FMT(this->annotation_prefix, ".vel<vel_m0?"));

    // if protection mode is enabled, add proportional pitch up command
    // output = pitch_command + protection_on.out * k_gain.output
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(k_gain->get_output(), protection_on.out, output - pitch_command), FMT(this->annotation_prefix, ".add_proportional_pitch_up"));
}

template<typename FieldT>
void high_speed_protection_gadget<FieldT>::generate_r1cs_witness()
{
    pitch_command.evaluate(this->pb);
    velocity.evaluate(this->pb);

    k_gain->generate_r1cs_witness();
    comp_vel_over_threshold->generate_r1cs_witness();
    comp_vel_below_m0->generate_r1cs_witness();

    // if velocity > vel_m0 + threshold, activate hs_protection
    // protection_on_1 = protection_on.in + comp_vel_over_threshold * (1 - protection_on.in)
    this->pb.val(protection_on_1) = this->pb.val(vel_over_threshold).is_zero()? this->pb.val(protection_on.in) : FieldT(1);

    // if velocity < vel_m0, deactivate hs_protection
    this->pb.val(protection_on.out) = this->pb.val(vel_below_m0).is_zero()? this->pb.val(protection_on_1) : FieldT(0);

    // if protection mode is enabled, add proportional pitch up command
    // output = pitch_command + protection_on.out * k_gain.output
    this->pb.val(output) = this->pb.lc_val(pitch_command) + (this->pb.val(protection_on.out).is_zero()? FieldT(0) : this->pb.val(k_gain->get_output()));
}

template<typename FieldT>
const pb_variable<FieldT>& high_speed_protection_gadget<FieldT>::get_output() const
{
    return output;
}

template<typename FieldT>
const pb_variable<FieldT>& high_speed_protection_gadget<FieldT>::get_is_enabled() const
{
    return protection_on.out;
}

template<typename FieldT>
bool high_speed_protection_gadget<FieldT>::is_hsp_enabled() const
{
    return !this->pb.val(protection_on.out).is_zero();
}

template<typename FieldT>
void pitch_attitude_protection_gadget<FieldT>::generate_r1cs_constraints()
{
    comp_pitch_max->generate_r1cs_constraints();
    comp_pitch_min->generate_r1cs_constraints();
	limit_pitch_max->generate_r1cs_constraints();
	limit_pitch_min->generate_r1cs_constraints();

    // if pitch > pitch_max, limit pitch command
    // pitch_command_1 = pitch_command + pitch_ge_max * (pitch_limited_max - pitch_command)
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(pitch_ge_max, pitch_limited_max - pitch_command, pitch_command_1 - pitch_command), FMT(this->annotation_prefix, ".pitch>pitch_max?"));

    // if pitch < pitch_min, limit pitch command
    // output = pitch_command_1 + pitch_lt_min * (pitch_limited_min - pitch_command_1)
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(pitch_lt_min, pitch_limited_min - pitch_command_1, output - pitch_command_1), FMT(this->annotation_prefix, ".pitch<pitch_min?"));
}

template<typename FieldT>
void pitch_attitude_protection_gadget<FieldT>::generate_r1cs_witness()
{
    pitch_command.evaluate(this->pb);
    pitch_angle.evaluate(this->pb);

    comp_pitch_max->generate_r1cs_witness();
    comp_pitch_min->generate_r1cs_witness();
	limit_pitch_max->generate_r1cs_witness();
	limit_pitch_min->generate_r1cs_witness();

    // if pitch > pitch_max, limit pitch command
    // pitch_command_1 = pitch_command + pitch_ge_max * (pitch_limited_max - pitch_command)
    this->pb.val(pitch_command_1) = this->pb.val(pitch_ge_max).is_zero()? this->pb.lc_val(pitch_command) : this->pb.val(pitch_limited_max);

    // if pitch < pitch_min, limit pitch command
    // output = pitch_command_1 + pitch_lt_min * (pitch_limited_min - pitch_command_1)
    this->pb.val(output) = this->pb.val(pitch_lt_min).is_zero()? this->pb.val(pitch_command_1) : this->pb.val(pitch_limited_min);
}

template<typename FieldT>
const pb_variable<FieldT>& pitch_attitude_protection_gadget<FieldT>::get_output() const
{
    return output;
}

template<typename FieldT>
void bank_angle_protection_gadget<FieldT>::generate_r1cs_constraints()
{
    comp_phi_stab_pos->generate_r1cs_constraints();
    comp_phi_stab_neg->generate_r1cs_constraints();
    division_pos->generate_r1cs_constraints();
    division_neg->generate_r1cs_constraints();


    // if phi > phi_stab, select command for protection mode
    // selected_command = roll_command + bank_ge_stab_pos * (roll_command_protected_pos - roll_command)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(bank_ge_stab_pos, roll_command_protected_pos - roll_command, selected_command - roll_command), FMT(this->annotation_prefix, ".selection_condition"));
    // output = selected_command + bank_lt_stab_neg * (roll_command_protected_neg - selected_command)
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(bank_lt_stab_neg, roll_command_protected_neg - selected_command, output - selected_command), FMT(this->annotation_prefix, ".select_command"));
}

template<typename FieldT>
void bank_angle_protection_gadget<FieldT>::generate_r1cs_witness()
{
    roll_command.evaluate(this->pb);
    bank_angle.evaluate(this->pb);

    comp_phi_stab_pos->generate_r1cs_witness();
    comp_phi_stab_neg->generate_r1cs_witness();
    division_pos->generate_r1cs_witness();
    division_neg->generate_r1cs_witness();

    // if phi > phi_stab, select command for protection mode
    // selected_command = roll_command + bank_ge_stab_pos * (roll_command_protected_pos - roll_command)
    this->pb.val(selected_command) = this->pb.val(bank_ge_stab_pos).is_zero()? this->pb.lc_val(roll_command): this->pb.val(roll_command_protected_pos);
    // output = selected_command + bank_lt_stab_neg * (roll_command_protected_neg - selected_command)
    this->pb.val(output) = this->pb.val(bank_lt_stab_neg).is_zero()? this->pb.val(selected_command): this->pb.val(roll_command_protected_neg);
}

template<typename FieldT>
const pb_variable<FieldT>& bank_angle_protection_gadget<FieldT>::get_output() const
{
    return output;
}

template<typename FieldT>
bool bank_angle_protection_gadget<FieldT>::is_bap_enabled() const
{
    return !this->pb.val(bank_ge_stab_pos).is_zero() || !this->pb.val(bank_lt_stab_neg).is_zero();
}
