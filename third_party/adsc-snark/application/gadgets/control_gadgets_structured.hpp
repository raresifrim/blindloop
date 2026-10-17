/** @file
 *****************************************************************************

 Declaration of interfaces for control gadgets

 Requires a structured protoboard, as gadgets are stateful

 Includes:
 pid_structured_gadget: Discrete PID Controller with Lowpass-Filter on D-Component

 pt1_structured_gadget: Discrete PT1 Controller

 integrator_structured_gadget: Discrete Integrator

 gain_gadgets: Simple Gain (Multiplication). Not stateful
 *****************************************************************************/

#ifndef _CONTROL_GADGETS_STRUCTURED_H
#define _CONTROL_GADGETS_STRUCTURED_H

#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/state_structured.hpp"
#include "application/gadgets/integer_arithmetic.hpp"

/**
 * pid control gadget
 * discrete pid controller derived from continuous transfer-function using forward-euler approximation:
 * P + I*Ts*1/(z-1) + D/(Tf + Ts*1/(z-1))
 *
 * P,I,D are the controller gains
 * Ts is the discretization time constant (= control loop frequency)
 * Tf is the filter time for realizing the D-term
 *
 * Multiplying out coefficients results in the following transfer function:
 *
 * b0 * z^2 + b1 * z + b2
 * ----------------------
 * z^2 + a1*z + a2
 *
 * this is equivalent to the state-space model representation
 * in controllable canonical form:
 *
 * x(t+1) = Ax(t) + Bu(t)
 * y(t) = Cx(t) + du(t)
 *
 * A =  [0      1]
 *      [-a2  -a1]
 *
 * B =  [0]
 *      [1]
 *
 * C = [b2-a2*b0    b1-a1*b0]
 *
 * d = b0
 *
 * with coefficients
 * a1 = Ts/Tf - 2
 * a2 = 1 - Ts/Tf
 * b0 = P+D/Tf
 * b1 = P*(Ts/Tf - 2) + I*Ts - 2*D/Tf
 * b2 = P(1 - Ts/Tf) + I*Ts*(Ts/Tf - 1) + D/Tf
 *
 *  Precision:
 *  number of bits to shift the coefficients:
 *  p = 1 << precision
 *  x(t+1) = ((A*p)x(t) + (B*p)*u(t))/p
 *  y(t) = ((C*p)*x(t) + (d*p)*u(t))/p
 *  (where *p and /p is element-wise)
 *
 *  The higher the precision, the lower the rounding errors
 *
 *  Word Size:
 *  Number of bits to represent the state and the output values
 */
template<typename FieldT>
class pid_structured_gadget : public gadget<FieldT> {
private:
    pb_state_structured<FieldT> x_0;
    pb_state_structured<FieldT> x_1;
    std::shared_ptr<fixed_division_gadget<FieldT>> division_x1;
    std::shared_ptr<fixed_division_gadget<FieldT>> division_y;
    int a10, a11, c0, c1, b01, d;
public:
    const pb_variable<FieldT> &output;


    pid_structured_gadget(structured_protoboard<FieldT>& pb,
                          ::state_manager<FieldT> &s_manager,
                          const linear_combination<FieldT> &input,
               const pb_variable<FieldT> &output,
               double p_gain,
               double i_gain,
               double d_gain,
               double tf,
               double ts,
               const unsigned int precision,
               const unsigned int word_size,
               const std::string &annotation_prefix="") :
            gadget<FieldT>(pb, annotation_prefix),
            x_0(pb, s_manager.id_block_in, s_manager.id_block_out, FieldT(0), annotation_prefix),
            x_1(pb, s_manager.id_block_in, s_manager.id_block_out, FieldT(0), annotation_prefix),
            output(output)
    {
        int precision_factor = (1 << precision);
        double a1, a2, b0, b1, b2;
        a1 = ts/tf - 2;
        a2 = 1 - ts/tf;
        b0 = p_gain+d_gain/tf;
        b1 = p_gain*(ts/tf - 2) + i_gain*ts - 2*d_gain/tf;
        b2 = p_gain*(1 - ts/tf) + i_gain*ts*(ts/tf - 1) + d_gain/tf;

        a10 = -a2*precision_factor;
        a11 = -a1*precision_factor;
        c0 = (b2-a2*b0)*precision_factor;
        c1 = (b1-a1*b0)*precision_factor;
        b01 = 1*precision_factor;
        d = b0*precision_factor;

        division_x1.reset(new fixed_division_gadget<FieldT>(this->pb, word_size, a10*x_0.in + a11*x_1.in + b01*input, precision_factor, x_1.out, FMT(this->annotation_prefix, ".division_x1")));
        division_y.reset(new fixed_division_gadget<FieldT>(this->pb, word_size, c0*x_0.in + c1*x_1.in, precision_factor, output, FMT(this->annotation_prefix, ".division_y")));

        s_manager.add_state(x_0);
        s_manager.add_state(x_1);
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


/**
 * pt1 control gadget
 *
 * from Lunze Regelungstechnik II, Example 11.2
 * State Transfer function
 * x' = -1/T*x + 1/T*u
 * y = K * x
 *
 * Time discrete:
 * x(t+1) = a*x(t) + (1-a)*u(t)
 * y = K*x(t)
 *
 * a = exp(-ts/T)
 *
 * K: k_gain, proportional amplification
 * T: t_const, filter time
 * ts: discretization time
 *
 *  Precision:
 *  number of bits to shift the coefficients:
 *  p = 1 << precision
 *  x_new = ((a*p)*x + ((1-a)*p)*u)/p
 *  y = (K*p)*x/p
 *
 *  The higher the precision, the lower the rounding errors
 *
 *  Word Size:
 *  Number of bits to represent the state and the output values
 */
template<typename FieldT>
class pt1_structured_gadget : public gadget<FieldT> {
private:
    int coeff_k;
    int coeff_x;
    int coeff_u;
    pb_state_structured<FieldT> x_i;
    state_manager<FieldT> &s_manager;
    const unsigned int precision;
    const unsigned int word_size;
    std::shared_ptr<fixed_division_gadget<FieldT>> division_x;
    std::shared_ptr<fixed_division_gadget<FieldT>> division_y;
    const pb_linear_combination<FieldT> input;
    const pb_variable<FieldT> &output;

public:


    pt1_structured_gadget(structured_protoboard<FieldT>& pb,
                          ::state_manager<FieldT> &s_manager,
                          const pb_linear_combination<FieldT> &input,
                            const pb_variable<FieldT> &output,
               const double k_gain,
               const double t_const,
               const double ts,
               const unsigned int precision,
               const unsigned int word_size,
               const std::string &annotation_prefix="") :
            gadget<FieldT>(pb, annotation_prefix),
            x_i(pb, s_manager.id_block_in, s_manager.id_block_out, FieldT(0), annotation_prefix),
            s_manager(s_manager), precision(precision), word_size(word_size), input(input), output(output)
    {
        int precision_factor = (1 << precision);
        coeff_x = exp(-ts/t_const) * precision_factor;
        coeff_u = -expm1(-ts/t_const) * precision_factor;
        coeff_k = k_gain * precision_factor;

        division_x.reset(new fixed_division_gadget<FieldT>(this->pb, word_size, coeff_x * x_i.in + coeff_u * input, precision_factor, x_i.out, FMT(this->annotation_prefix, ".division_x")));
        division_y.reset(new fixed_division_gadget<FieldT>(this->pb, word_size, coeff_k * x_i.in, precision_factor, output, FMT(this->annotation_prefix, ".division_y")));
        s_manager.add_state(x_i);
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

/**
 * integrator control gadget
 *
 * Discrete-Time Integrator
 * that uses Backward-Euler Approximation
 * State Transfer function
 *
 * Time discrete:
 * y(t) = y(t-1) + K*ts*u(t)
*
 *
 * K: k_gain, proportional amplification
 * ts: discretization time
 *
 *  Precision:
 *  number of bits to shift the coefficients:
 *  p = 1 << precision
 *  y(t) = y(t-1) + (K*p*ts*u(t)) / p
*
 *  The higher the precision, the lower the rounding errors
 *
 *  Word Size:
 *  Number of bits to represent the output values
 */
template<typename FieldT>
class integrator_structured_gadget : public gadget<FieldT> {
private:
    int coeff_k;
    pb_state_structured<FieldT> x_i;
    state_manager<FieldT> &s_manager;
    const unsigned int precision;
    const unsigned int word_size;
    std::shared_ptr<fixed_division_gadget<FieldT>> division;
    const pb_linear_combination<FieldT> input;
    const pb_variable<FieldT> delta;

public:

    integrator_structured_gadget(structured_protoboard<FieldT>& pb,
                          ::state_manager<FieldT> &s_manager,
                          const pb_linear_combination<FieldT> &input,
               const double k_gain,
               const double ts,
               const unsigned int precision,
               const unsigned int word_size,
               const std::string &annotation_prefix="") :
            gadget<FieldT>(pb, annotation_prefix),
            x_i(pb, s_manager.id_block_in, s_manager.id_block_out, FieldT(0), annotation_prefix),
            s_manager(s_manager), precision(precision), word_size(word_size), input(input)
    {
        int precision_factor = (1 << precision);
        coeff_k = k_gain * ts * precision_factor;
        delta.allocate(pb, FMT(this->annotation_prefix, ".delta"));

        division.reset(new fixed_division_gadget<FieldT>(this->pb, word_size, coeff_k * input, precision_factor, delta, FMT(this->annotation_prefix, ".division")));
        s_manager.add_state(x_i);
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_output() const;
};

/**
 * limited integrator control gadget
 *
 * Discrete-Time Integrator with upper and lower limits
 * that uses Backward-Euler Approximation
 * State Transfer function
 *
 * Time discrete:
 * y(t) = limit(y(t-1) + K*ts*u(t), min, max)
 *
 *
 * K: k_gain, proportional amplification
 * ts: discretization time
 *
 *  Precision:
 *  number of bits to shift the coefficients:
 *  p = 1 << precision
 *  y(t) = y(t-1) + (K*p*ts*u(t)) / p
*
 *  The higher the precision, the lower the rounding errors
 *
 *  Word Size:
 *  Number of bits to represent the output values
 */
template<typename FieldT>
class limited_integrator_structured_gadget : public gadget<FieldT> {
private:
    int coeff_k;
    pb_state_structured<FieldT> x_i;
    state_manager<FieldT> &s_manager;
    const unsigned int precision;
    const unsigned int word_size;
    std::shared_ptr<fixed_division_gadget<FieldT>> division;
    std::shared_ptr<limit_gadget<FieldT>> limit;
    const pb_linear_combination<FieldT> input;
    pb_variable<FieldT> delta;

public:

    limited_integrator_structured_gadget(structured_protoboard<FieldT>& pb,
                          ::state_manager<FieldT> &s_manager,
                          const linear_combination<FieldT> &input,
               double k_gain,
               double ts,
               int min,
               int max,
               unsigned int precision,
               unsigned int word_size,
               const std::string &annotation_prefix="") :
            gadget<FieldT>(pb, annotation_prefix),
            x_i(pb, s_manager.id_block_in, s_manager.id_block_out, FieldT(0), annotation_prefix),
            s_manager(s_manager), precision(precision), word_size(word_size), input(pb, input)
    {
        int precision_factor = (1 << precision);
        coeff_k = k_gain * ts * precision_factor;
        delta.allocate(pb, FMT(this->annotation_prefix, ".delta"));

        division.reset(new fixed_division_gadget<FieldT>(this->pb, word_size, coeff_k * this->input, precision_factor, delta, FMT(this->annotation_prefix, ".division")));
        limit.reset(new limit_gadget<FieldT>(this->pb, word_size, min, max, delta + x_i.in, x_i.out, FMT(this->annotation_prefix, ".limit")));
        s_manager.add_state(x_i);
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_output() const;
};

/**
 * gain control gadget
 *
 * fixed gain multiplier
 *
 * State Transfer function
 *
 * Time discrete:
 * y(t) = K*u(t)
*
 *
 * K: k_gain, proportional amplification
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
template<typename FieldT>
class gain_gadget : public gadget<FieldT> {
private:
    int coeff_k;
    const unsigned int precision;
    const unsigned int word_size;
    std::shared_ptr<fixed_division_gadget<FieldT>> division;
    pb_variable<FieldT> output;

public:
    gain_gadget(protoboard<FieldT>& pb,
               const linear_combination<FieldT> &input,
               const double k_gain,
               const unsigned int precision,
               const unsigned int word_size,
               const std::string &annotation_prefix="") :
            gadget<FieldT>(pb, annotation_prefix),
            precision(precision), word_size(word_size)
    {
        int precision_factor = (1 << precision);
        coeff_k = k_gain * precision_factor;
        output.allocate(pb, FMT(this->annotation_prefix, ".out"));

        division.reset(new fixed_division_gadget<FieldT>(this->pb, word_size, coeff_k * input, precision_factor, output, FMT(this->annotation_prefix, ".division")));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
    const pb_variable<FieldT>& get_output() const;

};

#include "control_gadgets_structured.tcc"

#endif //_CONTROL_GADGETS_STRUCTURED_H
