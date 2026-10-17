/** @file
 *****************************************************************************

 Implementation of interfaces for control gadget.

 See control_gadgets_structured.hpp

 *****************************************************************************/

#include "control_gadgets_structured.hpp"

template<typename FieldT>
void pid_structured_gadget<FieldT>::generate_r1cs_constraints()
{
    this->pb.add_r1cs_constraint(r1cs_constraint<FieldT>(1, x_1.in, x_0.out), FMT(this->annotation_prefix, "(x0.out=x1_in)"));

    division_x1->generate_r1cs_constraints();
    division_y->generate_r1cs_constraints();
}

template<typename FieldT>
void pid_structured_gadget<FieldT>::generate_r1cs_witness()
{
    this->pb.val(x_0.out) = this->pb.val(x_1.in);

    division_x1->generate_r1cs_witness();
    division_y->generate_r1cs_witness();
}

template<typename FieldT>
void pt1_structured_gadget<FieldT>::generate_r1cs_constraints()
{
    division_x->generate_r1cs_constraints();
    division_y->generate_r1cs_constraints();
}

template<typename FieldT>
void pt1_structured_gadget<FieldT>::generate_r1cs_witness()
{
    division_x->generate_r1cs_witness();
    division_y->generate_r1cs_witness();
}

template<typename FieldT>
void integrator_structured_gadget<FieldT>::generate_r1cs_constraints()
{
    division->generate_r1cs_constraints();
    this->pb.add_r1cs_constraint(x_i.in + delta, ONE, x_i.out);
}

template<typename FieldT>
void integrator_structured_gadget<FieldT>::generate_r1cs_witness()
{
    division->generate_r1cs_witness();
    this->pb.val(x_i.out) = this->pb.val(x_i.in) + this->pb.val(delta);
}

template<typename FieldT>
const pb_variable<FieldT>& integrator_structured_gadget<FieldT>::get_output() const
{
    return x_i.out;
}

template<typename FieldT>
void limited_integrator_structured_gadget<FieldT>::generate_r1cs_constraints()
{
    division->generate_r1cs_constraints();
    limit->generate_r1cs_constraints();
}

template<typename FieldT>
void limited_integrator_structured_gadget<FieldT>::generate_r1cs_witness()
{
    division->generate_r1cs_witness();
    limit->generate_r1cs_witness();
}

template<typename FieldT>
const pb_variable<FieldT>& limited_integrator_structured_gadget<FieldT>::get_output() const
{
    return x_i.out;
}

template<typename FieldT>
void gain_gadget<FieldT>::generate_r1cs_constraints()
{
    division->generate_r1cs_constraints();
}

template<typename FieldT>
void gain_gadget<FieldT>::generate_r1cs_witness()
{
    division->generate_r1cs_witness();
}

template<typename FieldT>
const pb_variable<FieldT>& gain_gadget<FieldT>::get_output() const
{
    return output;
}