/** @file
 *****************************************************************************

 Implementation of interfaces for integer arithmetic gadget.

 See integer_arithmetic.hpp

 *****************************************************************************/

#include "integer_arithmetic.hpp"

template<typename FieldT>
void fixed_division_gadget<FieldT>::generate_r1cs_constraints()
{
    range_r->generate_r1cs_constraints();
    range_q->generate_r1cs_constraints();
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(divisor, q, -r + a), FMT(this->annotation_prefix, ".q*d+r=a"));
}

template<typename FieldT>
void fixed_division_gadget<FieldT>::generate_r1cs_witness()
{
    long a_val;
    long r_val;
    long q_val;

    a.evaluate(this->pb);

    a_val = field_to_signed_long(this->pb.lc_val(a));
    q_val = integer_division(a_val, divisor);

    r_val = a_val - divisor * q_val;

    this->pb.val(r) = FieldT(r_val);
    this->pb.val(q) = FieldT(q_val);

    range_r->generate_r1cs_witness();
    range_q->generate_r1cs_witness();
}


