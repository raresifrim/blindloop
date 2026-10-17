/** @file
 *****************************************************************************

 Implementation of interfaces for comparison gadget.

 See comp_gadgets.hpp

 *****************************************************************************/

#include "comp_gadgets.hpp"

template<typename FieldT>
void limit_gadget<FieldT>::generate_r1cs_constraints()
{
    comp_lower->generate_r1cs_constraints();
    comp_upper->generate_r1cs_constraints();

    // l_limited_val = too_small * min + (1 - too_small) * val
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(value, (1 - too_small), l_limited_value - too_small*min), FMT(this->annotation_prefix, " lower limit constraint"));

    // limited_val = too_large * max + (1 - too_large) * l_limited_val
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(l_limited_value, (1 - too_large),  -too_large*max + limited_value), FMT(this->annotation_prefix, " upper limit constraint"));
}

template<typename FieldT>
void limit_gadget<FieldT>::generate_r1cs_witness()
{
    value.evaluate(this->pb);

    comp_lower->generate_r1cs_witness();
    comp_upper->generate_r1cs_witness();

    this->pb.val(l_limited_value) = !this->pb.val(too_small).is_zero() ? FieldT(min) : this->pb.lc_val(value);
    this->pb.val(limited_value) = !this->pb.val(too_large).is_zero() ? FieldT(max) : this->pb.val(l_limited_value);
}

template<typename FieldT>
void limit_max_gadget<FieldT>::generate_r1cs_constraints()
{
    comp_upper->generate_r1cs_constraints();

    // limited_val = too_large * max + (1 - too_large) * l_limited_val
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(l_limited_value, (1 - too_large),  -too_large*max + limited_value), FMT(this->annotation_prefix, " upper limit constraint"));
}

template<typename FieldT>
void limit_max_gadget<FieldT>::generate_r1cs_witness()
{
    value.evaluate(this->pb);

    comp_upper->generate_r1cs_witness();

    this->pb.val(limited_value) = !this->pb.val(too_large).is_zero() ? FieldT(max) : this->pb.val(l_limited_value);
}

template<typename FieldT>
void limit_min_gadget<FieldT>::generate_r1cs_constraints()
{
    comp_lower->generate_r1cs_constraints();

    // l_limited_val = too_small * min + (1 - too_small) * val
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(value, (1 - too_small), l_limited_value - too_small*min), FMT(this->annotation_prefix, " lower limit constraint"));
}

template<typename FieldT>
void limit_min_gadget<FieldT>::generate_r1cs_witness()
{
    value.evaluate(this->pb);

    comp_lower->generate_r1cs_witness();

    this->pb.val(l_limited_value) = !this->pb.val(too_small).is_zero() ? FieldT(min) : this->pb.lc_val(value);
}

template<typename FieldT>
void assert_positive_gadget<FieldT>::generate_r1cs_constraints()
{
    pack_value->generate_r1cs_constraints(true);
}

template<typename FieldT>
void assert_positive_gadget<FieldT>::generate_r1cs_witness()
{
    value.evaluate(this->pb);
    pack_value->generate_r1cs_witness_from_packed();
}
