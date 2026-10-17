/** @file
 *****************************************************************************

 Implementation of interfaces for sequence check gadget.

 See sequence_check_gadget.hpp .

 *****************************************************************************/

template<typename FieldT>
void sequence_check_gadget<FieldT>::generate_r1cs_constraints()
{
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(1, n.out, n.in + 1), FMT(this->annotation_prefix, "(n=n+1)"));
}

template<typename FieldT>
void sequence_check_gadget<FieldT>::generate_r1cs_witness()
{
    this->pb.val(n.out) = this->pb.val(n.in) + FieldT::one();
}