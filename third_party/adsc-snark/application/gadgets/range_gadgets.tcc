/** @file
 *****************************************************************************

 Implementation of interfaces for range gadgets.

 See range_gadgets.hpp

 *****************************************************************************/

#include "range_gadgets.hpp"

template<typename FieldT>
void range_gadget<FieldT>::generate_r1cs_constraints()
{
    // boolean constrain bits
    for (size_t i = 0; i < bits.size(); ++i)
    {
        libsnark::generate_boolean_r1cs_constraint<FieldT>(this->pb, bits[i], FMT(this->annotation_prefix, ".bitness_%zu", i));
    }

    // compute coefficients
    FieldT coeff = FieldT::one();
    std::vector<libsnark::linear_term<FieldT> > all_terms;
    for (size_t i = 0; i < bits.size() - 1; ++i)
    {
        all_terms.emplace_back(coeff * bits[i]);
        coeff += coeff;
    }
    // last coefficient
    all_terms.emplace_back(coeff_n * bits.back());

    // min as offset
    all_terms.emplace_back(min*libsnark::ONE);

    // add min as offset
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(1, all_terms, value), FMT(this->annotation_prefix, ".sum")); // this constraint could be merged with another
}

template<typename FieldT>
void range_gadget<FieldT>::generate_r1cs_witness()
{
    value.evaluate(this->pb);
    FieldT r = this->pb.lc_val(value) - min;

    if (r >= coeff_n){
        this->pb.val(bits.back()) = FieldT::one();
        r -= coeff_n;
    }else{
        this->pb.val(bits.back()) = FieldT::zero();
    }

    const libff::bigint<FieldT::num_limbs> rint = r.as_bigint();
    for (size_t i = 0; i < bits.size() - 1; ++i){
        this->pb.val(bits[i]) = rint.test_bit(i) ? FieldT::one() : FieldT::zero();
    }

}
