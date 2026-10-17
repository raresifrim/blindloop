/** @file
 *****************************************************************************

 Declaration of interfaces for duplex voter gadget

 Compares two inputs against a threshold and outputs the average
 *****************************************************************************/

#ifndef DUPLEX_VOTER_GADGET_H
#define DUPLEX_VOTER_GADGET_H

#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp"
#include "libsnark/gadgetlib1/gadget.hpp"
#include "application/gadgets/comp_gadgets.hpp"
#include "application/gadgets/integer_arithmetic.hpp"

// duplex voter gadget
// checks that two values are within limit
// outputs average
template<typename FieldT>
class duplex_voter_gadget : public libsnark::gadget<FieldT> {
private:
    const int limit;
    std::shared_ptr<range_gadget<FieldT>> input_limit_gadget;
    std::shared_ptr<fixed_division_gadget<FieldT>> division;
public:
    const libsnark::pb_variable<FieldT> &input1;
    const libsnark::pb_variable<FieldT> &input2;
    const libsnark::pb_variable<FieldT> &voted_value;

    duplex_voter_gadget(libsnark::protoboard<FieldT>& pb,
                          const libsnark::pb_variable<FieldT> &input1,
                          const libsnark::pb_variable<FieldT> &input2,
                          const libsnark::pb_variable<FieldT> &voted_value,
                          const unsigned int wordsize,
                          const int limit,
                          const std::string &annotation_prefix="") :
            libsnark::gadget<FieldT>(pb, annotation_prefix), limit(limit), input1(input1), input2(input2), voted_value(voted_value)
    {
        libsnark::pb_linear_combination<FieldT> diff;
        diff.assign(this->pb, input1 - input2);
        input_limit_gadget.reset(new range_gadget<FieldT>(this->pb, -limit, limit,
                          diff, FMT(this->annotation_prefix, ".input_limit_gadget")));

        libsnark::pb_linear_combination<FieldT> sum;
        sum.assign(this->pb, input1+input2);

        division.reset(new fixed_division_gadget<FieldT>(this->pb, wordsize, sum, 2,
                voted_value, FMT(this->annotation_prefix, ".division")));
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


#include "duplex_voter_gadget.tcc"

#endif