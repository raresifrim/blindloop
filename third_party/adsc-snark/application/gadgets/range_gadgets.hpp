/** @file
 *****************************************************************************

 Declaration of interfaces for range gadgets

 range_gadget: checks whether a value is within a fixed range.
 *****************************************************************************/

#ifndef RANGE_GADGETS_H
#define RANGE_GADGETS_H

#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/pb_variable.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "utils.h"

template<typename FieldT>
class range_gadget : public libsnark::gadget<FieldT> {
    // checks whether value is in range
private:
    libsnark::pb_variable_array<FieldT> bits;
    long coeff_n;

public:
    int n;
    const long min;
    const long max;
    const libsnark::pb_linear_combination<FieldT> value;

    range_gadget(libsnark::protoboard<FieldT>& pb,
                       long min,
                       long max,
                       const libsnark::pb_linear_combination<FieldT> &value,
                       const std::string &annotation_prefix="") :
            libsnark::gadget<FieldT>(pb, annotation_prefix), min(min), max(max), value(value)
    {
        assert(max > min);
        n = num_bits(max-min);

        // last coefficient
        coeff_n = (max - min) - (1 << (n-1)) + 1;

        bits.allocate(pb, n, FMT(this->annotation_prefix, ".bits"));


    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

#include "range_gadgets.tcc"

#endif //RANGE_GADGETS_H
