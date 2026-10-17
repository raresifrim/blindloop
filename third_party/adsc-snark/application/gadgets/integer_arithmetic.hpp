/** @file
 *****************************************************************************

 Declaration of interfaces for integer arithmetic gadgets

 fixed_division_gadget: divides value by a constant, rounds towards negative
 infinity. This is integer division, not division in the field
 *****************************************************************************/

#ifndef INTEGER_ARTIHMETIC_H
#define INTEGER_ARTIHMETIC_H

#include <memory>

#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"
#include "application/gadgets/range_gadgets.hpp"

template<typename FieldT>
class fixed_division_gadget : public libsnark::gadget<FieldT> {
/**
 * output q = a // d rounded towards -inf
 *
 * Constraints
 * (1) q*d + r = a (mod P)
 * (2) 0 <= r < d
 * (3) |q| < n
 *
 *
 * if |a| < n, n <= sqrt(P)-2, 0 < d < sqrt(P), then there exists one solution:
 *
 * q*d +r = a (mod P) <=> exists integer k, such that q*d + r - a = k*P
 * => q = (k*P + a - r) / d
 * if k = 0:
 * |q| = |(a - r) / d| <= | a/d |  <  n (ok, all equations satisfied)
 * if k != 0:
 * |q| = |(k*P + a - r) / d| >=  |(P - |a| - r) / d| > |P - sqrt(P) -r|/d >= sqrt(P) - 2 >= n (constr. 3 not satisfied)
 *
 * n = 1 << (output_bits - 1)
 *
 *  Output bits:
 *  number of bits required to represent the (signed) output value
 *  the larger, the more constraints
 */
private:
    libsnark::pb_variable<FieldT> r;
    const libsnark::pb_variable<FieldT> &q;
    std::shared_ptr<range_gadget<FieldT>> range_r;
    std::shared_ptr<range_gadget<FieldT>> range_q;
public:
    const libsnark::pb_linear_combination<FieldT> a;
    const unsigned int divisor;

    fixed_division_gadget(libsnark::protoboard<FieldT>& pb,
                    const unsigned int output_bits,
                    const libsnark::linear_combination<FieldT> &a,
                    const unsigned int divisor,
                    const libsnark::pb_variable<FieldT> &q,
                    const std::string &annotation_prefix="") :
            libsnark::gadget<FieldT>(pb, annotation_prefix), q(q), a(pb, a), divisor(divisor)
    {
        long range_min, range_max;
        assert(divisor > 1);
        assert(((size_t) num_bits(divisor)) < FieldT::num_bits / 2);
        assert(output_bits < sizeof(long) * 8 / 2 - 1); // if larger ranges are needed, we can change type of range to bigint
        assert(output_bits < FieldT::num_bits / 2 - 1); // if larger ranges are needed, we need other constraints
        range_max = (1 << (output_bits-1)) - 1;
        range_min = -(1 << (output_bits-1));

        r.allocate(this->pb, FMT(this->annotation_prefix, ".r"));

        range_r.reset(new range_gadget<FieldT>(this->pb, 0, divisor-1, r, FMT(this->annotation_prefix, ".range_r")));
        range_q.reset(new range_gadget<FieldT>(this->pb, range_min, range_max, q, FMT(this->annotation_prefix, ".range_q")));
    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


#include "integer_arithmetic.tcc"
#endif //INTEGER_ARTIHMETIC_H
