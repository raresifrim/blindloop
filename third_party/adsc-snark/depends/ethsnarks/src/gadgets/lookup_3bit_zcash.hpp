#ifndef ETHSNARKS_LOOKUP_3BIT_ZCASH_HPP_
#define ETHSNARKS_LOOKUP_3BIT_ZCASH_HPP_

// This is the zcash 3bit lookup with only

#include "ethsnarks.hpp"

namespace ethsnarks {


class lookup_3bit_zcash_gadget : public GadgetT
{
public:
    const std::vector<FieldT> c;
    const LinearCombinationArrayT b;
    VariableT r;

    // Bit-field selectors
    const VariableT b12;

    lookup_3bit_zcash_gadget(
        ProtoboardT &in_pb,
        const std::vector<FieldT> in_constants,
        const LinearCombinationArrayT in_bits,
        const std::string& annotation_prefix
    );

    const VariableT& result();

    void generate_r1cs_constraints();

    void generate_r1cs_witness ();
};

class lookup_3bitx2_zcash_gadget : public GadgetT
{
public:
    const std::vector<FieldT> u;
    const std::vector<FieldT> v;
    const LinearCombinationArrayT b;
    VariableT r_u;
    VariableT r_v;

    // Bit-field selectors
    const VariableT b12;

    lookup_3bitx2_zcash_gadget(
            ProtoboardT &in_pb,
            const std::vector<FieldT> in_constants_u,
            const std::vector<FieldT> in_constants_v,
            const LinearCombinationArrayT in_bits,
            const std::string& annotation_prefix
    );

    const VariableT& result_u();

    const VariableT& result_v();

    void generate_r1cs_constraints();

    void generate_r1cs_witness ();
};


// namespace ethsnarks
}

// ETHSNARKS_LOOKUP_3BIT_ZCASH_HPP_
#endif
