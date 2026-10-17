#ifndef ETHSNARKS_ASSERTZEROP_HPP_
#define ETHSNARKS_ASSERTZEROP_HPP_

#include "ethsnarks.hpp"


namespace ethsnarks {

/**
* Constrains m_X to be non-zero
*/
class AssertNonZero : public GadgetT {
public:
    // Input variable
    const VariableT m_X;

    // 1/X
    const VariableT m_M;

    AssertNonZero(
        ProtoboardT& in_pb,
        const VariableT& in_var,
        const std::string &annotation_prefix);

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};

// namespace ethsnarks
}

// ETHSNARKS_ASSERTZEROP_HPP_
#endif
