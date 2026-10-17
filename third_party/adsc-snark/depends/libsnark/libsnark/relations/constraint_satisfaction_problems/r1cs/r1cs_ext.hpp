/** @file
 *****************************************************************************

 Helper classes for R1CS constraint system with additional information

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_EXT_HPP_
#define R1CS_EXT_HPP_

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace libsnark {


/**
 * R1CS constraint system with additional private-input size information
 */
template<typename FieldT>
class r1cs_ad_constraint_system : public r1cs_constraint_system<FieldT>{
public:
    size_t private_input_size;

    r1cs_ad_constraint_system(r1cs_constraint_system<FieldT> &&cs, size_t private_input_size) :
            r1cs_constraint_system<FieldT>(std::move(cs)),
            private_input_size(private_input_size)
    {}
};

/**
 * R1CS constraint system with additional state size information
 */
template<typename FieldT>
class r1cs_sc_constraint_system : public r1cs_constraint_system<FieldT>{
public:
    size_t state_size;

    r1cs_sc_constraint_system(r1cs_constraint_system<FieldT> &&cs, size_t state_size) :
            r1cs_constraint_system<FieldT>(std::move(cs)),
            state_size(state_size)
    {}
};

/**
 * R1CS constraint system with additional commitment size information
 */
template<typename FieldT>
class r1cs_cc_constraint_system : public r1cs_constraint_system<FieldT>{
public:
    size_t commitment_size;
    std::vector<size_t> n;

    r1cs_cc_constraint_system(r1cs_constraint_system<FieldT> &&cs, const std::vector<size_t> &n) :
            r1cs_constraint_system<FieldT>(std::move(cs)),
            commitment_size(0),
            n(n)
    {
        for(size_t i = 0; i < n.size(); ++i){
            commitment_size += n[i];
        }
    }
};

/**
 * R1CS constraint system with additional private-input and state size information
 */
template<typename FieldT>
class r1cs_adsc_constraint_system : public r1cs_constraint_system<FieldT>{
public:
    size_t private_input_size;
    size_t state_size;

    r1cs_adsc_constraint_system() :
            r1cs_constraint_system<FieldT>()
    {}

    r1cs_adsc_constraint_system(r1cs_constraint_system<FieldT> &&cs, size_t private_input_size, size_t state_size) :
            r1cs_constraint_system<FieldT>(std::move(cs)),
            private_input_size(private_input_size),
            state_size(state_size)
    {}
};


} // libsnark


#endif // R1CS_EXT_HPP_
