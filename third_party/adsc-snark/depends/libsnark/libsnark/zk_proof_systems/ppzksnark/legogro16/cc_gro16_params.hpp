/** @file
 *****************************************************************************

 Declaration of public-parameter selector for ccGro16

 *****************************************************************************/

#ifndef CC_GRO16_PARAMS_HPP_
#define CC_GRO16_PARAMS_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp>

namespace libsnark {

/**
 * Below are various template aliases (used for convenience).
 */

template<typename ppT>
using cc_gro16_constraint_system = r1cs_cc_constraint_system<libff::Fr<ppT> >;

template<typename ppT>
using cc_gro16_primary_input = r1cs_primary_input<libff::Fr<ppT> >;

template<typename ppT>
using cc_gro16_auxiliary_input = r1cs_auxiliary_input<libff::Fr<ppT> >;

template<typename ppT>
using cc_gro16_commitment_key = libff::G1_vector<ppT>;

template<typename ppT>
using cc_gro16_opening = libff::Fr<ppT>;

template<typename ppT>
using cc_gro16_commitment = libff::G1<ppT>;

} // libsnark

#endif // CC_GRO16_PARAMS_HPP_
