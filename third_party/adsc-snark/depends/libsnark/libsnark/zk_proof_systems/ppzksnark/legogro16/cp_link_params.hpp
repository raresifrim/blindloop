/** @file
 *****************************************************************************

 Declaration of public-parameter selector for CPlink

 *****************************************************************************/

#ifndef CP_LINK_PARAMS_HPP_
#define CP_LINK_PARAMS_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cc_gro16_params.hpp>

namespace libsnark {

/**
 * Below are various template aliases (used for convenience).
 */

// Commitment key, coefficients [f]1 of relation-dependent commitment
template<typename ppT>
using cp_link_ck_special = cc_gro16_commitment_key<ppT>;

template<typename ppT>
using cp_link_ck_special_vector = std::vector<cp_link_ck_special<ppT>>;

// Commitment key of CPlink, contains generic coefficients [h]1
template<typename ppT>
using cp_link_ck_generic = libff::G1_vector<ppT>;

// Commitment of cplink for the relation-specific commitment
template<typename ppT>
using cp_link_commitment_special = cc_gro16_commitment<ppT>;

// Commitment of cplink for the generic commitment
template<typename ppT>
using cp_link_commitment_generic = libff::G1<ppT>;

template<typename ppT>
using cp_link_commitment_generic_vector = std::vector<libff::G1<ppT>>;

// Commitment of cplink for the relation-specific commitment
template<typename ppT>
using cp_link_opening_special = cc_gro16_opening<ppT>;

// Commitment of cplink for the generic commitment
template<typename ppT>
using cp_link_opening_generic = libff::Fr<ppT>;

template<typename ppT>
using cp_link_opening_generic_vector = std::vector<cp_link_opening_generic<ppT>>;

// assignment
template<typename ppT>
using cp_link_assignment = libff::Fr_vector<ppT>;

template<typename ppT>
using cp_link_assignment_vector = std::vector<libff::Fr_vector<ppT>>;

} // libsnark

#endif // CP_LINK_PARAMS_HPP_
