/** @file
 *****************************************************************************

 Declaration of public-parameter selector for LegoGro16

 *****************************************************************************/

#ifndef LEGO_GRO16_PARAMS_HPP_
#define LEGO_GRO16_PARAMS_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cc_gro16_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cp_link_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/pedersen_commitment.hpp>

namespace libsnark {

/**
 * Below are various template aliases (used for convenience).
 */

template<typename ppT>
using lego_gro16_commitment_vector = pedersen_commitment_commitment_vector<ppT>;

template<typename ppT>
using lego_gro16_commitment_pair = pedersen_commitment_pair<ppT>;

template<typename ppT>
using lego_gro16_commitment_pair_vector = std::vector<pedersen_commitment_pair<ppT>>;

template<typename ppT>
using lego_gro16_assignment = cp_link_assignment<ppT>;

template<typename ppT>
using lego_gro16_assignment_vector = std::vector<lego_gro16_assignment<ppT>>;

template<typename ppT>
using lego_gro16_opening_vector = cp_link_opening_generic_vector<ppT>;

template<typename ppT>
using lego_gro16_commitment_key = cp_link_ck_generic<ppT>;

template<typename ppT>
using lego_gro16_constraint_system = cc_gro16_constraint_system<ppT>;

template<typename ppT>
using lego_gro16_primary_input = cc_gro16_primary_input<ppT>;

template<typename ppT>
using lego_gro16_auxiliary_input = cc_gro16_auxiliary_input<ppT>;

} // libsnark

#endif // LEGO_GRO16_PARAMS_HPP_
