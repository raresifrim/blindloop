/** @file
 *****************************************************************************

 Declaration of public-parameter selector for Pedersen Commitment

 *****************************************************************************/

#ifndef PEDERSEN_COMMITMENT_PARAMS_HPP_
#define PEDERSEN_COMMITMENT_PARAMS_HPP_

#include <libff/algebra/curves/public_params.hpp>

namespace libsnark {

/**
 * Below are various template aliases (used for convenience).
 */


// Commitment key of Pedersen Commitment, contains (generic) coefficients [h]1
template<typename ppT>
using pedersen_commitment_key = libff::G1_vector<ppT>;

template<typename ppT>
using pedersen_commitment_commitment = libff::G1<ppT>;

template<typename ppT>
using pedersen_commitment_commitment_vector = std::vector<pedersen_commitment_commitment<ppT>>;

template<typename ppT>
using pedersen_commitment_opening = libff::Fr<ppT>;

template<typename ppT>
using pedersen_commitment_opening_vector = std::vector<pedersen_commitment_opening<ppT>>;

template<typename ppT>
using pedersen_commitment_assignment = libff::Fr_vector<ppT>;

template<typename ppT>
using pedersen_commitment_assignment_vector = std::vector<pedersen_commitment_assignment<ppT>>;

} // libsnark

#endif // PEDERSEN_COMMITMENT_PARAMS_HPP_
