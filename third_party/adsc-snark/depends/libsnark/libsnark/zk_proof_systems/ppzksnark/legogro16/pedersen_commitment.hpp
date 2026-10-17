/** @file
*****************************************************************************

Declaration of interfaces for the Pedersen Commitment


*****************************************************************************/

#ifndef PEDERSEN_COMMITMENT_HPP_
#define PEDERSEN_COMMITMENT_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/pedersen_commitment_params.hpp>

namespace libsnark {

template<typename ppT>
struct pedersen_commitment_pair {
    pedersen_commitment_commitment<ppT> commitment;
    pedersen_commitment_opening<ppT> opening;
};


/***************************** Main algorithms *******************************/


template<typename ppT>
pedersen_commitment_key<ppT> pedersen_commitment_generator(size_t max_input_size);

template<typename ppT>
pedersen_commitment_pair<ppT> pedersen_commitment_commit(const pedersen_commitment_key<ppT> &ck,
                                                         const pedersen_commitment_assignment<ppT> &assignment);

template<typename ppT>
bool pedersen_commitment_verify(const pedersen_commitment_key<ppT> &ck,
                                const pedersen_commitment_commitment<ppT> &commitment,
                                const pedersen_commitment_assignment<ppT> &assignment,
                                const pedersen_commitment_opening<ppT> &opening);


} // libsnark

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/pedersen_commitment.tcc>

#endif // PEDERSEN_COMMITMENT_HPP_
