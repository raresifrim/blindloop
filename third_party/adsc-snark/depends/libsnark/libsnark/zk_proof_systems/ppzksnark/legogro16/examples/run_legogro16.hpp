/** @file
 *****************************************************************************

 Declaration of functionality that runs LegoGro16

 *****************************************************************************/

#ifndef RUN_LEGO_GRO16_HPP_
#define RUN_LEGO_GRO16_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

namespace libsnark {

/**
 * Runs the LegoGro16
 *
 * Optionally, also test the serialization routines for keys and proofs.
 * (This takes additional time.)
 */
template<typename ppT>
bool run_lego_gro16(const r1cs_example<libff::Fr<ppT> > &example,
                        const std::vector<size_t> &commitment_slots,
                        const bool test_serialization);

} // libsnark

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/examples/run_legogro16.tcc>

#endif // RUN_LEGO_GRO16_HPP_
