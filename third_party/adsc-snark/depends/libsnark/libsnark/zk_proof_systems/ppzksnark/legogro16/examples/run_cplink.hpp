/** @file
 *****************************************************************************

 Declaration of functionality that runs the LegoSNARK CP-LINK

 References: https://eprint.iacr.org/2019/142
 *****************************************************************************/

#ifndef RUN_CP_LINK_HPP_
#define RUN_CP_LINK_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>

namespace libsnark {

/**
*
 */
template<typename ppT>
bool run_cplink(size_t commitment_size);

} // libsnark

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/examples/run_cplink.tcc>

#endif // RUN_CP_LINK_HPP_
