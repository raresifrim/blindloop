/** @file
 *****************************************************************************

 Declaration of functionality that runs a LegoGro16 SNARK with state-consistency

 *****************************************************************************/

#ifndef RUN_LEGO_GRO16_SC_HPP_
#define RUN_LEGO_GRO16_SC_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_ext_examples.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp>

namespace libsnark {


template<typename ppT>
bool run_lego_gro16_sc(const r1cs_sc_example<libff::Fr<ppT>> &example,
                           size_t state_size,
                           size_t iterations,
                           bool test_serialization);

} // libsnark

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/examples/run_legogro16_sc.tcc>

#endif // RUN_LEGO_GRO16_SC_HPP_
