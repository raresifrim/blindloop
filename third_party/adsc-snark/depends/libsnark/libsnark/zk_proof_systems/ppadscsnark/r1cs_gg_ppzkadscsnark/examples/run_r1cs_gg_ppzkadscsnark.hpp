/** @file
 *****************************************************************************

 Declaration of functionality that runs the R1CS GG-ppZKADSCSNARK for
 a given R1CS example.


 *****************************************************************************/

#ifndef RUN_R1CS_GG_PPZKADSCSNARK_HPP_
#define RUN_R1CS_GG_PPZKADSCSNARK_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_ext_examples.hpp>

namespace libsnark {

/**
 * Runs the ppZKADSCSNARK (authenticate, generator, prover, and verifier) for a given
 * R1CS example (specified by a constraint system, input, and witness).
 *
 * Optionally, also test the serialization routines for keys and proofs.
 * (This takes additional time.)
 */
template<typename ppT>
bool run_r1cs_gg_ppzkadscsnark(r1cs_adsc_example<libff::Fr<ppT>> &example,
                             size_t private_input_size,
                             size_t state_size,
                            size_t iterations,
                            bool test_serialization);

} // libsnark

#include <libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppzkadscsnark/examples/run_r1cs_gg_ppzkadscsnark.tcc>

#endif // RUN_R1CS_GG_PPZKADSCSNARK_HPP_
