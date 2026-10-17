/** @file
 *****************************************************************************


 Implementation of functionality that runs a LegoGro16 SNARK with state-consistency

 See run_legogro16_sc.hpp .

 *****************************************************************************/

#ifndef RUN_LEGO_GRO16_SC_TCC_
#define RUN_LEGO_GRO16_SC_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/sc_legogro16.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp>

namespace libsnark {

template<typename ppT>
bool run_lego_gro16_sc(r1cs_sc_example<libff::Fr<ppT>> &example,
                           size_t state_size,
                           size_t iterations,
                           bool test_serialization)
{
    libff::enter_block("Call to run_lego_gro16_sc");
    
    libff::enter_block("Call to r1cs_to_r1cs_sc");
    lego_gro16_constraint_system<ppT> constraint_system = r1cs_to_r1cs_cc(std::move(example.constraint_system), {state_size, state_size});
    libff::leave_block("Call to r1cs_to_r1cs_sc");

    // Check, if constraint system is satisfied within each iteration
    for(size_t t = 0; t < iterations; ++t){
        r1cs_variable_assignment<libff::Fr<ppT>> auxiliary_input(example.state_assignment[t]);
        auxiliary_input.insert(auxiliary_input.end(), example.state_assignment[t+1].begin(), example.state_assignment[t+1].end());
        auxiliary_input.insert(auxiliary_input.end(), example.witness_assignment[t].begin(), example.witness_assignment[t].end());
        assert(constraint_system.is_satisfied(example.primary_input[t], auxiliary_input));
    }

    libff::print_header("R1CS SC LegoGro16 Generator");
    sc_lego_gro16_keypair<ppT> keypair = sc_lego_gro16_generator<ppT>(constraint_system, example.state_assignment[0]);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    sc_lego_gro16_processed_verification_key<ppT> pvk = sc_lego_gro16_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<sc_lego_gro16_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<sc_lego_gro16_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<sc_lego_gro16_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    sc_lego_gro16_commitment<ppT> previous_commitment = keypair.initial_commitment;
    sc_lego_gro16_prover_state<ppT> prover_state = keypair.initial_prover_state;
    bool result = true;
    for(size_t t = 0; t < iterations; ++t) {
        libff::print_header("R1CS SC LegoGro16 Prover");

        std::pair<sc_lego_gro16_proof<ppT>, sc_lego_gro16_commitment<ppT>> proof =
                                                                sc_lego_gro16_prover<ppT>(keypair.pk,
                                                                                     constraint_system,
                                                                                     example.primary_input[t],
                                                                                     example.state_assignment[t],
                                                                                     example.state_assignment[t+1],
                                                                                     example.witness_assignment[t],
                                                                                     prover_state);
        printf("\n"); libff::print_indent(); libff::print_mem("after prover");

        if (test_serialization) {
            libff::enter_block("Test serialization of proof");
            proof.first = libff::reserialize<sc_lego_gro16_proof<ppT> >(proof.first);
            proof.second = libff::reserialize<sc_lego_gro16_commitment<ppT> >(proof.second);
            libff::leave_block("Test serialization of proof");
        }

        libff::print_header("R1CS SC LegoGro16 Verifier");
        bool ans = sc_lego_gro16_verifier_strong_IC<ppT>(keypair.vk, example.primary_input[t], proof.first, proof.second, previous_commitment);

        printf("\n");
        libff::print_indent();
        libff::print_mem("after verifier");
        printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

        libff::print_header("R1CS SC LegoGro16 Online Verifier");
#ifndef NDEBUG
        bool ans2 = sc_lego_gro16_online_verifier_strong_IC<ppT>(pvk, example.primary_input[t], proof.first, proof.second, previous_commitment);
#endif
        assert(ans == ans2);
        previous_commitment = proof.second;
        result = result && ans;
    }

    libff::leave_block("Call to run_lego_gro16_sc");

    return result;
}

} // libsnark

#endif // RUN_LEGO_GRO16_SC_TCC_
