/** @file
 *****************************************************************************

 Implementation of functionality that runs LegoGro16
 See run_lego_gro16.hpp .

 *****************************************************************************/

#ifndef RUN_LEGO_GRO16_TCC_
#define RUN_LEGO_GRO16_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/legogro16.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/pedersen_commitment.hpp>
#include <libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.hpp>

namespace libsnark {


template<typename ppT>
bool run_lego_gro16(const r1cs_example<libff::Fr<ppT> > &example,
                        const std::vector<size_t> &commitment_slots,
                        const bool test_serialization)
{
    r1cs_example<libff::Fr<ppT> > example_copy(example);
    libff::enter_block("Call to run_lego_gro16");

    libff::enter_block("Call to r1cs_to_r1cs_cc");
    lego_gro16_constraint_system<ppT> constraint_system = r1cs_to_r1cs_cc(std::move(example_copy.constraint_system), commitment_slots);
    libff::leave_block("Call to r1cs_to_r1cs_cc");

    // get assignments to slots
    lego_gro16_assignment_vector<ppT> assignments;
    size_t n = 0;
    for(size_t i = 0; i < commitment_slots.size(); ++i){
        assignments.push_back(lego_gro16_assignment<ppT>(example_copy.auxiliary_input.begin() + n, example_copy.auxiliary_input.begin() + n + commitment_slots[i]));
        n += commitment_slots[i];
    }

    libff::print_header("Pedersen Commitment Generator");
    pedersen_commitment_key<ppT> ck = pedersen_commitment_generator<ppT>(constraint_system.commitment_size);
    printf("\n"); libff::print_indent(); libff::print_mem("after pedersen generator");

    pedersen_commitment_commitment_vector<ppT> commitments;
    pedersen_commitment_opening_vector<ppT> openings;
    for(size_t i = 0; i < assignments.size(); ++i) {
        libff::print_header("Pedersen Commit");
        pedersen_commitment_pair<ppT> pair = pedersen_commitment_commit<ppT>(ck, assignments[i]);
        commitments.push_back(pair.commitment);
        openings.push_back(pair.opening);
        libff::print_header("Pedersen Verify");
        bool result = pedersen_commitment_verify<ppT>(ck, pair.commitment, assignments[i], pair.opening);
        assert(result);
    }

    printf("\n");
    libff::print_indent();
    libff::print_mem("after pedersen commit and verify commit");

    libff::print_header("R1CS LegoGro16 Generator");
    lego_gro16_keypair<ppT> keypair = lego_gro16_generator<ppT>(ck, constraint_system);
    printf("\n"); libff::print_indent(); libff::print_mem("after generator");

    libff::print_header("Preprocess verification key");
    lego_gro16_processed_verification_key<ppT> pvk = lego_gro16_verifier_process_vk<ppT>(keypair.vk);

    if (test_serialization)
    {
        libff::enter_block("Test serialization of keys");
        keypair.pk = libff::reserialize<lego_gro16_proving_key<ppT> >(keypair.pk);
        keypair.vk = libff::reserialize<lego_gro16_verification_key<ppT> >(keypair.vk);
        pvk = libff::reserialize<lego_gro16_processed_verification_key<ppT> >(pvk);
        libff::leave_block("Test serialization of keys");
    }

    libff::print_header("R1CS LegoGro16 Prover");
    lego_gro16_proof<ppT> proof = lego_gro16_prover<ppT>(keypair.pk,
                                                         constraint_system,
                                                         example_copy.primary_input,
                                                         commitments,
                                                         openings,
                                                         example_copy.auxiliary_input);
    printf("\n"); libff::print_indent(); libff::print_mem("after prover");

    if (test_serialization)
    {
        libff::enter_block("Test serialization of proof");
        proof = libff::reserialize<lego_gro16_proof<ppT> >(proof);
        libff::leave_block("Test serialization of proof");
    }

    libff::print_header("R1CS LegoGro16 Verifier");
    const bool ans = lego_gro16_verifier_strong_IC<ppT>(keypair.vk, example_copy.primary_input, commitments, proof);
    printf("\n"); libff::print_indent(); libff::print_mem("after verifier");
    printf("* The verification result is: %s\n", (ans ? "PASS" : "FAIL"));

    libff::print_header("R1CS LegoGro16 Online Verifier");
#ifndef NDEBUG
    const bool ans2 = lego_gro16_online_verifier_strong_IC<ppT>(pvk, example_copy.primary_input, commitments, proof);
#endif
    assert(ans == ans2);

    libff::leave_block("Call to run_lego_gro16");

    return ans;
}

} // libsnark

#endif // RUN_LEGO_GRO16_TCC_
