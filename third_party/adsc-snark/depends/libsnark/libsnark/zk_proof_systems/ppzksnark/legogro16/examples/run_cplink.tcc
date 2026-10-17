/** @file
 *****************************************************************************

 Implementation of functionality that runs the LegoSNARK CP-LINK

 See run_cplink.hpp .

 *****************************************************************************/

#ifndef RUN_CP_LINK_TCC_
#define RUN_CP_LINK_TCC_

#include <sstream>
#include <type_traits>

#include <libff/common/profiling.hpp>

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/legogro16.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/pedersen_commitment.hpp>
#include <libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.hpp>

namespace libsnark {


/**
 */
template<typename ppT>
bool run_cplink(size_t commitment_size)
{

    libff::enter_block("Call to run_cplink");

    pedersen_commitment_assignment<ppT> assignment;
    for(size_t i = 0; i < commitment_size; ++i){
        assignment.push_back(libff::Fr<ppT>::random_element());
    }

    pedersen_commitment_key<ppT> ck1 = pedersen_commitment_generator<ppT>(commitment_size);
    pedersen_commitment_key<ppT> ck2 = pedersen_commitment_generator<ppT>(commitment_size);

    pedersen_commitment_pair<ppT> cp1, cp2;

    cp1 = pedersen_commitment_commit<ppT>(ck1, assignment);
    cp2 = pedersen_commitment_commit<ppT>(ck2, assignment);

    assert(cp1.commitment != cp2.commitment);
    assert(pedersen_commitment_verify<ppT>(ck1, cp1.commitment, assignment, cp1.opening));
    assert(pedersen_commitment_verify<ppT>(ck2, cp2.commitment, assignment, cp2.opening));
    assert(!pedersen_commitment_verify<ppT>(ck1, cp2.commitment, assignment, cp1.opening));
    assert(!pedersen_commitment_verify<ppT>(ck1, cp1.commitment, assignment, cp2.opening));

    pedersen_commitment_commitment_vector<ppT> c1_v = pedersen_commitment_commitment_vector<ppT>({cp1.commitment});
    pedersen_commitment_opening_vector<ppT> o1_v = pedersen_commitment_opening_vector<ppT>({cp1.opening});
    pedersen_commitment_assignment_vector<ppT> assignment_v = pedersen_commitment_assignment_vector<ppT>({assignment});

    cp_link_relation<ppT> rel;
    rel.ck_f.push_back(cp_link_ck_special<ppT>(ck2.begin(), ck2.begin() + 1));
    rel.ck_f.push_back(cp_link_ck_special<ppT>(ck2.begin() + 1, ck2.begin() + 1 + commitment_size));
    cp_link_keypair<ppT> keypair = cp_link_generator(ck1, rel);

    cp_link_proof<ppT> proof = cp_link_prover(keypair.pk,
                                      cp2.commitment,
                                      c1_v,
                                      assignment_v,
                                      o1_v,
                                      cp2.opening);

    const bool ans = cp_link_verifier(keypair.vk,
                                      cp2.commitment,
                                      c1_v,
                                        proof);
    return ans;
}

} // libsnark

#endif // RUN_CP_LINK_TCC_
