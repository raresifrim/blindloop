/** @file
*****************************************************************************

Implementation  of interfaces for LegoSNARK LegoGro16

*****************************************************************************/

#ifndef LEGO_GRO16_TCC_
#define LEGO_GRO16_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cp_link.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cc_gro16.hpp>


namespace libsnark {

template<typename ppT>
bool lego_gro16_proving_key<ppT>::operator==(const lego_gro16_proving_key<ppT> &other) const
{
    return (this->ck_cc_gro16 == other.ck_cc_gro16 &&
            this->pk_cc_gro16 == other.pk_cc_gro16 &&
            this->pk_cp_link == other.pk_cp_link
            );
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const lego_gro16_proving_key<ppT> &pk)
{
    out << pk.ck_cc_gro16 << OUTPUT_NEWLINE;
    out << pk.pk_cc_gro16 << OUTPUT_NEWLINE;
    out << pk.pk_cp_link << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, lego_gro16_proving_key<ppT> &pk)
{
    in >> pk.ck_cc_gro16;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.pk_cc_gro16;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.pk_cp_link;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
bool lego_gro16_verification_key<ppT>::operator==(const lego_gro16_verification_key<ppT> &other) const
{
    return (this->vk_cc_gro16 == other.vk_cc_gro16 &&
            this->vk_cp_link == other.vk_cp_link);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const lego_gro16_verification_key<ppT> &vk)
{
    out << vk.vk_cc_gro16 << OUTPUT_NEWLINE;
    out << vk.vk_cp_link << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, lego_gro16_verification_key<ppT> &vk)
{
    in >> vk.vk_cc_gro16;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.vk_cp_link;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool lego_gro16_processed_verification_key<ppT>::operator==(const lego_gro16_processed_verification_key<ppT> &other) const
{
    return (this->pvk_cc_gro16 == other.pvk_cc_gro16 &&
            this->pvk_cp_link == other.pvk_cp_link);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const lego_gro16_processed_verification_key<ppT> &pvk)
{
    out << pvk.pvk_cc_gro16 << OUTPUT_NEWLINE;
    out << pvk.pvk_cp_link << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, lego_gro16_processed_verification_key<ppT> &pvk)
{
    in >> pvk.pvk_cc_gro16;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.pvk_cp_link;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool lego_gro16_proof<ppT>::operator==(const lego_gro16_proof<ppT> &other) const
{
    return (this->commitment == other.commitment &&
            this->pi_link == other.pi_link &&
            this->pi_gro16 == other.pi_gro16);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const lego_gro16_proof<ppT> &proof)
{
    out << proof.commitment << OUTPUT_NEWLINE;
    out << proof.pi_link << OUTPUT_NEWLINE;
    out << proof.pi_gro16 << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, lego_gro16_proof<ppT> &proof)
{
    in >> proof.commitment;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.pi_link;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.pi_gro16;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}



template <typename ppT>
lego_gro16_keypair<ppT> lego_gro16_generator(const lego_gro16_commitment_key<ppT> &ck, const lego_gro16_constraint_system<ppT> &r1cs)
{
    libff::enter_block("Call to lego_gro16_generator");

    cc_gro16_keypair<ppT> keypair_cc_gro16 = cc_gro16_generator<ppT>(r1cs);

    // The CP-Link Relation is parameterized by the special commitment key (denoted f in LegoSNARK paper)
    // and is built from the commitment slot information and the ccGro16 commitment key (the factors for the D Part of the Proof)
    cp_link_relation<ppT> rel_link;

    cp_link_ck_special<ppT> f0;
    f0.push_back(keypair_cc_gro16.ck[0]);
    rel_link.ck_f.push_back(f0);

    size_t nf = 1;
    for(size_t i = 0; i < r1cs.n.size(); ++i){
        cp_link_ck_special<ppT> fi(keypair_cc_gro16.ck.begin() + nf, keypair_cc_gro16.ck.begin() + nf + r1cs.n[i]);
        rel_link.ck_f.push_back(fi);
        nf += r1cs.n[i];
    }

    cp_link_keypair<ppT> keypair_cp_link = cp_link_generator(ck, rel_link);

    libff::leave_block("Call to lego_gro16_generator");
    lego_gro16_verification_key<ppT> vk = lego_gro16_verification_key<ppT>(keypair_cc_gro16.vk,
                                                                           keypair_cp_link.vk);

    lego_gro16_proving_key<ppT> pk = lego_gro16_proving_key<ppT>(std::move(keypair_cc_gro16.ck),
                                                               std::move(keypair_cc_gro16.pk),
                                                               std::move(keypair_cp_link.pk));

    pk.print_size();
    vk.print_size();

    return lego_gro16_keypair<ppT>(std::move(pk), std::move(vk));
}

template <typename ppT>
lego_gro16_proof<ppT> lego_gro16_prover(const lego_gro16_proving_key<ppT> &pk,
                                        const lego_gro16_constraint_system<ppT> &constraint_system,
                                        const lego_gro16_primary_input<ppT> &primary_input,
                                        const lego_gro16_commitment_vector<ppT> &commitments,
                                        const lego_gro16_opening_vector<ppT> &openings,
                                        const lego_gro16_auxiliary_input<ppT> &auxiliary_input)
{
    assert(commitments.size() == constraint_system.n.size());
    assert(openings.size() == constraint_system.n.size());
    libff::enter_block("Call to lego_gro16_prover");
    cc_gro16_ccproof<ppT> ccproof = cc_gro16_prover(pk.pk_cc_gro16, constraint_system, primary_input, auxiliary_input);

    cp_link_assignment_vector<ppT> assignments;

    size_t n = 0;
    for(size_t i = 0; i < constraint_system.n.size(); ++i){
        assignments.push_back(cp_link_assignment<ppT>(auxiliary_input.begin() + n, auxiliary_input.begin() + n + constraint_system.n[i]));
        n += constraint_system.n[i];
    }

    cp_link_proof<ppT> pi_link = cp_link_prover(pk.pk_cp_link,
                                                ccproof.commitment,
                                                commitments,
                                                assignments,
                                                openings,
                                                ccproof.opening);

    libff::leave_block("Call to lego_gro16_prover");

    lego_gro16_proof<ppT> proof = lego_gro16_proof<ppT>(std::move(ccproof.commitment), std::move(pi_link), std::move(ccproof.proof));
    proof.print_size();

    return proof;
}

template <typename ppT>
lego_gro16_processed_verification_key<ppT> lego_gro16_verifier_process_vk(const lego_gro16_verification_key<ppT> &vk)
{
    libff::enter_block("Call to lego_gro16_verifier_process_vk");

    lego_gro16_processed_verification_key<ppT> pvk;
    pvk.pvk_cc_gro16 = cc_gro16_verifier_process_vk(vk.vk_cc_gro16);
    pvk.pvk_cp_link = cp_link_verifier_process_vk(vk.vk_cp_link);
    libff::leave_block("Call to lego_gro16_verifier_process_vk");

    return pvk;
}

template <typename ppT>
bool lego_gro16_online_verifier_weak_IC(const lego_gro16_processed_verification_key<ppT> &pvk,
                                               const lego_gro16_primary_input<ppT> &primary_input,
                                               const lego_gro16_commitment_vector<ppT> &commitments,
                                               const lego_gro16_proof<ppT> &proof)
{
    libff::enter_block("Call to lego_gro16_online_verifier_weak_IC");
    bool result = true;
    result &= cp_link_online_verifier(pvk.pvk_cp_link,
                                      proof.commitment,
                                      commitments,
                                      proof.pi_link);

    result &= cc_gro16_online_verifier_weak_IC(pvk.pvk_cc_gro16,
                                               primary_input,
                                               proof.commitment,
                                               proof.pi_gro16);

    libff::leave_block("Call to lego_gro16_online_verifier_weak_IC");

    return result;
}

template<typename ppT>
bool lego_gro16_verifier_weak_IC(const lego_gro16_verification_key<ppT> &vk,
                                        const lego_gro16_primary_input<ppT> &primary_input,
                                 const lego_gro16_commitment_vector<ppT> &commitments,
                                 const lego_gro16_proof<ppT> &proof)
{
    libff::enter_block("Call to lego_gro16_verifier_weak_IC");
    lego_gro16_processed_verification_key<ppT> pvk = lego_gro16_verifier_process_vk<ppT>(vk);
    bool result = lego_gro16_online_verifier_weak_IC<ppT>(pvk, primary_input, commitments,proof);
    libff::leave_block("Call to lego_gro16_verifier_weak_IC");
    return result;
}

template<typename ppT>
bool lego_gro16_online_verifier_strong_IC(const lego_gro16_processed_verification_key<ppT> &pvk,
                                          const lego_gro16_primary_input<ppT> &primary_input,
                                          const lego_gro16_commitment_vector<ppT> &commitments,
                                          const lego_gro16_proof<ppT> &proof)
{
    bool result = true;
    libff::enter_block("Call to lego_gro16_online_verifier_strong_IC");

    result &= cp_link_online_verifier(pvk.pvk_cp_link,
                                      proof.commitment,
                                      commitments,
                                      proof.pi_link);

    result &= cc_gro16_online_verifier_strong_IC(pvk.pvk_cc_gro16,
                                               primary_input,
                                               proof.commitment,
                                               proof.pi_gro16);


    libff::leave_block("Call to lego_gro16_online_verifier_strong_IC");
    return result;
}

template<typename ppT>
bool lego_gro16_verifier_strong_IC(const lego_gro16_verification_key<ppT> &vk,
                                   const lego_gro16_primary_input<ppT> &primary_input,
                                   const lego_gro16_commitment_vector<ppT> &commitments,
                                   const lego_gro16_proof<ppT> &proof)
{
    libff::enter_block("Call to lego_gro16_verifier_strong_IC");
    lego_gro16_processed_verification_key<ppT> pvk = lego_gro16_verifier_process_vk<ppT>(vk);
    bool result = lego_gro16_online_verifier_strong_IC<ppT>(pvk, primary_input, commitments,proof);
    libff::leave_block("Call to lego_gro16_verifier_strong_IC");
    return result;
}



} // libsnark
#endif // LEGO_GRO16_TCC_
