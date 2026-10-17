/** @file
*****************************************************************************

Implementation of interfaces for the LegoSNARK CP-link CP-SNARK

See cp_link.hpp .


*****************************************************************************/

#ifndef CP_LINK_TCC_
#define CP_LINK_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace libsnark {

template<typename ppT>
bool cp_link_proving_key<ppT>::operator==(const cp_link_proving_key<ppT> &other) const
{
    return (this->P == other.P);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cp_link_proving_key<ppT> &pk)
{
    out << pk.P;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, cp_link_proving_key<ppT> &pk)
{
    in >> pk.P;
    return in;
}

template<typename ppT>
bool cp_link_verification_key<ppT>::operator==(const cp_link_verification_key<ppT> &other) const
{
    return (this->C == other.C &&
            this->a == other.a);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cp_link_verification_key<ppT> &vk)
{
    out << vk.C << OUTPUT_NEWLINE;
    out << vk.a << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, cp_link_verification_key<ppT> &vk)
{
    in >> vk.C;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.a;
    libff::consume_OUTPUT_NEWLINE(in);

    return in;
}

template<typename ppT>
bool cp_link_processed_verification_key<ppT>::operator==(const cp_link_processed_verification_key<ppT> &other) const
{
    return (this->C == other.C &&
            this->a == other.a);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cp_link_processed_verification_key<ppT> &vk)
{
    out << vk.C << OUTPUT_NEWLINE;
    out << vk.a << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, cp_link_processed_verification_key<ppT> &vk)
{
    in >> vk.C;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.a;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
bool cp_link_proof<ppT>::operator==(const cp_link_proof<ppT> &other) const
{
    return (this->Pi == other.Pi);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cp_link_proof<ppT> &proof)
{
    out << proof.Pi << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, cp_link_proof<ppT> &proof)
{
    in >> proof.Pi;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}


template <typename ppT>
cp_link_keypair<ppT> cp_link_generator(const cp_link_ck_generic<ppT> &ck_generic, const cp_link_relation<ppT> &rel)
{
    libff::enter_block("Call to cp_link_generator");
    assert(rel.ck_f[0].size() == 1);
    size_t ell = rel.ck_f.size() - 1;
    //size_t m = rel.get_m();
    //size_t t = m + ell + 1;

    /* Generate secret randomness */
    const libff::Fr<ppT> a = libff::Fr<ppT>::random_element();
    libff::Fr_vector<ppT> k;
    for(size_t i = 0; i < ell + 1; ++i){
        k.push_back(libff::Fr<ppT>::random_element());
    }

    /* Compute the proving key */
    // M^T *k
    // columns 1 to ell
    libff::G1_vector<ppT> P;
    for(size_t i = 0; i < ell; ++i){
        P.push_back(k[i] * ck_generic[0]);
    }
    // column ell + 1
    P.push_back(k[ell] * rel.ck_f[0][0]);

    // remaining columns
    for(size_t i = 0; i < ell; ++i){
        for(size_t j = 0; j < rel.ck_f[i+1].size(); ++j){
            P.push_back(k[i] * ck_generic[j+1] + k[ell]*rel.ck_f[i+1][j]);
        }
    }

    /* Compute the verification key */
    libff::G2_vector<ppT> C_g2;
    for(size_t i = 0; i < ell + 1; ++i){
        C_g2.push_back(a*k[i]*libff::G2<ppT>::one());
    }
    libff::G2<ppT> a_g2 = a*libff::G2<ppT>::one();


    libff::leave_block("Call to cp_link_generator");

    cp_link_verification_key<ppT> vk = cp_link_verification_key<ppT>(C_g2, a_g2);

    cp_link_proving_key<ppT> pk = cp_link_proving_key<ppT>(std::move(P));

    pk.print_size();
    vk.print_size();

    return cp_link_keypair<ppT>(std::move(pk), std::move(vk));
}

template <typename ppT>
cp_link_proof<ppT> cp_link_prover(const cp_link_proving_key<ppT> &pk,
                                  const cp_link_commitment_special<ppT> &c_special,
                                  const cp_link_commitment_generic_vector<ppT> &c_generic,
                                  const cp_link_assignment_vector<ppT> &assignment,
                                  const cp_link_opening_generic_vector<ppT> &o_generic,
                                  const cp_link_opening_special<ppT> &o_special)
{
    // Not sure, why there is c_special and c_generic, in the paper, they
    // are in the function head but are not used
    libff::UNUSED(c_generic);
    libff::UNUSED(c_special);

    size_t m = 0;
    for(size_t i = 0; i < assignment.size(); ++i){
        m += assignment[i].size();
    }

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    assert(pk.P.size() == o_generic.size() + 1 + m);
    libff::enter_block("Call to cp_link_prover");

    cp_link_assignment<ppT> omega(o_generic);
    omega.push_back(o_special);
    for(size_t i = 0; i < assignment.size(); ++i){
        omega.insert(omega.end(), assignment[i].begin(), assignment[i].end());
    }

    libff::G1<ppT> pi = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.P.begin(),
            pk.P.end(),
            omega.begin(),
            omega.end(),
            chunks);

    libff::leave_block("Call to cp_link_prover");

    cp_link_proof<ppT> proof = cp_link_proof<ppT>(std::move(pi));
    proof.print_size();

    return proof;
}

template <typename ppT>
cp_link_processed_verification_key<ppT> cp_link_verifier_process_vk(const cp_link_verification_key<ppT> &vk)
{
    libff::enter_block("Call to cp_link_verifier_process_vk");

    cp_link_processed_verification_key<ppT> pvk;
    pvk.a = ppT::precompute_G2(vk.a);
    for(size_t i = 0; i < vk.C.size(); ++i){
        pvk.C.push_back(ppT::precompute_G2(vk.C[i]));
    }

    libff::leave_block("Call to cp_link_verifier_process_vk");

    return pvk;
}

template<typename ppT>
bool cp_link_online_verifier(const cp_link_processed_verification_key<ppT> &vk,
                      const cp_link_commitment_special<ppT> &c_special,
                      const cp_link_commitment_generic_vector<ppT> &c_generic,
                      const cp_link_proof<ppT> &proof)
{
    assert(vk.C.size() == c_generic.size() + 1);
    libff::enter_block("Call to cp_link_verifier");

    bool result = true;
    libff::G1_precomp<ppT> c_special_precomp = ppT::precompute_G1(c_special);
    std::vector<libff::G1_precomp<ppT>> c_generic_precomp;

    for(size_t i = 0; i < c_generic.size(); ++i){
        c_generic_precomp.push_back(ppT::precompute_G1(c_generic[i]));
    }
    libff::G1_precomp<ppT> pi_precomp = ppT::precompute_G1(proof.Pi);


    libff::Fqk<ppT> QAP1 = ppT::miller_loop(pi_precomp,  vk.a);
    libff::Fqk<ppT> QAP2 = ppT::miller_loop(c_special_precomp, vk.C.back());
    for(size_t i = 0; i < c_generic_precomp.size(); ++i){
        QAP2 *= ppT::miller_loop(c_generic_precomp[i], vk.C[i]);
    }

    const libff::GT<ppT> QAP = ppT::final_exponentiation(QAP1 * QAP2.inverse());

    if (QAP != libff::GT<ppT>::one())
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("CP link check failed.\n");
        }
        result = false;
    }

    libff::leave_block("Call to cp_link_verifier");

    return result;
}


template<typename ppT>
bool cp_link_verifier(const cp_link_verification_key<ppT> &vk,
                      const cp_link_commitment_special<ppT> &c_special,
                      const cp_link_commitment_generic_vector<ppT> &c_generic,
                      const cp_link_proof<ppT> &proof)
{
    libff::enter_block("Call to cp_link_verifier");
    cp_link_processed_verification_key<ppT> pvk = cp_link_verifier_process_vk<ppT>(vk);
    bool result = cp_link_online_verifier<ppT>(pvk, c_special, c_generic, proof);
    libff::leave_block("Call to cp_link_verifier");
    return result;
}

} // libsnark
#endif // CP_LINK_TCC_
