/** @file
*****************************************************************************

Declaration of functionality of commitment-carrying Groth16


*****************************************************************************/

#ifndef CC_GRO16_HPP_
#define CC_GRO16_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cc_gro16_params.hpp>

namespace libsnark {

/******************************** Proving key ********************************/

template<typename ppT>
class cc_gro16_proving_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_proving_key<ppT> &pk);

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_proving_key<ppT> &pk);

/**
 * A proving key for ccGro16.
 */
template<typename ppT>
class cc_gro16_proving_key {
public:
    libff::G1<ppT> alpha_g1;
    libff::G1<ppT> beta_g1;
    libff::G2<ppT> beta_g2;
    libff::G1<ppT> delta_g1;
    libff::G2<ppT> delta_g2;
    libff::G1<ppT> eta_over_gamma_g1;
    libff::G1<ppT> eta_over_delta_g1;

    libff::G1_vector<ppT> gamma_ABC_commitment_g1;
    libff::G1_vector<ppT> A_query; // this could be a sparse vector if we had multiexp for those
    knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > B_query;
    libff::G1_vector<ppT> H_query;
    libff::G1_vector<ppT> L_query;

    cc_gro16_proving_key() {};
    cc_gro16_proving_key<ppT>& operator=(const cc_gro16_proving_key<ppT> &other) = default;
    cc_gro16_proving_key(const cc_gro16_proving_key<ppT> &other) = default;
    cc_gro16_proving_key(cc_gro16_proving_key<ppT> &&other) = default;
    cc_gro16_proving_key(libff::G1<ppT> &&alpha_g1,
                                  libff::G1<ppT> &&beta_g1,
                                  libff::G2<ppT> &&beta_g2,
                                  libff::G1<ppT> &&delta_g1,
                                  libff::G2<ppT> &&delta_g2,
                                  libff::G1<ppT> &&eta_over_gamma_g1,
                                  libff::G1<ppT> &&eta_over_delta_g1,
                                  libff::G1_vector<ppT> &&gamma_ABC_commitment_g1,
                                  libff::G1_vector<ppT> &&A_query,
                                  knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > &&B_query,
                                  libff::G1_vector<ppT> &&H_query,
                                  libff::G1_vector<ppT> &&L_query) :
        alpha_g1(std::move(alpha_g1)),
        beta_g1(std::move(beta_g1)),
        beta_g2(std::move(beta_g2)),
        delta_g1(std::move(delta_g1)),
        delta_g2(std::move(delta_g2)),
        eta_over_gamma_g1(std::move(eta_over_gamma_g1)),
        eta_over_delta_g1(std::move(eta_over_delta_g1)),
        gamma_ABC_commitment_g1(std::move(gamma_ABC_commitment_g1)),
        A_query(std::move(A_query)),
        B_query(std::move(B_query)),
        H_query(std::move(H_query)),
        L_query(std::move(L_query))
        {};


    size_t G1_size() const
    {
        return 5 + A_query.size() + B_query.domain_size() + H_query.size() + L_query.size() + gamma_ABC_commitment_g1.size();
    }

    size_t G2_size() const
    {
        return 2 + B_query.domain_size();
    }

    size_t G1_sparse_size() const
    {
        return 5 + A_query.size() + B_query.size() + H_query.size() + L_query.size() + gamma_ABC_commitment_g1.size();
    }

    size_t G2_sparse_size() const
    {
        return 2 + B_query.size();
    }

    size_t size_in_bits() const
    {
        return (G1_size() * libff::G1<ppT>::size_in_bits() + G2_size() * libff::G2<ppT>::size_in_bits());
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in PK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* Non-zero G1 elements in PK: %zu\n", this->G1_sparse_size());
        libff::print_indent(); printf("* G2 elements in PK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* Non-zero G2 elements in PK: %zu\n", this->G2_sparse_size());
        libff::print_indent(); printf("* PK size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const cc_gro16_proving_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const cc_gro16_proving_key<ppT> &pk);
    friend std::istream& operator>> <ppT>(std::istream &in, cc_gro16_proving_key<ppT> &pk);
};


/******************************* Verification key ****************************/

template<typename ppT>
class cc_gro16_verification_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_verification_key<ppT> &vk);

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_verification_key<ppT> &vk);

/**
 * A verification key for ccGro16.
 */
template<typename ppT>
class cc_gro16_verification_key {
public:
    libff::GT<ppT> alpha_g1_beta_g2;
    libff::G2<ppT> gamma_g2;
    libff::G2<ppT> delta_g2;

    accumulation_vector<libff::G1<ppT> > gamma_ABC_g1;

    cc_gro16_verification_key() = default;
    cc_gro16_verification_key(const libff::GT<ppT> &alpha_g1_beta_g2,
                                       const libff::G2<ppT> &gamma_g2,
                                       const libff::G2<ppT> &delta_g2,
                                       const accumulation_vector<libff::G1<ppT> > &gamma_ABC_g1) :
        alpha_g1_beta_g2(alpha_g1_beta_g2),
        gamma_g2(gamma_g2),
        delta_g2(delta_g2),
        gamma_ABC_g1(gamma_ABC_g1)
    {};

    size_t G1_size() const
    {
        return gamma_ABC_g1.size();
    }

    size_t G2_size() const
    {
        return 2;
    }

    size_t GT_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
        return (gamma_ABC_g1.size_in_bits() + 2 * libff::G2<ppT>::size_in_bits() + 1 * libff::GT<ppT>::ceil_size_in_bits());
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in VK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in VK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* GT elements in VK: %zu\n", this->GT_size());
        libff::print_indent(); printf("* VK size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const cc_gro16_verification_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const cc_gro16_verification_key<ppT> &vk);
    friend std::istream& operator>> <ppT>(std::istream &in, cc_gro16_verification_key<ppT> &vk);

    static cc_gro16_verification_key<ppT> dummy_verification_key(const size_t input_size);
};


/************************ Processed verification key *************************/

template<typename ppT>
class cc_gro16_processed_verification_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_processed_verification_key<ppT> &pvk);

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_processed_verification_key<ppT> &pvk);

/**
 * A processed verification key for ccGro16.
 *
 * Compared to a (non-processed) verification key, a processed verification key
 * contains a small constant amount of additional pre-computed information that
 * enables a faster verification time.
 */
template<typename ppT>
class cc_gro16_processed_verification_key {
public:
    libff::GT<ppT> vk_alpha_g1_beta_g2;
    libff::G2_precomp<ppT> vk_gamma_g2_precomp;
    libff::G2_precomp<ppT> vk_delta_g2_precomp;

    accumulation_vector<libff::G1<ppT> > gamma_ABC_g1;

    bool operator==(const cc_gro16_processed_verification_key &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const cc_gro16_processed_verification_key<ppT> &pvk);
    friend std::istream& operator>> <ppT>(std::istream &in, cc_gro16_processed_verification_key<ppT> &pvk);
};


/********************************** Key pair *********************************/

/**
 * A key pair for ccGro16, which consists of a proving key and a verification key.
 */
template<typename ppT>
class cc_gro16_keypair {
public:
    cc_gro16_proving_key<ppT> pk;
    cc_gro16_verification_key<ppT> vk;
    cc_gro16_commitment_key<ppT> ck;

    cc_gro16_keypair() = default;
    cc_gro16_keypair(const cc_gro16_keypair<ppT> &other) = default;
    cc_gro16_keypair(cc_gro16_proving_key<ppT> &&pk,
                       cc_gro16_verification_key<ppT> &&vk,
                       cc_gro16_commitment_key<ppT> &&ck) :
        pk(std::move(pk)),
        vk(std::move(vk)),
        ck(std::move(ck))
    {}

    cc_gro16_keypair(cc_gro16_keypair<ppT> &&other) = default;
};

/*********************************** Proof ***********************************/

template<typename ppT>
class cc_gro16_proof;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_proof<ppT> &proof);

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_proof<ppT> &proof);

/**
 * A proof for ccGro16.
 *
 * While the proof has a structure, externally one merely opaquely produces,
 * serializes/deserializes, and verifies proofs. We only expose some information
 * about the structure for statistics purposes.
 */
template<typename ppT>
class cc_gro16_proof {
public:
    libff::G1<ppT> g_A;
    libff::G2<ppT> g_B;
    libff::G1<ppT> g_C;

    cc_gro16_proof()
    {
        // invalid proof with valid curve points
        this->g_A = libff::G1<ppT>::one();
        this->g_B = libff::G2<ppT>::one();
        this->g_C = libff::G1<ppT>::one();
    }
    cc_gro16_proof(libff::G1<ppT> &&g_A,
                            libff::G2<ppT> &&g_B,
                            libff::G1<ppT> &&g_C) :
        g_A(std::move(g_A)),
        g_B(std::move(g_B)),
        g_C(std::move(g_C))
    {};

    size_t G1_size() const
    {
        return 2;
    }

    size_t G2_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits() 
                + G2_size() * libff::G2<ppT>::size_in_bits();
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in proof: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in proof: %zu\n", this->G2_size());
        libff::print_indent(); printf("* Proof size in bits: %zu\n", this->size_in_bits());
    }

    bool is_well_formed() const
    {
        return (g_A.is_well_formed() &&
                g_B.is_well_formed() &&
                g_C.is_well_formed());
    }

    bool operator==(const cc_gro16_proof<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const cc_gro16_proof<ppT> &proof);
    friend std::istream& operator>> <ppT>(std::istream &in, cc_gro16_proof<ppT> &proof);
};

/*********************************** CC-Proof ***********************************/

template<typename ppT>
class cc_gro16_ccproof;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cc_gro16_ccproof<ppT> &proof);

template<typename ppT>
std::istream& operator>>(std::istream &in, cc_gro16_ccproof<ppT> &proof);

/**
* A commit-carrying proof for ccGro16.
*
* Includes proof, commitment and opening
*
*/
template<typename ppT>
class cc_gro16_ccproof {
public:
    cc_gro16_proof<ppT> proof;
    cc_gro16_commitment<ppT> commitment;
    cc_gro16_opening<ppT> opening;

    cc_gro16_ccproof()
    {
        // invalid proof with valid curve points
        this->proof = cc_gro16_proof<ppT>();
        this->commitment = cc_gro16_commitment<ppT>::one();
        this->opening = cc_gro16_opening<ppT>(1);
    }

    cc_gro16_ccproof(cc_gro16_proof<ppT> &&proof,
                    cc_gro16_commitment<ppT> &&commitment,
                    const cc_gro16_opening<ppT> &opening) :
            proof(std::move(proof)),
            commitment(std::move(commitment)),
            opening(opening)
    {};

    size_t G1_size() const
    {
        return proof.G1_size() + 1;
    }

    size_t G2_size() const
    {
        return proof.G2_size();
    }

    size_t Fr_size() const
    {
        return 1;
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits()
               + G2_size() * libff::G2<ppT>::size_in_bits()
               + Fr_size() * libff::Fr<ppT>::ceil_size_in_bits();
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in proof: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in proof: %zu\n", this->G2_size());
        libff::print_indent(); printf("* Fr elements in proof: %zu\n", this->Fr_size());
        libff::print_indent(); printf("* Proof size in bits: %zu\n", this->size_in_bits());
    }

    bool is_well_formed() const
    {
        return (proof.is_well_formed() &&
                commitment.is_well_formed());
    }

    bool operator==(const cc_gro16_ccproof<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const cc_gro16_ccproof<ppT> &proof);
    friend std::istream& operator>> <ppT>(std::istream &in, cc_gro16_ccproof<ppT> &proof);
};

/***************************** Main algorithms *******************************/

/**
 * A generator algorithm for ccGro16.
 *
 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
 */
template<typename ppT>
cc_gro16_keypair<ppT> cc_gro16_generator(const cc_gro16_constraint_system<ppT> &cs);

/**
 * A prover algorithm for ccGro16.
 *
 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
 * produces a proof (of knowledge) that attests to the following statement:
 *               ``there exists Y such that CS(X,Y)=0''.
 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
 */
template<typename ppT>
cc_gro16_ccproof<ppT> cc_gro16_prover(const cc_gro16_proving_key<ppT> &pk,
                                                      const cc_gro16_constraint_system<ppT> &constraint_system,
                                                      const cc_gro16_primary_input<ppT> &primary_input,
                                                      const cc_gro16_auxiliary_input<ppT> &auxiliary_input);

/*
  Below are four variants of verifier algorithm for ccGro16.

  These are the four cases that arise from the following two choices:

  (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
  In the latter case, we call the algorithm an "online verifier".

  (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
  Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
  weak input consistency requires that |primary_input| <= CS.num_inputs (and
  the primary input is implicitly padded with zeros up to length CS.num_inputs).
*/

/**
 * A verifier algorithm for ccGro16 that:
 * (1) accepts a non-processed verification key, and
 * (2) has weak input consistency.
 */
template<typename ppT>
bool cc_gro16_verifier_weak_IC(const cc_gro16_verification_key<ppT> &vk,
                                        const cc_gro16_primary_input<ppT> &primary_input,
                                        const cc_gro16_commitment<ppT> &commitment,
                                        const cc_gro16_proof<ppT> &proof);

/**
 * A verifier algorithm for ccGro16 that:
 * (1) accepts a non-processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool cc_gro16_verifier_strong_IC(const cc_gro16_verification_key<ppT> &vk,
                                          const cc_gro16_primary_input<ppT> &primary_input,
                                          const cc_gro16_commitment<ppT> &commitment,
                                          const cc_gro16_proof<ppT> &proof);

/**
 * Convert a (non-processed) verification key into a processed verification key.
 */
template<typename ppT>
cc_gro16_processed_verification_key<ppT> cc_gro16_verifier_process_vk(const cc_gro16_verification_key<ppT> &vk);

/**
 * A verifier algorithm for ccGro16 that:
 * (1) accepts a processed verification key, and
 * (2) has weak input consistency.
 */
template<typename ppT>
bool cc_gro16_online_verifier_weak_IC(const cc_gro16_processed_verification_key<ppT> &pvk,
                                               const cc_gro16_primary_input<ppT> &input,
                                               const cc_gro16_commitment<ppT> &commitment,
                                               const cc_gro16_proof<ppT> &proof);

/**
 * A verifier algorithm for ccGro16 that:
 * (1) accepts a processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool cc_gro16_online_verifier_strong_IC(const cc_gro16_processed_verification_key<ppT> &pvk,
                                                 const cc_gro16_primary_input<ppT> &primary_input,
                                                 const cc_gro16_commitment<ppT> &commitment,
                                                 const cc_gro16_proof<ppT> &proof);

/****************************** Miscellaneous ********************************/


} // libsnark

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cc_gro16.tcc>

#endif // CC_GRO16_HPP_
