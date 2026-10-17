/** @file
*****************************************************************************

Declaration of interfaces for LegoSNARK LegoGro16


*****************************************************************************/

#ifndef LEGO_GRO16_HPP_
#define LEGO_GRO16_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/legogro16_params.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cp_link.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cc_gro16.hpp>

namespace libsnark {

/******************************** Proving key ********************************/

template<typename ppT>
class lego_gro16_proving_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const lego_gro16_proving_key<ppT> &pk);

template<typename ppT>
std::istream& operator>>(std::istream &in, lego_gro16_proving_key<ppT> &pk);

/**
 * A proving key for LegoGro16.
 */
template<typename ppT>
class lego_gro16_proving_key {
public:
    cc_gro16_commitment_key<ppT> ck_cc_gro16;
    cc_gro16_proving_key<ppT> pk_cc_gro16;
    cp_link_proving_key<ppT> pk_cp_link;

    lego_gro16_proving_key() {};
    lego_gro16_proving_key<ppT>& operator=(const lego_gro16_proving_key<ppT> &other) = default;
    lego_gro16_proving_key(const lego_gro16_proving_key<ppT> &other) = default;
    lego_gro16_proving_key(lego_gro16_proving_key<ppT> &&other) = default;
    lego_gro16_proving_key(cc_gro16_commitment_key<ppT> &&ck_cc_gro16,
                          cc_gro16_proving_key<ppT> &&pk_cc_gro16,
                          cp_link_proving_key<ppT> &&pk_cp_link) :
            ck_cc_gro16(std::move(ck_cc_gro16)),
            pk_cc_gro16(std::move(pk_cc_gro16)),
            pk_cp_link(std::move(pk_cp_link))
        {};


    size_t G1_size() const
    {
        return ck_cc_gro16.size() + pk_cc_gro16.G1_size() + pk_cp_link.G1_size();
    }

    size_t G2_size() const
    {
        return pk_cc_gro16.G2_size() + pk_cp_link.G2_size();
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
        libff::print_indent(); printf("* G2 elements in PK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* PK size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const lego_gro16_proving_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const lego_gro16_proving_key<ppT> &pk);
    friend std::istream& operator>> <ppT>(std::istream &in, lego_gro16_proving_key<ppT> &pk);
};


/******************************* Verification key ****************************/

template<typename ppT>
class lego_gro16_verification_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const lego_gro16_verification_key<ppT> &vk);

template<typename ppT>
std::istream& operator>>(std::istream &in, lego_gro16_verification_key<ppT> &vk);

/**
 * A verification key for LegoGro16.
 */
template<typename ppT>
class lego_gro16_verification_key {
public:
    cc_gro16_verification_key<ppT> vk_cc_gro16;
    cp_link_verification_key<ppT> vk_cp_link;


    lego_gro16_verification_key() = default;
    lego_gro16_verification_key(
                                const cc_gro16_verification_key<ppT> &vk_cc_gro16,
                                const cp_link_verification_key<ppT> &vk_cp_link) :
            vk_cc_gro16(vk_cc_gro16),
            vk_cp_link(vk_cp_link)
    {};

    size_t G1_size() const
    {
        return vk_cc_gro16.G1_size() + vk_cp_link.G1_size();
    }

    size_t G2_size() const
    {
        return vk_cc_gro16.G2_size() + vk_cp_link.G2_size();
    }

    size_t GT_size() const
    {
        return vk_cc_gro16.GT_size() + vk_cp_link.GT_size();
    }

    size_t size_in_bits() const
    {
        return (G1_size() * libff::G1<ppT>::size_in_bits() + G2_size() * libff::G2<ppT>::size_in_bits() + GT_size() * libff::GT<ppT>::ceil_size_in_bits());
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

    bool operator==(const lego_gro16_verification_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const lego_gro16_verification_key<ppT> &vk);
    friend std::istream& operator>> <ppT>(std::istream &in, lego_gro16_verification_key<ppT> &vk);

};


/************************ Processed verification key *************************/

template<typename ppT>
class lego_gro16_processed_verification_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const lego_gro16_processed_verification_key<ppT> &pvk);

template<typename ppT>
std::istream& operator>>(std::istream &in, lego_gro16_processed_verification_key<ppT> &pvk);

/**
 * A processed verification key for LegoGro16.
 *
 * Compared to a (non-processed) verification key, a processed verification key
 * contains a small constant amount of additional pre-computed information that
 * enables a faster verification time.
 */
template<typename ppT>
class lego_gro16_processed_verification_key {
public:
    cc_gro16_processed_verification_key<ppT> pvk_cc_gro16;
    cp_link_processed_verification_key<ppT> pvk_cp_link;

    bool operator==(const lego_gro16_processed_verification_key &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const lego_gro16_processed_verification_key<ppT> &pvk);
    friend std::istream& operator>> <ppT>(std::istream &in, lego_gro16_processed_verification_key<ppT> &pvk);
};


/********************************** Key pair *********************************/

/**
 * A key pair for LegoGro16, which consists of a proving key and a verification key.
 */
template<typename ppT>
class lego_gro16_keypair {
public:
    lego_gro16_proving_key<ppT> pk;
    lego_gro16_verification_key<ppT> vk;

    lego_gro16_keypair() = default;
    lego_gro16_keypair(const lego_gro16_keypair<ppT> &other) = default;
    lego_gro16_keypair(lego_gro16_proving_key<ppT> &&pk,
                              lego_gro16_verification_key<ppT> &&vk) :
        pk(std::move(pk)),
        vk(std::move(vk))
    {}

    lego_gro16_keypair(lego_gro16_keypair<ppT> &&other) = default;
};


/*********************************** Proof ***********************************/

template<typename ppT>
class lego_gro16_proof;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const lego_gro16_proof<ppT> &proof);

template<typename ppT>
std::istream& operator>>(std::istream &in, lego_gro16_proof<ppT> &proof);

/**
 * A proof for LegoGro16.
 *
 * While the proof has a structure, externally one merely opaquely produces,
 * serializes/deserializes, and verifies proofs. We only expose some information
 * about the structure for statistics purposes.
 */
template<typename ppT>
class lego_gro16_proof {
public:
    cc_gro16_commitment<ppT> commitment;
    cp_link_proof<ppT> pi_link;
    cc_gro16_proof<ppT> pi_gro16;

    lego_gro16_proof() = default;

    lego_gro16_proof(cc_gro16_commitment<ppT> &&commitment,
                    cp_link_proof<ppT> &&pi_link,
                    cc_gro16_proof<ppT> &&pi_gro16) :
            commitment(std::move(commitment)),
            pi_link(std::move(pi_link)),
            pi_gro16(std::move(pi_gro16))
    {};

    size_t G1_size() const
    {
        return 1 + pi_link.G1_size() + pi_gro16.G1_size();
    }

    size_t G2_size() const
    {
        return pi_link.G2_size() + pi_gro16.G2_size();
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits() + G2_size() * libff::G2<ppT>::size_in_bits();
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
        return (pi_link.is_well_formed() &&
                pi_gro16.is_well_formed());
    }

    bool operator==(const lego_gro16_proof<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const lego_gro16_proof<ppT> &proof);
    friend std::istream& operator>> <ppT>(std::istream &in, lego_gro16_proof<ppT> &proof);
};


/***************************** Main algorithms *******************************/

/**
 * A generator algorithm for LegoGro16.
 *
 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
 */
template<typename ppT>
lego_gro16_keypair<ppT> lego_gro16_generator(const lego_gro16_commitment_key<ppT> &ck, const lego_gro16_constraint_system<ppT> &cs);

/**
 * A prover algorithm for LegoGro16.
 *
 * auxiliary input contains also assignments for commitments
 */
template<typename ppT>
lego_gro16_proof<ppT> lego_gro16_prover(const lego_gro16_proving_key<ppT> &pk,
                                                      const lego_gro16_constraint_system<ppT> &constraint_system,
                                                      const lego_gro16_primary_input<ppT> &primary_input,
                                                      const lego_gro16_commitment_vector<ppT> &commitments,
                                                      const lego_gro16_opening_vector<ppT> &openings,
                                                      const lego_gro16_auxiliary_input<ppT> &auxiliary_input);

/*
  Below are four variants of verifier algorithm for LegoGro16.

  These are the four cases that arise from the following two choices:

  (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
  In the latter case, we call the algorithm an "online verifier".

  (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
  Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
  weak input consistency requires that |primary_input| <= CS.num_inputs (and
  the primary input is implicitly padded with zeros up to length CS.num_inputs).
*/

/**
 * A verifier algorithm for LegoGro16 that:
 * (1) accepts a non-processed verification key, and
 * (2) has weak input consistency.
 */
template<typename ppT>
bool lego_gro16_verifier_weak_IC(const lego_gro16_verification_key<ppT> &vk,
                                        const lego_gro16_primary_input<ppT> &primary_input,
                                 const lego_gro16_commitment_vector<ppT> &commitments,
                                 const lego_gro16_proof<ppT> &proof);

/**
 * A verifier algorithm for LegoGro16 that:
 * (1) accepts a non-processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool lego_gro16_verifier_strong_IC(const lego_gro16_verification_key<ppT> &vk,
                                          const lego_gro16_primary_input<ppT> &primary_input,
                                        const lego_gro16_commitment_vector<ppT> &commitments,
                                        const lego_gro16_proof<ppT> &proof);

/**
 * Convert a (non-processed) verification key into a processed verification key.
 */
template<typename ppT>
lego_gro16_processed_verification_key<ppT> lego_gro16_verifier_process_vk(const lego_gro16_verification_key<ppT> &vk);

/**
 * A verifier algorithm for LegoGro16 that:
 * (1) accepts a processed verification key, and
 * (2) has weak input consistency.
 */
template<typename ppT>
bool lego_gro16_online_verifier_weak_IC(const lego_gro16_processed_verification_key<ppT> &pvk,
                                               const lego_gro16_primary_input<ppT> &input,
                                               const lego_gro16_commitment_vector<ppT> &commitments,
                                               const lego_gro16_proof<ppT> &proof);

/**
 * A verifier algorithm for LegoGro16 that:
 * (1) accepts a processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool lego_gro16_online_verifier_strong_IC(const lego_gro16_processed_verification_key<ppT> &pvk,
                                                 const lego_gro16_primary_input<ppT> &primary_input,
                                                const lego_gro16_commitment_vector<ppT> &commitments,
                                                const lego_gro16_proof<ppT> &proof);

} // libsnark

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/legogro16.tcc>

#endif // LEGO_GRO16_HPP_
