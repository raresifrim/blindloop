/** @file
*****************************************************************************

Declaration of interfaces for LegoGro16 SNARK with State-Consistency


*****************************************************************************/

#ifndef SC_LEGO_GRO16_HPP_
#define SC_LEGO_GRO16_HPP_

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/legogro16.hpp>

namespace libsnark {

/******************************** Proving key ********************************/

template<typename ppT>
class sc_lego_gro16_proving_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const sc_lego_gro16_proving_key<ppT> &pk);

template<typename ppT>
std::istream& operator>>(std::istream &in, sc_lego_gro16_proving_key<ppT> &pk);

/**
 * A proving key for State Consistent LegoGro16.
 */
template<typename ppT>
class sc_lego_gro16_proving_key {
public:
    lego_gro16_proving_key<ppT> pk_lego_gro16;
    pedersen_commitment_key<ppT> commitment_key;

    sc_lego_gro16_proving_key() {};
    sc_lego_gro16_proving_key<ppT>& operator=(const sc_lego_gro16_proving_key<ppT> &other) = default;
    sc_lego_gro16_proving_key(const sc_lego_gro16_proving_key<ppT> &other) = default;
    sc_lego_gro16_proving_key(sc_lego_gro16_proving_key<ppT> &&other) = default;
    sc_lego_gro16_proving_key(lego_gro16_proving_key<ppT> &&pk_lego_gro16,
                              pedersen_commitment_key<ppT> &&commitment_key) :
                    pk_lego_gro16(std::move(pk_lego_gro16)),
                    commitment_key(std::move(commitment_key))
        {};


    size_t G1_size() const
    {
        return pk_lego_gro16.G1_size() + commitment_key.size();
    }

    size_t G2_size() const
    {
        return pk_lego_gro16.G2_size();
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

    bool operator==(const sc_lego_gro16_proving_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const sc_lego_gro16_proving_key<ppT> &pk);
    friend std::istream& operator>> <ppT>(std::istream &in, sc_lego_gro16_proving_key<ppT> &pk);
};


/******************************* Verification key ****************************/


/**
 * A verification key for SC-LegoGro16.
 */
template<typename ppT>
using sc_lego_gro16_verification_key = lego_gro16_verification_key<ppT>;


/************************ Processed verification key *************************/

template<typename ppT>
using sc_lego_gro16_processed_verification_key = lego_gro16_processed_verification_key<ppT>;

template<typename ppT>
class  sc_lego_gro16_prover_state {
public:
    pedersen_commitment_pair<ppT> cp;

    sc_lego_gro16_prover_state() :
        cp()
    {}
};

/*********************************** Proof ***********************************/
template<typename ppT>
using sc_lego_gro16_proof = lego_gro16_proof<ppT>;

/*********************************** Commitment ***********************************/

template<typename ppT>
using sc_lego_gro16_commitment = pedersen_commitment_commitment<ppT>;

/********************************** Key pair *********************************/

/**
 * A key pair for LegoGro16, which consists of a proving key and a verification key.
 */
template<typename ppT>
class sc_lego_gro16_keypair {
public:
    sc_lego_gro16_proving_key<ppT> pk;
    sc_lego_gro16_verification_key<ppT> vk;
    sc_lego_gro16_commitment<ppT> initial_commitment;
    sc_lego_gro16_prover_state<ppT> initial_prover_state;

    sc_lego_gro16_keypair() = default;
    sc_lego_gro16_keypair(const sc_lego_gro16_keypair<ppT> &other) = default;
    sc_lego_gro16_keypair(sc_lego_gro16_proving_key<ppT> &&pk,
                          sc_lego_gro16_verification_key<ppT> &&vk,
                          sc_lego_gro16_commitment<ppT> &&initial_commitment,
                          sc_lego_gro16_prover_state<ppT> &&initial_prover_state) :
            pk(std::move(pk)),
            vk(std::move(vk)),
            initial_commitment(std::move(initial_commitment)),
            initial_prover_state(std::move(initial_prover_state))
    {}

    sc_lego_gro16_keypair(sc_lego_gro16_keypair<ppT> &&other) = default;
};

/***************************** Main algorithms *******************************/

/**
 * A generator algorithm for LegoGro16.
 *
 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
 */
template<typename ppT>
sc_lego_gro16_keypair<ppT> sc_lego_gro16_generator(const lego_gro16_constraint_system<ppT> &cs, const lego_gro16_assignment<ppT> &initial_state);

/**
 * A prover algorithm for LegoGro16.
 *
 * auxiliary input contains also assignments for commitments
 */
template<typename ppT>
std::pair<sc_lego_gro16_proof<ppT>, sc_lego_gro16_commitment<ppT>> sc_lego_gro16_prover(
                                              const sc_lego_gro16_proving_key<ppT> &pk,
                                              const lego_gro16_constraint_system<ppT> &constraint_system,
                                              const lego_gro16_primary_input<ppT> &primary_input,
                                              const lego_gro16_assignment<ppT> &state_input,
                                              const lego_gro16_assignment<ppT> &state_update_input,
                                              const lego_gro16_assignment<ppT> &witness_input,
                                              sc_lego_gro16_prover_state<ppT> &prover_state);

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
bool sc_lego_gro16_verifier_weak_IC(const sc_lego_gro16_verification_key<ppT> &vk,
                                    const lego_gro16_primary_input<ppT> &primary_input,
                                    const sc_lego_gro16_proof<ppT> &proof,
                                    const sc_lego_gro16_commitment<ppT> &commitment,
                                    const sc_lego_gro16_commitment<ppT> &commitment_previous);

/**
 * A verifier algorithm for LegoGro16 that:
 * (1) accepts a non-processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool sc_lego_gro16_verifier_strong_IC(const sc_lego_gro16_verification_key<ppT> &vk,
                                    const lego_gro16_primary_input<ppT> &primary_input,
                                    const sc_lego_gro16_proof<ppT> &proof,
                                    const sc_lego_gro16_commitment<ppT> &commitment,
                                    const sc_lego_gro16_commitment<ppT> &commitment_previous);

/**
 * Convert a (non-processed) verification key into a processed verification key.
 */
template<typename ppT>
sc_lego_gro16_processed_verification_key<ppT> sc_lego_gro16_verifier_process_vk(const sc_lego_gro16_verification_key<ppT> &vk);

/**
 * A verifier algorithm for LegoGro16 that:
 * (1) accepts a processed verification key, and
 * (2) has weak input consistency.
 */
template<typename ppT>
bool sc_lego_gro16_online_verifier_weak_IC(const sc_lego_gro16_processed_verification_key<ppT> &vk,
                                            const lego_gro16_primary_input<ppT> &primary_input,
                                            const sc_lego_gro16_proof<ppT> &proof,
                                            const sc_lego_gro16_commitment<ppT> &commitment,
                                            const sc_lego_gro16_commitment<ppT> &commitment_previous);

/**
 * A verifier algorithm for LegoGro16 that:
 * (1) accepts a processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool sc_lego_gro16_online_verifier_strong_IC(const sc_lego_gro16_processed_verification_key<ppT> &vk,
                                            const lego_gro16_primary_input<ppT> &primary_input,
                                            const sc_lego_gro16_proof<ppT> &proof,
                                            const sc_lego_gro16_commitment<ppT> &commitment,
                                            const sc_lego_gro16_commitment<ppT> &commitment_previous);

} // libsnark

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/sc_legogro16.tcc>

#endif // SC_LEGO_GRO16_HPP_
