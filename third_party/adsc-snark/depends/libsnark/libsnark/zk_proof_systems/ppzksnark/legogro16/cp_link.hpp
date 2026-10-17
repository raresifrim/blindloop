/** @file
*****************************************************************************

Declaration of interfaces for the LegoSNARK CP-link CP-SNARK


*****************************************************************************/

#ifndef CP_LINK_HPP_
#define CP_LINK_HPP_

#include <memory>

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cp_link_params.hpp>

namespace libsnark {



/******************************** Relation ********************************/

template<typename ppT>
class cp_link_relation {
public:
    // f0 is commitment_keys[0] and must have size() = 1
    cp_link_ck_special_vector<ppT> ck_f;

    size_t get_n(size_t i) const {
        return ck_f[i].size();
    }

    size_t get_m() const {
        size_t m = 0;
        for(size_t i = 0; i < ck_f.size(); ++i){
            m += get_n(i);
        }
        return m;
    }
};

/******************************** Proving key ********************************/

template<typename ppT>
class cp_link_proving_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cp_link_proving_key<ppT> &pk);

template<typename ppT>
std::istream& operator>>(std::istream &in, cp_link_proving_key<ppT> &pk);

/**
 * A proving key for the LegoSNARK CPlink CP-SNARK.
 */
template<typename ppT>
class cp_link_proving_key {
public:
    libff::G1_vector<ppT> P;

    cp_link_proving_key() {};
    cp_link_proving_key<ppT>& operator=(const cp_link_proving_key<ppT> &other) = default;
    cp_link_proving_key(const cp_link_proving_key<ppT> &other) = default;
    cp_link_proving_key(cp_link_proving_key<ppT> &&other) = default;
    cp_link_proving_key(libff::G1_vector<ppT> &&P) :
        P(std::move(P))
        {};


    size_t G1_size() const
    {
        return P.size();
    }

    size_t G2_size() const
    {
        return 0;
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

    bool operator==(const cp_link_proving_key<ppT> &other) const;
};


/******************************* Verification key ****************************/

template<typename ppT>
class cp_link_verification_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cp_link_verification_key<ppT> &vk);

template<typename ppT>
std::istream& operator>>(std::istream &in, cp_link_verification_key<ppT> &vk);

/**
 * A verification key for the LegoSNARK CPlink CP-SNARK.
 */
template<typename ppT>
class cp_link_verification_key {
public:
    libff::G2_vector<ppT> C;
    libff::G2<ppT> a;

    cp_link_verification_key() = default;
    cp_link_verification_key(const libff::G2_vector<ppT> &C,
                             const libff::G2<ppT> &a) :
        C(C),
        a(a)
    {};

    size_t G1_size() const
    {
        return 1 + C.size();
    }

    size_t G2_size() const
    {
        return 0;
    }

    size_t GT_size() const
    {
        return 0;
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

    bool operator==(const cp_link_verification_key<ppT> &other) const;
};

template<typename ppT>
class cp_link_processed_verification_key {
public:
    std::vector<libff::G2_precomp<ppT>> C;
    libff::G2_precomp<ppT> a;

    bool operator==(const cp_link_processed_verification_key<ppT> &other) const;
};


/********************************** Key pair *********************************/

/**
 * A key pair for the LegoSNARK CPlink CP-SNARK, which consists of a proving key and a verification key.
 */
template<typename ppT>
class cp_link_keypair {
public:
    cp_link_proving_key<ppT> pk;
    cp_link_verification_key<ppT> vk;

    cp_link_keypair() = default;
    cp_link_keypair(const cp_link_keypair<ppT> &other) = default;
    cp_link_keypair(cp_link_proving_key<ppT> &&pk,
                              cp_link_verification_key<ppT> &&vk) :
        pk(std::move(pk)),
        vk(std::move(vk))
    {}

    cp_link_keypair(cp_link_keypair<ppT> &&other) = default;
};


/*********************************** Proof ***********************************/

template<typename ppT>
class cp_link_proof;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const cp_link_proof<ppT> &proof);

template<typename ppT>
std::istream& operator>>(std::istream &in, cp_link_proof<ppT> &proof);

/**
 * A proof for the LegoSNARK CPlink CP-SNARK.
 *
 * While the proof has a structure, externally one merely opaquely produces,
 * serializes/deserializes, and verifies proofs. We only expose some information
 * about the structure for statistics purposes.
 */
template<typename ppT>
class cp_link_proof {
public:
    libff::G1<ppT> Pi;

    cp_link_proof()
    {
        // invalid proof with valid curve points
        this->Pi = libff::G1<ppT>::one();
    }
    cp_link_proof(libff::G1<ppT> &&Pi) :
        Pi(std::move(Pi))
    {};

    size_t G1_size() const
    {
        return 1;
    }

    size_t G2_size() const
    {
        return 0;
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
        return (Pi.is_well_formed());
    }

    bool operator==(const cp_link_proof<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const cp_link_proof<ppT> &proof);
    friend std::istream& operator>> <ppT>(std::istream &in, cp_link_proof<ppT> &proof);
};


/***************************** Main algorithms *******************************/

/**
 * A generator algorithm for the LegoSNARK CPlink CP-SNARK.
 *
 * Given a R1CS constraint system CS, this algorithm produces proving and verification keys for CS.
 */
template<typename ppT>
cp_link_keypair<ppT> cp_link_generator(const cp_link_ck_generic<ppT> &ck_generic, const cp_link_relation<ppT> &rel);

/**
 * A prover algorithm for the LegoSNARK CPlink CP-SNARK.
 *
 * Given a R1CS primary input X and a R1CS auxiliary input Y, this algorithm
 * produces a proof (of knowledge) that attests to the following statement:
 *               ``there exists Y such that CS(X,Y)=0''.
 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
 */
template<typename ppT>
cp_link_proof<ppT> cp_link_prover(const cp_link_proving_key<ppT> &pk,
                                      const cp_link_commitment_special<ppT> &c_special,
                                      const cp_link_commitment_generic_vector<ppT> &c_generic,
                                      const cp_link_assignment_vector<ppT> &assignment,
                                      const cp_link_opening_generic_vector<ppT> &o_generic,
                                      const cp_link_opening_special<ppT> &o_special);

template <typename ppT>
cp_link_processed_verification_key<ppT> cp_link_verifier_process_vk(const cp_link_verification_key<ppT> &vk);

/**
 * A verifier algorithm for the LegoSNARK CPlink CP-SNARK that:
 * (1) accepts a processed verification key, and
 */
template<typename ppT>
bool cp_link_online_verifier(const cp_link_processed_verification_key<ppT> &vk,
                             const cp_link_commitment_special<ppT> &c_special,
                             const cp_link_commitment_generic_vector<ppT> &c_generic,
                             const cp_link_proof<ppT> &proof);

/**
 * A verifier algorithm for the LegoSNARK CPlink CP-SNARK that:
 * (1) accepts a processed verification key, and
 */
template<typename ppT>
bool cp_link_verifier(const cp_link_verification_key<ppT> &vk,
                             const cp_link_commitment_special<ppT> &c_special,
                             const cp_link_commitment_generic_vector<ppT> &c_generic,
                             const cp_link_proof<ppT> &proof);



} // libsnark

#include <libsnark/zk_proof_systems/ppzksnark/legogro16/cp_link.tcc>

#endif // CP_LINK_HPP_
