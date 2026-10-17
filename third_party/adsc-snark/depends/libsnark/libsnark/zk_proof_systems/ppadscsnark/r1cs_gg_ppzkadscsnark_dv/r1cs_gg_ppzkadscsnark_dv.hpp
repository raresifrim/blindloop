/** @file
*****************************************************************************

Declaration of interfaces for a ppZKADSCSNARK for R1CS with a security proof
in the generic group (GG) model with a designated verifier

*****************************************************************************/

#ifndef R1CS_GG_PPZKADSCSNARK_DV_HPP_
#define R1CS_GG_PPZKADSCSNARK_DV_HPP_

#include <libff/algebra/curves/public_params.hpp>

#include <libsnark/common/data_structures/accumulation_vector.hpp>
#include <libsnark/knowledge_commitment/knowledge_commitment.hpp>
#include <libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppzkadscsnark_dv/r1cs_gg_ppzkadscsnark_dv_params.hpp>
#include <libsnark/common/crypto/mac/hmac.hpp>

namespace libsnark {

/******************************** Proving key ********************************/

template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_proving_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &pk);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &pk);

/**
 * A proving key for the R1CS GG-ppZKADSCSNARK.
 */
template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_proving_key {
public:
    libff::G1<ppT> alpha_g1;
    libff::G1<ppT> beta_g1;
    libff::G1<ppT> delta_g1;
    libff::G1<ppT> epsilon_g1;
    libff::G1<ppT> eta_g1;
    libff::G1<ppT> kappa_g1;
    libff::G1_vector<ppT> A_query;
    knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > B_query;
    libff::G1_vector<ppT> Pi_witness;
    libff::G1_vector<ppT> Pi_state;
    libff::G1_vector<ppT> Pi_stateupdate;
    libff::G1_vector<ppT> Pi_priv_input;
    libff::G1_vector<ppT> H_query;
    libff::G1_vector<ppT> Ri;

    libff::G2<ppT> beta_g2;
    libff::G2<ppT> delta_g2;

    r1cs_gg_ppzkadscsnark_dv_proving_key() {};
    r1cs_gg_ppzkadscsnark_dv_proving_key<ppT>& operator=(const r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &other) = default;
    r1cs_gg_ppzkadscsnark_dv_proving_key(const r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &other) = default;
    r1cs_gg_ppzkadscsnark_dv_proving_key(r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &&other) = default;
    r1cs_gg_ppzkadscsnark_dv_proving_key(libff::G1<ppT> &&alpha_g1,
                                      libff::G1<ppT> &&beta_g1,
                                      libff::G1<ppT> &&delta_g1,
                                      libff::G1<ppT> &&epsilon_g1,
                                      libff::G1<ppT> &&eta_g1,
                                      libff::G1<ppT> &&kappa_g1,
                                      libff::G1_vector<ppT> &&A_query,
                                  knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > &&B_query,
                                  libff::G1_vector<ppT> &&Pi_witness,
                                  libff::G1_vector<ppT> &&Pi_state,
                                  libff::G1_vector<ppT> &&Pi_stateupdate,
                                  libff::G1_vector<ppT> &&Pi_priv_input,
                                  libff::G1_vector<ppT> &&H_query,
                                  libff::G1_vector<ppT> &&Ri,
                                  libff::G2<ppT> &&beta_g2,
                                  libff::G2<ppT> &&delta_g2) :
        alpha_g1(std::move(alpha_g1)),
        beta_g1(std::move(beta_g1)),
        delta_g1(std::move(delta_g1)),
        epsilon_g1(std::move(epsilon_g1)),
        eta_g1(std::move(eta_g1)),
        kappa_g1(std::move(kappa_g1)),

        A_query(std::move(A_query)),
        B_query(std::move(B_query)),

        Pi_witness(std::move(Pi_witness)),
        Pi_state(std::move(Pi_state)),
        Pi_stateupdate(std::move(Pi_stateupdate)),
        Pi_priv_input(std::move(Pi_priv_input)),
        H_query(std::move(H_query)),
        Ri(std::move(Ri)),
        beta_g2(std::move(beta_g2)),
        delta_g2(std::move(delta_g2))
        {};

    size_t G1_size() const
    {
        return 6
            + A_query.size()
            + B_query.domain_size()
            + Pi_witness.size()
            + Pi_state.size()
            + Pi_stateupdate.size()
            + Pi_priv_input.size()
            + H_query.size()
            + Ri.size();
    }

    size_t G2_size() const
    {
        return 2 + B_query.domain_size();
    }

    size_t G1_sparse_size() const
    {
        return 6
            + A_query.size()
            + B_query.size()
            + Pi_witness.size()
            + Pi_state.size()
            + Pi_stateupdate.size()
            + Pi_priv_input.size()
            + H_query.size()
            + Ri.size();
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

    bool operator==(const r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &pk);
    friend std::istream& operator>> <ppT>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &pk);
};


/******************************* Verification key ****************************/

template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_verification_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk);

/**
 * A verification key for the designated verifier R1CS GG-ppZKADSCSNARK.
 * The verification key is private, the prover is not allowed to see it
 */
template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_verification_key {
public:
    libff::G1<ppT> one_g1;
    libff::G2<ppT> one_m_g2; // minus one
    libff::Fr<ppT> delta;
    libff::Fr<ppT> epsilon;
    libff::Fr<ppT> eta;
    libff::Fr<ppT> kappa;

    std::vector<libff::Fr<ppT>> Pi_statement;

    libff::GT<ppT> alpha_g1_beta_g2;
    std::vector<r1cs_gg_ppzkadscsnark_dv_mac_key<ppT>> mac_keys;
    r1cs_gg_ppzkadscsnark_dv_verification_key() = default;
    r1cs_gg_ppzkadscsnark_dv_verification_key(
                                         libff::G1<ppT> &&one_g1,
                                         libff::G2<ppT> &&one_m_g2,
                                         libff::Fr<ppT> delta,
                                         libff::Fr<ppT> epsilon,
                                         libff::Fr<ppT> eta,
                                         libff::Fr<ppT> kappa,
                                         std::vector<libff::Fr<ppT>> &&Pi_statement,
                                         libff::GT<ppT> &&alpha_g1_beta_g2,
                                         std::vector<r1cs_gg_ppzkadscsnark_dv_mac_key<ppT>> &&mac_keys) :
            one_g1(std::move(one_g1)),
            one_m_g2(std::move(one_m_g2)),
            delta(delta),
            epsilon(epsilon),
            eta(eta),
            kappa(kappa),
            Pi_statement(std::move(Pi_statement)),
            alpha_g1_beta_g2(std::move(alpha_g1_beta_g2)),
            mac_keys(std::move(mac_keys))
    {};

    size_t G1_size() const
    {
        return 1;
    }

    size_t G2_size() const
    {
        return 1;
    }

    size_t GT_size() const
    {
        return 1;
    }

    size_t Fr_size() const
    {
        return Pi_statement.size() + 4;
    }

    size_t pkey_size() const
    {
        size_t size = 0;
        for (auto &key: mac_keys)
        {
            size += key.size_in_bytes();
        }
        return size;
    }

    size_t size_in_bits() const
    {
        return (
                G1_size() * libff::G1<ppT>::size_in_bits() +
                G2_size() * libff::G2<ppT>::size_in_bits() +
                GT_size() * libff::GT<ppT>::ceil_size_in_bits() +
                Fr_size() * libff::Fr<ppT>::ceil_size_in_bits() +
                pkey_size() * 8
                );
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in VK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in VK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* GT elements in VK: %zu\n", this->GT_size());
        libff::print_indent(); printf("* Fr elements in VK: %zu\n", this->Fr_size());
        libff::print_indent(); printf("* PKey bytes in VK: %zu\n", this->pkey_size());
        libff::print_indent(); printf("* VK size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk);
    friend std::istream& operator>> <ppT>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk);

    static r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> dummy_verification_key(size_t input_size, size_t signatures);
};


/************************ Processed verification key *************************/

template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_processed_verification_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk);

/**
 * A processed verification key for the R1CS GG-ppZKADSCSNARK.
 *
 * Compared to a (non-processed) verification key, a processed verification key
 * contains a small constant amount of additional pre-computed information that
 * enables a faster verification time.
 */
template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_processed_verification_key {
public:
    libff::G1<ppT> one_g1;
    libff::G2_precomp<ppT> one_m_g2_precomp; // minus one
    libff::Fr<ppT> delta;
    libff::Fr<ppT> epsilon;
    libff::Fr<ppT> eta;
    libff::Fr<ppT> kappa;

    std::vector<libff::Fr<ppT>> Pi_statement;

    libff::GT<ppT> alpha_g1_beta_g2;
    std::vector<r1cs_gg_ppzkadscsnark_dv_mac_key<ppT>> mac_keys;

    bool operator==(const r1cs_gg_ppzkadscsnark_dv_processed_verification_key &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk);
    friend std::istream& operator>> <ppT>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk);
};

/******************************* Authentication key ****************************/

template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_authentication_key;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT> &ak);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT> &ak);

/**
* An authentication key for the R1CS GG-ppZKADSCSNARK.
* Parts of the authentication key are private: the privkey, the prover should not have access to it
* T_g1 and delta_g1 are public, the prover is allowed to see it
*/
template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_authentication_key {
public:
    r1cs_gg_ppzkadscsnark_dv_mac_key<ppT> mac_key;
    libff::G1_vector<ppT> T_g1;
    libff::G1<ppT> delta_g1;

    r1cs_gg_ppzkadscsnark_dv_authentication_key() = default;
    r1cs_gg_ppzkadscsnark_dv_authentication_key( const r1cs_gg_ppzkadscsnark_dv_mac_key<ppT> &mac_key,
                                              const libff::G1_vector<ppT> &T_g1,
                                              const libff::G1<ppT> &delta_g1) :
            mac_key(mac_key),
            T_g1(T_g1),
            delta_g1(delta_g1)
    {};

    size_t G1_size() const
    {
        return T_g1.size() + 1;
    }

    size_t G2_size() const
    {
        return 0;
    }

    size_t GT_size() const
    {
        return 0;
    }

    size_t Fr_size() const
    {
        return 0;
    }

    size_t Pkey_size() const
    {
        return mac_key.size_in_bytes();
    }

    size_t size_in_bits() const
    {
        return (
                G1_size() * libff::G1<ppT>::size_in_bits() +
                G2_size() * libff::G2<ppT>::size_in_bits() +
                GT_size() * libff::GT<ppT>::ceil_size_in_bits() +
                Fr_size() * libff::Fr<ppT>::ceil_size_in_bits() +
                Pkey_size() * 8
        );
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in VK: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in VK: %zu\n", this->G2_size());
        libff::print_indent(); printf("* GT elements in VK: %zu\n", this->GT_size());
        libff::print_indent(); printf("* Fr elements in VK: %zu\n", this->Fr_size());
        libff::print_indent(); printf("* Pkey bytes in VK: %zu\n", this->Pkey_size());
        libff::print_indent(); printf("* AK size in bits: %zu\n", this->size_in_bits());
    }

    bool operator==(const r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT> &other) const;

};

/**
* Authenticated inputs for the R1CS GG-ppZKADSCSNARK.
*/
template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_authenticated_input;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT> &ai);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT> &ai);

template<typename ppT>
class  r1cs_gg_ppzkadscsnark_dv_authenticated_input {
public:
    r1cs_gg_ppzkadscsnark_dv_assignment<ppT> values;
    libff::G1<ppT> D_g1;
    libff::Fr<ppT> bD;
    r1cs_gg_ppzkadscsnark_dv_mac<ppT> mac;

    bool operator==(const r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT> &other) const;
};

/**
* Prover state for the R1CS GG-ppZKADSCSNARK.
*/
template<typename ppT>
class  r1cs_gg_ppzkadscsnark_dv_prover_state {
public:
    libff::Fr<ppT> bE;

    r1cs_gg_ppzkadscsnark_dv_prover_state() :
        bE(libff::Fr<ppT>::zero())
    {}
};

/*********************************** Proof ***********************************/

template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_proof;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof);

/**
 * A proof for the R1CS GG-ppZKADSCSNARK.
 *
 * While the proof has a structure, externally one merely opaquely produces,
 * serializes/deserializes, and verifies proofs. We only expose some information
 * about the structure for statistics purposes.
 */
template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_proof {
public:
    libff::G1<ppT> A_g1;
    libff::G1<ppT> C_g1;
    libff::G1_vector<ppT> D_g1_vec;

    libff::G2<ppT> B_g2;
    std::vector<r1cs_gg_ppzkadscsnark_dv_mac<ppT>> macs;

    r1cs_gg_ppzkadscsnark_dv_proof()
    {
        // invalid proof with valid curve points
        this->A_g1 = libff::G1<ppT>::one();
        this->C_g1 = libff::G1<ppT>::one();
        this->D_g1_vec = libff::G1_vector<ppT>();
        this->B_g2 = libff::G2<ppT>::one();
    }

    r1cs_gg_ppzkadscsnark_dv_proof(libff::G1<ppT> &&A_g1,
                            libff::G1<ppT> &&C_g1,
                            libff::G1_vector<ppT> &&D_g1_vec,
                            libff::G2<ppT> &&B_g2,
                            std::vector<r1cs_gg_ppzkadscsnark_dv_mac<ppT>> &&macs) :
        A_g1(std::move(A_g1)),
        C_g1(std::move(C_g1)),
        D_g1_vec(std::move(D_g1_vec)),
        B_g2(std::move(B_g2)),
        macs(std::move(macs))
    {};

    size_t G1_size() const
    {
        return 2 + D_g1_vec.size();
    }

    size_t G2_size() const
    {
        return 1;
    }

    size_t Sig_size() const
    {
        size_t result = 0;
        for (auto &mac: macs)
        {
            result += mac.size_in_bytes();
        }
        return result;
    }

    size_t size_in_bits() const
    {
        return G1_size() * libff::G1<ppT>::size_in_bits()
            + G2_size() * libff::G2<ppT>::size_in_bits()
            + Sig_size() * 8;
    }

    void print_size() const
    {
        if(libff::inhibit_profiling_info) {
            return;
        }
        libff::print_indent(); printf("* G1 elements in proof: %zu\n", this->G1_size());
        libff::print_indent(); printf("* G2 elements in proof: %zu\n", this->G2_size());
        libff::print_indent(); printf("* Sig bytes in proof: %zu\n", this->Sig_size());
        libff::print_indent(); printf("* Proof size in bits: %zu\n", this->size_in_bits());
    }

    bool is_well_formed() const
    {
        bool result = true;

        if (!A_g1.is_well_formed()
            || !C_g1.is_well_formed()
            || !B_g2.is_well_formed())
        {
            result = false;
        }

        if (D_g1_vec.size() != macs.size())
        {
            result = false;
        }

        for (auto &D: D_g1_vec)
        {
            if (!D.is_well_formed())
            {
                result = false;
            }
        }

        for (auto &mac: macs)
        {
            if (!mac.is_well_formed())
            {
                result = false;
            }
        }
        return result;
    }

    bool operator==(const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof);
    friend std::istream& operator>> <ppT>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof);
};

/**
 * A commitment for states for R1CS GG-ppZKADSCSNARK.
 *
 * This is a commitment to the computational state that can be verified in combination with a proof
 */

template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_commitment;

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &c);

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &c);

template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_commitment {
public:
    libff::G1<ppT> E_g1;

    r1cs_gg_ppzkadscsnark_dv_commitment()
    {
        // invalid commitment with valid curve points
        this->E_g1 = libff::G1<ppT>::one();
    }

    r1cs_gg_ppzkadscsnark_dv_commitment(libff::G1<ppT> &&E_g1) :
        E_g1(std::move(E_g1))
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
        libff::print_indent(); printf("* Commitment size in bits: %zu\n", this->size_in_bits());
    }

    bool is_well_formed() const
    {
        return E_g1.is_well_formed();
    }

    bool operator==(const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &other) const;
    friend std::ostream& operator<< <ppT>(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &c);
    friend std::istream& operator>> <ppT>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &c);
};

/********************************** Key pair *********************************/

/**
 * A key pair for the R1CS GG-ppZKADSCSNARK, which consists of a proving key, a verification key,
 * and an authentication key
 */
template<typename ppT>
class r1cs_gg_ppzkadscsnark_dv_keypair {
public:
    r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> pk;
    r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> vk;
    std::vector<r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT>> aks;
    r1cs_gg_ppzkadscsnark_dv_commitment<ppT> initial_commitment;

    r1cs_gg_ppzkadscsnark_dv_keypair() = default;
    r1cs_gg_ppzkadscsnark_dv_keypair(const r1cs_gg_ppzkadscsnark_dv_keypair<ppT> &other) = default;
    r1cs_gg_ppzkadscsnark_dv_keypair(r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &&pk,
                                r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &&vk,
                                std::vector<r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT>> &&aks,
                                r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &&initial_commitment) :
            pk(std::move(pk)),
            vk(std::move(vk)),
            aks(std::move(aks)),
            initial_commitment(std::move(initial_commitment))
    {}

    r1cs_gg_ppzkadscsnark_dv_keypair(r1cs_gg_ppzkadscsnark_dv_keypair<ppT> &&other) = default;
};

/***************************** Main algorithms *******************************/

/**
 * A generator algorithm for the R1CS GG-ppZKADSCSNARK.
 *
 * Given a R1CS constraint system CS, this algorithm produces proving, verification and authentication keys for CS.
 */
template<typename ppT>
r1cs_gg_ppzkadscsnark_dv_keypair<ppT> r1cs_gg_ppzkadscsnark_dv_generator(const r1cs_gg_ppzkadscsnark_dv_constraint_system<ppT> &r1cs,
                                                               const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &initial_state,
                                                               std::vector<size_t> private_input_blocks=std::vector<size_t>());

/**
 * An authentication algorithm for the R1CS GG-ppZKADSCSNARK.
 *
 * Given a set of input values, this algorithm outputs the authenticated values
 */
template<typename ppT>
r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT> r1cs_gg_ppzkadscsnark_dv_authenticate(const r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT> &ak, const r1cs_gg_ppzkadscsnark_dv_label<ppT> &label, const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &input);

/**
 * A prover algorithm for the R1CS GG-ppZKADSCSNARK.
 *
 * Given a R1CS primary input PHI, a R1CS authenticated input X a R1CS auxiliary input OMEGA and state S with state update S', this algorithm
 * produces a proof (of knowledge) that attests to the following statement:
 *               ``there exists Y such that CS(PHI,X,S,S', OMEGA)=0 and S'_(t-1) = S'_(t) and X has been authenticated'' .
 * Above, CS is the R1CS constraint system that was given as input to the generator algorithm.
 */
template<typename ppT>
std::pair<r1cs_gg_ppzkadscsnark_dv_proof<ppT>, r1cs_gg_ppzkadscsnark_dv_commitment<ppT>> r1cs_gg_ppzkadscsnark_dv_prover(
                              const r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &pk,
                              const r1cs_gg_ppzkadscsnark_dv_constraint_system<ppT> &constraint_system,
                              const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &primary_input,
                              const std::vector<r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT>> &authenticated_inputs,
                              const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &state_input,
                              const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &state_update_input,
                              const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &witness_input,
                              r1cs_gg_ppzkadscsnark_dv_prover_state<ppT> &prover_state);

/*
  Below are four variants of verifier algorithm for the R1CS GG-ppZKADSCSNARK.

  These are the four cases that arise from the following two choices:

  (1) The verifier accepts a (non-processed) verification key or, instead, a processed verification key.
  In the latter case, we call the algorithm an "online verifier".

  (2) The verifier checks for "weak" input consistency or, instead, "strong" input consistency.
  Strong input consistency requires that |primary_input| = CS.num_inputs, whereas
  weak input consistency requires that |primary_input| <= CS.num_inputs (and
  the primary input is implicitly padded with zeros up to length CS.num_inputs).
*/

/**
 * A verifier algorithm for the R1CS GG-ppZKADSCSNARK that:
 * (1) accepts a non-processed verification key, and
 * (2) has weak input consistency.
 */
template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_verifier_weak_IC(const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk,
                                        const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &primary_input,
                                        const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof,
                                        const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment,
                                        const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment_previous,
                                        const r1cs_gg_ppzkadscsnark_dv_label<ppT> &iteration);

/**
 * A verifier algorithm for the R1CS GG-ppZKADSCSNARK that:
 * (1) accepts a non-processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_verifier_strong_IC(const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk,
                                        const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &primary_input,
                                        const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof,
                                        const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment,
                                        const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment_previous,
                                        const r1cs_gg_ppzkadscsnark_dv_label<ppT> &iteration);

/**
 * Convert a (non-processed) verification key into a processed verification key.
 */
template<typename ppT>
r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> r1cs_gg_ppzkadscsnark_dv_verifier_process_vk(
    const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk);

/**
 * A verifier algorithm for the R1CS GG-ppZKADSCSNARK that:
 * (1) accepts a processed verification key, and
 * (2) has weak input consistency.
 */
template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_online_verifier_weak_IC(const r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk,
                                               const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &input,
                                               const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof,
                                               const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment,
                                               const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment_previous,
                                               const r1cs_gg_ppzkadscsnark_dv_label<ppT> &iteration);

/**
 * A verifier algorithm for the R1CS GG-ppZKADSCSNARK that:
 * (1) accepts a processed verification key, and
 * (2) has strong input consistency.
 */
template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_online_verifier_strong_IC(const r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk,
                                                 const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &primary_input,
                                                 const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof,
                                                 const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment,
                                                 const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment_previous,
                                                 const r1cs_gg_ppzkadscsnark_dv_label<ppT> &iteration);


} // libsnark

#include <libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppzkadscsnark_dv/r1cs_gg_ppzkadscsnark_dv.tcc>

#endif // R1CS_GG_PPZKADSCSNARK_DV_HPP_
