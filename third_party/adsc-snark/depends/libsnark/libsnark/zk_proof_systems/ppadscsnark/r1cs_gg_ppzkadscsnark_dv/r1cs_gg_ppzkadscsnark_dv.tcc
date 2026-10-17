/** @file
*****************************************************************************

Implementation of interfaces for a ppZKADSCSNARK for R1CS.

See r1cs_gg_ppzkadscsnark_dv.hpp .


*****************************************************************************/

#ifndef R1CS_GG_PPZKADSCSNARK_DV_TCC_
#define R1CS_GG_PPZKADSCSNARK_DV_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/common/serialization.hpp>

#include <libsnark/common/crypto/mac/hmac.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

#include <libsnark/knowledge_commitment/kc_multiexp.hpp>
#include <libsnark/reductions/r1cs_to_plain_qap/r1cs_to_plain_qap.hpp>

#include "r1cs_gg_ppzkadscsnark_dv.hpp"
#include "r1cs_gg_ppzkadscsnark_dv_params.hpp"

namespace libsnark {


template<typename ppT>
r1cs_gg_ppzkadscsnark_dv_mac_key<ppT> r1cs_gg_ppzkadscsnark_dv_mac_generate()
{
    return hmac_sha256_generate_key();
}

template<typename ppT>
r1cs_gg_ppzkadscsnark_dv_mac<ppT> r1cs_gg_ppzkadscsnark_dv_mac_compute(const r1cs_gg_ppzkadscsnark_dv_mac_key<ppT> &key, const libff::G1<ppT> &value, const r1cs_gg_ppzkadscsnark_dv_label<ppT> &label)
{
    // Serialize value || label
    std::stringstream ss;
    ss << value << label;
    std::string serialized = ss.str();
    return hmac_sha256_compute_mac(key, std::vector<uint8_t>(serialized.begin(), serialized.end()));
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_mac_verify(const r1cs_gg_ppzkadscsnark_dv_mac_key<ppT> &key, const r1cs_gg_ppzkadscsnark_dv_mac<ppT> &mac, const libff::G1<ppT> &value, const r1cs_gg_ppzkadscsnark_dv_label<ppT> &label)
{
    // Serialize D_g1 || label
    std::stringstream ss;
    ss << value << label;
    std::string serialized = ss.str();
    return hmac_sha256_verify_mac(key, mac, std::vector<uint8_t>(serialized.begin(), serialized.end()));
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_proving_key<ppT>::operator==(const r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &other) const
{
    return (this->alpha_g1 == other.alpha_g1 &&
            this->beta_g1 == other.beta_g1 &&
            this->delta_g1 == other.delta_g1 &&
            this->epsilon_g1 == other.epsilon_g1 &&
            this->eta_g1 == other.eta_g1 &&
            this->kappa_g1 == other.kappa_g1 &&
            this->A_query == other.A_query &&
            this->B_query == other.B_query &&
            this->Pi_witness == other.Pi_witness &&
            this->Pi_state == other.Pi_state &&
            this->Pi_stateupdate == other.Pi_stateupdate &&
            this->Pi_priv_input == other.Pi_priv_input &&
            this->H_query == other.H_query &&
            this->Ri == other.Ri &&
            this->beta_g2 == other.beta_g2 &&
            this->delta_g2 == other.delta_g2
            );
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &pk)
{
    out << pk.alpha_g1 << OUTPUT_NEWLINE;
    out << pk.beta_g1 << OUTPUT_NEWLINE;
    out << pk.delta_g1 << OUTPUT_NEWLINE;
    out << pk.epsilon_g1 << OUTPUT_NEWLINE;
    out << pk.eta_g1 << OUTPUT_NEWLINE;
    out << pk.kappa_g1 << OUTPUT_NEWLINE;
    out << pk.beta_g2 << OUTPUT_NEWLINE;
    out << pk.delta_g2 << OUTPUT_NEWLINE;

    out << pk.A_query;
    out << pk.B_query;
    out << pk.Pi_witness;
    out << pk.Pi_state;
    out << pk.Pi_stateupdate;
    out << pk.Pi_priv_input;
    out << pk.H_query;
    out << pk.Ri;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &pk)
{
    in >> pk.alpha_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.beta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.epsilon_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.eta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.kappa_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pk.delta_g2;
    libff::consume_OUTPUT_NEWLINE(in);

    in >> pk.A_query;
    in >> pk.B_query;
    in >> pk.Pi_witness;
    in >> pk.Pi_state;
    in >> pk.Pi_stateupdate;
    in >> pk.Pi_priv_input;
    in >> pk.H_query;
    in >> pk.Ri;

    return in;
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_verification_key<ppT>::operator==(const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &other) const
{
    return (
            this->one_g1 == other.one_g1 &&
            this->one_m_g2 == other.one_m_g2 &&
            this->delta == other.delta &&
            this->epsilon == other.epsilon &&
            this->eta == other.eta &&
            this->kappa == other.kappa &&
            this->Pi_statement == other.Pi_statement &&
            this->alpha_g1_beta_g2 == other.alpha_g1_beta_g2 &&
            this->mac_keys == other.mac_keys
            );
}


template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk)
{
    out << vk.one_g1 << OUTPUT_NEWLINE;
    out << vk.one_m_g2 << OUTPUT_NEWLINE;
    out << vk.delta << OUTPUT_NEWLINE;
    out << vk.epsilon << OUTPUT_NEWLINE;
    out << vk.eta << OUTPUT_NEWLINE;
    out << vk.kappa << OUTPUT_NEWLINE;
    out << vk.Pi_statement << OUTPUT_NEWLINE;
    out << vk.alpha_g1_beta_g2 << OUTPUT_NEWLINE;
    libff::operator<<(out, vk.mac_keys) << OUTPUT_NEWLINE;

    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk)
{
    in >> vk.one_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.one_m_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.delta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.epsilon;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.eta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.kappa;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.Pi_statement;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> vk.alpha_g1_beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    libff::operator>>(in, vk.mac_keys);
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> r1cs_gg_ppzkadscsnark_dv_verification_key<ppT>::dummy_verification_key(size_t input_size, size_t signatures)
{
    r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> result;
    result.one_g1 = libff::G1<ppT>::random_element();
    result.one_m_g2 = libff::G2<ppT>::random_element();
    result.delta = libff::Fr<ppT>::random_element();
    result.epsilon = libff::Fr<ppT>::random_element();
    result.eta = libff::Fr<ppT>::random_element();
    result.kappa = libff::Fr<ppT>::random_element();

    libff::Fr_vector<ppT> v;
    for (size_t i = 0; i < input_size; ++i)
    {
        v.emplace_back(libff::Fr<ppT>::random_element());
    }

    result.Pi_statement = v;
    result.alpha_g1_beta_g2 = libff::Fr<ppT>::random_element() * libff::GT<ppT>::random_element();

    std::vector<r1cs_gg_ppzkadscsnark_dv_mac_key<ppT>> mac_keys;
    for (size_t i = 0; i < signatures; ++i)
    {
        r1cs_gg_ppzkadscsnark_dv_mac_key<ppT> mac_key;
        mac_key = r1cs_gg_ppzkadscsnark_dv_mac_generate<ppT>();
        mac_keys.push_back(mac_key);
    }

    result.mac_keys = mac_keys;
    return result;
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT>::operator==(const r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &other) const
{
    return (
        this->Pi_statement == other.Pi_statement &&
        this->alpha_g1_beta_g2 == other.alpha_g1_beta_g2 &&
        this->one_g1 == other.one_g1 &&
        this->one_m_g2_precomp == other.one_m_g2_precomp &&
        this->delta == other.delta &&
        this->epsilon == other.epsilon &&
        this->eta == other.eta &&
        this->kappa == other.kappa &&
        this->mac_keys == other.mac_keys
    );
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk)
{
    out << pvk.Pi_statement << OUTPUT_NEWLINE;
    out << pvk.alpha_g1_beta_g2 << OUTPUT_NEWLINE;
    out << pvk.one_g1 << OUTPUT_NEWLINE;
    out << pvk.one_m_g2_precomp << OUTPUT_NEWLINE;
    out << pvk.delta << OUTPUT_NEWLINE;
    out << pvk.epsilon << OUTPUT_NEWLINE;
    out << pvk.eta << OUTPUT_NEWLINE;
    out << pvk.kappa << OUTPUT_NEWLINE;
    libff::operator<<(out, pvk.mac_keys) << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk)
{
    in >> pvk.Pi_statement;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.alpha_g1_beta_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.one_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.one_m_g2_precomp;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.delta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.epsilon;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.eta;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> pvk.kappa;
    libff::consume_OUTPUT_NEWLINE(in);
    libff::operator>>(in, pvk.mac_keys);
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT>::operator==(const r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT> &other) const
{
    return (this->mac_key == other.mac_key &&
    this->T_g1 == other.T_g1 &&
    this->delta_g1 == other.delta_g1);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT> &ak)
{
    out << ak.mac_key << OUTPUT_NEWLINE;
    out << ak.T_g1 << OUTPUT_NEWLINE;
    out << ak.delta_g1 << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT> &ak)
{
    in >> ak.mac_key;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ak.T_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ak.delta_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT>::operator==(const r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT> &other) const
{
    return (this->values == other.values &&
            this->D_g1 == other.D_g1 &&
            this->bD == other.bD &&
            this->mac == other.mac);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT> &ai)
{
    out << ai.values << OUTPUT_NEWLINE;
    out << ai.D_g1 << OUTPUT_NEWLINE;
    out << ai.bD << OUTPUT_NEWLINE;
    out << ai.mac << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT> &ai)
{
    in >> ai.values;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ai.D_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ai.bD;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> ai.mac;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_proof<ppT>::operator==(const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &other) const
{
    return (this->A_g1 == other.A_g1 &&
            this->C_g1 == other.C_g1 &&
            this->D_g1_vec == other.D_g1_vec &&
            this->B_g2 == other.B_g2 &&
            this->macs == other.macs);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof)
{
    out << proof.A_g1 << OUTPUT_NEWLINE;
    out << proof.C_g1 << OUTPUT_NEWLINE;
    out << proof.D_g1_vec << OUTPUT_NEWLINE;
    out << proof.B_g2 << OUTPUT_NEWLINE;
    libff::operator<<(out, proof.macs) << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof)
{
    in >> proof.A_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.C_g1;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.D_g1_vec;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.B_g2;
    libff::consume_OUTPUT_NEWLINE(in);
    libff::operator>>(in, proof.macs);
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_commitment<ppT>::operator==(const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &other) const
{
    return this->E_g1 == other.E_g1;
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &c)
{
    out << c.E_g1;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &c)
{
    in >> c.E_g1;
    return in;
}



template <typename ppT>
r1cs_gg_ppzkadscsnark_dv_keypair<ppT> r1cs_gg_ppzkadscsnark_dv_generator(const r1cs_gg_ppzkadscsnark_dv_constraint_system<ppT> &r1cs,
                                                               const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &initial_state,
                                                               std::vector<size_t> private_input_blocks)
{
    libff::enter_block("Call to r1cs_gg_ppzkadscsnark_dv_generator");
    assert(initial_state.size() == r1cs.state_size);

    // Default case, just one authentication key for entire private-input-block
    if (private_input_blocks.size() == 0)
    {
        private_input_blocks.push_back(r1cs.private_input_size);
    }

#ifndef NDEBUG
    size_t acc = 0;
    for(size_t i = 0; i < private_input_blocks.size(); ++i){
        assert(private_input_blocks[i] != 0);
        acc += private_input_blocks[i];
    }
    assert(acc == r1cs.private_input_size);
#endif

    /* Make the B_query "lighter" if possible */
    //r1cs.swap_AB_if_beneficial();
    // This step can be carried out before inputting into the generator,
    // as this changes the constraint system -> and the prover needs the same constraint system

    /* Generate secret randomness */
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> alpha = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> beta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> delta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> kappa = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> eta = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> epsilon = libff::Fr<ppT>::random_element();

    const libff::Fr<ppT> delta_inverse = delta.inverse();

    libff::Fr_vector<ppT> Ti;
    libff::Fr_vector<ppT> Ri;

    Ti.reserve(r1cs.private_input_size);
    for (size_t i = 0; i < r1cs.private_input_size; ++i)
    {
        Ti.push_back(libff::Fr<ppT>::random_element());
    }
    Ri.reserve(r1cs.state_size);
    for (size_t i = 0; i < r1cs.state_size; ++i)
    {
        Ri.push_back(libff::Fr<ppT>::random_element());
    }

    libff::enter_block("Generate signing keys");
    std::vector<r1cs_gg_ppzkadscsnark_dv_mac_key<ppT>> mac_keys;

    for (size_t i = 0; i < private_input_blocks.size(); ++i)
    {
        r1cs_gg_ppzkadscsnark_dv_mac_key<ppT> key;
        key = r1cs_gg_ppzkadscsnark_dv_mac_generate<ppT>();
        mac_keys.push_back(key);
    }
    libff::leave_block("Generate signing keys");


    /* A quadratic arithmetic program evaluated at t. */
    // use plain function here, as r1cs_to_qap_instance adds some constraints to strengthen the QAP
    // this is only required for the older Pinocchio-based SNARKs
    qap_instance_evaluation<libff::Fr<ppT> > qap = r1cs_to_plain_qap_instance_map_with_evaluation(r1cs, t);

    if(!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("* QAP number of variables: %zu\n", qap.num_variables());
        libff::print_indent();
        printf("* QAP pre degree: %zu\n", r1cs.constraints.size());
        libff::print_indent();
        printf("* QAP degree: %zu\n", qap.degree());
        libff::print_indent();
        printf("* QAP number of input variables: %zu\n", qap.num_inputs());
    }

    libff::enter_block("Compute query densities");
    size_t non_zero_At = 0;
    size_t non_zero_Bt = 0;
    for (size_t i = 0; i < qap.num_variables() + 1; ++i)
    {
        if (!qap.At[i].is_zero())
        {
            ++non_zero_At;
        }
        if (!qap.Bt[i].is_zero())
        {
            ++non_zero_Bt;
        }
    }
    libff::leave_block("Compute query densities");

    /* qap.{At,Bt,Ct,Ht} are now in unspecified state, but we do not use them later */
    libff::Fr_vector<ppT> At = std::move(qap.At);
    libff::Fr_vector<ppT> Bt = std::move(qap.Bt);
    libff::Fr_vector<ppT> Ct = std::move(qap.Ct);
    libff::Fr_vector<ppT> Ht = std::move(qap.Ht);

    /* The gamma inverse product component: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * gamma^{-1}. */
    libff::enter_block("Compute Pi_statement_t for R1CS verification key");
    libff::Fr_vector<ppT> Pi_statement_t;
    Pi_statement_t.reserve(qap.num_inputs() + 1);

    for (size_t i = 0; i < qap.num_inputs() + 1; ++i)
    {
        Pi_statement_t.emplace_back(beta * At[i] + alpha * Bt[i] + Ct[i]);
    }
    libff::leave_block("Compute Pi_statement_t for R1CS verification key");

    /* The product component for the witness: (beta*A_i(t) + alpha*B_i(t) + C_i(t)) * delta^{-1}. */
    libff::enter_block("Compute Pi_witness_t for R1CS proving key");
    libff::Fr_vector<ppT> Pi_witness_t;
    Pi_witness_t.reserve(qap.num_variables() - qap.num_inputs() - r1cs.private_input_size - 2*r1cs.state_size);
    const size_t Pi_witness_offset = qap.num_inputs() + 1 + r1cs.private_input_size + 2*r1cs.state_size;
    for (size_t i = 0; i < qap.num_variables() - qap.num_inputs() - r1cs.private_input_size - 2*r1cs.state_size; ++i)
    {
        Pi_witness_t.emplace_back((beta * At[Pi_witness_offset + i] + alpha * Bt[Pi_witness_offset + i] + Ct[Pi_witness_offset + i]) * delta_inverse);
    }
    libff::leave_block("Compute Pi_witness_t for R1CS proving key");

    /* The product component for the state: (beta*A_i(t) + alpha*B_i(t) + C_i(t) - eta*R_{s2s(i)}) * delta^{-1}. */
    libff::enter_block("Compute Pi_state_t for R1CS proving key");
    libff::Fr_vector<ppT> Pi_state_t;
    Pi_state_t.reserve(r1cs.state_size);

    const size_t Pi_state_offset = qap.num_inputs() + 1 + r1cs.private_input_size;
    for (size_t i = 0; i < r1cs.state_size; ++i)
    {
        Pi_state_t.emplace_back((beta *  At[Pi_state_offset + i]
                                + alpha * Bt[Pi_state_offset + i]
                                + Ct[Pi_state_offset + i]
                                - eta*Ri[i])  * delta_inverse);
    }
    libff::leave_block("Compute Pi_state_t for R1CS proving key");


    /* The product component for the state update: (beta*A_i(t) + alpha*B_i(t) + C_i(t) - kappa R_i) * delta^{-1}. */
    libff::enter_block("Compute Pi_stateupdate_t for R1CS proving key");
    libff::Fr_vector<ppT> Pi_stateupdate_t;
    Pi_stateupdate_t.reserve(r1cs.state_size);

    const size_t Pi_stateupdate_offset = qap.num_inputs() + 1 + r1cs.private_input_size + r1cs.state_size;
    for (size_t i = 0; i < r1cs.state_size; ++i)
    {
        Pi_stateupdate_t.emplace_back((beta * At[Pi_stateupdate_offset + i]
            + alpha * Bt[Pi_stateupdate_offset + i]
            + Ct[Pi_stateupdate_offset + i]
            - kappa * Ri[i]) * delta_inverse);
    }
    libff::leave_block("Compute Pi_stateupdate_t for R1CS proving key");


    /* The product component for the private input: (beta*A_i(t) + alpha*B_i(t) + C_i(t) - epsilon*T_i) * delta^{-1}. */
    libff::enter_block("Compute Pi_priv_input_t for R1CS proving key");
    libff::Fr_vector<ppT> Pi_priv_input_t;
    Pi_priv_input_t.reserve(r1cs.private_input_size);

    const size_t Pi_priv_input_offset = qap.num_inputs() + 1;
    for (size_t i = 0; i < r1cs.private_input_size; ++i)
    {
        Pi_priv_input_t.emplace_back((beta * At[Pi_priv_input_offset + i]
            + alpha * Bt[Pi_priv_input_offset + i]
            + Ct[Pi_priv_input_offset + i]
            - epsilon*Ti[i]) * delta_inverse);
    }
    libff::leave_block("Compute Pi_priv_input_t for R1CS proving key");

    /**
     * Note that H for Groth's proof system is degree d-2, but the QAP
     * reduction returns coefficients for degree d polynomial H (in
     * style of PGHR-type proof systems)
     */
    Ht.resize(Ht.size() - 2);

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Generating G1 MSM window table");
    const libff::G1<ppT> g1_generator = libff::G1<ppT>::random_element();
    const size_t g1_scalar_count = non_zero_At + non_zero_Bt + qap.num_variables();
    const size_t g1_scalar_size = libff::Fr<ppT>::ceil_size_in_bits();
    const size_t g1_window_size = libff::get_exp_window_size<libff::G1<ppT> >(g1_scalar_count);

    if(!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("* G1 window: %zu\n", g1_window_size);
    }
    libff::window_table<libff::G1<ppT> > g1_table = libff::get_window_table(g1_scalar_size, g1_window_size, g1_generator);
    libff::leave_block("Generating G1 MSM window table");

    libff::enter_block("Generating G2 MSM window table");
    const libff::G2<ppT> G2_gen = libff::G2<ppT>::random_element();
    const size_t g2_scalar_count = non_zero_Bt;
    const size_t g2_scalar_size = libff::Fr<ppT>::ceil_size_in_bits();
    size_t g2_window_size = libff::get_exp_window_size<libff::G2<ppT> >(g2_scalar_count);

    if(!libff::inhibit_profiling_info) {
        libff::print_indent();
        printf("* G2 window: %zu\n", g2_window_size);
    }
    libff::window_table<libff::G2<ppT> > g2_table = libff::get_window_table(g2_scalar_size, g2_window_size, G2_gen);
    libff::leave_block("Generating G2 MSM window table");

    libff::enter_block("Generate R1CS proving key");
    libff::G1<ppT> alpha_g1 = alpha * g1_generator;
    libff::G1<ppT> beta_g1 = beta * g1_generator;
    libff::G1<ppT> delta_g1 = delta * g1_generator;
    libff::G1<ppT> epsilon_g1 = epsilon * g1_generator;
    libff::G1<ppT> eta_g1 = eta * g1_generator;
    libff::G1<ppT> kappa_g1 = kappa * g1_generator;

    libff::G2<ppT> beta_g2 = beta * G2_gen;
    libff::G2<ppT> delta_g2 = delta * G2_gen;

    libff::enter_block("Generate queries");
    libff::enter_block("Compute the A-query", false);
    libff::G1_vector<ppT> A_query = batch_exp(g1_scalar_size, g1_window_size, g1_table, At);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(A_query);
#endif
    libff::leave_block("Compute the A-query", false);

    libff::enter_block("Compute the B-query", false);
    knowledge_commitment_vector<libff::G2<ppT>, libff::G1<ppT> > B_query = kc_batch_exp(libff::Fr<ppT>::ceil_size_in_bits(), g2_window_size, g1_window_size, g2_table, g1_table, libff::Fr<ppT>::one(), libff::Fr<ppT>::one(), Bt, chunks);
    // NOTE: if USE_MIXED_ADDITION is defined,
    // kc_batch_exp will convert its output to special form internally
    libff::leave_block("Compute the B-query", false);

    libff::enter_block("Compute the H-query", false);
    libff::G1_vector<ppT> H_delta_query = batch_exp_with_coeff(g1_scalar_size, g1_window_size, g1_table, qap.Zt * delta_inverse, Ht);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(H_delta_query);
#endif
    libff::leave_block("Compute the H-query", false);

    libff::enter_block("Compute Pi_witness", false);
    libff::G1_vector<ppT> Pi_witness = batch_exp(g1_scalar_size, g1_window_size, g1_table, Pi_witness_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Pi_witness);
#endif
    libff::leave_block("Compute Pi_witness", false);
    libff::enter_block("Compute Pi_state", false);
    libff::G1_vector<ppT> Pi_state = batch_exp(g1_scalar_size, g1_window_size, g1_table, Pi_state_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Pi_state);
#endif
    libff::leave_block("Compute Pi_state", false);
    libff::enter_block("Compute Pi_stateupdate", false);
    libff::G1_vector<ppT> Pi_stateupdate = batch_exp(g1_scalar_size, g1_window_size, g1_table, Pi_stateupdate_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Pi_stateupdate);
#endif
    libff::leave_block("Compute Pi_stateupdate", false);
    libff::enter_block("Compute Pi_priv_input", false);
    libff::G1_vector<ppT> Pi_priv_input = batch_exp(g1_scalar_size, g1_window_size, g1_table, Pi_priv_input_t);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Pi_priv_input);
#endif
    libff::leave_block("Compute Pi_priv_input", false);
    libff::enter_block("Compute Ti_g1", false);
    libff::G1_vector<ppT> Ti_g1 = batch_exp(g1_scalar_size, g1_window_size, g1_table, Ti);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Ti_g1);
#endif
    libff::leave_block("Compute Ti_g1", false);
    libff::enter_block("Compute Ri_g1", false);
    libff::G1_vector<ppT> Ri_g1 = batch_exp(g1_scalar_size, g1_window_size, g1_table, Ri);
#ifdef USE_MIXED_ADDITION
    libff::batch_to_special<libff::G1<ppT> >(Ri_g1);
#endif
    libff::leave_block("Compute Ri_g1", false);

    libff::leave_block("Generate queries");

    libff::leave_block("Generate R1CS proving key");

    libff::enter_block("Generate R1CS verification key");
    libff::GT<ppT> alpha_g1_beta_g2 = ppT::reduced_pairing(alpha_g1, beta_g2);
    libff::G2<ppT> one_m_g2 = -G2_gen;
    libff::G1<ppT> one_g1 = g1_generator;
    libff::leave_block("Generate R1CS verification key");

    libff::enter_block("Generate initial commitment");
    libff::G1<ppT> evaluation_commitment = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            Ri_g1.begin(),
            Ri_g1.end(),
            initial_state.begin(),
            initial_state.end(),
            chunks);

    libff::leave_block("Generate initial commitment");


    libff::leave_block("Call to r1cs_gg_ppzkadscsnark_dv_generator");

    std::vector<r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT>> aks;
    for(size_t i = 0; i < private_input_blocks.size(); ++i){
        size_t num_inputs = private_input_blocks[i];
        libff::G1_vector<ppT> T_part(Ti_g1.begin(), Ti_g1.begin() + num_inputs);
        Ti_g1.erase(Ti_g1.begin(), Ti_g1.begin() + num_inputs);
        r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT> ak = r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT>(
            mac_keys[i], T_part, delta_g1);
        ak.print_size();
        aks.push_back(ak);
    }

    r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> vk = r1cs_gg_ppzkadscsnark_dv_verification_key<ppT>(
                                                                                std::move(one_g1),
                                                                                std::move(one_m_g2),
                                                                                delta,
                                                                                epsilon,
                                                                                eta,
                                                                                kappa,
                                                                                std::move(Pi_statement_t),
                                                                                std::move(alpha_g1_beta_g2),
                                                                                std::move(mac_keys));

    r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> pk = r1cs_gg_ppzkadscsnark_dv_proving_key<ppT>(std::move(alpha_g1),
                                                                               std::move(beta_g1),
                                                                               std::move(delta_g1),
                                                                               std::move(epsilon_g1),
                                                                               std::move(eta_g1),
                                                                               std::move(kappa_g1),
                                                                               std::move(A_query),
                                                                               std::move(B_query),
                                                                               std::move(Pi_witness),
                                                                               std::move(Pi_state),
                                                                               std::move(Pi_stateupdate),
                                                                               std::move(Pi_priv_input),
                                                                               std::move(H_delta_query),
                                                                               std::move(Ri_g1),
                                                                               std::move(beta_g2),
                                                                               std::move(delta_g2)
                                                                               );


    r1cs_gg_ppzkadscsnark_dv_commitment<ppT> initial_commitment(std::move(evaluation_commitment));


    pk.print_size();
    vk.print_size();

    return r1cs_gg_ppzkadscsnark_dv_keypair<ppT>(std::move(pk), std::move(vk), std::move(aks), std::move(initial_commitment));
}

template<typename ppT>
r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT> r1cs_gg_ppzkadscsnark_dv_authenticate(const r1cs_gg_ppzkadscsnark_dv_authentication_key<ppT> &ak, const r1cs_gg_ppzkadscsnark_dv_label<ppT> &label, const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &input)
{
    assert(input.size() == ak.T_g1.size());

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    // Pick randomisation value
    const libff::Fr<ppT> bD = libff::Fr<ppT>::random_element();

    r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT> ai;
    ai.values = input;

    ai.D_g1 = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
        ak.T_g1.begin(),
        ak.T_g1.end(),
        input.begin(),
        input.end(),
        chunks) + bD * ak.delta_g1;

    ai.bD = bD;

    ai.mac = r1cs_gg_ppzkadscsnark_dv_mac_compute<ppT>(ak.mac_key, ai.D_g1, label);
    return ai;
}


template <typename ppT>
std::pair<r1cs_gg_ppzkadscsnark_dv_proof<ppT>, r1cs_gg_ppzkadscsnark_dv_commitment<ppT>> r1cs_gg_ppzkadscsnark_dv_prover(
                              const r1cs_gg_ppzkadscsnark_dv_proving_key<ppT> &pk,
                              const r1cs_gg_ppzkadscsnark_dv_constraint_system<ppT> &constraint_system,
                              const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &primary_input,
                              const std::vector<r1cs_gg_ppzkadscsnark_dv_authenticated_input<ppT>> &authenticated_inputs,
                              const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &state_input,
                              const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &state_update_input,
                              const r1cs_gg_ppzkadscsnark_dv_assignment<ppT> &witness_input,
                              r1cs_gg_ppzkadscsnark_dv_prover_state<ppT> &prover_state)
{
    libff::enter_block("Call to r1cs_gg_ppzkadscsnark_dv_prover");

    r1cs_gg_ppzkadscsnark_dv_auxiliary_input<ppT> auxiliary_input;
    auxiliary_input.reserve(constraint_system.private_input_size + state_input.size() + state_update_input.size() + witness_input.size());
    for (auto &ai: authenticated_inputs)
    {
        auxiliary_input.insert(auxiliary_input.end(), ai.values.begin(), ai.values.end());
    }
    assert(auxiliary_input.size() == constraint_system.private_input_size);
    auxiliary_input.insert(auxiliary_input.end(), state_input.begin(), state_input.end());
    auxiliary_input.insert(auxiliary_input.end(), state_update_input.begin(), state_update_input.end());
    auxiliary_input.insert(auxiliary_input.end(), witness_input.begin(), witness_input.end());

#ifdef DEBUG
    assert(constraint_system.is_satisfied(primary_input, auxiliary_input));
#endif

    libff::enter_block("Compute the polynomial H");
    const qap_witness<libff::Fr<ppT> > qap_wit = r1cs_to_plain_qap_witness_map(constraint_system, primary_input, auxiliary_input, libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero());

    /* We are dividing degree 2(d-1) polynomial by degree d polynomial
       and not adding a PGHR-style zk-patch, so our H is degree d-2 */
    assert(!qap_wit.coefficients_for_H[qap_wit.degree()-2].is_zero());
    assert(qap_wit.coefficients_for_H[qap_wit.degree()-1].is_zero());
    assert(qap_wit.coefficients_for_H[qap_wit.degree()].is_zero());
    libff::leave_block("Compute the polynomial H");

#ifdef DEBUG
    const libff::Fr<ppT> t = libff::Fr<ppT>::random_element();
    qap_instance_evaluation<libff::Fr<ppT> > qap_inst = r1cs_to_plain_qap_instance_map_with_evaluation(constraint_system, t);
    assert(qap_inst.is_satisfied(qap_wit));
#endif

    /* Zero-knowledge randomization masks */
    const libff::Fr<ppT> bA = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> bB = libff::Fr<ppT>::random_element();
    const libff::Fr<ppT> bE = libff::Fr<ppT>::random_element();

    // const libff::Fr<ppT> bA = libff::Fr<ppT>::zero();
    // const libff::Fr<ppT> bB = libff::Fr<ppT>::zero();
    // const libff::Fr<ppT> bE = libff::Fr<ppT>::zero();

#ifdef DEBUG
    assert(qap_wit.coefficients_for_ABCs.size() == qap_wit.num_variables());
    assert(pk.A_query.size() == qap_wit.num_variables()+1);
    assert(pk.B_query.domain_size() == qap_wit.num_variables()+1);
    assert(pk.H_query.size() == qap_wit.degree() - 1);
    assert(pk.Pi_witness.size() == qap_wit.num_variables() - qap_wit.num_inputs() - constraint_system.private_input_size - 2*constraint_system.state_size);
    assert(pk.Pi_state.size() == constraint_system.state_size);
    assert(pk.Pi_stateupdate.size() == constraint_system.state_size);
    assert(pk.Pi_priv_input.size() == constraint_system.private_input_size);
    assert(pk.Ri.size() == constraint_system.state_size);
#endif

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::enter_block("Compute the proof");

    libff::enter_block("Compute evaluation to A-query", false);
    libff::Fr_vector<ppT> const_padded_assignment(1, libff::Fr<ppT>::one());
    const_padded_assignment.insert(const_padded_assignment.end(), qap_wit.coefficients_for_ABCs.begin(), qap_wit.coefficients_for_ABCs.end());

    libff::G1<ppT> evaluation_At = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
                                                                        libff::Fr<ppT>,
                                                                        libff::multi_exp_method_BDLO12>(
        pk.A_query.begin(),
        pk.A_query.begin() + qap_wit.num_variables() + 1,
        const_padded_assignment.begin(),
        const_padded_assignment.begin() + qap_wit.num_variables() + 1,
        chunks);
    libff::leave_block("Compute evaluation to A-query", false);

    libff::enter_block("Compute evaluation to B-query", false);
    knowledge_commitment<libff::G2<ppT>, libff::G1<ppT> > evaluation_Bt = kc_multi_exp_with_mixed_addition<libff::G2<ppT>,
            libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
                    pk.B_query,
                    0,
                    qap_wit.num_variables() + 1,
                    const_padded_assignment.begin(),
                    const_padded_assignment.begin() + qap_wit.num_variables() + 1,
                    chunks);
    libff::leave_block("Compute evaluation to B-query", false);

    libff::enter_block("Compute evaluation to H-query", false);
    libff::G1<ppT> evaluation_H_t = libff::multi_exp<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.H_query.begin(),
            pk.H_query.begin() + (qap_wit.degree() - 1),
            qap_wit.coefficients_for_H.begin(),
            qap_wit.coefficients_for_H.begin() + (qap_wit.degree() - 1),
            chunks);
    libff::leave_block("Compute evaluation to H-query", false);

    libff::enter_block("Compute evaluation to L-query", false);
    libff::G1<ppT> evaluation_Pi_witness_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
        pk.Pi_witness.begin(),
        pk.Pi_witness.end(),
        const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + 2*constraint_system.state_size,
        const_padded_assignment.end(),
        chunks);
    libff::G1<ppT> evaluation_Pi_state_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
        pk.Pi_state.begin(),
        pk.Pi_state.end(),
        const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size,
        const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + constraint_system.state_size,
        chunks);
    libff::G1<ppT> evaluation_Pi_stateupdate_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.Pi_stateupdate.begin(),
            pk.Pi_stateupdate.end(),
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + constraint_system.state_size,
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + 2*constraint_system.state_size,
            chunks);
    libff::G1<ppT> evaluation_Pi_priv_input_t = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            pk.Pi_priv_input.begin(),
            pk.Pi_priv_input.end(),
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1,
            const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size,
            chunks);
    libff::leave_block("Compute evaluation to L-query", false);


    libff::enter_block("Compute evaluation to Pi_commitment", false);
    libff::G1<ppT> evaluation_commitment = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
        libff::Fr<ppT>,
        libff::multi_exp_method_BDLO12>(
        pk.Ri.begin(),
        pk.Ri.end(),
        const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + constraint_system.state_size,
        const_padded_assignment.begin() + qap_wit.num_inputs() + 1 + constraint_system.private_input_size + 2*constraint_system.state_size,
        chunks);
    libff::leave_block("Compute evaluation to Pi_commitment", false);

    /* A = alpha + sum_i(a_i*A_i(t)) + b_A*delta */
    libff::G1<ppT> A_g1 = pk.alpha_g1 + evaluation_At + bA*pk.delta_g1;

    /* B = beta + sum_i(a_i*B_i(t)) + b_B*delta*/
    libff::G2<ppT> B_g2 = pk.beta_g2 + evaluation_Bt.g + bB*pk.delta_g2;
    libff::G1<ppT> B_g1 = pk.beta_g1 + evaluation_Bt.h + bB*pk.delta_g1;

    /* C = sum_i(a_i*(Pi_witness + Pi_state + Pi_stateupdate + Pi_priv_input) ) + H(t)*Z(t))/delta */
    libff::G1<ppT> C_g1 = evaluation_Pi_witness_t
            + evaluation_Pi_state_t
            + evaluation_Pi_stateupdate_t
            + evaluation_Pi_priv_input_t
            + evaluation_H_t
            + bB*A_g1 + bA*B_g1
            - (bA*bB)*pk.delta_g1
            - prover_state.bE*pk.eta_g1
            - bE*pk.kappa_g1;

    for (auto &ai: authenticated_inputs)
    {
        C_g1 = C_g1 - ai.bD*pk.epsilon_g1;
    }

    libff::G1<ppT> E_g1 = evaluation_commitment + bE*pk.delta_g1;
    libff::leave_block("Compute the proof");

    /* Update prover state with current randomization mask */
    prover_state.bE = bE;

    /* Collect authenticated commitments */
    std::vector<r1cs_gg_ppzkadscsnark_dv_mac<ppT>> macs;
    libff::G1_vector<ppT> D_g1_vec;
    for (auto &ai: authenticated_inputs)
    {
        macs.push_back(ai.mac);
        D_g1_vec.push_back(ai.D_g1);
    }


    libff::leave_block("Call to r1cs_gg_ppzkadscsnark_dv_prover");

    r1cs_gg_ppzkadscsnark_dv_proof<ppT> proof = r1cs_gg_ppzkadscsnark_dv_proof<ppT>(std::move(A_g1),
                                                                      std::move(C_g1),
                                                                      std::move(D_g1_vec),
                                                                      std::move(B_g2),
                                                                      std::move(macs));
    proof.print_size();

    r1cs_gg_ppzkadscsnark_dv_commitment<ppT> commitment = r1cs_gg_ppzkadscsnark_dv_commitment<ppT>(std::move(E_g1));
    commitment.print_size();

    return std::pair<r1cs_gg_ppzkadscsnark_dv_proof<ppT>, r1cs_gg_ppzkadscsnark_dv_commitment<ppT>>(proof, commitment);
}

template <typename ppT>
r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> r1cs_gg_ppzkadscsnark_dv_verifier_process_vk(const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk)
{
    libff::enter_block("Call to r1cs_gg_ppzkadscsnark_dv_verifier_process_vk");

    r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> pvk;

    pvk.one_g1 = vk.one_g1;
    pvk.one_m_g2_precomp = ppT::precompute_G2(vk.one_m_g2);

    pvk.delta = vk.delta;
    pvk.epsilon = vk.epsilon;
    pvk.eta = vk.eta;
    pvk.kappa = vk.kappa;

    pvk.Pi_statement = vk.Pi_statement;
    pvk.alpha_g1_beta_g2 = vk.alpha_g1_beta_g2;
    pvk.mac_keys = vk.mac_keys;

    libff::leave_block("Call to r1cs_gg_ppzkadscsnark_dv_verifier_process_vk");
    return pvk;
}

template <typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_online_verifier_weak_IC(const r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk,
                                               const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &input,
                                               const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof,
                                               const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment,
                                               const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment_previous,
                                               const r1cs_gg_ppzkadscsnark_dv_label<ppT> &iteration)
{
    libff::enter_block("Call to r1cs_gg_ppzkadscsnark_dv_online_verifier_weak_IC");
    assert(pvk.Pi_statement.size() >= input.size() + 1);

    libff::enter_block("Accumulate input");
    libff::Fr<ppT> accumulated_input = pvk.Pi_statement[0]; // factor is one, first input is always the "constant"
    for (size_t i = 1; i < pvk.Pi_statement.size() && i - 1 < input.size(); ++i)
    {
    	accumulated_input += pvk.Pi_statement[i]*input[i-1];
    }
    const libff::G1<ppT> acc = accumulated_input * pvk.one_g1;
    libff::leave_block("Accumulate input");

    bool result = true;

    libff::enter_block("Check if the proof is well-formed");
    // we do not check commitment_previous, as it has already been checked in the previous iteration
    // we assume, that the proving party stores the proof_previous, so it can be trusted once verified
    if (!proof.is_well_formed() || !commitment.is_well_formed())
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("At least one of the proof elements does not lie on the curve.\n");
        }
        result = false;
    }
    libff::leave_block("Check if the proof is well-formed");

    libff::enter_block("Check authenticated commitments");
    libff::G1<ppT> D_acc = libff::G1<ppT>::zero();
    if (pvk.mac_keys.size() != proof.D_g1_vec.size() || pvk.mac_keys.size() != proof.macs.size())
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("Number of authenticated inputs incorrect.\n");
        }
        result = false;
    }
    for (size_t i = 0; i < pvk.mac_keys.size(); ++i)
    {
        libff::G1<ppT> D_g1 = proof.D_g1_vec[i];

        if (r1cs_gg_ppzkadscsnark_dv_mac_verify<ppT>(pvk.mac_keys[i], proof.macs[i], D_g1, iteration))
        {
            D_acc = D_acc + D_g1;
        }
        else
        {
            if (!libff::inhibit_profiling_info)
            {
                libff::print_indent(); printf("Input mac %ud incorrect.\n", (unsigned int) i);
            }
            result = false;
        }
    }
    libff::leave_block("Check authenticated commitments");

    libff::enter_block("Online pairing computations");
    libff::enter_block("Check QAP divisibility");
    const libff::G1<ppT> icdee = acc + pvk.delta*proof.C_g1 + pvk.epsilon*D_acc + pvk.eta*commitment_previous.E_g1 + pvk.kappa*commitment.E_g1;
    const libff::G1_precomp<ppT> proof_g_A_precomp = ppT::precompute_G1(proof.A_g1);
    const libff::G2_precomp<ppT> proof_g_B_precomp = ppT::precompute_G2(proof.B_g2);
    const libff::G1_precomp<ppT> icdee_precomp = ppT::precompute_G1(icdee);

    const libff::Fqk<ppT> QAP1 = ppT::double_miller_loop(proof_g_A_precomp,  proof_g_B_precomp,
                                                         icdee_precomp,  pvk.one_m_g2_precomp);
    const libff::GT<ppT> QAP = ppT::final_exponentiation(QAP1);

    if (QAP != pvk.alpha_g1_beta_g2)
    {
        if (!libff::inhibit_profiling_info)
        {
            libff::print_indent(); printf("QAP divisibility check failed.\n");
        }
        result = false;
    }
    libff::leave_block("Check QAP divisibility");
    libff::leave_block("Online pairing computations");

    libff::leave_block("Call to r1cs_gg_ppzkadscsnark_dv_online_verifier_weak_IC");

    return result;
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_verifier_weak_IC(const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk,
                                        const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &primary_input,
                                        const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof,
                                        const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment,
                                        const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment_previous,
                                        const r1cs_gg_ppzkadscsnark_dv_label<ppT> &iteration)
{
    libff::enter_block("Call to r1cs_gg_ppzkadscsnark_dv_verifier_weak_IC");
    r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> pvk = r1cs_gg_ppzkadscsnark_dv_verifier_process_vk<ppT>(vk);
    bool result = r1cs_gg_ppzkadscsnark_dv_online_verifier_weak_IC<ppT>(pvk, primary_input, proof, commitment, commitment_previous, iteration);
    libff::leave_block("Call to r1cs_gg_ppzkadscsnark_dv_verifier_weak_IC");
    return result;
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_online_verifier_strong_IC(const r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> &pvk,
                                                 const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &primary_input,
                                                 const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof,
                                                 const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment,
                                                 const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment_previous,
                                                 const r1cs_gg_ppzkadscsnark_dv_label<ppT> &iteration)
{
    bool result = true;
    libff::enter_block("Call to r1cs_gg_ppzkadscsnark_dv_online_verifier_strong_IC");

    if (pvk.Pi_statement.size() != primary_input.size() + 1)
    {
        libff::print_indent(); printf("Input length differs from expected (got %zu, expected %zu).\n", primary_input.size(), pvk.Pi_statement.size()-1);
        result = false;
    }
    else
    {
        result = r1cs_gg_ppzkadscsnark_dv_online_verifier_weak_IC(pvk, primary_input, proof,
                                                    commitment, commitment_previous, iteration);
    }

    libff::leave_block("Call to r1cs_gg_ppzkadscsnark_dv_online_verifier_strong_IC");
    return result;
}

template<typename ppT>
bool r1cs_gg_ppzkadscsnark_dv_verifier_strong_IC(const r1cs_gg_ppzkadscsnark_dv_verification_key<ppT> &vk,
                                        const r1cs_gg_ppzkadscsnark_dv_primary_input<ppT> &primary_input,
                                        const r1cs_gg_ppzkadscsnark_dv_proof<ppT> &proof,
                                        const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment,
                                        const r1cs_gg_ppzkadscsnark_dv_commitment<ppT> &commitment_previous,
                                        const r1cs_gg_ppzkadscsnark_dv_label<ppT> &iteration)
{
    libff::enter_block("Call to r1cs_gg_ppzkadscsnark_dv_verifier_strong_IC");
    r1cs_gg_ppzkadscsnark_dv_processed_verification_key<ppT> pvk = r1cs_gg_ppzkadscsnark_dv_verifier_process_vk<ppT>(vk);
    bool result = r1cs_gg_ppzkadscsnark_dv_online_verifier_strong_IC<ppT>(pvk, primary_input, proof,
                                                                            commitment, commitment_previous, iteration);
    libff::leave_block("Call to r1cs_gg_ppzkadscsnark_dv_verifier_strong_IC");
    return result;
}


} // libsnark
#endif // R1CS_GG_PPZKADSCSNARK_DV_TCC_
