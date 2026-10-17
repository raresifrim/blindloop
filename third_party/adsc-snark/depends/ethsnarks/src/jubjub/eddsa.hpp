#ifndef JUBJUB_EDDSA_HPP_
#define JUBJUB_EDDSA_HPP_

// Copyright (c) 2018 @HarryR
// License: LGPL-3.0+

#include "ethsnarks.hpp"

#include "gadgets/field2bits_strict.hpp"

#include "jubjub/params.hpp"
#include "jubjub/validator.hpp"
#include "jubjub/point.hpp"
#include "jubjub/pedersen_hash.hpp"
#include "gadgets/poseidon_orig.hpp"
#include "jubjub/scalarmult.hpp"
#include "jubjub/fixed_base_mul.hpp"
#include "jubjub/adder.hpp"

#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>


namespace ethsnarks {

namespace jubjub {


template<class T>
class Signature;


template<class T>
bool eddsa_open(
    const EdwardsPoint& A,
    const Signature<T>& sig,
    const libff::bit_vector& msg
);


template<class T>
class Signature {
public:
    EdwardsPoint R;
    FieldT s;

    bool open( const EdwardsPoint& A, const libff::bit_vector& msg ) const
    {
        return eddsa_open<T>(A, this, msg);
    }
};


/**
* Use a compatible gadget to verify an EdDSA signature
*/
template<class T>
bool eddsa_open(
    const Params& params,
    const EdwardsPoint& B,
    const EdwardsPoint& A,
    const Signature<T>& sig,
    const libff::bit_vector& msg
) {
    ProtoboardT pb;

    const auto msg_var_bits = make_var_array(pb, msg.size(), "msg_var_bits");
    msg_var_bits.fill_with_bits(pb, msg);

    const auto s_var_bits = make_var_array(pb, FieldT::ceil_size_in_bits(), "s_var_bits");
    s_var_bits.fill_with_bits_of_field_element(pb, sig.s);

    T the_gadget(pb, params,
        B,
        A.as_VariablePointT(pb, "A"),
        sig.R.as_VariablePointT(pb, "R"),
        s_var_bits,
        msg_var_bits,
        "the_gadget");

    the_gadget.generate_r1cs_constraints();
    the_gadget.generate_r1cs_witness();
    return pb.is_satisfied();
}


/**
* Auto-fill base point from Params
*/
template<class T>
bool eddsa_open(
    const Params& params,
    const EdwardsPoint& A,
    const Signature<T>& sig,
    const libff::bit_vector& msg
) {
    const EdwardsPoint B(params.Gx, params.Gy);
    return eddsa_open<T>(params, B, A, sig, msg);
}


template<class T>
bool eddsa_open(
    const EdwardsPoint& A,
    const Signature<T>& sig,
    const libff::bit_vector& msg
) {
    const Params params;
    return eddsa_open<T>(params, A, sig, msg);
}


class EdDSA_HashRAM_gadget : public GadgetT
{
public:
    field2bits_strict m_R_x_bits;           // R_x_bits = BITS(R.x)
    field2bits_strict m_A_x_bits;           // A_x_bits = BITS(A.x)
    const VariableArrayT m_RAM_bits;
    PedersenHashToBits m_hash_RAM;          // hash_RAM = H(R, A, M)

    EdDSA_HashRAM_gadget(
        ProtoboardT& in_pb,
        const Params& in_params,
        const VariablePointT& in_R,
        const VariablePointT& in_A,
        const VariableArrayT& in_M,
        const std::string& annotation_prefix
    );

    void generate_r1cs_constraints();

    void generate_r1cs_witness();

    const VariableArrayT& result();
};

class EdDSA_HashRAM_Poseidon_gadget : public GadgetT
{
public:
    LinearCombinationArrayT m_RAM;
    PoseidonHashToBits m_hash_RAM;          // hash_RAM = H(R, A, M)
    EdDSA_HashRAM_Poseidon_gadget(
            ProtoboardT& in_pb,
            const VariablePointT& in_R,
            const LinearCombinationT &in_A_x,
            const VariableArrayT& in_M,
            const std::string& annotation_prefix
    );

    void generate_r1cs_constraints();

    void generate_r1cs_witness();

    const VariableArrayT& result();
};


class PureEdDSA : public GadgetT
{
public:
    PointValidator m_validator_R;           // IsValid(R)
    fixed_base_mul m_lhs;                   // lhs = B*s
    EdDSA_HashRAM_gadget m_hash_RAM;        // hash_RAM = H(R,A,M)
    ScalarMult m_At;                        // A*hash_RAM
    PointAdder m_rhs;                       // rhs = R + (A*hash_RAM)

    PureEdDSA(
        ProtoboardT& in_pb,
        const Params& in_params,
        const EdwardsPoint& in_base,    // B
        const VariablePointT& in_A,      // A
        const VariablePointT& in_R,      // R
        const VariableArrayT& in_s,      // s
        const VariableArrayT& in_msg,    // m
        const std::string& annotation_prefix);

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};

class PureEdDSAPoseidon : public GadgetT
{
public:
    PointValidator m_validator_R;           // IsValid(R)
    fixed_base_mul m_lhs;                   // lhs = B*s
    EdDSA_HashRAM_Poseidon_gadget m_hash_RAM;        // hash_RAM = H(R,A,M)
    ScalarMult m_At;                        // A*hash_RAM
    PointAdder m_rhs;                       // rhs = R + (A*hash_RAM)

    PureEdDSAPoseidon(
            ProtoboardT& in_pb,
            const Params& in_params,
            const EdwardsPoint& in_base,    // B
            const VariablePointT& in_A,      // A
            const VariablePointT& in_R,      // R
            const VariableArrayT& in_s,      // s
            const VariableArrayT& in_msg,    // m
            const std::string& annotation_prefix);

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};

class PureEdDSAPoseidonFixed : public GadgetT
{
public:
    PointValidator m_validator_R;           // IsValid(R)
    fixed_base_mul_mg_3b m_lhs;                   // lhs = B*s
    EdDSA_HashRAM_Poseidon_gadget m_hash_RAM;        // hash_RAM = H(R,A,M)
    fixed_base_mul_mg_3b m_At;                        // A*hash_RAM
    PointAdder m_rhs;                       // rhs = R + (A*hash_RAM)

    PureEdDSAPoseidonFixed(
            ProtoboardT& in_pb,
            const Params& in_params,
            const EdwardsPoint& in_base,    // B
            const EdwardsPoint& in_A,      // A
            const VariablePointT& in_R,      // R
            const VariableArrayT& in_s,      // s
            const VariableArrayT& in_msg,    // m
            const std::string& annotation_prefix);

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};


class EdDSA
{
public:
    PedersenHashToBits m_msg_hashed;        // M = H(m)

    PureEdDSA m_verifier;

    EdDSA(
        ProtoboardT& in_pb,
        const Params& in_params,
        const EdwardsPoint& in_base,    // B
        const VariablePointT& in_A,      // A
        const VariablePointT& in_R,      // R
        const VariableArrayT& in_s,      // s
        const VariableArrayT& in_msg,    // m
        const std::string& annotation_prefix);

    void generate_r1cs_constraints();

    void generate_r1cs_witness();
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_EDDSA_HPP_
#endif
