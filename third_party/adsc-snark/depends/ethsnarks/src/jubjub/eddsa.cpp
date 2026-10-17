// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "jubjub/eddsa.hpp"
#include "utils.hpp"

namespace ethsnarks {

namespace jubjub {

EdDSA_HashRAM_gadget::EdDSA_HashRAM_gadget(
    ProtoboardT& in_pb,
    const Params& in_params,
    const VariablePointT& in_R,
    const VariablePointT& in_A,
    const VariableArrayT& in_M,
    const std::string& annotation_prefix
) :
    GadgetT(in_pb, annotation_prefix),

    // Convert X & Y coords to bits for hash function
    m_R_x_bits(in_pb, in_R.x, FMT(this->annotation_prefix, ".R_x_bits")),
    m_A_x_bits(in_pb, in_A.x, FMT(this->annotation_prefix, ".A_x_bits")),

    // Prefix the message with R and A.
    m_RAM_bits(flatten({
        m_R_x_bits.result(),
        m_A_x_bits.result(),
        in_M,
    })),

    m_hash_RAM(in_pb, in_params, "EdDSA_Verify.RAM", m_RAM_bits, FMT(this->annotation_prefix, ".hash_RAM"))
{
}


void EdDSA_HashRAM_gadget::generate_r1cs_constraints()
{
    m_R_x_bits.generate_r1cs_constraints();
    m_A_x_bits.generate_r1cs_constraints();
    m_hash_RAM.generate_r1cs_constraints();
}


void EdDSA_HashRAM_gadget::generate_r1cs_witness()
{
    m_R_x_bits.generate_r1cs_witness();
    m_A_x_bits.generate_r1cs_witness();
    m_hash_RAM.generate_r1cs_witness();

//    std::cout << "Hash in gadget " << std::endl;
//    for (size_t i = 0; i < m_hash_RAM.m_hash.padded_bits.size(); i++){
//        std::cout << (this->pb.val(m_hash_RAM.m_hash.padded_bits[i]) == FieldT::one() ? "1" : "0");
//        if (i % 16 == 0){
//            std::cout << std::endl;
//        }
//    }
//    std::cout << std::endl;

}


const VariableArrayT& EdDSA_HashRAM_gadget::result()
{
    return m_hash_RAM.result();
}

EdDSA_HashRAM_Poseidon_gadget::EdDSA_HashRAM_Poseidon_gadget(
        ProtoboardT& in_pb,
        const VariablePointT& in_R,
        const LinearCombinationT &in_A_x,
        const VariableArrayT& in_M,
        const std::string& annotation_prefix
) :
        GadgetT(in_pb, annotation_prefix),


        // Prefix the message with R and A.
        m_RAM(flatten_lc(
                                   in_R.x,
                                   in_A_x,
                                   in_M
                           )),

        m_hash_RAM(in_pb, m_RAM, FMT(this->annotation_prefix, ".hash_RAM"))
{
}


void EdDSA_HashRAM_Poseidon_gadget::generate_r1cs_constraints()
{
    m_hash_RAM.generate_r1cs_constraints();
}


void EdDSA_HashRAM_Poseidon_gadget::generate_r1cs_witness()
{
    m_hash_RAM.generate_r1cs_witness();

//    std::cout << "Hash in gadget " << std::endl;
//    for (size_t i = 0; i < m_hash_RAM.m_hash.padded_bits.size(); i++){
//        std::cout << (this->pb.val(m_hash_RAM.m_hash.padded_bits[i]) == FieldT::one() ? "1" : "0");
//        if (i % 16 == 0){
//            std::cout << std::endl;
//        }
//    }
//    std::cout << std::endl;

}


const VariableArrayT& EdDSA_HashRAM_Poseidon_gadget::result()
{
    return m_hash_RAM.result();
}


// --------------------------------------------------------------------



PureEdDSA::PureEdDSA(
    ProtoboardT& in_pb,
    const Params& in_params,
    const EdwardsPoint& in_base,    // B
    const VariablePointT& in_A,     // A
    const VariablePointT& in_R,     // R
    const VariableArrayT& in_s,     // s
    const VariableArrayT& in_msg,   // m
    const std::string& annotation_prefix
) :
    GadgetT(in_pb, annotation_prefix),

    // IsValid(R)
    m_validator_R(in_pb, in_params, in_R.x, in_R.y, FMT(this->annotation_prefix, ".validator_R")),

    // lhs = ScalarMult(B, s)
    m_lhs(in_pb, in_params, in_base.x, in_base.y, in_s, FMT(this->annotation_prefix, ".lhs")),

    // hash_RAM = H(R, A, M)
    m_hash_RAM(in_pb, in_params, in_R, in_A, in_msg, FMT(this->annotation_prefix, ".hash_RAM")),

    // At = ScalarMult(A,hash_RAM)
    m_At(in_pb, in_params, in_A.x, in_A.y, m_hash_RAM.result(), FMT(this->annotation_prefix, ".At = A * hash_RAM")),

    // rhs = PointAdd(R, At)
    m_rhs(in_pb, in_params, in_R.x, in_R.y, m_At.result_x(), m_At.result_y(), FMT(this->annotation_prefix, ".rhs"))
{ }


void PureEdDSA::generate_r1cs_constraints()
{
    m_validator_R.generate_r1cs_constraints();
    m_lhs.generate_r1cs_constraints();
    m_hash_RAM.generate_r1cs_constraints();
    m_At.generate_r1cs_constraints();
    m_rhs.generate_r1cs_constraints();

    // Verify the two points are equal
    this->pb.add_r1cs_constraint(
        ConstraintT(m_lhs.result_x(), FieldT::one(), m_rhs.result_x()),
        FMT(this->annotation_prefix, " lhs.x == rhs.x"));

    this->pb.add_r1cs_constraint(
        ConstraintT(m_lhs.result_y(), FieldT::one(), m_rhs.result_y()),
        FMT(this->annotation_prefix, " lhs.y == rhs.y"));
}


void PureEdDSA::generate_r1cs_witness()
{
    m_validator_R.generate_r1cs_witness();
    m_lhs.generate_r1cs_witness();
    m_hash_RAM.generate_r1cs_witness();
    m_At.generate_r1cs_witness();
    m_rhs.generate_r1cs_witness();
}

PureEdDSAPoseidon::PureEdDSAPoseidon(
        ProtoboardT& in_pb,
        const Params& in_params,
        const EdwardsPoint& in_base,    // B
        const VariablePointT& in_A,     // A
        const VariablePointT& in_R,     // R
        const VariableArrayT& in_s,     // s
        const VariableArrayT& in_msg,   // m
        const std::string& annotation_prefix
) :
        GadgetT(in_pb, annotation_prefix),

        // IsValid(R)
        m_validator_R(in_pb, in_params, in_R.x, in_R.y, FMT(this->annotation_prefix, ".validator_R")),

        // lhs = ScalarMult(B, s)
        m_lhs(in_pb, in_params, in_base.x, in_base.y, in_s, FMT(this->annotation_prefix, ".lhs")),

        // hash_RAM = H(R, A, M)
        m_hash_RAM(in_pb, in_R, in_A.x, in_msg, FMT(this->annotation_prefix, ".hash_RAM")),

        // At = ScalarMult(A,hash_RAM)
        m_At(in_pb, in_params, in_A.x, in_A.y, m_hash_RAM.result(), FMT(this->annotation_prefix, ".At = A * hash_RAM")),

        // rhs = PointAdd(R, At)
        m_rhs(in_pb, in_params, in_R.x, in_R.y, m_At.result_x(), m_At.result_y(), FMT(this->annotation_prefix, ".rhs"))
{ }


void PureEdDSAPoseidon::generate_r1cs_constraints()
{
    m_validator_R.generate_r1cs_constraints();
    m_lhs.generate_r1cs_constraints();
    m_hash_RAM.generate_r1cs_constraints();
    m_At.generate_r1cs_constraints();
    m_rhs.generate_r1cs_constraints();

    // Verify the two points are equal
    this->pb.add_r1cs_constraint(
            ConstraintT(m_lhs.result_x(), FieldT::one(), m_rhs.result_x()),
            FMT(this->annotation_prefix, " lhs.x == rhs.x"));

    this->pb.add_r1cs_constraint(
            ConstraintT(m_lhs.result_y(), FieldT::one(), m_rhs.result_y()),
            FMT(this->annotation_prefix, " lhs.y == rhs.y"));
}


void PureEdDSAPoseidon::generate_r1cs_witness()
{
    m_validator_R.generate_r1cs_witness();
    m_lhs.generate_r1cs_witness();
    m_hash_RAM.generate_r1cs_witness();
    m_At.generate_r1cs_witness();
    m_rhs.generate_r1cs_witness();
}

VariableArrayT make_binary_scalar_array(ProtoboardT &pb, FieldT v){
    VariableArrayT scalar;
    scalar.allocate(pb, 58, "scalar");
    scalar.fill_with_bits_of_field_element(pb, v);
    return scalar;
}

PureEdDSAPoseidonFixed::PureEdDSAPoseidonFixed(
        ProtoboardT& in_pb,
        const Params& in_params,
        const EdwardsPoint& in_base,    // B
        const EdwardsPoint& in_A,     // A
        const VariablePointT& in_R,     // R
        const VariableArrayT& in_s,     // s
        const VariableArrayT& in_msg,   // m
        const std::string& annotation_prefix
) :
        GadgetT(in_pb, annotation_prefix),

        // IsValid(R)
        m_validator_R(in_pb, in_params, in_R.x, in_R.y, FMT(this->annotation_prefix, ".validator_R")),

        // lhs = ScalarMult(B, s)
        m_lhs(in_pb, in_params, in_base.x, in_base.y, in_s, FMT(this->annotation_prefix, ".lhs")),

        // hash_RAM = H(R, A, M)
        m_hash_RAM(in_pb, in_R, LinearCombinationT(in_pb, libsnark::ONE*in_A.x), in_msg, FMT(this->annotation_prefix, ".hash_RAM")),

        // At = ScalarMult(A,hash_RAM)
        m_At(in_pb, in_params, in_A.x, in_A.y, m_hash_RAM.result(), FMT(this->annotation_prefix, ".At = A * hash_RAM")),

        // rhs = PointAdd(R, At)
        m_rhs(in_pb, in_params, in_R.x, in_R.y, m_At.result_x(), m_At.result_y(), FMT(this->annotation_prefix, ".rhs"))
{
}


void PureEdDSAPoseidonFixed::generate_r1cs_constraints()
{
    m_validator_R.generate_r1cs_constraints();
    m_lhs.generate_r1cs_constraints();
    m_hash_RAM.generate_r1cs_constraints();
    m_At.generate_r1cs_constraints();
    m_rhs.generate_r1cs_constraints();

    // Verify the two points are equal
    this->pb.add_r1cs_constraint(
            ConstraintT(m_lhs.result_x(), FieldT::one(), m_rhs.result_x()),
            FMT(this->annotation_prefix, " lhs.x == rhs.x"));

    this->pb.add_r1cs_constraint(
            ConstraintT(m_lhs.result_y(), FieldT::one(), m_rhs.result_y()),
            FMT(this->annotation_prefix, " lhs.y == rhs.y"));
}


void PureEdDSAPoseidonFixed::generate_r1cs_witness()
{
    m_validator_R.generate_r1cs_witness();
    m_lhs.generate_r1cs_witness();
    m_hash_RAM.generate_r1cs_witness();
    m_At.generate_r1cs_witness();
    m_rhs.generate_r1cs_witness();
}

// --------------------------------------------------------------------

// I don't get the point of this. Why is the input message getting hashed twice? -> Here is some explanation:
// https://www.cryptologie.net/article/497/eddsa-ed25519-ed25519-ietf-ed25519ph-ed25519ctx-hasheddsa-pureeddsa-wtf/
// TLDR: Prehashing the message is can be useful for streaming access to message (not really needed here)
EdDSA::EdDSA(
    ProtoboardT& in_pb,
    const Params& in_params,
    const EdwardsPoint& in_base,    // B
    const VariablePointT& in_A,     // A
    const VariablePointT& in_R,     // R
    const VariableArrayT& in_s,     // s
    const VariableArrayT& in_msg,   // m
    const std::string& annotation_prefix
) :
    // M = H(m)
    m_msg_hashed(in_pb, in_params, "EdDSA_Verify.M", in_msg, FMT(annotation_prefix, ".msg_hashed")),

    m_verifier(in_pb, in_params, in_base, in_A, in_R, in_s, m_msg_hashed.result(), annotation_prefix)
{ }


void EdDSA::generate_r1cs_constraints()
{
    m_msg_hashed.generate_r1cs_constraints();
    m_verifier.generate_r1cs_constraints();
}


void EdDSA::generate_r1cs_witness()
{
    m_msg_hashed.generate_r1cs_witness();
    m_verifier.generate_r1cs_witness();
}


// namespace jubjub
}

// namespace ethsnarks
}
