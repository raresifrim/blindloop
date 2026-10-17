// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "jubjub/pedersen_hash.hpp"

namespace ethsnarks {

namespace jubjub {

// Warning: this padding scheme (and maybe other elements of the pedersen hash)
// make it unsecure, when not restricted to fixed message lengths
PedersenHash::PedersenHash(
    ProtoboardT& in_pb,
    const Params& in_params,
    const char *name,
    const VariableArrayT& in_bits,
    const std::string& annotation_prefix
) :
    GadgetT(in_pb, annotation_prefix)
{

    // Pad in_bits
    int num_pbs = (3 - in_bits.size() % 3) % 3;
    if (num_pbs > 0){
        libff::bit_vector padding(num_pbs, false);
        VariableArrayT padding_bits = VariableArray_from_bits(in_pb, padding, FMT(this->annotation_prefix, ".padding"));
        padded_bits = flatten({in_bits, padding_bits});
    }else{
        padded_bits = in_bits;
    }

    m_commitment.reset(new fixed_base_mul_zcash( in_pb, in_params,
        EdwardsPoint::make_basepoints(name, fixed_base_mul_zcash::basepoints_required(padded_bits.size()), in_params),
        padded_bits,
        FMT(annotation_prefix, ".commitment")));
}


const VariableT& PedersenHash::result_x() const
{
    return m_commitment->result_x();
}


const VariableT& PedersenHash::result_y() const
{
    return m_commitment->result_y();
}


void PedersenHash::generate_r1cs_constraints ()
{
    m_commitment->generate_r1cs_constraints();
}


void PedersenHash::generate_r1cs_witness ()
{
    m_commitment->generate_r1cs_witness();
}


// --------------------------------------------------------------------


PedersenHashToBits::PedersenHashToBits(
    ProtoboardT& in_pb,
    const Params& in_params,
    const char *name,
    const VariableArrayT& in_bits,
    const std::string& annotation_prefix
) :
    GadgetT(in_pb, annotation_prefix),
    m_hash(in_pb, in_params, name, in_bits, FMT(this->annotation_prefix, ".hash")),
    m_tobits(in_pb, m_hash.result_x(), FMT(this->annotation_prefix, ".tobits"))
{ }


/**
* Resulting bits
*/
const VariableArrayT& PedersenHashToBits::result() const
{
    return m_tobits.result();
}


void PedersenHashToBits::generate_r1cs_constraints ()
{
    m_hash.generate_r1cs_constraints();
    m_tobits.generate_r1cs_constraints();
}


void PedersenHashToBits::generate_r1cs_witness ()
{
    m_hash.generate_r1cs_witness();
    m_tobits.generate_r1cs_witness();
}


// namespace jubjub
}

// namespace ethsnarks
}