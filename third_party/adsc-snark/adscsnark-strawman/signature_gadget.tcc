/** @file
 *****************************************************************************

 Implementation of interfaces for signature gadget.

 See signature_gadget.hpp .

 *****************************************************************************/

#ifndef SIGNATURE_GADGET_TCC
#define SIGNATURE_GADGET_TCC

#include "signature_gadget.hpp"

template<typename FieldT>
void signature_gadget_pedersen<FieldT>::generate_r1cs_constraints ()
{
    // Fix public key into SNARK
    // generate_r1cs_constraints is called by generator -> this means pb.val(A.x) present at generator will
    // be encoded into the SNARK. If the prover falsely inserts a different A.x, the verifier will reject it
    generate_r1cs_equals_const_constraint(this->pb, libsnark::pb_linear_combination<FieldT>(A.x), FieldT(pubkey.pkey.X.as_bigint()), ".fixed_pubkey");

    for(size_t i=0; i < variables.size(); i++){
        pack_gadgets[i].generate_r1cs_constraints(true);
    }
    eddsa_gadget->generate_r1cs_constraints();
}

template<typename FieldT>
void signature_gadget_pedersen<FieldT>::generate_r1cs_witness (libsnark::eddsa_sf_signature<ethsnarks::default_inner_ec_pp> sig)
{
    // fixed pubkey
    this->pb.val(A.x) = pubkey.pkey.X.as_bigint();
    this->pb.val(A.y) = pubkey.pkey.Y.as_bigint();

    FieldT s1 = FieldT(sig.s.as_bigint());
    sig_S.fill_with_bits_of_field_element(this->pb, s1);
    sig.R.to_affine_coordinates();
    this->pb.val(sig_R.x) = sig.R.X.as_bigint();
    this->pb.val(sig_R.y) = sig.R.Y.as_bigint();

    for(size_t i=0; i < variables.size(); i++){
        pack_gadgets[i].generate_r1cs_witness_from_packed();
    }
    eddsa_gadget->generate_r1cs_witness();
}

template<typename FieldT>
void signature_gadget_pedersen<FieldT>::allocate ()
{
    for(size_t i=0; i < this->variables.size(); i++){
        int offset;

        libsnark::pb_variable_array<FieldT> v_bits;
        v_bits.allocate(this->pb, types[i].size, FMT(this->annotation_prefix, ".v_bits%d", i));
        bits.insert(bits.end(), v_bits.begin(), v_bits.end());

        libsnark::pb_linear_combination<FieldT> val;
        // shift value, if it is signed
        offset = types[i].is_signed ? 1 << (types[i].size - 1) : 0;
        val.assign(this->pb, variables[i] + offset*libsnark::ONE);
        libsnark::packing_gadget<FieldT> pack_v(this->pb, v_bits, val, FMT(this->annotation_prefix, ".pack_v%i", i));

        pack_gadgets.push_back(pack_v);
    }
    eddsa_gadget.reset(new ethsnarks::jubjub::PureEdDSA(this->pb, params, B, A, sig_R, sig_S, bits, FMT(this->annotation_prefix, ".eddsa")));
}

template<typename FieldT>
void signature_gadget_pedersen<FieldT>::add_variable(const libsnark::pb_variable<FieldT> &v, unsigned int size, bool is_signed)
{
    variable_type_t vt;
    variables.push_back(v);
    vt.size = size;
    vt.is_signed = is_signed;
    types.push_back(vt);
}


template<typename FieldT>
void signature_gadget_poseidon<FieldT>::generate_r1cs_constraints ()
{
    eddsa_gadget->generate_r1cs_constraints();
}

template<typename FieldT>
void signature_gadget_poseidon<FieldT>::generate_r1cs_witness (libsnark::eddsa_sf_signature<ethsnarks::default_inner_ec_pp> sig)
{
    FieldT s1 = FieldT(sig.s.as_bigint());
    sig_S.fill_with_bits_of_field_element(this->pb, s1);
    sig.R.to_affine_coordinates();
    this->pb.val(sig_R.x) = sig.R.X.as_bigint();
    this->pb.val(sig_R.y) = sig.R.Y.as_bigint();

    eddsa_gadget->generate_r1cs_witness();
}

template<typename FieldT>
void signature_gadget_poseidon<FieldT>::allocate ()
{
    // Use a fixed public key (public key is baked into relation)
    eddsa_gadget.reset(new ethsnarks::jubjub::PureEdDSAPoseidonFixed(this->pb, params, B, A, sig_R, sig_S, values, FMT(this->annotation_prefix, ".eddsa")));
}

template<typename FieldT>
void signature_gadget_poseidon<FieldT>::add_variable(const libsnark::pb_variable<FieldT> &v)
{
    values.push_back(v);
}

template<typename FieldT>
void signature_gadget_poseidon<FieldT>::add_variable(const libsnark::pb_variable<FieldT> &v,  unsigned int size, bool is_signed)
{
    this->add_variable(v);
}

#endif