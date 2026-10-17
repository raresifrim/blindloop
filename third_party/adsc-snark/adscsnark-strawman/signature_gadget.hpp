/** @file
 *****************************************************************************

 Declaration of interfaces for signature gadget

 Signature gadget verifies a signature. Two versions are provided:
 1. signature_gadget_pedersen: Uses pedersen hash for hashing message
 2. signature_gadget_poseidon: Uses poseidon hash for hashing message

 Signature scheme is EDDSA on a SNARK-friendly curve (jubjub or similar), curve
 depends on selected SNARK curve
 *****************************************************************************/

#ifndef SIGNATURE_GADGET_H
#define SIGNATURE_GADGET_H

#include <cstdint>
#include <memory>

#include <libsnark/gadgetlib1/gadget.hpp>
#include <libsnark/libsnark/gadgetlib1/pb_variable.hpp>
#include <ethsnarks/src/jubjub/eddsa.hpp>
#include <libsnark/common/crypto/signature/eddsa_snarkfriendly.hpp>

typedef struct variable_type_ {
    int size;
    bool is_signed;
} variable_type_t;

template<typename FieldT>
class signature_gadget_pedersen : public libsnark::gadget<FieldT>{
private:
    const ethsnarks::jubjub::Params params;  // This member must live within this object, as eddsa gadget has reference to it
    std::vector<libsnark::pb_variable<FieldT>> variables;
    std::vector<variable_type_t> types;
    std::shared_ptr<ethsnarks::jubjub::PureEdDSA> eddsa_gadget;
    std::vector<libsnark::packing_gadget<FieldT>> pack_gadgets;
    libsnark::pb_variable_array<FieldT> bits;
    ethsnarks::jubjub::VariablePointT sig_R;
    libsnark::pb_variable_array<FieldT> sig_S;
    ethsnarks::jubjub::VariablePointT A;
    libsnark::eddsa_sf_pubkey<ethsnarks::default_inner_ec_pp> pubkey;
    ethsnarks::jubjub::EdwardsPoint B;


public:
    signature_gadget_pedersen(libsnark::protoboard<FieldT> &pb,
                 const libsnark::eddsa_sf_pubkey<ethsnarks::default_inner_ec_pp> &pubkey,
                 const std::string &annotation_prefix=""):
            libsnark::gadget<FieldT>(pb, annotation_prefix),
                        params(), sig_R(pb, "sig_R"), A(pb, "A"), pubkey(pubkey), B(params.Gx, params.Gy)

    {
        this->pubkey.pkey.to_affine_coordinates();
        sig_S = ethsnarks::make_var_array(pb, FieldT::ceil_size_in_bits(), FMT(annotation_prefix, ".sig_S"));

    };

    void generate_r1cs_constraints ();

    void generate_r1cs_witness(libsnark::eddsa_sf_signature<ethsnarks::default_inner_ec_pp> sig);

    /**
     * allocate variables in protoboard
     * Allocate has to be called before generate_r1cs_constraints
     * Usually, these things are completed in the constructor of the gadget,
     * however, moving allocate outside allows adding additional states
     */
    void allocate();

    void add_variable(const libsnark::pb_variable<FieldT> &v, unsigned int size, bool is_signed);
};

template<typename FieldT>
class signature_gadget_poseidon : public libsnark::gadget<FieldT>{
private:
    const ethsnarks::jubjub::Params params;  // This member must live within this object, as eddsa gadget has reference to it
    //std::shared_ptr<PureEdDSAPoseidon> eddsa_gadget;
    std::shared_ptr<ethsnarks::jubjub::PureEdDSAPoseidonFixed> eddsa_gadget;
    libsnark::pb_variable_array<FieldT> values;
    ethsnarks::jubjub::VariablePointT sig_R;
    libsnark::pb_variable_array<FieldT> sig_S;
    //VariablePointT A;
    ethsnarks::jubjub::EdwardsPoint A;
    libsnark::eddsa_sf_pubkey<ethsnarks::default_inner_ec_pp> pubkey;
    ethsnarks::jubjub::EdwardsPoint B;


public:
    signature_gadget_poseidon(libsnark::protoboard<FieldT> &pb,
                     const libsnark::eddsa_sf_pubkey<ethsnarks::default_inner_ec_pp> &pubkey,
                     const std::string &annotation_prefix=""):
            libsnark::gadget<FieldT>(pb, annotation_prefix),
            params(), sig_R(pb, "sig_R"), pubkey(pubkey), B(params.Gx, params.Gy)

    {
        this->pubkey.pkey.to_affine_coordinates();
        A.x = ethsnarks::default_inner_ec_pp::inner2outer(this->pubkey.pkey.X);
        A.y = ethsnarks::default_inner_ec_pp::inner2outer(this->pubkey.pkey.Y);
        sig_S = ethsnarks::make_var_array(pb, FieldT::ceil_size_in_bits(), FMT(annotation_prefix, ".sig_S"));

    };

    void generate_r1cs_constraints ();

    void generate_r1cs_witness (libsnark::eddsa_sf_signature<ethsnarks::default_inner_ec_pp> sig);

    /**
     * allocate variables in protoboard
     * Allocate has to be called before generate_r1cs_constraints
     * Usually, these things are completed in the constructor of the gadget,
     * however, moving allocate outside allows adding additional states
     */
    void allocate();

    void add_variable(const libsnark::pb_variable<FieldT> &v);

    /**
     *
     * Just for compatibility to pedersen hash, size and is_signed are ignored
     *
     * @param v: variable
     * @param size: ignored
     * @param is_signed: ignored
     */
    void add_variable(const libsnark::pb_variable<FieldT> &v, unsigned int size, bool is_signed);

};

template<typename FieldT>
using signature_gadget = signature_gadget_poseidon<FieldT>;

//template<typename FieldT>
//using signature_gadget = signature_gadget_pedersen<FieldT>;

#include "signature_gadget.tcc"

#endif //SIGNATURE_GADGET_H
