#ifndef ETHSNARKS_HPP_
#define ETHSNARKS_HPP_

#include <libff/common/default_types/ec_pp.hpp>
#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/gadgetlib1/gadget.hpp>
#include "r1cs_gg_ppzksnark_zok/r1cs_gg_ppzksnark_zok.hpp"

#include "inner_ec_pp.hpp"

namespace ethsnarks {

typedef libff::bigint<libff::default_ec_pp::Fp_type::num_limbs> LimbT;
typedef libff::default_ec_pp::G1_type G1T;
typedef libff::default_ec_pp::G2_type G2T;
typedef libff::default_ec_pp ppT;

typedef libff::Fq<ppT> FqT;
typedef libff::Fr<ppT> FieldT;
typedef libsnark::r1cs_constraint<FieldT> ConstraintT;
typedef libsnark::protoboard<FieldT> ProtoboardT;
typedef libsnark::pb_variable<ethsnarks::FieldT> VariableT;
typedef libsnark::pb_variable_array<FieldT> VariableArrayT;
typedef libsnark::pb_linear_combination<FieldT> LinearCombinationT;
typedef libsnark::pb_linear_combination_array<FieldT> LinearCombinationArrayT;
typedef libsnark::linear_term<FieldT> LinearTermT;
typedef libsnark::gadget<ethsnarks::FieldT> GadgetT;

typedef libsnark::r1cs_gg_ppzksnark_zok_proof<ppT> ProofT;
typedef libsnark::r1cs_gg_ppzksnark_zok_proving_key<ppT> ProvingKeyT;
typedef libsnark::r1cs_gg_ppzksnark_zok_verification_key<ppT> VerificationKeyT;
typedef libsnark::r1cs_gg_ppzksnark_zok_primary_input<ppT> PrimaryInputT;
typedef libsnark::r1cs_gg_ppzksnark_zok_auxiliary_input<ppT> AuxiliaryInputT;

}

#endif
