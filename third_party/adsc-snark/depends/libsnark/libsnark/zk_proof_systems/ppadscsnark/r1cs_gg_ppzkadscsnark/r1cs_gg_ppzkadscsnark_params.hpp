/** @file
 *****************************************************************************

 Declaration of public-parameter selector for the R1CS GG-ppZKADSCSNARK.

 *****************************************************************************/

#ifndef R1CS_GG_PPZKADSCSNARK_PARAMS_HPP_
#define R1CS_GG_PPZKADSCSNARK_PARAMS_HPP_

#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/common/crypto/signature/eddsa.hpp>
#include <libsnark/common/crypto/signature/eddsa_snarkfriendly.hpp>
#include <libsnark/common/curve/curve_properties.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp>

namespace libsnark {

/**
 * Below are various template aliases (used for convenience).
 */

template<typename ppT>
using r1cs_gg_ppzkadscsnark_constraint_system = r1cs_adsc_constraint_system<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_primary_input = r1cs_primary_input<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_auxiliary_input = r1cs_auxiliary_input<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_assignment = r1cs_variable_assignment<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_label = libff::Fr<ppT>;


#ifdef SIGNATURE_SNARKFRIENDLY
 // Use Snark-friendly EdDSA implementation (on matching inner [jubjub] curve and with poseidon hash) for signature scheme
 template<typename ppT>
 using r1cs_gg_ppzkadscsnark_signature_keypair = eddsa_sf_keypair<EC_Inner<ppT>>;

 template<typename ppT>
 using r1cs_gg_ppzkadscsnark_signature_pubkey = eddsa_sf_pubkey<EC_Inner<ppT>>;

 template<typename ppT>
 using r1cs_gg_ppzkadscsnark_signature_privkey = eddsa_sf_privkey<EC_Inner<ppT>>;

 template<typename ppT>
 using r1cs_gg_ppzkadscsnark_signature_signature = eddsa_sf_signature<EC_Inner<ppT>>;
#else
// Use OpenSSL EdDSA implementation for signature scheme
template<typename ppT>
using r1cs_gg_ppzkadscsnark_signature_keypair = signature_eddsa_keypair;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_signature_pubkey = signature_eddsa_pubkey;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_signature_privkey = signature_eddsa_privkey;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_signature_signature = signature_eddsa_signature;
#endif


} // libsnark

#endif // R1CS_GG_PPZKADSCSNARK_PARAMS_HPP_
