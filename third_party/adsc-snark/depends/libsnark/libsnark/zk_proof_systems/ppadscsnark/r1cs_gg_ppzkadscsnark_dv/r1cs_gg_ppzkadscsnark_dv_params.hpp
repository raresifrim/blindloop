/** @file
 *****************************************************************************

 Declaration of public-parameter selector for the R1CS GG-ppZKADSCSNARK.

 *****************************************************************************/

#ifndef R1CS_GG_PPZKADSCSNARK_DV_PARAMS_HPP_
#define R1CS_GG_PPZKADSCSNARK_DV_PARAMS_HPP_

#include <libff/algebra/curves/public_params.hpp>
#include <libsnark/common/crypto/mac/hmac.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp>

namespace libsnark {

/**
 * Below are various template aliases (used for convenience).
 */

template<typename ppT>
using r1cs_gg_ppzkadscsnark_dv_constraint_system = r1cs_adsc_constraint_system<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_dv_primary_input = r1cs_primary_input<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_dv_auxiliary_input = r1cs_auxiliary_input<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_dv_assignment = r1cs_variable_assignment<libff::Fr<ppT> >;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_dv_label = libff::Fr<ppT>;

// Use OpenSSL EdDSA implementation for signature scheme
template<typename ppT>
using r1cs_gg_ppzkadscsnark_dv_mac_key = hmac_sha256_key;

template<typename ppT>
using r1cs_gg_ppzkadscsnark_dv_mac = hmac_sha256_mac;


} // libsnark

#endif // R1CS_GG_PPZKADSCSNARK_DV_PARAMS_HPP_
