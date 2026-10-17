/** @file
 *****************************************************************************

 This file defines default_r1cs_gg_ppzksnark_pp based on the elliptic curve
 choice selected in ec_pp.hpp.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef LEGO_GRO16_PP_HPP_
#define LEGO_GRO16_PP_HPP_

#include <libff/common/default_types/ec_pp.hpp>

namespace libsnark {
typedef libff::default_ec_pp default_lego_gro16_pp;
} // libsnark

#endif // LEGO_GRO16_PP_HPP_
