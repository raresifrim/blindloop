/**
* Helper functions for curve chains, where the base field
* of one curve (the inner curve) is the scalar field of another curve
* (the outer curve)
*/

#ifndef CURVE_PROPERTIES_HPP
#define CURVE_PROPERTIES_HPP

#include <libff/algebra/curves/alt_bn128/alt_bn128_pp.hpp>
#include <libff/algebra/curves/bn124/bn124_pp.hpp>
#include <libff/algebra/curves/bn183/bn183_pp.hpp>
#include <libff/algebra/curves/bn254/bn254_pp.hpp>
#include <libff/algebra/curves/edwards58/edwards58_pp.hpp>
#include <libff/algebra/curves/edwards61/edwards61_pp.hpp>
#include <libff/algebra/curves/edwards97/edwards97_pp.hpp>
#include <libff/algebra/curves/edwards181/edwards181_pp.hpp>

#include <libff/algebra/curves/baby_jubjub/baby_jubjub_pp.hpp>
#include <libff/algebra/curves/jubjub_bn124/jubjub_bn124_pp.hpp>
#include <libff/algebra/curves/jubjub_bn183/jubjub_bn183_pp.hpp>
#include <libff/algebra/curves/jubjub_bn254/jubjub_bn254_pp.hpp>
#include <libff/algebra/curves/jubjub_ed58/jubjub_ed58_pp.hpp>
#include <libff/algebra/curves/jubjub_ed61/jubjub_ed61_pp.hpp>
#include <libff/algebra/curves/jubjub_ed97/jubjub_ed97_pp.hpp>
#include <libff/algebra/curves/jubjub_ed181/jubjub_ed181_pp.hpp>

#include "libsnark/common/crypto/digest/poseidon_parameters.hpp"

namespace libsnark {

template <typename T>
struct EC_Properties_T;

template <>
struct EC_Properties_T<libff::alt_bn128_pp> {
    using inner_curve = libff::baby_jubjub_pp;
    using poseidon_params = PoseidonParametersALTBN128;
};

template <>
struct EC_Properties_T<libff::bn124_pp> {
    using inner_curve = libff::jubjub_bn124_pp;
    using poseidon_params = PoseidonParametersBN124;
};

template <>
struct EC_Properties_T<libff::bn183_pp> {
    using inner_curve = libff::jubjub_bn183_pp;
    using poseidon_params = PoseidonParametersBN183;
};

template <>
struct EC_Properties_T<libff::bn254_pp> {
    using inner_curve = libff::jubjub_bn254_pp;
    using poseidon_params = PoseidonParametersBN254;
};

template <>
struct EC_Properties_T<libff::edwards58_pp> {
    using inner_curve = libff::jubjub_ed58_pp;
    using poseidon_params = PoseidonParametersED58;
};

template <>
struct EC_Properties_T<libff::edwards61_pp> {
    using inner_curve = libff::jubjub_ed61_pp;
    using poseidon_params = PoseidonParametersED61;
};

template <>
struct EC_Properties_T<libff::edwards97_pp> {
    using inner_curve = libff::jubjub_ed97_pp;
    using poseidon_params = PoseidonParametersED97;
};

template <>
struct EC_Properties_T<libff::edwards181_pp> {
    using inner_curve = libff::jubjub_ed181_pp;
    using poseidon_params = PoseidonParametersED181;
};


template <typename T>
using EC_Inner = typename EC_Properties_T<T>::inner_curve;

template <typename T>
using PoseidonParameters = typename EC_Properties_T<T>::poseidon_params;

}
#endif //CURVE_PROPERTIES_HPP
