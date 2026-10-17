#ifndef INNER_EC_PP_HPP_
#define INNER_EC_PP_HPP_

/**** Pick the inner elliptic curve corresponding to the outer curve ****/

#include <libff/common/default_types/ec_aliases.hpp>

#ifdef CURVE_ALT_BN128
#define ETHSNARKS_CURVE_SUPPORTED
#include <libff/algebra/curves/baby_jubjub/baby_jubjub_pp.hpp>
namespace ethsnarks {
    typedef libff::baby_jubjub_pp default_inner_ec_pp;
}
#endif


#ifdef CURVE_EDWARDS58
#define ETHSNARKS_CURVE_SUPPORTED
#include <libff/algebra/curves/jubjub_ed58/jubjub_ed58_pp.hpp>
namespace ethsnarks {
    typedef libff::jubjub_ed58_pp default_inner_ec_pp;
}
#endif


#ifdef CURVE_EDWARDS61
#define ETHSNARKS_CURVE_SUPPORTED
#include <libff/algebra/curves/jubjub_ed61/jubjub_ed61_pp.hpp>
namespace ethsnarks {
    typedef libff::jubjub_ed61_pp default_inner_ec_pp;
}
#endif


#ifdef CURVE_EDWARDS97
#define ETHSNARKS_CURVE_SUPPORTED
#include <libff/algebra/curves/jubjub_ed97/jubjub_ed97_pp.hpp>
namespace ethsnarks {
    typedef libff::jubjub_ed97_pp default_inner_ec_pp;
}
#endif


#ifdef CURVE_EDWARDS181
#define ETHSNARKS_CURVE_SUPPORTED
#include <libff/algebra/curves/jubjub_ed181/jubjub_ed181_pp.hpp>
namespace ethsnarks {
    typedef libff::jubjub_ed181_pp default_inner_ec_pp;
}
#endif


#ifdef CURVE_BN124
#define ETHSNARKS_CURVE_SUPPORTED
#include <libff/algebra/curves/jubjub_bn124/jubjub_bn124_pp.hpp>
namespace ethsnarks {
    typedef libff::jubjub_bn124_pp default_inner_ec_pp;
}
#endif

#ifdef CURVE_BN183
#define ETHSNARKS_CURVE_SUPPORTED
#include <libff/algebra/curves/jubjub_bn183/jubjub_bn183_pp.hpp>
namespace ethsnarks {
    typedef libff::jubjub_bn183_pp default_inner_ec_pp;
}
#endif

#ifdef CURVE_BN254
#define ETHSNARKS_CURVE_SUPPORTED
#include <libff/algebra/curves/jubjub_bn254/jubjub_bn254_pp.hpp>
namespace ethsnarks {
    typedef libff::jubjub_bn254_pp default_inner_ec_pp;
}
#endif

#ifndef ETHSNARKS_CURVE_SUPPORTED
#error: Missing CURVE_* symbol definition or curve not supported by ethsnarks
#endif

#endif // INNER_EC_PP_HPP_