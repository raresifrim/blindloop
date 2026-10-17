/** @file
 *****************************************************************************
 *  Interface of pseudo-random-function
 *
 *  prp: A pseudo-random-function based on AES128, uses openssl
 *****************************************************************************/

#ifndef PRF_HPP
#define PRF_HPP

namespace libsnark {

template<typename FieldT>
FieldT prp(const FieldT key, const FieldT label);

}

#include <libsnark/common/crypto/prf/prf.tcc>

#endif //PRF_HPP
