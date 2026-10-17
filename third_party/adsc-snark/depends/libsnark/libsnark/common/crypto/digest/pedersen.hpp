/**
* SNARK-friendly Pedersen hash on Edwards curve
* This only works with edwards curves with cofactor 8
* Usually the template parameter ppT is the inner (jubjub) curve
*/

#ifndef LIBSNARK_PEDERSEN_HPP
#define LIBSNARK_PEDERSEN_HPP

namespace libsnark {

template<typename ppT>
libff::G1<ppT> point_from_hash(char* bytes, size_t n);

template<typename ppT>
libff::G1<ppT> pedersen_hash_basepoint(const char* name, unsigned int i);

template<typename ppT>
libff::G1<ppT> pedersen_hash(std::vector<bool> bits);

}

#include "pedersen.tcc"

#endif //LIBSNARK_PEDERSEN_HPP
