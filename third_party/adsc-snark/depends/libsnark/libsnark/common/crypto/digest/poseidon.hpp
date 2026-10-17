/** @file
 *****************************************************************************

 Declaration of interfaces for snark-friendly Poseidon hash

 this implementation corresponds to the original poseidon paper
 https://eprint.iacr.org/2019/458

 constants are fixed and have been precomputed with the poseidon authors'
 tool: https://extgit.iaik.tugraz.at/krypto/hadeshash

 this includes the Poseidon permutation and a sponge construction for
 hashing variable-size messages

 for the gadget, see ethsnarks
 *****************************************************************************/


#ifndef LIBSNARK_POSEIDON_ORIG_HPP_
#define LIBSNARK_POSEIDON_ORIG_HPP_

#include "poseidon_parameters.hpp"

namespace libsnark {


template<typename Parameters>
void poseidon_permutation(const Parameters &param, std::vector<typename Parameters::Fr> &state);

template<typename Parameters>
const std::vector<typename Parameters::Fr> poseidon_sponge(const Parameters &param, const std::vector<typename Parameters::Fr> &inputs);



// namespace libsnark
}

#include "poseidon.tcc"

#endif //LIBSNARK_POSEIDON_ORIG_HPP_
