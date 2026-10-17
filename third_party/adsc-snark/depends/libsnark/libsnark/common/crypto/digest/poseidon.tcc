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


#ifndef LIBSNARK_POSEIDON_ORIG_TCC_
#define LIBSNARK_POSEIDON_ORIG_TCC_

#include "poseidon.hpp"

namespace libsnark {

/**
* One round of the Poseidon permutation:
*
*    - takes a state of `t` elements
*    - adds the round constant to each element in the state
*    - performs exponentiation on the first `n` elements of the state
*    - creates `o` outputs, mixed using a matrix vector transform
*
* This generic version can be used as either a 'full', 'partial' or 'last' round.
* It avoids computing as many constraints as is possible, given all the information.
*/
template<typename Parameters>
void poseidon_round(const Parameters &param, std::vector<typename Parameters::Fr> &state, size_t nSBox, size_t round_num) {
	typedef typename Parameters::Fr Fr;

    assert(state.size() == param.t);
	const size_t constant_offset = round_num * param.t;

	// 1. Add Round Constants
	for(size_t h = 0; h < param.t; ++h)
    {
    	state[h] += param.rc[constant_offset + h];
	}

	// 2. Sub Words
	for(size_t h = 0; h < nSBox; ++h)
	{
        state[h] = Parameters::SBox::compute(state[h]);
	}

	// 3. Mix Layer
	std::vector<Fr> s;
	s.reserve(param.t);
	for(size_t h = 0; h < param.t; ++h)
    {
		const size_t m_offset = h * param.t;
		Fr sh = 0;
    	for (size_t j = 0; j < param.t; ++j)
        {
			sh += state[j] * param.mds[m_offset + j];
        }
        s.push_back(sh);
    }

    for(size_t h = 0; h < param.t; ++h)
    {
    	state[h] = s[h];

		// Debugging statements
    	//std::cout << "o[" << round_num << "][" << h << "] = ";
    	//state[h].print();
    }

}

template<typename Parameters>
void poseidon_permutation(const Parameters &param, std::vector<typename Parameters::Fr> &state)
{
  	assert(state.size() == param.t);
 	size_t round = 0;

    // rf/2 full rounds
  	for(size_t i = 0; i < param.rf/2; ++i) {
  		poseidon_round(param, state, param.t, round++);
	}

	// rp partial rounds
	for(size_t i = 0; i < param.rp; ++i) {
		poseidon_round(param, state, 1, round++);
	}

	// rf/2 full rounds
	for(size_t i = 0; i < param.rf/2; ++i) {
		poseidon_round(param, state, param.t, round++);
	}
}

template<typename Parameters>
const std::vector<typename Parameters::Fr> poseidon_sponge(const Parameters &param, const std::vector<typename Parameters::Fr> &inputs) {
    typedef typename Parameters::Fr Fr;

    const size_t n_inputs = inputs.size();
    const size_t rate = param.t - param.c;
    const size_t n_permutations = (n_inputs + rate - 1) / rate; // = ceil(n_inputs/r)

    std::vector<Fr> state(param.t, Fr::zero());
    for (size_t i = 0; i < n_permutations; ++i) {
        for (size_t j = 0; j < rate; ++j) {
        	if (i*rate + j < n_inputs)
        	{
        		state[j + param.c] += inputs[i*rate + j];
        	}
        }

        poseidon_permutation(param, state);
    }

    std::vector<Fr> out(state.begin() + param.c, state.begin() + 2*param.c);
    return out;
}


// namespace libsnark
}

#endif //LIBSNARK_POSEIDON_ORIG_TCC_
