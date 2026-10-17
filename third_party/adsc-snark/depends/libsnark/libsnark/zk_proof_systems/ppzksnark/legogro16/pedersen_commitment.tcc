/** @file
*****************************************************************************

Implementation of interfaces for the Pedersen Commitment

*****************************************************************************/

#ifndef PEDERSEN_COMMITMENT_TCC_
#define PEDERSEN_COMMITMENT_TCC_

#include <algorithm>
#include <cassert>
#include <functional>
#include <iostream>
#include <sstream>

#include <libff/algebra/scalar_multiplication/multiexp.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#ifdef MULTICORE
#include <omp.h>
#endif

namespace libsnark {

template<typename ppT>
pedersen_commitment_key<ppT> pedersen_commitment_generator(size_t max_input_size)
{
    libff::enter_block("Call to pedersen_commitment_generator");
    pedersen_commitment_key<ppT> ck;

    for(size_t i = 0; i < max_input_size + 1; ++i){
        ck.push_back(libff::G1<ppT>::random_element());
    }

    libff::leave_block("Call to pedersen_commitment_generator");
    return ck;
}

template <typename ppT>
pedersen_commitment_pair<ppT> pedersen_commitment_commit(const pedersen_commitment_key<ppT> &ck,
                                                         const pedersen_commitment_assignment<ppT> &assignment)
{
    libff::enter_block("Call to pedersen_commitment_commit");
    assert(ck.size() > assignment.size());

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    pedersen_commitment_opening<ppT> opening = pedersen_commitment_opening<ppT>::random_element();
    libff::Fr_vector<ppT> extended_assignment;
    extended_assignment.push_back(opening);
    extended_assignment.insert(extended_assignment.end(), assignment.begin(), assignment.end());

    libff::G1<ppT> commitment = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            ck.begin(),
            ck.begin() + extended_assignment.size(),
            extended_assignment.begin(),
            extended_assignment.end(),
            chunks);


    pedersen_commitment_pair<ppT> result;
    result.commitment = commitment;
    result.opening = opening;
    libff::leave_block("Call to pedersen_commitment_commit");

    return result;
}

template<typename ppT>
bool pedersen_commitment_verify(const pedersen_commitment_key<ppT> &ck,
                                const pedersen_commitment_commitment<ppT> &commitment,
                                const pedersen_commitment_assignment<ppT> &assignment,
                                const pedersen_commitment_opening<ppT> &opening)
{
    libff::enter_block("Call to pedersen_commitment_verify");
    assert(ck.size() > assignment.size());

#ifdef MULTICORE
    const size_t chunks = omp_get_max_threads(); // to override, set OMP_NUM_THREADS env var or call omp_set_num_threads()
#else
    const size_t chunks = 1;
#endif

    libff::Fr_vector<ppT> extended_assignment;
    extended_assignment.push_back(opening);
    extended_assignment.insert(extended_assignment.end(), assignment.begin(), assignment.end());

    libff::G1<ppT> commitment2 = libff::multi_exp_with_mixed_addition<libff::G1<ppT>,
            libff::Fr<ppT>,
            libff::multi_exp_method_BDLO12>(
            ck.begin(),
            ck.begin() + extended_assignment.size(),
            extended_assignment.begin(),
            extended_assignment.end(),
            chunks);


    bool result = (commitment == commitment2);

    libff::leave_block("Call to pedersen_commitment_verify");
    return result;
}

} // libsnark
#endif // PEDERSEN_COMMITMENT_TCC_
