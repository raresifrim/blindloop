/** @file
 *****************************************************************************

 Implementation of interfaces for a R1CS-to-R1CS reduction.

 See r1cs_to_r1cs.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_TO_R1CS_TCC_
#define R1CS_TO_R1CS_TCC_

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libfqfft/evaluation_domain/get_evaluation_domain.hpp>

namespace libsnark {

template<typename FieldT>
void r1cs_add_input_constraints(r1cs_constraint_system<FieldT> &cs)
{
    for (size_t i = 0; i <= cs.num_inputs(); ++i)
    {
        cs.add_constraint(r1cs_constraint<FieldT>(linear_term<FieldT>(i, FieldT::one()), 0, 0), FMT("additional_input_constraint", "%d", i));
    }
}

template<typename FieldT>
void r1cs_add_block_constraints(r1cs_constraint_system<FieldT> &cs, size_t block_size,
                                size_t block_start)
{
    for (size_t i = block_start; i < block_start + block_size; ++i)
    {
        cs.add_constraint(r1cs_constraint<FieldT>(linear_term<FieldT>(i, FieldT::one()), 0, 0), FMT("additional_block_constraint", "%d", i));
    }
}

template<typename FieldT>
void r1cs_add_2block_constraints(r1cs_constraint_system<FieldT> &cs, size_t block_size,
                                 size_t block1_start, size_t block2_start)
{
    for (size_t i = 0; i < block_size; ++i)
    {
        linear_combination<FieldT> lc;
        lc.add_term(linear_term<FieldT>(block1_start + i, FieldT::one()));
        lc.add_term(linear_term<FieldT>(block2_start + i, FieldT::one()));
        cs.add_constraint(r1cs_constraint<FieldT>(lc, 0, 0), FMT("additional_block_constraint", "%d", i));
    }
}

template<typename FieldT>
void r1cs_add_nblock_constraints(r1cs_constraint_system<FieldT> &cs,
                                 std::vector<size_t> block_start,
                                 std::vector<size_t> block_size)
{
    assert(block_start.size() == block_size.size());
    size_t max_block_size = *std::max_element(block_size.begin(), block_size.end());
    for (size_t i = 0; i < max_block_size; ++i)
    {
        linear_combination<FieldT> lc;
        for(size_t j = 0; j < block_start.size(); ++j){
            if(i < block_size[j]){
                lc.add_term(linear_term<FieldT>(block_start[j] + i, FieldT::one()));
            }
        }
        cs.add_constraint(r1cs_constraint<FieldT>(lc, 0, 0), FMT("additional_block_constraint", "%d", i));
    }
}

template<typename FieldT>
r1cs_ad_constraint_system<FieldT> r1cs_to_r1cs_ad(r1cs_constraint_system<FieldT> &&cs, size_t private_input_size)
{
    assert(private_input_size < cs.auxiliary_input_size);
    r1cs_ad_constraint_system<FieldT> result(std::move(cs), private_input_size);
    r1cs_add_block_constraints(result, private_input_size, cs.primary_input_size+1); // + 1, because first ONE variable is not accounted for in primary_input_size
    result.swap_AB_if_beneficial();
    return result;
}

template<typename FieldT>
r1cs_sc_constraint_system<FieldT> r1cs_to_r1cs_sc(r1cs_constraint_system<FieldT> &&cs, size_t state_size)
{
    assert(2*state_size < cs.auxiliary_input_size);
    r1cs_sc_constraint_system<FieldT> result(std::move(cs), state_size);
    r1cs_add_2block_constraints(result, state_size, cs.primary_input_size+1, cs.primary_input_size+1+state_size); // + 1, because first ONE variable is not accounted for in primary_input_size
    result.swap_AB_if_beneficial();
    return result;
}

// TODO: Rename to strengthen constraint system
template<typename FieldT>
r1cs_adsc_constraint_system<FieldT> r1cs_to_r1cs_adsc(r1cs_constraint_system<FieldT> &&cs, size_t private_input_size, size_t state_size)
{
    assert(private_input_size + 2*state_size <= cs.auxiliary_input_size);
    r1cs_adsc_constraint_system<FieldT> result(std::move(cs), private_input_size, state_size);
    r1cs_add_nblock_constraints(result,
                                {cs.primary_input_size+1, cs.primary_input_size+1+private_input_size,cs.primary_input_size+1+private_input_size+state_size},
                                {private_input_size, state_size, state_size});
    result.swap_AB_if_beneficial();
    return result;
}

template<typename FieldT>
r1cs_cc_constraint_system<FieldT> r1cs_to_r1cs_cc(r1cs_constraint_system<FieldT> &&cs, const std::vector<size_t> &commitment_slots)
{
    size_t n = 0;
    for(size_t i = 0; i < commitment_slots.size(); ++i){
        n += commitment_slots[i];
    }
    assert(n <= cs.auxiliary_input_size);
    r1cs_cc_constraint_system<FieldT> result(std::move(cs), commitment_slots);
    r1cs_add_block_constraints(result,n, cs.primary_input_size+1);
    result.swap_AB_if_beneficial();
    return result;
}

} // libsnark

#endif // R1CS_TO_R1CS_TCC_
