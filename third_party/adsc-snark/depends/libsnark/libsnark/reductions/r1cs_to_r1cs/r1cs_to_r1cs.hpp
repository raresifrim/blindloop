/** @file
 *****************************************************************************

 Declaration of interfaces for a R1CS-to-R1CS reduction, this is for
 adding additional constraints to enforce non-degeneracy conditions.

 The non-degeneracy conditions are required for some SNARKs, see \[Parno2015]

 When using these reductions, make sure to use r1cs_to_plain_qap for further
 reduction to QAP, as the original r1cs_to_qap adds constraints for the
 input values

 References:

 \[Parno2015]
 "A Note on the Unsoundness of vnTinyRAM’s SNARK",
 Brian Parno,
 <https://eprint.iacr.org/2015/437.pdf>



 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_TO_R1CS_HPP_
#define R1CS_TO_R1CS_HPP_

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp>

namespace libsnark {

/**
 * Add constraints to make input terms linearly independent
 *
 * This will add cs.input_size constraints
 */
template<typename FieldT>
void r1cs_add_input_constraints(r1cs_constraint_system<FieldT> &cs);

/**
 * Add constraints to make a block of terms linearly independent to each other
 * and let the span of the block and the span of the remaining terms be {0}
 *
 * This will add block_size constraints
 */
template<typename FieldT>
void r1cs_add_block_constraints(r1cs_constraint_system<FieldT> &cs, size_t block_size,
                                                          size_t block_start);

/**
 * Given two blocks of equal size, we add constraints, such that
 * 1. The terms of the first block are linearly independent to each other
 * 2. The terms of the second block are linearly independent to each other
 * 3. The intersection of the span of the terms of the first block and the span
 * of the remaining terms is {0} and The intersection of the span of the terms
 * of the second block and the span of the remaining terms is {0}
 *
 * The blocks may not overlap!
 *
 * This will add block_size constraints
 */
template<typename FieldT>
void r1cs_add_2block_constraints(r1cs_constraint_system<FieldT> &cs, size_t block_size,
                                                           size_t block1_start, size_t block2_start);

/**
 * Converts a regular r1cs to an r1cs for authenticated data,
 * in particular, it adds additional constraints to fulfill the non-degeneracy condition
 *
 * This will add private_input_size constraints
 *
 */
template<typename FieldT>
r1cs_ad_constraint_system<FieldT> r1cs_to_r1cs_ad(r1cs_constraint_system<FieldT> &&cs, size_t private_input_size);

/**
 * Converts a regular r1cs to an r1cs for state consistency,
 * in particular, it adds additional constraints to fulfill the non-degeneracy conditions
 *
 * This will add state_size constraints
 *
 */
template<typename FieldT>
r1cs_sc_constraint_system<FieldT> r1cs_to_r1cs_sc(r1cs_constraint_system<FieldT> &&cs, size_t state_size);

/**
 * Converts a regular r1cs to an r1cs for state consistency and on authenticated data,
 * in particular, it adds additional constraints to fulfill the non-degeneracy conditions
 *
 * This will add max(private_input_size, state_size) constraints
 *
 */
template<typename FieldT>
r1cs_adsc_constraint_system<FieldT> r1cs_to_r1cs_adsc(r1cs_constraint_system<FieldT> &&cs, size_t private_input_size, size_t state_size);

/**
 * Converts a regular r1cs to an r1cs with commitment slots for a CP-SNARK,
 * in particular, it adds additional constraints to fulfill the non-degeneracy conditions
 *
 * This will add sum_i(commitment_slots[i]) constraints
 *
 */
template<typename FieldT>
r1cs_cc_constraint_system<FieldT> r1cs_to_r1cs_cc(r1cs_constraint_system<FieldT> &&cs, const std::vector<size_t> &commitment_slots);


} // libsnark

#include <libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.tcc>

#endif // R1CS_TO_R1CS_HPP_
