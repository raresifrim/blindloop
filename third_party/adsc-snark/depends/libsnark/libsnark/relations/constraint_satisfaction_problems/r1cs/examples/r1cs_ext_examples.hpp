/** @file
 *****************************************************************************

 Declaration of interfaces for a R1CS example, as well as functions to sample
 R1CS examples with prescribed parameters (according to some distribution).

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_EXT_EXAMPLES_HPP_
#define R1CS_EXT_EXAMPLES_HPP_

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs_ext.hpp>

namespace libsnark {

/**
 * A R1CS example comprises a R1CS constraint system, R1CS input, and R1CS witness.
 */
template<typename FieldT>
struct r1cs_sc_example {
    r1cs_constraint_system<FieldT> constraint_system;
    std::vector<r1cs_primary_input<FieldT>> primary_input;
    std::vector<r1cs_variable_assignment<FieldT>> witness_assignment;
    std::vector<r1cs_variable_assignment<FieldT>> state_assignment;

    r1cs_sc_example() = default;
    r1cs_sc_example(const r1cs_sc_example &other) = default;
    r1cs_sc_example(const r1cs_constraint_system<FieldT> &constraint_system,
                         const std::vector<r1cs_primary_input<FieldT>> &primary_input,
                         const std::vector<r1cs_variable_assignment<FieldT>> &witness_assignment,
                           const std::vector<r1cs_variable_assignment<FieldT>> &state_assignment) :
        constraint_system(constraint_system),
        primary_input(primary_input),
        witness_assignment(witness_assignment),
        state_assignment(state_assignment)
    {};
    r1cs_sc_example(r1cs_constraint_system<FieldT> &&constraint_system,
                         std::vector<r1cs_primary_input<FieldT>> &&primary_input,
                         std::vector<r1cs_variable_assignment<FieldT>> &&witness_assignment,
                         std::vector<r1cs_variable_assignment<FieldT>> &&state_assignment) :
        constraint_system(std::move(constraint_system)),
        primary_input(std::move(primary_input)),
        witness_assignment(std::move(witness_assignment)),
        state_assignment(std::move(state_assignment))
    {};
};

template<typename FieldT>
struct r1cs_adsc_example {
    r1cs_constraint_system<FieldT> constraint_system;
    std::vector<r1cs_primary_input<FieldT>> primary_input;
    std::vector<r1cs_variable_assignment<FieldT>> private_input;
    std::vector<r1cs_variable_assignment<FieldT>> witness_assignment;
    std::vector<r1cs_variable_assignment<FieldT>> state_assignment;

    r1cs_adsc_example() = default;
    r1cs_adsc_example(const r1cs_adsc_example &other) = default;
    r1cs_adsc_example(const r1cs_constraint_system<FieldT> &constraint_system,
                            const std::vector<r1cs_primary_input<FieldT>> &primary_input,
                            const std::vector<r1cs_variable_assignment<FieldT>> &private_input,
                            const std::vector<r1cs_variable_assignment<FieldT>> &witness_assignment,
                            const std::vector<r1cs_variable_assignment<FieldT>> &state_assignment) :
            constraint_system(constraint_system),
            primary_input(primary_input),
            private_input(private_input),
            witness_assignment(witness_assignment),
            state_assignment(state_assignment)
    {};
    r1cs_adsc_example(r1cs_constraint_system<FieldT> &&constraint_system,
                            std::vector<r1cs_primary_input<FieldT>> &&primary_input,
                            std::vector<r1cs_variable_assignment<FieldT>> &&private_input,
                            std::vector<r1cs_variable_assignment<FieldT>> &&witness_assignment,
                            std::vector<r1cs_variable_assignment<FieldT>> &&state_assignment) :
            constraint_system(std::move(constraint_system)),
            primary_input(std::move(primary_input)),
            private_input(std::move(private_input)),
            witness_assignment(std::move(witness_assignment)),
            state_assignment(std::move(state_assignment))
    {};
};

/**
 * Generate a R1CS example such that:
 * - the number of constraints of the R1CS constraint system is num_constraints;
 * - the number of variables of the R1CS constraint system is (approximately) num_constraints;
 * - the number of inputs of the R1CS constraint system is num_inputs;
 * - the R1CS input consists of ``full'' field elements (typically require the whole log|Field| bits to represent).
 */
template<typename FieldT>
r1cs_sc_example<FieldT> generate_r1cs_sc_example_with_field_input(const size_t num_constraints,
                                                            const size_t num_inputs,
                                                            const size_t num_states,
                                                            const size_t num_iterations);

template<typename FieldT>
r1cs_adsc_example<FieldT> generate_r1cs_adsc_example_with_field_input(const size_t num_constraints,
                                                                  const size_t num_private_inputs,
                                                                  const size_t num_inputs,
                                                                  const size_t num_states,
                                                                  const size_t num_iterations);


} // libsnark

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_ext_examples.tcc>

#endif // R1CS_EXT_EXAMPLES_HPP_
