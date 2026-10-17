/** @file
 *****************************************************************************

 Implementation of functions to sample R1CS examples with prescribed parameters
 (according to some distribution).

 See r1cs_examples.hpp .

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/

#ifndef R1CS_EXT_EXAMPLES_TCC_
#define R1CS_EXT_EXAMPLES_TCC_

#include <cassert>

#include <libff/common/utils.hpp>

namespace libsnark {

template<typename FieldT>
r1cs_sc_example<FieldT> generate_r1cs_sc_example_with_field_input(const size_t num_constraints,
                                                            const size_t num_inputs,
                                                            const size_t num_states,
                                                            const size_t num_iterations)
{
    libff::enter_block("Call to generate_r1cs_sc_example_with_field_input");

    assert(num_constraints > num_states - 2 && num_constraints > 2);
    assert(num_iterations > 0);

    r1cs_constraint_system<FieldT> cs;
    cs.primary_input_size = num_inputs;
    cs.auxiliary_input_size = num_constraints + num_states;

    std::vector<r1cs_primary_input<FieldT>> primary_input_v;
    std::vector<r1cs_variable_assignment<FieldT>> witness_assignment_v;
    std::vector<r1cs_variable_assignment<FieldT>> state_assignment_v;

    r1cs_primary_input<FieldT> primary_input;
    r1cs_variable_assignment<FieldT> sn_w_assignment;
    r1cs_variable_assignment<FieldT> state_assignment;

    // Initial state
    for(size_t i = 0; i < num_states; i++){
        state_assignment.push_back(FieldT::random_element());
    }
    FieldT const_a = FieldT::random_element();
    FieldT const_b = FieldT::random_element();
    for(size_t t = 0; t < num_iterations; ++t) {
        linear_combination<FieldT> A0, B0, C01, C02;
        primary_input.clear();
        sn_w_assignment.clear();
        A0 = linear_combination<FieldT>();
        B0 = linear_combination<FieldT>();
        C01 = linear_combination<FieldT>();
        C02 = linear_combination<FieldT>();

        FieldT a = const_a;
        FieldT b = const_b;
        FieldT c1, c2;
        A0.add_term(0, a);
        B0.add_term(0, b);

        for (size_t i = 1; i <= num_inputs; ++i) {
            FieldT v = FieldT::random_element();
            primary_input.push_back(v);
            A0.add_term(i, FieldT(i));
            a += FieldT(i) * v;
        }

        for (size_t i = num_inputs + 1; i <= num_inputs + num_states; ++i) {
            FieldT v = state_assignment[i  - num_inputs - 1];
            B0.add_term(i, FieldT(i));
            b += FieldT(i) * v;
        }

        C01.add_term(num_inputs + 1 + num_states, 1);
        c1 = a * b;
        if (t == 0) {
            cs.add_constraint(r1cs_constraint<FieldT>(A0, B0, C01),
                              "sum(input_i*i) * sum(state_i*i) = c1"); //sum(input_i*i) * sum(state_i*i) = c1
        }
        C02.add_term(num_inputs + 1 + num_states + 1, 1);
        c2 = a + b;
        if (t == 0) {
            cs.add_constraint(r1cs_constraint<FieldT>(A0 + B0, 1, C02),
                              "sum(input_i*i) + sum(state_i*i) = c2"); //sum(input_i*i) + sum(state_i*i) = c2
        }
        sn_w_assignment.push_back(c1);
        sn_w_assignment.push_back(c2);
        a = c1;
        b = c2;
        for (size_t i = num_inputs + 1 + num_states; i < num_inputs + 1 + num_states + num_constraints - 2; ++i) {
            linear_combination<FieldT> A, B, C;
            if (i % 2) {
                // a * b = c
                A.add_term(i, 1);
                B.add_term(i + 1, 1);
                C.add_term(i + 2, 1);
                FieldT tmp = a * b;
                sn_w_assignment.push_back(tmp);
                a = b;
                b = tmp;
            } else {
                // a + b = c
                B.add_term(0, 1);
                A.add_term(i, 1);
                A.add_term(i + 1, 1);
                C.add_term(i + 2, 1);
                FieldT tmp = a + b;
                sn_w_assignment.push_back(tmp);
                a = b;
                b = tmp;
            }
            if (t == 0) {
                cs.add_constraint(r1cs_constraint<FieldT>(A, B, C), FMT("C", "%d", i));
            }
        }

        primary_input_v.push_back(primary_input);
        state_assignment_v.push_back(state_assignment);
        witness_assignment_v.push_back(r1cs_variable_assignment<FieldT>(sn_w_assignment.begin() + num_states, sn_w_assignment.end()));

        r1cs_auxiliary_input<FieldT> auxiliary_input(state_assignment);
        auxiliary_input.insert(auxiliary_input.end(), sn_w_assignment.begin(), sn_w_assignment.end());

        /* sanity checks */
        assert(cs.num_variables() == primary_input.size() + state_assignment.size() + sn_w_assignment.size());

        assert(cs.is_satisfied(primary_input, auxiliary_input));

        // get next state
        state_assignment = r1cs_variable_assignment<FieldT>(sn_w_assignment.begin(), sn_w_assignment.begin() + num_states);

    }

    state_assignment_v.push_back(state_assignment);

    /* sanity checks */
    assert(cs.num_variables() >= num_inputs);
    assert(cs.num_inputs() == num_inputs);
    assert(cs.num_constraints() == num_constraints);

    libff::leave_block("Call to generate_r1cs_sc_example_with_field_input");

    return r1cs_sc_example<FieldT>(std::move(cs), std::move(primary_input_v), std::move(witness_assignment_v), std::move(state_assignment_v));
}

template<typename FieldT>
r1cs_adsc_example<FieldT> generate_r1cs_adsc_example_with_field_input(const size_t num_constraints,
                                                                  const size_t num_inputs,
                                                                  const size_t num_private_inputs,
                                                                  const size_t num_states,
                                                                  const size_t num_iterations)
{
    libff::enter_block("Call to generate_r1cs_adsc_example_with_field_input");

    assert(num_constraints >= 2);
    assert(num_iterations > 0);

    r1cs_constraint_system<FieldT> cs;
    cs.primary_input_size = num_inputs;
    cs.auxiliary_input_size = std::max(num_constraints, num_states) + num_private_inputs + num_states;

    std::vector<r1cs_primary_input<FieldT>> primary_input_v;
    std::vector<r1cs_variable_assignment<FieldT>> private_input_v;
    std::vector<r1cs_variable_assignment<FieldT>> witness_assignment_v;
    std::vector<r1cs_variable_assignment<FieldT>> state_assignment_v;

    r1cs_primary_input<FieldT> primary_input;
    r1cs_variable_assignment<FieldT> private_input;
    r1cs_variable_assignment<FieldT> sn_w_assignment;
    r1cs_variable_assignment<FieldT> state_assignment;

    // Initial state
    for(size_t i = 0; i < num_states; i++){
        state_assignment.push_back(FieldT::random_element());
    }

    FieldT const_a = FieldT::random_element();
    FieldT const_b = FieldT::random_element();
    for(size_t t = 0; t < num_iterations; ++t) {
        linear_combination<FieldT> A0, B0, C01, C02;
        primary_input.clear();
        private_input.clear();
        sn_w_assignment.clear();
        A0 = linear_combination<FieldT>();
        B0 = linear_combination<FieldT>();
        C01 = linear_combination<FieldT>();
        C02 = linear_combination<FieldT>();

        FieldT a = const_a;
        FieldT b = const_b;
        FieldT c1, c2;
        A0.add_term(0, a);
        B0.add_term(0, b);
        size_t idx = 1;

        for (; idx <= num_inputs; ++idx) {
            FieldT v = FieldT::random_element();
            primary_input.push_back(v);
            A0.add_term(idx, FieldT(idx));
            a += FieldT(idx) * v;
        }

        for (; idx <= num_inputs + num_private_inputs; ++idx) {
            FieldT v = FieldT::random_element();
            private_input.push_back(v);
            A0.add_term(idx, FieldT(idx));
            a += FieldT(idx) * v;
        }

        for (; idx <= num_inputs + num_private_inputs + num_states; ++idx) {
            FieldT v = state_assignment[idx  - num_inputs - num_private_inputs - 1];
            B0.add_term(idx, FieldT(idx));
            b += FieldT(idx) * v;
        }

        // If we have less num_constraints than num_states, we need to fill up the remaining state variables. The constraint system will be underdetermined
        if(num_states > num_constraints) {
            for (; idx <= num_inputs + num_private_inputs + 2 * num_states - num_constraints; ++idx) {
                FieldT v = FieldT::random_element();
                sn_w_assignment.push_back(v);
                A0.add_term(idx, FieldT(idx));
                a += FieldT(idx) * v;
            }
        }

        C01.add_term(idx, 1);
        c1 = a * b;
        ++idx;
        C02.add_term(idx, 1);
        c2 = a + b;
        ++idx;
        sn_w_assignment.push_back(c1);
        sn_w_assignment.push_back(c2);

        if (t == 0) {
            cs.add_constraint(r1cs_constraint<FieldT>(A0, B0, C01),
                              "(sum(input_i*i) + sum(rstate_i*i)) * sum(state_i*i) = c1 + const"); //sum(input_i*i) * sum(state_i*i) = c1
            cs.add_constraint(r1cs_constraint<FieldT>(A0 + B0, 1, C02),
                              "sum(input_i*i) + sum(state_i*i) = c2 + const"); //sum(input_i*i) + sum(state_i*i) = c2
        }

        a = c1;
        b = c2;
        // Fill up remaining constraints
        for (size_t c = 0; c < num_constraints - 2; ++c) {
            size_t i = idx + c;
            linear_combination<FieldT> A, B, C;
            if (i % 2) {
                // a * b = c
                A.add_term(i-2, 1);
                B.add_term(i-1, 1);
                C.add_term(i, 1);
                FieldT tmp = a * b;
                sn_w_assignment.push_back(tmp);
                a = b;
                b = tmp;
            } else {
                // a + b = c
                B.add_term(0, 1);
                A.add_term(i-2, 1);
                A.add_term(i-1, 1);
                C.add_term(i, 1);
                FieldT tmp = a + b;
                sn_w_assignment.push_back(tmp);
                a = b;
                b = tmp;
            }
            if (t == 0) {
                cs.add_constraint(r1cs_constraint<FieldT>(A, B, C), FMT("C", "%d", i));
            }
        }


        primary_input_v.push_back(primary_input);
        private_input_v.push_back(private_input);
        state_assignment_v.push_back(state_assignment);
        witness_assignment_v.push_back(r1cs_variable_assignment<FieldT>(sn_w_assignment.begin() + num_states, sn_w_assignment.end()));

        r1cs_auxiliary_input<FieldT> auxiliary_input(private_input);
        auxiliary_input.insert(auxiliary_input.end(), state_assignment.begin(), state_assignment.end());
        auxiliary_input.insert(auxiliary_input.end(), sn_w_assignment.begin(), sn_w_assignment.end());

        /* sanity checks */
        assert(cs.num_variables() == primary_input.size() + private_input.size() + state_assignment.size() + sn_w_assignment.size());

        assert(cs.is_satisfied(primary_input, auxiliary_input));

        // get next state
        state_assignment = r1cs_variable_assignment<FieldT>(sn_w_assignment.begin(), sn_w_assignment.begin() + num_states);

    }

    state_assignment_v.push_back(state_assignment);

    /* sanity checks */
    assert(cs.num_variables() >= num_inputs);
    assert(cs.num_inputs() == num_inputs);
    assert(cs.num_constraints() == num_constraints);

    libff::leave_block("Call to generate_r1cs_adsc_example_with_field_input");

    return r1cs_adsc_example<FieldT>(std::move(cs), std::move(primary_input_v), std::move(private_input_v), std::move(witness_assignment_v), std::move(state_assignment_v));
}

} // libsnark

#endif // R1CS_EXT_EXAMPLES_TCC
