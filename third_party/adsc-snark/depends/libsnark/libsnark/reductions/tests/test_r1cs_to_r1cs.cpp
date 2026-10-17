/** @file
 *****************************************************************************
 Test program that tests R1CS to R1CS reductions on a synthetic R1CS instance.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>

#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/reductions/r1cs_to_plain_qap/r1cs_to_plain_qap.hpp>
#include <libsnark/reductions/r1cs_to_qap/r1cs_to_qap.hpp>
#include <libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.hpp>

using namespace libsnark;


template<typename ppT>
void print_r1cs(r1cs_constraint_system<libff::Fr<ppT>> constraint_system, r1cs_primary_input<libff::Fr<ppT>> primary_input,
                r1cs_auxiliary_input<libff::Fr<ppT>> auxiliary_input){
#ifdef DEBUG
    r1cs_variable_assignment<libff::Fr<ppT>> full_variable_assignment = primary_input;
    full_variable_assignment.insert(full_variable_assignment.end(), auxiliary_input.begin(), auxiliary_input.end());
    for(size_t i = 0; i < constraint_system.num_constraints(); ++i) {
        dump_r1cs_constraint(constraint_system.constraints[i], full_variable_assignment, constraint_system.variable_annotations);
    }
#else
    libff::UNUSED(constraint_system, primary_input, auxiliary_input);
    std::cout << "Enable DEBUG flag to print constraint system" << std::endl;
#endif
}

template<typename ppT>
void print_lagrange_coeffs(std::vector<std::map<size_t, libff::Fr<ppT>> > coeffs, size_t maxc){
    for(size_t i = 0; i <  coeffs.size(); ++i){
        printf("x_%lu:\t", i);
        for(size_t j = 0; j < maxc; j++){
            printf("%lu\t", coeffs[i][j].as_ulong());
        }
        printf("\n");
    }
}

template<typename ppT>
bool compare_lagrange_coeffs(std::vector<std::map<size_t, libff::Fr<ppT>> > coeffs1, std::vector<std::map<size_t, libff::Fr<ppT>> > coeffs2, size_t maxc){
    if (coeffs1.size() != coeffs2.size()){
        return false;
    }
    for(size_t i = 0; i < coeffs1.size(); ++i){
        for(size_t j = 0; j < maxc; j++){
            if (coeffs1[i][j] != coeffs2[i][j]){
                return false;
            }
        }
    }
    return true;
}

#ifndef NDEBUG
template<typename ppT>
void test_r1cs_to_r1cs_reduction(size_t num_constraints,
                         size_t input_size)
{
    libff::print_header("(enter) Test R1CS to R1CS reduction");
    libff::Fr<ppT> t(221533);
    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);

    printf("Original R1CS:\n");
    print_r1cs<ppT>(example.constraint_system, example.primary_input, example.auxiliary_input);

    // Original QAP reduction, that adds non-degeneracy constraints
    qap_instance<libff::Fr<ppT>> qap_direct = r1cs_to_qap_instance_map(example.constraint_system);
    qap_instance_evaluation<libff::Fr<ppT>> qap_eval_direct = r1cs_to_qap_instance_map_with_evaluation(example.constraint_system, t);
    qap_witness<libff::Fr<ppT>> qap_witness_direct = r1cs_to_qap_witness_map(example.constraint_system,
                                                example.primary_input,
                                                example.auxiliary_input,
                                                   libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero());

    // Separated into two steps
    r1cs_add_input_constraints(example.constraint_system);

    printf("Modified R1CS:\n");
    print_r1cs<ppT>(example.constraint_system, example.primary_input, example.auxiliary_input);


    qap_instance<libff::Fr<ppT>> qap_ts = r1cs_to_plain_qap_instance_map(example.constraint_system);
    qap_instance_evaluation<libff::Fr<ppT>> qap_eval_ts = r1cs_to_plain_qap_instance_map_with_evaluation(example.constraint_system, t);
    qap_witness<libff::Fr<ppT>> qap_witness_ts = r1cs_to_plain_qap_witness_map(example.constraint_system,
                                                                             example.primary_input,
                                                                             example.auxiliary_input,
                                                                               libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero(), libff::Fr<ppT>::zero());


    assert(compare_lagrange_coeffs<ppT>(qap_direct.A_in_Lagrange_basis, qap_ts.A_in_Lagrange_basis, num_constraints+input_size+1));
    assert(compare_lagrange_coeffs<ppT>(qap_direct.B_in_Lagrange_basis, qap_ts.B_in_Lagrange_basis, num_constraints+input_size+1));
    assert(compare_lagrange_coeffs<ppT>(qap_direct.C_in_Lagrange_basis, qap_ts.C_in_Lagrange_basis, num_constraints+input_size+1));

    assert(qap_direct.num_variables() == qap_ts.num_variables());
    //assert(qap_direct.degree() == qap_ts.degree()); ok if not equal
    assert(qap_direct.num_inputs() == qap_ts.num_inputs());

    assert(qap_eval_direct.At == qap_eval_ts.At);
    assert(qap_eval_direct.Bt == qap_eval_ts.Bt);
    assert(qap_eval_direct.Ct == qap_eval_ts.Ct);
    assert(qap_eval_direct.Ht == qap_eval_ts.Ht);
    assert(qap_eval_direct.Zt == qap_eval_ts.Zt);
    assert(qap_eval_direct.num_variables() == qap_eval_ts.num_variables());
    assert(qap_eval_direct.degree() == qap_eval_ts.degree());
    assert(qap_eval_direct.num_inputs() == qap_eval_ts.num_inputs());

    assert(qap_witness_direct.coefficients_for_ABCs == qap_witness_ts.coefficients_for_ABCs);
    assert(qap_witness_direct.coefficients_for_H == qap_witness_ts.coefficients_for_H);
    assert(qap_witness_direct.num_variables() == qap_witness_ts.num_variables());
    assert(qap_witness_direct.degree() == qap_witness_ts.degree());
    assert(qap_witness_direct.num_inputs() == qap_witness_ts.num_inputs());
    libff::print_header("(leave) Test R1CS to R1CS reduction");
}

int main()
{
    libff::default_ec_pp::init_public_params();
    libff::start_profiling();

    test_r1cs_to_r1cs_reduction<libff::default_ec_pp>(2, 1);
}
#else // NDEBUG
int main()
{
    printf("All tests here depend on assert() which is disabled by -DNDEBUG. Please recompile and run again.\n");
}
#endif // NDEBUG
