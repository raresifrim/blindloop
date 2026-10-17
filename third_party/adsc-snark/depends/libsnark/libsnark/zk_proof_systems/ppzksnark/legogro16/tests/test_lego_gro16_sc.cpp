/** @file
 *****************************************************************************

 Test LegoGro16 SNARK with State-Consistency

 *****************************************************************************/
#include <cassert>
#include <cstdio>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>

#include <libsnark/common/default_types/lego_gro16_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_ext_examples.hpp>
#include <libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/examples/run_legogro16_sc.hpp>

using namespace libsnark;

#ifndef NDEBUG
template<typename ppT>
void test_lego_gro16_sc(size_t num_constraints,
                         size_t input_size,
                         size_t state_size,
                         size_t iterations)
{
    libff::print_header("(enter) Test LegroGro16 State Consistency");

    const bool test_serialization = false;
    //r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, input_size);
    r1cs_sc_example<libff::Fr<ppT> > example = generate_r1cs_sc_example_with_field_input<libff::Fr<ppT> >(num_constraints, input_size, state_size, iterations);

    const bool bit = run_lego_gro16_sc<ppT>(example, state_size, iterations, test_serialization);
    assert(bit);

    libff::print_header("(leave) Test LegoGro16 State Consistency");
}

int main()
{
    default_lego_gro16_pp::init_public_params();
    libff::start_profiling();

    test_lego_gro16_sc<default_lego_gro16_pp>(4, 1, 2, 5);
}
#else // NDEBUG
int main()
{
    printf("All tests here depend on assert() which is disabled by -DNDEBUG. Please recompile and run again.\n");
}
#endif // NDEBUG
