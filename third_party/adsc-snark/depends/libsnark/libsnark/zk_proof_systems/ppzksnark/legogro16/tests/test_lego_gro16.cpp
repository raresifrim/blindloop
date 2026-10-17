/** @file
 *****************************************************************************

 Tests LegoGro16 SNARK

 *****************************************************************************/
#include <cassert>

#include <libff/common/profiling.hpp>

#include <libsnark/common/default_types/lego_gro16_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/examples/run_legogro16.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/legogro16/examples/run_cplink.hpp>

using namespace libsnark;

#ifndef NDEBUG
template<typename ppT>
void test_lego_gro16(size_t num_constraints,
                         const std::vector<size_t> &commitment_slots,
                         size_t input_size)
{
    libff::print_header("(enter) Test LegoGro16");

    const bool test_serialization = false;
    bool bit;

    bit = run_cplink<ppT>(100);
    assert(bit);

    r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_field_input<libff::Fr<ppT> >(num_constraints, input_size);


    bit = run_lego_gro16<ppT>(example, commitment_slots, test_serialization);
    assert(bit);

    libff::print_header("(leave) Test LegoGro16");
}

int main()
{
    default_lego_gro16_pp::init_public_params();
    libff::start_profiling();

    test_lego_gro16<default_lego_gro16_pp>(1000, {2, 23, 4}, 100);
}
#else // NDEBUG
int main()
{
    printf("All tests here depend on assert() which is disabled by -DNDEBUG. Please recompile and run again.\n");
}
#endif // NDEBUG
