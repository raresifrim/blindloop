/** @file
 *****************************************************************************
 Test program that exercises the designated verifier ppZKADSCSNARK (first authenticator,
 then generator, then prover, then verifier) on a synthetic R1CS instance.

 *****************************************************************************/
#include <cassert>

#include <libff/common/profiling.hpp>

#include <libsnark/common/default_types/r1cs_gg_ppzkadscsnark_dv_pp.hpp>
#include <libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppzkadscsnark_dv/examples/run_r1cs_gg_ppzkadscsnark_dv.hpp>

using namespace libsnark;

#ifndef NDEBUG
template<typename ppT>
void test_r1cs_gg_ppzkadscsnark_dv(size_t num_constraints,
                         size_t public_io_size,
                         size_t private_input_size,
                         size_t state_size,
                         size_t iterations)
{
    libff::print_header("(enter) Test R1CS GG-ppZKADSCSNARK dv");

    const bool test_serialization = true;
    //r1cs_example<libff::Fr<ppT> > example = generate_r1cs_example_with_binary_input<libff::Fr<ppT> >(num_constraints, public_io_size);
    r1cs_adsc_example<libff::Fr<ppT> > example = generate_r1cs_adsc_example_with_field_input<libff::Fr<ppT> >(num_constraints, public_io_size, private_input_size, state_size, iterations);

    const bool bit = run_r1cs_gg_ppzkadscsnark_dv<ppT>(example, private_input_size, state_size, iterations, test_serialization);
    assert(bit);

    libff::print_header("(leave) Test R1CS GG-ppZKADSCSNARK dv");
}

int main()
{
    default_r1cs_gg_ppzkadscsnark_dv_pp::init_public_params();
    libff::start_profiling();

    test_r1cs_gg_ppzkadscsnark_dv<default_r1cs_gg_ppzkadscsnark_dv_pp>(10, 1, 2, 2, 5);
}
#else // NDEBUG
int main()
{
    printf("All tests here depend on assert() which is disabled by -DNDEBUG. Please recompile and run again.\n");
}
#endif // NDEBUG
