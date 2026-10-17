#include "gadgets/poseidon_orig.hpp"
#include "jubjub/point.hpp"
#include "utils.hpp"

namespace ethsnarks {

void benchmark_poseidon(size_t input_size)
{
    ProtoboardT pb;
    LinearCombinationArrayT inputs = make_var_array(pb, input_size, "inputs");
    std::cout << "Benchmark Poseidon, input-size = " << input_size << " variables" << std::endl;

    PoseidonSponge_Precomputed<false> gadget(pb, inputs, "gadget");

    gadget.generate_r1cs_constraints();
    std::cout << "Constraints: " << pb.num_constraints() << std::endl;
}


// namespace ethsnarks
}

int main( int argc, char **argv )
{
    const size_t num_inputs = 1025;

    // Types for board 
    ethsnarks::ppT::init_public_params();
    ethsnarks::default_inner_ec_pp::init_public_params();

    ethsnarks::benchmark_poseidon(num_inputs);
    return 0;
}