#include "jubjub/eddsa.hpp"
#include "jubjub/point.hpp"
#include "utils.hpp"

namespace ethsnarks {

using jubjub::EdwardsPoint;
using jubjub::fixed_base_mul_zcash;
using jubjub::Params;
using jubjub::VariablePointT;


void benchmark_pure_eddsa(size_t msg_size)
{
    const Params params;
    ProtoboardT pb;
    EdwardsPoint B(params.Gx, params.Gy); // Base point is generator from curve params
    VariablePointT A(pb, "A"); // This is the public key. No need to correctly initialize it for benchmarking
    VariablePointT R(pb, "R"); // Part of the signature
    VariableArrayT s = make_var_array(pb, FieldT::ceil_size_in_bits(), "s"); // Part of the signature
    VariableArrayT msg = make_var_array(pb, msg_size, "msg");
    std::cout << "Benchmark pure EdDSA, msg-size = " << msg_size << " bits" << std::endl;

    jubjub::PureEdDSA gadget(pb, params, B, A, R, s, msg, "PureEdDSA");

    gadget.generate_r1cs_constraints();
    std::cout << "Constraints: " << pb.num_constraints() << std::endl;
}

void benchmark_pure_eddsa_poseidon(size_t msg_size)
{
    const Params params;
    ProtoboardT pb;
    EdwardsPoint B(params.Gx, params.Gy); // Base point is generator from curve params
    VariablePointT A(pb, "A"); // This is the public key. No need to correctly initialize it for benchmarking
    VariablePointT R(pb, "R"); // Part of the signature
    VariableArrayT s = make_var_array(pb, FieldT::ceil_size_in_bits(), "s"); // Part of the signature
    VariableArrayT msg = make_var_array(pb, msg_size, "msg");
    std::cout << "Benchmark pure EdDSA, msg-size = " << msg_size << " variables" << std::endl;

    jubjub::PureEdDSAPoseidon gadget(pb, params, B, A, R, s, msg, "PureEdDSA");

    gadget.generate_r1cs_constraints();
    std::cout << "Constraints: " << pb.num_constraints() << std::endl;
}

void benchmark_pure_eddsa_poseidon_fixed(size_t msg_size)
{
    const Params params;
    ProtoboardT pb;
    EdwardsPoint B(params.Gx, params.Gy); // Base point is generator from curve params
    EdwardsPoint A(params.Gx, params.Gy); // This is the public key
    VariablePointT R(pb, "R"); // Part of the signature
    VariableArrayT s = make_var_array(pb, FieldT::ceil_size_in_bits(), "s"); // Part of the signature
    VariableArrayT msg = make_var_array(pb, msg_size, "msg");
    std::cout << "Benchmark pure EdDSA, msg-size = " << msg_size << " variables" << std::endl;

    jubjub::PureEdDSAPoseidonFixed gadget(pb, params, B, A, R, s, msg, "PureEdDSA");

    gadget.generate_r1cs_constraints();
    std::cout << "Constraints: " << pb.num_constraints() << std::endl;
}


// namespace ethsnarks
}

int main( int argc, char **argv )
{
    const size_t num_inputs = 1000;

    // Types for board 
    ethsnarks::ppT::init_public_params();
    ethsnarks::default_inner_ec_pp::init_public_params();

    ethsnarks::benchmark_pure_eddsa(num_inputs); // warning: this is input bits
    ethsnarks::benchmark_pure_eddsa_poseidon(num_inputs); // this is input variables (each is ~250bits for Baby-Jubjub)
    ethsnarks::benchmark_pure_eddsa_poseidon_fixed(num_inputs); // this is input variables
    return 0;
}