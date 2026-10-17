// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#include "ethsnarks.hpp"
#include "stubs.hpp"

#include "gadgets/shamir_poly.hpp"


using ethsnarks::ppT;


namespace ethsnarks {


bool test_shamirs_poly()
{
    ProtoboardT pb;

    auto rand_input = FieldT::random_element();
    std::vector<FieldT> rand_alpha = {
        FieldT::random_element(), FieldT::random_element(),
        FieldT::random_element(), FieldT::random_element()
    };

    const VariableT in_input = make_variable(pb, rand_input, "in_input");
    pb.set_input_sizes(1);

    const VariableArrayT in_alpha = make_var_array(pb, rand_alpha.size(), "in_alpha");
    in_alpha.fill_with_field_elements(pb, rand_alpha);

    shamir_poly the_gadget(pb, in_input, in_alpha, "gadget");
    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();

    if( ! pb.is_satisfied() ) {
        std::cerr << "Not satisfied!\n";
        return false;
    }

    return stub_test_proof_verify(pb);
}

// namespace ethsnarks
}


int main( int argc, char **argv )
{
    ppT::init_public_params();

    if( ! ethsnarks::test_shamirs_poly() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    std::cout << "OK\n";
    return 0;
}
