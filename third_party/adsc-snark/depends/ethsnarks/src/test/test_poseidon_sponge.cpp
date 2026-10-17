// Copyright (c) 2019 HarryR
// License: LGPL-3.0+

#include <libff/common/serialization.hpp>
#include <libsnark/common/crypto/digest/poseidon.hpp>
#include <libsnark/common/curve/curve_properties.hpp>

#include "utils.hpp"
#include "gadgets/poseidon_orig.hpp"
#include "stubs.hpp"


using ethsnarks::ppT;
using ethsnarks::FieldT;
using ethsnarks::ProtoboardT;
using ethsnarks::VariableT;
using ethsnarks::make_var_array;
using ethsnarks::PoseidonSponge_Gadget;
using ethsnarks::FifthPower_gadget;
using ethsnarks::stub_test_proof_verify;

using std::cout;
using std::cerr;


//static bool test_constants( ) {
//    ProtoboardT pb;
//    const auto inputs = make_var_array(pb, 2, "input");
//    Poseidon128<2,1> p(pb, inputs, "gadget");
//
//    struct constant_test {
//        const char *name;
//        const FieldT& actual;
//        const FieldT expected;
//    };
//    const constant_test tests[] = {
//        {"C[0]", p.constants.C[0], FieldT("14397397413755236225575615486459253198602422701513067526754101844196324375522")},
//        {"C[-1]", p.constants.C.back(), FieldT("10635360132728137321700090133109897687122647659471659996419791842933639708516")},
//        {"M[0][0]", p.constants.M[0], FieldT("19167410339349846567561662441069598364702008768579734801591448511131028229281")},
//        {"M[-1][-1]", p.constants.M.back(), FieldT("20261355950827657195644012399234591122288573679402601053407151083849785332516")}
//    };
//
//    for( const auto& t : tests )
//    {
//        if( t.actual != t.expected )
//        {
//            cerr << "FAIL Constant check " << t.name << " != "; t.expected.print();
//            cerr << " value is: "; t.actual.print();
//            return false;
//        }
//    }
//
//    return true;
//}


static bool test_poseidon_sponge_verify() {
    ProtoboardT pb;

    auto var_inputs = ethsnarks::VariableArrayT_to_pb_lc(make_var_array(pb, "input", {1, 2, 3, 4}));

    ethsnarks::PoseidonSponge_Precomputed<true> the_gadget(
            pb,
            var_inputs,
            "gadget"
            );

    the_gadget.generate_r1cs_witness();
    the_gadget.generate_r1cs_constraints();
    if( ! pb.is_satisfied() ) {
        return false;
    }

    /*
    #ifdef DEBUG
    ethsnarks::dump_pb_r1cs_constraints(pb);
    #endif
    */

    const FieldT result = pb.val(the_gadget.result());
    cout << pb.num_constraints() << " constraints\n";
    cout << "Result: " << result << std::endl;

#ifdef CURVE_BN254
    const FieldT expected("1686186900114925873547349014474626234110309484134592404139292384785003831617");
    if (result != expected){
        return false;
    }
#endif

    auto var_inputs2 = ethsnarks::VariableArrayT_to_pb_lc(make_var_array(pb, "input2", {1, 2, 3, 4, 5, 6, 7, 8, 9, 10}));

    ethsnarks::PoseidonSponge_Precomputed<true> the_gadget2(
            pb,
            var_inputs2,
            "gadget"
    );

    the_gadget2.generate_r1cs_witness();
    the_gadget2.generate_r1cs_constraints();
    if( ! pb.is_satisfied() ) {
        return false;
    }
    const FieldT result2 = pb.val(the_gadget.result());
    cout << pb.num_constraints() << " constraints\n";
    cout << "Result: " << result2 << std::endl;

    //bool r = stub_test_proof_verify( pb );
    bool r = pb.is_satisfied();
    return r;
}


static bool test_poseidon_sponge_libsnark_vals(std::vector<libsnark::PoseidonParameters<libff::default_ec_pp>::Fr> inputs)
{
    typedef libsnark::PoseidonParameters<libff::default_ec_pp> Parameters;
    typedef Parameters::Fr Fr;
    Parameters param = Parameters();

    std::vector<Fr> inputs2 = inputs;
    inputs2[0] = Fr("200");

    assert(libsnark::poseidon_sponge(param, inputs) != libsnark::poseidon_sponge(param, inputs2));
    assert(ethsnarks::PoseidonSponge_Precomputed<true>::hash(inputs) != ethsnarks::PoseidonSponge_Precomputed<true>::hash(inputs2));

    std::vector<Fr> output_libsnark = libsnark::poseidon_sponge(param, inputs);
    if (output_libsnark.size() != 1)
    {
        return false;
    }
    Fr result_libsnark = output_libsnark[0];
    cout << "Poseidon digest libsnark: " << result_libsnark << std::endl;

    Fr result_ethsnarks = ethsnarks::PoseidonSponge_Precomputed<true>::hash(inputs);
    cout << "Poseidon digest ethsnark: " << result_ethsnarks << std::endl;

    return result_libsnark == result_ethsnarks;
}

static bool test_poseidon_sponge_libsnark()
{
    typedef libsnark::PoseidonParameters<libff::default_ec_pp> Parameters;
    typedef Parameters::Fr Fr;
    Parameters param = Parameters();
    bool result;

    std::vector<Fr> inputs = {Fr("124"), Fr("609677209687"), Fr("5523"), Fr("2435264"), Fr("3"), Fr("562460"), Fr("8741015")};
    result = test_poseidon_sponge_libsnark_vals(inputs);

    inputs = {Fr("275"), Fr("5"), Fr("456")};
    result &= test_poseidon_sponge_libsnark_vals(inputs);

    inputs = std::vector<Fr>();
    for (size_t i = 0; i < 1000; ++i)
    {
        inputs.push_back(Fr(i));
    }
    result &= test_poseidon_sponge_libsnark_vals(inputs);

    inputs[3] = Fr::zero();
    result &= test_poseidon_sponge_libsnark_vals(inputs);

    return result;
}

int main()
{
    ppT::init_public_params();

    if( ! test_poseidon_sponge_verify() )
        return 1;

    if (! test_poseidon_sponge_libsnark() )
        return 2;

    std::cout << "OK" << std::endl;
    return 0;
}
