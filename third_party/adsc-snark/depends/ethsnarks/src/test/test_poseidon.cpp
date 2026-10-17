// Copyright (c) 2019 HarryR
// License: LGPL-3.0+

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
using ethsnarks::Poseidon_Precomputed;
using ethsnarks::stub_test_proof_verify;

using std::cout;
using std::cerr;


static bool test_constants( ) {
    ProtoboardT pb;
    const auto inputs = make_var_array(pb, 2, "input");
    Poseidon_Precomputed<4,5> p(pb, inputs, 0, "gadget");

    struct constant_test {
        const char *name;
        const FieldT& actual;
        const FieldT expected;
    };
    const constant_test tests[] = {
        {"C[0]", p.constants.C[0], FieldT("1302239555262414373374689806120238567451910671048356388761256768881091977026")},
        {"C[-1]", p.constants.C.back(), FieldT("19711276008373408462398739099936823239389914489313560182281159321304186912571")},
        {"M[0][0]", p.constants.M[0], FieldT("10781049117828596494234980348561910771925104116162051481202082622387836924012")},
        {"M[-1][-1]", p.constants.M.back(), FieldT("1595649435727440360680749106991490474809376734622877759628613919721687640869")}
    };

    for( const auto& t : tests )
    {
        if( t.actual != t.expected )
        {
            cerr << "FAIL Constant check " << t.name << " != "; t.expected.print();
            cerr << " value is: "; t.actual.print();
            return false;
        }
    }    

    return true;
}


static bool test_prove_verify() {
    ProtoboardT pb;

    auto var_inputs = make_var_array(pb, "input", {1, 2, 3, 4});

    Poseidon_Precomputed<4,5> the_gadget(pb, var_inputs, 0, "gadget");
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

    cout << pb.num_constraints() << " constraints\n";
    //return stub_test_proof_verify( pb );
    return pb.is_satisfied();
}

static bool test_against_libsnark()
{
    typedef libsnark::PoseidonParameters<libff::default_ec_pp> Parameters;
    typedef Parameters::Fr Fr;
    Parameters param = Parameters();

    //std::vector<Fr> inputs = {Fr("124"), Fr("609677209687"), Fr("5523"), Fr("2435264"), Fr("3"), Fr("562460"), Fr("8741015")};
    std::vector<Fr> inputs(param.t, Fr::zero());
    inputs[0] = Fr("20");
    inputs[2] = Fr("23540");

    std::vector<Fr> output_libsnark = inputs;
    libsnark::poseidon_permutation(param, output_libsnark);
    cout << "Poseidon permutation libsnark: " << output_libsnark << std::endl;

    std::vector<Fr> output_ethsnarks = ethsnarks::Poseidon_Precomputed<POSEIDON_PARAM_T, POSEIDON_PARAM_T, true>::permute(inputs);
    cout << "Poseidon permutation ethsnark: " << output_ethsnarks << std::endl;

    return output_libsnark == output_ethsnarks;
}

static int test_vectors()
{
    const auto actual = Poseidon_Precomputed<5,5>::permute({0, 1, 2, 3, 4});
    const FieldT expected("454957455121345586845062157181250659690836909969675544465082691114068521797");
    if( actual[0] != expected ) {
        cerr << "poseidon([0,1,2,3,4]) incorrect result, got ";
        actual[0].print();
        return 3;
    }

    const auto actual2 = Poseidon_Precomputed<5,5>::permute({1, 2, 3, 4, 0});
    const FieldT expected2("1686186900114925873547349014474626234110309484134592404139292384785003831617");
    if( actual2[0] != expected2 ) {
        cerr << "poseidon([1,2,3,4,0]) incorrect result, got ";
        actual2[0].print();
        return 4;
    }

    const auto actual3 = Poseidon_Precomputed<5,1>::permute({1, 2, 3, 4, 0});
    const FieldT expected3("1686186900114925873547349014474626234110309484134592404139292384785003831617");
    if( actual3[0] != expected3 ) {
        cerr << "poseidon([1,2,3,4,0]) incorrect result, got ";
        actual3[0].print();
        return 5;
    }

    return 0;
}


int main( int argc, char **argv )
{
    ppT::init_public_params();

    if( ! test_constants() ){
        return 1;
    }

    if( ! test_prove_verify() ){
        return 2;
    }

    int result_tv = test_vectors();
    if(result_tv)
    {
        return result_tv;
    }

    if ( ! test_against_libsnark())
    {
        return 6;
    }

    std::cout << "OK" << std::endl;
    return 0;
}
