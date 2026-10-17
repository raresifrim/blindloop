#include "jubjub/fixed_base_mul.hpp"
#include "utils.hpp"

// Only works with baby-jubjub (alt_bn128) due to fixed testvectors for these curves

namespace ethsnarks {


template<typename mul_gadget>
bool test_jubjub_mul_fixed()
{
    const int num_tests = 7;
    jubjub::Params params;


    FieldT scalars[num_tests] = {
            FieldT("53482891510615431577168724743356132495662554103773572771861111634748265227"),
            FieldT("6453482891510615431577168724743356132495662554103773572771861111634748265227"),
            FieldT("2448898939152157362354919928393896675030729525171754680356664027598736373555"),
            FieldT("1552022125667715425019859696476559258040599694988478133988940517652939206961"),
            FieldT("3084383904387355537929822935899012044714832314430843470401047018460193814908"),
            FieldT("2893107616799763478890623716427558600751081843139832838834090940590622693097"),
            FieldT("2972240793193772460920079731403158034525343346733889384477616629040385168542"),

    };

    FieldT expected_xs[num_tests] = {
            FieldT("12829160162953952577843490213202212620875220641248243794801199289446007534475"),
            FieldT("14404769628348642617958769113059441570295803354118213050215321178400191767982"),
            FieldT("3009532504567122865575175361519772114516237035302331803055002778327297757063"),
            FieldT("15539143650808924898363732422642079585256726528510825891383980576679116478922"),
            FieldT("68877991974750920742481111157538802806966305238913334668671217260612069345"),
            FieldT("8044923652354953454204108487904871069433021093297177496591274494314619718749"),
            FieldT("12847389476667356757919426285460434223959121435201219262525925117215764581405"),

    };

    FieldT expected_ys[num_tests] = {
            FieldT("1525534655961006512271714932224055968566017012184946316554522058053037271444"),
            FieldT("18111766293807611156003252744789679243232262386740234472145247764702249886343"),
            FieldT("20496310097979453877083775410844444836184215911019586917736523400237403295744"),
            FieldT("13338085363739466218001179802615925027581652522446868300236302136475497086433"),
            FieldT("3235257654974205472807791168483165799887311635015046425200907178857833220141"),
            FieldT("19318389687486637763868398709642549208000147623572525618616375652023649672833"),
            FieldT("4599088414280739343409788169162373647888404240048507491571846853704609459554"),
    };



    auto x = FieldT("17777552123799933955779906779655732241715742912184938656739573121738514868268");
    auto y = FieldT("2626589144620713026669568689430873010625803728049924121243784502389097019475");

    for(int i = 0; i < num_tests; i++) {
        ProtoboardT pb;
        auto scalar_val = scalars[i];
        auto expected_x = expected_xs[i];
        auto expected_y = expected_ys[i];

        VariableArrayT scalar;
        int nbits = scalar_val.as_bigint().num_bits();

        std::cout << "Test " << i << ": scalar=" << scalar_val << " nbits=" << nbits << std::endl;


        // nbits must be multiple of window_size
        if (nbits % 3 != 0) {
            nbits += 3 - nbits % 3;
        }

        scalar.allocate(pb, nbits, "scalar");
        scalar.fill_with_bits_of_field_element(pb, scalar_val);

        mul_gadget the_gadget(pb, params, x, y, scalar, "the_gadget");

        the_gadget.generate_r1cs_witness();
        the_gadget.generate_r1cs_constraints();

        if (!pb.is_satisfied()) {
            std::cerr << "not satisfied" << std::endl;
            return false;
        }

        if (pb.val(the_gadget.result_x()) != expected_x) {
            std::cerr << "x mismatch" << std::endl;
            return false;
        }

        if (pb.val(the_gadget.result_y()) != expected_y) {
            std::cerr << "y mismatch" << std::endl;
            return false;
        }

        if (  !pb.is_satisfied()){
            std::cerr << "not satisfied" << std::endl;
            return false;
        }

        std::cout << pb.num_constraints() << " constraints" << std::endl;
        std::cout << (pb.num_constraints() / float(scalar.size())) << " constraints per bit" << std::endl;
    }
    return true;
}



// namespace ethsnarks
}


int main( int argc, char **argv )
{
    // Types for board 
    ethsnarks::ppT::init_public_params();
    ethsnarks::default_inner_ec_pp::init_public_params();

    if( ! ethsnarks::test_jubjub_mul_fixed<ethsnarks::jubjub::fixed_base_mul>() )
    {
        std::cerr << "FAIL\n";
        return 1;
    }

    if( ! ethsnarks::test_jubjub_mul_fixed<ethsnarks::jubjub::fixed_base_mul_ed_3b>() )
    {
        std::cerr << "FAIL\n";
        return 2;
    }

    if( ! ethsnarks::test_jubjub_mul_fixed<ethsnarks::jubjub::fixed_base_mul_mg_3b>() )
    {
        std::cerr << "FAIL\n";
        return 3;
    }

    std::cout << "OK\n";
    return 0;
}
