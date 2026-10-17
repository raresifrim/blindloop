/** @file
*****************************************************************************

Generates Poseidon test vectors for other implementations
to compare against

*****************************************************************************/

#include "libsnark/zk_proof_systems/ppadscsnark/r1cs_gg_ppzkadscsnark/r1cs_gg_ppzkadscsnark.hpp"
#include "libsnark/common/crypto/digest/poseidon.hpp"

template<typename EcPP, typename Parameters>
void get_poseidon_test_vectors()
{
    EcPP::init_public_params();
    std::vector<libff::Fr<EcPP>> input1 = {
        libff::Fr<EcPP>("0"),
    };

    std::vector<libff::Fr<EcPP>> input2 = {
        libff::Fr<EcPP>("1"),
        libff::Fr<EcPP>("2"),
        libff::Fr<EcPP>("42"),
    };

    std::vector<libff::Fr<EcPP>> input3 = {
        libff::Fr<EcPP>("2347272"),
        libff::Fr<EcPP>("3512325"),
        libff::Fr<EcPP>("950157783"),
        libff::Fr<EcPP>("35"),
        libff::Fr<EcPP>("26357"),
        libff::Fr<EcPP>("354738949"),
        libff::Fr<EcPP>("30086"),
        libff::Fr<EcPP>("246849"),
        libff::Fr<EcPP>("56943"),
    };

    const size_t INPUT_4_SIZE = 100;
    std::vector<libff::Fr<EcPP>> input4;
    input4.reserve(INPUT_4_SIZE);
    for (size_t i = 0; i < INPUT_4_SIZE; ++i)
    {
        input4.push_back(libff::Fr<EcPP>(i));
    }

    std::vector<std::vector<libff::Fr<EcPP>>> inputs = {
        input1,
        input2,
        input3,
        input4,
    };

    auto parameters = Parameters();

    std::cout << "Group size: " << libff::Fr<EcPP>::num_bits << std::endl;

    for (auto &input: inputs)
    {
        auto digest = libsnark::poseidon_sponge(parameters, input);
        std::cout << "Input: " << std::endl;
        for (auto &d : input)
        {
            d.print();
        }
        std::cout << std::endl << "Digest: " << std::endl;
        for (auto &d : digest)
        {
            d.print();
        }
        std::cout << std::endl;
    }


}


int main() {
    get_poseidon_test_vectors<libff::bn254_pp, libsnark::PoseidonParametersBN254>();
    get_poseidon_test_vectors<libff::bn183_pp, libsnark::PoseidonParametersBN183>();
    get_poseidon_test_vectors<libff::bn124_pp, libsnark::PoseidonParametersBN124>();
    get_poseidon_test_vectors<libff::edwards181_pp, libsnark::PoseidonParametersED181>();
    get_poseidon_test_vectors<libff::edwards97_pp, libsnark::PoseidonParametersED97>();
    get_poseidon_test_vectors<libff::edwards61_pp, libsnark::PoseidonParametersED61>();
    get_poseidon_test_vectors<libff::edwards58_pp, libsnark::PoseidonParametersED58>();
}