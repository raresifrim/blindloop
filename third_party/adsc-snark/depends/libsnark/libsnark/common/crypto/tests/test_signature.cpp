/** @file
 *****************************************************************************
 Test signature routines

 *****************************************************************************/
#include <cassert>
#include <iostream>
#include <iomanip>

#include <libff/common/profiling.hpp>
#include <libff/common/serialization.hpp>
#include <libff/common/default_types/ec_pp.hpp>

#include <libff/algebra/curves/jubjub_bn124/jubjub_bn124_pp.hpp>
#include <libff/algebra/curves/jubjub_bn183/jubjub_bn183_pp.hpp>
#include <libff/algebra/curves/jubjub_bn254/jubjub_bn254_pp.hpp>
#include <libff/algebra/curves/jubjub_ed58/jubjub_ed58_pp.hpp>
#include <libff/algebra/curves/jubjub_ed61/jubjub_ed61_pp.hpp>
#include <libff/algebra/curves/jubjub_ed97/jubjub_ed97_pp.hpp>
#include <libff/algebra/curves/jubjub_ed181/jubjub_ed181_pp.hpp>

#include "libsnark/common/crypto/digest/poseidon_parameters.hpp"
#include "libsnark/common/crypto/signature/eddsa_snarkfriendly.hpp"
#include "libsnark/common/crypto/signature/eddsa.hpp"


#ifndef NDEBUG

using namespace libsnark;

void test_eddsa_signature(size_t size, bool serialize)
{
    libff::enter_block("Test EDDSA");
    std::vector<uint8_t> data;
    for (size_t i = 0; i < size; ++i){
        data.push_back((uint8_t) i);
    }

    libff::enter_block("generate keys");
    signature_eddsa_keypair keypair = signature_eddsa_generate();
    libff::leave_block("generate keys");


    signature_eddsa_keypair keypair2;

    if (serialize){
        keypair2 = libff::reserialize(keypair);
        assert(keypair2 == keypair);
    } else {
        keypair2 = keypair;
    }
    std::cout << "Keypair size: " << keypair2.size_in_bits() << std::endl;
    std::cout << "Keypair serialized size: " << libff::get_serialized_size(keypair2) << std::endl;

    libff::enter_block("sign");
    signature_eddsa_signature signature = signature_eddsa_sign(keypair2.privkey, data);
    libff::leave_block("sign");

    signature_eddsa_signature signature2;
    if (serialize){
        signature2 = libff::reserialize(signature);
        assert(signature2 == signature);
    } else {
        signature2 = signature;
    }
    std::cout << "Signature size: " << signature2.size_in_bits() << std::endl;
    std::cout << "Signature serialized size: " << libff::get_serialized_size(signature2) << std::endl;

    libff::enter_block("verify");
    bool verifies = signature_eddsa_verify(keypair2.pubkey, signature2, data);
    libff::leave_block("verify");

    assert(verifies);

    libff::leave_block("Test EDDSA");
}

template<typename ppT, typename PoseidonParametersT>
void test_eddsa_poseidon_signature(const PoseidonParametersT &param, size_t size, bool serialize)
{
    libff::enter_block("Test EDDSA Poseidon");
    std::vector<libff::Fq<ppT>> data;
    for (size_t i = 0; i < size; ++i){
        data.push_back(libff::Fq<ppT>(i));
    }

    libff::enter_block("generate keys");
    eddsa_sf_keypair<ppT> keypair = eddsa_sf_generate<ppT>();
    libff::leave_block("generate keys");


    eddsa_sf_keypair<ppT> keypair2;

    if (serialize){
        keypair2 = libff::reserialize(keypair);
        assert(keypair2 == keypair);
    } else {
        keypair2 = keypair;
    }
    std::cout << "Keypair size: " << keypair2.size_in_bits() << std::endl;
    std::cout << "Keypair serialized size: " << libff::get_serialized_size(keypair2) << std::endl;

    libff::enter_block("sign");
    eddsa_sf_signature<ppT> signature = eddsa_poseidon_sign<ppT>(param, keypair2.privkey, data);
    libff::leave_block("sign");

    eddsa_sf_signature<ppT> signature2;
    if (serialize){
        signature2 = libff::reserialize(signature);
        assert(signature2 == signature);
    } else {
        signature2 = signature;
    }
    std::cout << "Signature size: " << signature2.size_in_bits() << std::endl;
    std::cout << "Signature serialized size: " << libff::get_serialized_size(signature2) << std::endl;

    libff::enter_block("verify");
    bool verifies = eddsa_poseidon_verify<ppT>(param, keypair2.pubkey, signature2, data);
    libff::leave_block("verify");
    std::cout << "Verifies: " << verifies << std::endl;

    assert(verifies);

    data[0] += 1;
    verifies = eddsa_poseidon_verify<ppT>(param, keypair2.pubkey, signature2, data);
    assert(!verifies);

    libff::leave_block("Test EDDSA Poseidon");
}

template<typename ppT>
void test_eddsa_pedersen_signature(size_t size, bool serialize)
{
    libff::enter_block("Test EDDSA Pedersen");
    std::vector<uint8_t> data;
    for (size_t i = 0; i < size; ++i){
        data.push_back(static_cast<uint8_t>(i));
    }

    libff::enter_block("generate keys");
    eddsa_sf_keypair<ppT> keypair = eddsa_sf_generate<ppT>();
    libff::leave_block("generate keys");


    eddsa_sf_keypair<ppT> keypair2;

    if (serialize){
        keypair2 = libff::reserialize(keypair);
        assert(keypair2 == keypair);
    } else {
        keypair2 = keypair;
    }
    std::cout << "Keypair size: " << keypair2.size_in_bits() << std::endl;
    std::cout << "Keypair serialized size: " << libff::get_serialized_size(keypair2) << std::endl;

    libff::enter_block("sign");
    eddsa_sf_signature<ppT> signature = eddsa_pedersen_sign<ppT>(keypair2.privkey, data);
    libff::leave_block("sign");

    eddsa_sf_signature<ppT> signature2;
    if (serialize){
        signature2 = libff::reserialize(signature);
        assert(signature2 == signature);
    } else {
        signature2 = signature;
    }
    std::cout << "Signature size: " << signature2.size_in_bits() << std::endl;
    std::cout << "Signature serialized size: " << libff::get_serialized_size(signature2) << std::endl;

    libff::enter_block("verify");
    bool verifies = eddsa_pedersen_verify<ppT>(keypair2.pubkey, signature2, data);
    libff::leave_block("verify");
    std::cout << "Verifies: " << verifies << std::endl;

    assert(verifies);

    data[0] += 1;
    verifies = eddsa_pedersen_verify<ppT>(keypair2.pubkey, signature2, data);
    assert(!verifies);

    libff::leave_block("Test EDDSA Pedersen");
}

int main()
{
    libff::bn254_pp::init_public_params();
    libff::bn183_pp::init_public_params();
    libff::bn124_pp::init_public_params();
    libff::edwards58_pp::init_public_params();
    libff::edwards61_pp::init_public_params();
    libff::edwards97_pp::init_public_params();
    libff::edwards181_pp::init_public_params();

    libff::jubjub_bn124_pp::init_public_params();
    libff::jubjub_bn183_pp::init_public_params();
    libff::jubjub_bn254_pp::init_public_params();
    libff::jubjub_ed58_pp::init_public_params();
    libff::jubjub_ed61_pp::init_public_params();
    libff::jubjub_ed97_pp::init_public_params();
    libff::jubjub_ed181_pp::init_public_params();

    libff::start_profiling();
    test_eddsa_signature(1000, true);
    test_eddsa_poseidon_signature<libff::jubjub_bn124_pp>(PoseidonParametersBN124(), 1000, true);
    test_eddsa_poseidon_signature<libff::jubjub_bn183_pp>(PoseidonParametersBN183(), 1000, true);
    test_eddsa_poseidon_signature<libff::jubjub_bn254_pp>(PoseidonParametersBN254(), 1000, true);
    test_eddsa_poseidon_signature<libff::jubjub_ed58_pp>(PoseidonParametersED58(), 1000, true);
    test_eddsa_poseidon_signature<libff::jubjub_ed61_pp>(PoseidonParametersED61(), 1000, true);
    test_eddsa_poseidon_signature<libff::jubjub_ed97_pp>(PoseidonParametersED97(), 1000, true);
    test_eddsa_poseidon_signature<libff::jubjub_ed181_pp>(PoseidonParametersED181(), 1000, true);

    test_eddsa_pedersen_signature<libff::jubjub_bn124_pp>(1000, true);
    test_eddsa_pedersen_signature<libff::jubjub_bn183_pp>(1000, true);
    test_eddsa_pedersen_signature<libff::jubjub_bn254_pp>(1000, true);
    test_eddsa_pedersen_signature<libff::jubjub_ed58_pp>(1000, true);
    test_eddsa_pedersen_signature<libff::jubjub_ed61_pp>(1000, true);
    test_eddsa_pedersen_signature<libff::jubjub_ed97_pp>(1000, true);
    test_eddsa_pedersen_signature<libff::jubjub_ed181_pp>(1000, true);

}
#else // NDEBUG
int main()
{
    printf("All tests here depend on assert() which is disabled by -DNDEBUG. Please recompile and run again.\n");
}
#endif // NDEBUG
