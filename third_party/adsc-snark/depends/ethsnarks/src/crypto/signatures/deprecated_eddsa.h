/** @file
 *****************************************************************************

 Declaration of interfaces for ethsnarks EdDSA signature algorithm

 EdDSA is over jubjub curve (concrete curve depends on -DCURVE compilation flag)
 There are two versions:
 pedersen: uses pedersen hash for hashing message
 poseidon: uses poseidon hash for hashing message

 sign functions implement the same functionality as in ethsnarks/eddsa.py and
 can be used in C++ - only applications (no python required)
 verify functions just invoke the verification gadget (not optimized for speed)
 *****************************************************************************/

#ifndef CRYPTO_EDDSA_H
#define CRYPTO_EDDSA_H

#include <libff/common/default_types/ec_pp.hpp>
#include <ethsnarks.hpp>

namespace ethsnarks {

    typedef libff::Fr<libff::default_ec_pp> FieldS; // outer curve scalar field, == FieldT
    typedef libff::Fr<default_inner_ec_pp> FieldR; // inner curve scalar field
    typedef libff::Fq<default_inner_ec_pp> FieldQ; // inner curve base field
    typedef libff::G1<default_inner_ec_pp> Group1; // inner curve group

    typedef FieldR eddsa_private_key;
    typedef Group1 eddsa_public_key;

    struct serializable_value_t {
        int value;
        int size;
        bool is_signed;
    };

    struct eddsa_keypair {
        eddsa_private_key sk;
        eddsa_public_key pk;
    };


    typedef std::vector<unsigned char> eddsa_msg_char;
    typedef std::vector<FieldQ> eddsa_msg_field;
    typedef std::vector<serializable_value_t> eddsa_msg_ser_value;

    class EddsaSignature {
    public:
        Group1 R;
        FieldR s;

        EddsaSignature() {}

        EddsaSignature(Group1 R, FieldR s) : R(R), s(s) {}

        friend std::ostream &operator<<(std::ostream &out, const EddsaSignature &s);

        friend std::istream &operator>>(std::istream &in, EddsaSignature &s);
    };

    void init_eddsa();

    void eddsa_generate_keypair(eddsa_private_key &private_key, eddsa_public_key &pub_key);

    EddsaSignature eddsa_pedersen_sign(eddsa_msg_char msg, eddsa_private_key k);

    EddsaSignature eddsa_pedersen_sign(std::string msg, eddsa_private_key k);

    EddsaSignature eddsa_pedersen_sign(eddsa_msg_ser_value msg, eddsa_private_key k);

    EddsaSignature eddsa_poseidon_sign(eddsa_msg_field msg, eddsa_private_key k);

    EddsaSignature eddsa_poseidon_sign(std::string msg, eddsa_private_key k);

    bool eddsa_pedersen_verify(eddsa_msg_char msg, EddsaSignature sig, eddsa_public_key pubkey);

    bool eddsa_pedersen_verify(std::string msg, EddsaSignature sig, eddsa_public_key pubkey);

    bool eddsa_pedersen_verify(eddsa_msg_ser_value msg, EddsaSignature sig, eddsa_public_key pubkey);

    bool eddsa_poseidon_verify(eddsa_msg_field msg, EddsaSignature sig, eddsa_public_key pubkey);

    bool eddsa_poseidon_verify(std::string msg, EddsaSignature sig, eddsa_public_key pubkey);

}// namespace ethsnarks

#endif //CRYPTO_EDDSA_H
