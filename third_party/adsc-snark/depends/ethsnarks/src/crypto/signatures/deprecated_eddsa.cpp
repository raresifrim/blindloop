/** @file
 *****************************************************************************

 implementation of ethsnarks EdDSA signature algorithm

 See eddsa.h
 *****************************************************************************/

#include <libsnark/common/crypto/digest/sha.hpp>
#include <utility>

#include "eddsa.h"
#include "jubjub/eddsa.hpp"


using namespace libff;

namespace ethsnarks {

FieldR hash_secret(eddsa_private_key k, eddsa_msg_char msg){
    // Note: https://en.wikipedia.org/EdDSA calculates r differently: r = H(H_{b, ..., 2b-1}(k) || M)
    // This version here follows the python implementation in ethsnarks/ethsnarks/eddsa.py
    std::vector<uint8_t> hash = libsnark::digest_sha512_chunks({k.to_bytes(), msg});
    FieldR r;
    r.from_bytes(hash);
    return r;
}


void append_bytes_to_bits(std::vector<bool> &bits, std::vector<uint8_t> bytes, size_t max_bits=SIZE_MAX, bool reverse_bitorder=false) {
    for (size_t i = 0; i < bytes.size() && i*8 < max_bits; i++){
        for (size_t j = 0; j < 8 && i*8+j < max_bits; j++){
            if (reverse_bitorder) {
                bits.push_back(bytes[i] & (1 << (7-j)));
            }else {
                bits.push_back(bytes[i] & (1 << j));
            }
        }
    }
}

void append_bytes_to_bits(std::vector<bool> &bits, std::string bytes, size_t max_bits=SIZE_MAX, bool reverse_bitorder=false) {
    std::vector<uint8_t> b(bytes.begin(), bytes.end());
    append_bytes_to_bits(bits, b, max_bits, reverse_bitorder);
}

Group1 point_from_hash(char* bytes, size_t n){
    // Hash input
    std::vector<uint8_t> output_bytes = libsnark::digest_sha256(std::vector<uint8_t>(bytes, bytes+n));

    FieldQ y;
    y.from_bytes(output_bytes, true); // This is big endian here (Why is this not consistent to hash_secret (little endian)?
    Group1 result = Group1::from_y(y);

    // Multiply point by cofactor, ensures it's on the prime-order subgroup
    return result.dbl().dbl().dbl();
}

Group1 pedersen_hash_basepoint(const char* name, unsigned int i) {
    // Create a base point for use with the windowed pedersen hash function. The name and sequence
    // numbers are used a unique identifier. Then HashTo Point is run on the name +seq to get the
    // base point.

    if (i > 0xFFFF){
        throw std::invalid_argument("Sequence number invalid");
    }

    if (std::strlen(name) > 28) {
        throw std::invalid_argument("Name too long");
    }

    char data[33];
    std::sprintf(data, "%-28s%04X", name, i);

    return point_from_hash(data, 32);
}

Group1 pedersen_hash(std::vector<bool> bits){ // pass by reference for more performance (however cannot be const)
    const uint8_t N_WINDOWS = 62;
    const char P13N_EDDSA_VERIFY_RAM[] = "EdDSA_Verify.RAM";

    // Pad with 0 such that len(bits) = 0 (mod 3)
    uint8_t m = bits.size() % 3;
    if (m == 1 || m == 2) {
        bits.insert(bits.end(), 3-m, 0);
    }

    Group1 result = Group1::zero();
    Group1 current, segment;

    for (size_t i = 0; 3*i < bits.size(); i++){
        // Split bits into 3-bit windows
        uint8_t window = bits[3*i] | bits[3*i+1] << 1 | bits[3*i+2] << 2;
        int j = i % N_WINDOWS;

        if (j == 0){
            current = pedersen_hash_basepoint(P13N_EDDSA_VERIFY_RAM, i / N_WINDOWS);
        }else {
            current = current.dbl().dbl().dbl().dbl();
        }

        segment = FieldQ((window & 0b11) + 1) * current;
        if (window > 0b11) {
            segment = -segment;
        }
        result = result + segment;
        //Group1 tmp = result;
        //tmp.to_affine_coordinates();
        //tmp.print_coordinates();
    }
    return result;
}

FieldQ hash_public(Group1 R, Group1 A, eddsa_msg_char msg){
    // Uses pedersen hash on baby jubjub
    //std::bitset<2*baby_jubjub_r_bitcount> bits;
    //std::vector<uint8_t> bytes;
    std::vector<bool> bits;
    std::vector<uint8_t> b;

    bits.reserve(2*FieldQ::ceil_size_in_bits()+8*msg.size());

    // R, A, M to bits
    // in jubjub.py Point to bits is M.x.bits()
    R.to_affine_coordinates();
    A.to_affine_coordinates();

    append_bytes_to_bits(bits, R.X.to_bytes(), FieldQ::ceil_size_in_bits());
    append_bytes_to_bits(bits, A.X.to_bytes(), FieldQ::ceil_size_in_bits());

    // Serialize message
    append_bytes_to_bits(bits, msg, SIZE_MAX, false); // Python implementation does not reverse bitorder within byte

//    std::cout << "Hash while signing " << std::endl;
//    for (size_t i = 0; i < bits.size(); i++){
//        std::cout << (bits[i] ? "1" : "0");
//        if (i % 16 == 0){
//            std::cout << std::endl;
//        }
//    }
//    std::cout << std::endl;

    Group1 p = pedersen_hash(bits);
    p.to_affine_coordinates();
    return p.X;
}

FieldQ hash_public_poseidon(Group1 R, Group1 A, eddsa_msg_field msg){
    // R, A, M to bits
    // in jubjub.py Point to bits is M.x.bits()
    R.to_affine_coordinates();
    A.to_affine_coordinates();

    std::vector<FieldS> inputs({ethsnarks::default_inner_ec_pp::inner2outer(R.X),
                                ethsnarks::default_inner_ec_pp::inner2outer(A.X)});
    for(size_t i = 0; i < msg.size(); i++){
        inputs.push_back(ethsnarks::default_inner_ec_pp::inner2outer(msg[i]));
    }

//    std::cout << "Hash while signing " << std::endl;
//    for (size_t i = 0; i < bits.size(); i++){
//        std::cout << (bits[i] ? "1" : "0");
//        if (i % 16 == 0){
//            std::cout << std::endl;
//        }
//    }
//    std::cout << std::endl;

    const FieldT result = PoseidonSponge_Precomputed<true>::hash(inputs);
    return ethsnarks::default_inner_ec_pp::outer2inner(result);
}

EddsaSignature eddsa_pedersen_sign(eddsa_msg_char msg, eddsa_private_key k){
    libff::enter_block("EdDSA Pedersen signature");
    Group1 A = k * Group1::one();
    FieldR r = hash_secret(k, msg);
    Group1 R = r * Group1::one();

    FieldQ t = hash_public(R, A, msg);
    // Note: eddsa.py takes mod JUBJUB_E and later additionally JUBJUB_Q, instead of JUBJUB_L, which seems to be wrong?
    // In rare cases ~ 2^(-128), t is between JUBJUB_E and JUBJUB_Q -> Signature does not verify?

    FieldR S = r + k * FieldR(t.as_bigint());
    //std::cout << "r: " << r << std::endl << "R: " << R;

    libff::leave_block("EdDSA Pedersen signature");
    return EddsaSignature(R, S);
}

EddsaSignature eddsa_pedersen_sign(std::string msg, eddsa_private_key k){
    eddsa_msg_char m(msg.begin(), msg.end());
    return eddsa_pedersen_sign(m, k);
}

EddsaSignature eddsa_pedersen_sign(eddsa_msg_ser_value msg, eddsa_private_key k){
    eddsa_msg_char msg_char;
    msg_char.reserve(msg.size());

    for(size_t i = 0; i < msg.size(); i++){
        auto m = msg[i];
        int offset = m.is_signed ? 1 << (m.size - 1) : 0;
        int value = m.value + offset;

        // Serialize the value
        for(int j = 0; j < m.size/8; j++){
            unsigned char v = (value >> 8*j) & 0xFF;
            msg_char.push_back(v);
        }
    }

    return eddsa_pedersen_sign(msg_char, k);
}


EddsaSignature eddsa_poseidon_sign(eddsa_msg_field msg, eddsa_private_key k){
    libff::enter_block("EdDSA Poseidon signature");
    Group1 A = k * Group1::one();

    eddsa_msg_char m;
    for(auto field : msg){
        auto bytes = field.to_bytes();
        m.insert(m.end(), bytes.begin(), bytes.end());
    }

    FieldR r = hash_secret(k, m);
    Group1 R = r * Group1::one();

    FieldQ t = hash_public_poseidon(R, A, msg);

    FieldR S = r + k * FieldR(t.as_bigint());
    libff::leave_block("EdDSA Poseidon signature");
    return EddsaSignature(R, S);
}

// one character is encoded as one field element, which is inefficient. Better use eddsa_poseidon_sign(eddsa_msg_field, ...)
// directly
EddsaSignature eddsa_poseidon_sign(std::string msg, eddsa_private_key k){
    eddsa_msg_field m(msg.begin(), msg.end());
    return eddsa_poseidon_sign(m, k);
}



std::ostream& operator<<(std::ostream &out, const EddsaSignature &s)
{
    out << s.R;
    out << s.s;

    return out;
}

std::istream& operator>>(std::istream &in, EddsaSignature &s)
{
    in >> s.R;
    in >> s.s;

    return in;
}


// Difference to eddsa_open: S (in Signature) is element of baby_jubjub scalar field (f_r), not base field (f_q)
// Makes more sense, as s is multiplied with B in verify
bool eddsa_pedersen_verify(eddsa_msg_char msg, EddsaSignature sig, eddsa_public_key pubkey){
    libsnark::protoboard<FieldS> pb;
    jubjub::Params params; // Use default params (baby_jubjub)

    std::vector<bool> msgBits;
    append_bytes_to_bits(msgBits, msg, SIZE_MAX, false);

    libsnark::pb_variable_array<FieldS> msg_var_bits;
    libsnark::pb_variable_array<FieldS> s_var_bits;

    msg_var_bits.allocate(pb, msgBits.size(), "msg_var_bits");
    msg_var_bits.fill_with_bits(pb, msgBits);

    FieldS s = FieldS(sig.s.as_bigint());
    s_var_bits.allocate(pb, FieldS::ceil_size_in_bits(), "s_var_bits");
    s_var_bits.fill_with_bits_of_field_element(pb, s);

    pubkey.to_affine_coordinates();
    sig.R.to_affine_coordinates();
    const jubjub::EdwardsPoint B(params.Gx, params.Gy);
    const jubjub::EdwardsPoint A(pubkey.X.as_bigint(), pubkey.Y.as_bigint());
    const jubjub::EdwardsPoint R(sig.R.X.as_bigint(), sig.R.Y.as_bigint());

    jubjub::PureEdDSA eddsaGadget(pb, params, B, A.as_VariablePointT(pb, "A"), R.as_VariablePointT(pb, "R"), s_var_bits, msg_var_bits, "pure_eddsa");

    eddsaGadget.generate_r1cs_constraints();
    eddsaGadget.generate_r1cs_witness();
    return pb.is_satisfied();
}

bool eddsa_pedersen_verify(std::string msg, EddsaSignature sig, eddsa_public_key pubkey){
    eddsa_msg_char m(msg.begin(), msg.end());
    return eddsa_pedersen_verify(m, sig, pubkey);
}

bool eddsa_pedersen_verify(eddsa_msg_ser_value msg, EddsaSignature sig, eddsa_public_key pubkey){
    eddsa_msg_char msg_char;
    msg_char.reserve(msg.size());

    for(size_t i = 0; i < msg.size(); i++){
        auto m = msg[i];
        int offset = m.is_signed ? 1 << (m.size - 1) : 0;
        int value = m.value + offset;

        // Serialize the value
        for(int j = 0; j < m.size/8; j++){
            unsigned char v = (value >> 8*j) & 0xFF;
            msg_char.push_back(v);
        }
    }

    return eddsa_pedersen_verify(msg_char, sig, pubkey);
}

bool eddsa_poseidon_verify(eddsa_msg_field msg, EddsaSignature sig, eddsa_public_key pubkey){
    libsnark::protoboard<FieldS> pb;
    jubjub::Params params; // Use default params (baby_jubjub)

    libsnark::pb_variable_array<FieldS> msg_vars;
    libsnark::pb_variable_array<FieldS> s_var_bits;

    std::vector<FieldS> msg_c;
    for(size_t i = 0; i < msg.size(); ++i){
        msg_c.push_back(default_inner_ec_pp::inner2outer(msg[i]))    ;
    }

    msg_vars.allocate(pb, msg_c.size(), "msg_vars");
    msg_vars.fill_with_field_elements(pb, msg_c);

    FieldS s = FieldS(sig.s.as_bigint());
    s_var_bits.allocate(pb, FieldS::ceil_size_in_bits(), "s_var_bits");
    s_var_bits.fill_with_bits_of_field_element(pb, s);

    pubkey.to_affine_coordinates();
    sig.R.to_affine_coordinates();
    const jubjub::EdwardsPoint B(params.Gx, params.Gy);
    const jubjub::EdwardsPoint A(pubkey.X.as_bigint(), pubkey.Y.as_bigint());
    const jubjub::EdwardsPoint R(sig.R.X.as_bigint(), sig.R.Y.as_bigint());

    jubjub::PureEdDSAPoseidonFixed eddsaGadget(pb, params, B, A, R.as_VariablePointT(pb, "R"), s_var_bits, msg_vars, "pure_eddsa_poseidon_fixed");

    eddsaGadget.generate_r1cs_constraints();
    eddsaGadget.generate_r1cs_witness();
    return pb.is_satisfied();
}

bool eddsa_poseidon_verify(std::string msg, EddsaSignature sig, eddsa_public_key pubkey){
    eddsa_msg_field m(msg.begin(), msg.end());
    return eddsa_poseidon_verify(m, sig, pubkey);
}

void init_eddsa(){
    libff::default_ec_pp::init_public_params();
    ethsnarks::default_inner_ec_pp::init_public_params();
}

void eddsa_generate_keypair(eddsa_private_key &private_key, eddsa_public_key &pub_key){
    private_key = eddsa_private_key::random_element();

    pub_key = private_key * Group1::one(); // Public key Warning: Different to https://en.wikipedia.org/wiki/EdDSA:
    // where H_{0,...,b-1}(k) is used
}

} // namespace ethsnarks
