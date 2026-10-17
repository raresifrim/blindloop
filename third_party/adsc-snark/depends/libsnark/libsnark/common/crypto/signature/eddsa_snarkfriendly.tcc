/** @file
*****************************************************************************

Implementation of interfaces for EdDSA with Poseidon Hash

See eddsa_snarkfriendly.hpp .

*****************************************************************************/

#ifndef LIBSNARK_EDDSA_SNARKFRIENDLY_TCC_
#define LIBSNARK_EDDSA_SNARKFRIENDLY_TCC_

#include <cstdint>
#include <iostream>
#include <memory>

#include <libff/common/serialization.hpp>
#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libsnark/common/crypto/digest/sha.hpp>
#include <libsnark/common/crypto/digest/poseidon.hpp>
#include <libsnark/common/crypto/digest/pedersen.hpp>

#include "eddsa_snarkfriendly.hpp"

namespace libsnark {

template<typename ppT>
bool eddsa_sf_signature<ppT>::operator==(const eddsa_sf_signature<ppT> &other) const
{
    return (this->R == other.R
          && this->s == other.s);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const eddsa_sf_signature<ppT> &signature)
{
    out << signature.R << OUTPUT_NEWLINE;
    out << signature.s << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, eddsa_sf_signature<ppT> &signature)
{
    in >> signature.R;
    libff::consume_OUTPUT_NEWLINE(in);
	in >> signature.s;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
bool eddsa_sf_pubkey<ppT>::operator==(const eddsa_sf_pubkey<ppT> &other) const
{
    return this->pkey == other.pkey;
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const eddsa_sf_pubkey<ppT> &pubkey)
{
    out << pubkey.pkey;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, eddsa_sf_pubkey<ppT> &pubkey)
{
 	in >> pubkey.pkey;
    return in;
}

template<typename ppT>
bool eddsa_sf_privkey<ppT>::operator==(const eddsa_sf_privkey<ppT> &other) const
{
    return this->pkey == other.pkey;
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const eddsa_sf_privkey<ppT> &privkey)
{
    out << privkey.pkey;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, eddsa_sf_privkey<ppT> &privkey)
{
 	in >> privkey.pkey;
    return in;
}

template<typename ppT>
bool eddsa_sf_keypair<ppT>::operator==(const eddsa_sf_keypair<ppT> &other) const
{
    return (this->pubkey == other.pubkey
          && this->privkey == other.privkey);
}

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const eddsa_sf_keypair<ppT> &keypair)
{
    out << keypair.pubkey << OUTPUT_NEWLINE;
    out << keypair.privkey << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, eddsa_sf_keypair<ppT> &keypair)
{
    in >> keypair.pubkey;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> keypair.privkey;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename ppT>
eddsa_sf_keypair<ppT> eddsa_sf_generate() {
	libff::Fr<ppT> private_key = libff::Fr<ppT>::random_element();
    libff::G1<ppT> public_key = private_key * libff::G1<ppT>::one();

	eddsa_sf_pubkey<ppT> pubkey(public_key);
    eddsa_sf_privkey<ppT> privkey(private_key);
    return	eddsa_sf_keypair<ppT>(std::move(pubkey), std::move(privkey));
}

template<typename ppT>
libff::Fr<ppT> hash_secret(eddsa_sf_privkey<ppT> k, std::vector<uint8_t> msg){
    // Note: https://en.wikipedia.org/EdDSA calculates r differently: r = H(H_{b, ..., 2b-1}(k) || M)
    // This version here follows the python implementation in ethsnarks/ethsnarks/eddsa.py
    std::vector<uint8_t> hash = libsnark::digest_sha512_chunks({k.pkey.to_bytes(), msg});
    libff::Fr<ppT> r;
    r.from_bytes(hash);
    return r;
}

template<typename ppT, typename PoseidonParametersT>
libff::Fq<ppT> hash_public_poseidon(const PoseidonParametersT &param, libff::G1<ppT> R, libff::G1<ppT> A, const std::vector<libff::Fq<ppT>> &msg){
    // R, A, M to bits
    // in jubjub.py Point to bits is M.x.bits()
    R.to_affine_coordinates();
    A.to_affine_coordinates();

    std::vector<typename PoseidonParametersT::Fr> inputs;
    inputs.reserve(msg.size() + 2);
    inputs.push_back(libff::convert_field<typename PoseidonParametersT::Fr>(R.X));
    inputs.push_back(libff::convert_field<typename PoseidonParametersT::Fr>(A.X));
    for (const libff::Fq<ppT> &v: msg)
    {
        inputs.push_back(libff::convert_field<typename PoseidonParametersT::Fr>(v));
    }

    const auto result = poseidon_sponge(param, inputs);
    assert(result.size() == 1);
    return libff::convert_field<libff::Fq<ppT>>(result[0]);
}

inline void append_bytes_to_bits(std::vector<bool> &bits, std::vector<uint8_t> bytes, size_t max_bits=SIZE_MAX, bool reverse_bitorder=false) {
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

inline void append_bytes_to_bits(std::vector<bool> &bits, std::string bytes, size_t max_bits=SIZE_MAX, bool reverse_bitorder=false) {
    std::vector<uint8_t> b(bytes.begin(), bytes.end());
    append_bytes_to_bits(bits, b, max_bits, reverse_bitorder);
}

template<typename ppT>
libff::Fq<ppT> hash_public_pedersen(libff::G1<ppT> R, libff::G1<ppT> A, const std::vector<uint8_t> &msg){
    // Uses pedersen hash on baby jubjub
    //std::bitset<2*baby_jubjub_r_bitcount> bits;
    //std::vector<uint8_t> bytes;
    std::vector<bool> bits;
    std::vector<uint8_t> b;

    bits.reserve(2*libff::Fq<ppT>::ceil_size_in_bits()+8*msg.size());

    // R, A, M to bits
    // in jubjub.py Point to bits is M.x.bits()
    R.to_affine_coordinates();
    A.to_affine_coordinates();

    append_bytes_to_bits(bits, R.X.to_bytes(), libff::Fq<ppT>::ceil_size_in_bits());
    append_bytes_to_bits(bits, A.X.to_bytes(), libff::Fq<ppT>::ceil_size_in_bits());

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

    libff::G1<ppT> p = pedersen_hash<ppT>(bits);
    p.to_affine_coordinates();
    return p.X;
}

template<typename ppT, typename PoseidonParametersT> // ppT is curve for signature, so usually it is the inner (jubjub) curve, if one plans to prove the verification of such a signature inside a SNARK
eddsa_sf_signature<ppT> eddsa_poseidon_sign(const PoseidonParametersT &param, const eddsa_sf_privkey<ppT> &privkey, const std::vector<libff::Fq<ppT>> &msg)
{
    assert(PoseidonParametersT::Fr::mod == libff::Fq<ppT>::mod); // Poseidon Parameters must mach curve parameters
	libff::enter_block("libsnark EdDSA Poseidon signature");
    libff::G1<ppT> A = privkey.pkey * libff::G1<ppT>::one();

    std::vector<uint8_t> m;
    for(auto field : msg){
        auto bytes = field.to_bytes();
        m.insert(m.end(), bytes.begin(), bytes.end());
    }

    libff::Fr<ppT> r = hash_secret(privkey, m);
    libff::G1<ppT> R = r * libff::G1<ppT>::one();

    libff::Fq<ppT> t = hash_public_poseidon<ppT>(param, R, A, msg);

    libff::Fr<ppT> s = r + privkey.pkey * libff::Fr<ppT>(t.as_bigint());
    libff::leave_block("libsnark EdDSA Poseidon signature");
    return eddsa_sf_signature<ppT>(R, s);
}

template<typename ppT, typename PoseidonParametersT>
bool eddsa_poseidon_verify(const PoseidonParametersT &param, const eddsa_sf_pubkey<ppT> &pubkey, const eddsa_sf_signature<ppT> &signature, const std::vector<libff::Fq<ppT>> &msg)
{
    assert(PoseidonParametersT::Fr::mod == libff::Fq<ppT>::mod); // Poseidon Parameters must mach curve parameters

    libff::G1<ppT> A = pubkey.pkey;
    libff::G1<ppT> R = signature.R;
    libff::Fr<ppT> s = signature.s;

    // Check if R is a point on the curve
    if (!R.is_well_formed()) {
      return false;
    }

    // Check that R is not in the low order group
    if (R.dbl().dbl().dbl().is_zero()) {
      return false;
    }

    libff::Fq<ppT> t = hash_public_poseidon<ppT>(param, R, A, msg);
    const libff::G1<ppT> rhs = R + (t*A);
    const libff::G1<ppT> lhs = s*libff::G1<ppT>::one();

    return rhs == lhs;
}

template<typename ppT> // ppT is curve for signature, so usually it is the inner (jubjub) curve, if one plans to prove the verification of such a signature inside a SNARK
eddsa_sf_signature<ppT> eddsa_pedersen_sign(const eddsa_sf_privkey<ppT> &privkey, const std::vector<uint8_t> &msg)
{
	libff::enter_block("libsnark EdDSA Pedersen signature");
    libff::G1<ppT> A = privkey.pkey * libff::G1<ppT>::one();

    libff::Fr<ppT> r = hash_secret(privkey, msg);
    libff::G1<ppT> R = r * libff::G1<ppT>::one();

    libff::Fq<ppT> t = hash_public_pedersen<ppT>(R, A, msg);

    libff::Fr<ppT> s = r + privkey.pkey * libff::Fr<ppT>(t.as_bigint());
    libff::leave_block("libsnark EdDSA Pedersen signature");
    return eddsa_sf_signature<ppT>(R, s);
}

template<typename ppT>
bool eddsa_pedersen_verify(const eddsa_sf_pubkey<ppT> &pubkey, const eddsa_sf_signature<ppT> &signature, const std::vector<uint8_t> &msg)
{
    libff::G1<ppT> A = pubkey.pkey;
    libff::G1<ppT> R = signature.R;
    libff::Fr<ppT> s = signature.s;

    // Check if R is a point on the curve
    if (!R.is_well_formed()) {
      return false;
    }

    // Check that R is not in the low order group
    if (R.dbl().dbl().dbl().is_zero()) {
      return false;
    }

    libff::Fq<ppT> t = hash_public_pedersen<ppT>(R, A, msg);
    const libff::G1<ppT> rhs = R + (t*A);
    const libff::G1<ppT> lhs = s*libff::G1<ppT>::one();

    return rhs == lhs;
}

}

#endif //LIBSNARK_EDDSA_SNARKFRIENDLY_TCC_