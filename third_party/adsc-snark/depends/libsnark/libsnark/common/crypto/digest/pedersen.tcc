#ifndef LIBSNARK_PEDERSEN_TCC
#define LIBSNARK_PEDERSEN_TCC

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <cstring>

#include <libff/algebra/curves/public_params.hpp>
#include "sha.hpp"

namespace libsnark {

template<typename ppT>
libff::G1<ppT> point_from_hash(char* bytes, size_t n){
    // Hash input
    std::vector<uint8_t> output_bytes = libsnark::digest_sha256(std::vector<uint8_t>(bytes, bytes+n));

    libff::Fq<ppT> y;
    y.from_bytes(output_bytes, true); // This is big endian here (Why is this not consistent to hash_secret (little endian)?
    libff::G1<ppT> result = libff::G1<ppT>::from_y(y);

    // Multiply point by cofactor, ensures it's on the prime-order subgroup
    return result.dbl().dbl().dbl();
}

template<typename ppT>
libff::G1<ppT> pedersen_hash_basepoint(const char* name, unsigned int i) {
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

    return point_from_hash<ppT>(data, 32);
}

template<typename ppT>
libff::G1<ppT> pedersen_hash(std::vector<bool> bits){ // pass by reference for more performance (however cannot be const)
    const uint8_t N_WINDOWS = 62;
    const char P13N_EDDSA_VERIFY_RAM[] = "EdDSA_Verify.RAM";

    // Pad with 0 such that len(bits) = 0 (mod 3)
    uint8_t m = bits.size() % 3;
    if (m == 1 || m == 2) {
        bits.insert(bits.end(), 3-m, 0);
    }

    libff::G1<ppT> result = libff::G1<ppT>::zero();
    libff::G1<ppT> current, segment;

    for (size_t i = 0; 3*i < bits.size(); i++){
        // Split bits into 3-bit windows
        uint8_t window = bits[3*i] | bits[3*i+1] << 1 | bits[3*i+2] << 2;
        int j = i % N_WINDOWS;

        if (j == 0){
            current = pedersen_hash_basepoint<ppT>(P13N_EDDSA_VERIFY_RAM, i / N_WINDOWS);
        }else {
            current = current.dbl().dbl().dbl().dbl();
        }

        segment = libff::Fq<ppT>((window & 0b11) + 1) * current;
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

} // namespace libsnark
#endif //LIBSNARK_PEDERSEN_TCC
