/** @file
 *****************************************************************************

 utilities for gadgets.

 *****************************************************************************/

#include "utils.h"

std::vector<unsigned char> digest_to_bytes(libff::bit_vector bits){
    std::vector<unsigned char> result;
    result.reserve(bits.size()/8);
    unsigned char h;
    for(size_t i = 0; i < bits.size()/8; i++){
        h = 0;
        for(int j = 0; j < 8; j++){
            h = h << 1;
            h += bits[8*i+j];
        }
        result.emplace_back(h);
    }
    return result;
}

libff::bit_vector bytes_to_digest(std::vector<unsigned char> bytes){
    libff::bit_vector bits;
    bits.reserve(bytes.size()*8);
    for(size_t i = 0; i < bytes.size(); i++){
        for(int j = 7; j >= 0; --j){
            bits.emplace_back((bytes[i] >> j) & 0x01);
        }
    }
    return bits;
}

// digest_to_bytes and bytes to bits use different bit ordering!
libff::bit_vector bytes_to_bits(std::vector<unsigned char> bytes){
    libff::bit_vector bits;
    bits.reserve(bytes.size()*8);
    for(size_t i = 0; i < bytes.size(); i++){
        for(int j = 0; j < 8; ++j){
            bits.emplace_back((bytes[i] >> j) & 0x01);
        }
    }
    return bits;
}

void print_bytes_hex(std::vector<unsigned char> bytes){
    for (size_t i = 0; i < bytes.size(); i++){
        printf("%02X", bytes[i]);
    }
}

int num_bits(unsigned int value){
    int n = 0;
    while(value > 0){
        value >>= 1;
        n += 1;
    }
    return n;
}

/**
 * Integer division with truncation towards -inf
 */
long integer_division(long a, unsigned int d){
    long q, r;
    q = a / (long) d; // this operation should truncate towards zero for modern compilers. This is not guaranteed by all compilers (C89 or older)

    r = a - d * q;

    // We need truncation towards -inf
    if (r < 0){
        q -= 1;
    }
    return q;
}


