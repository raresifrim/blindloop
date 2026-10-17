/** @file
 *****************************************************************************

 interfaces for utilities for using gadgets.

 *****************************************************************************/


#ifndef GADGET_UTILS_H
#define GADGET_UTILS_H

#include <libff/common/utils.hpp>
#include <libff/algebra/field_utils/bigint.hpp>

std::vector<unsigned char> digest_to_bytes(libff::bit_vector bits);
libff::bit_vector bytes_to_digest(std::vector<unsigned char> bytes);
void print_bytes_hex(std::vector<unsigned char> bytes);
libff::bit_vector bytes_to_bits(std::vector<unsigned char> bytes);

int num_bits(unsigned int value);
long integer_division(long a, unsigned int d);


template<typename FieldT>
int field_to_signed_int(FieldT v, size_t n){
    auto val = (FieldT(2<<n) + v).as_bigint();
    if(val.test_bit(n)){
        return -(-v).as_ulong();
    }else{
        return v.as_ulong();
    }
}

template<typename FieldT>
int field_to_signed_int(FieldT v){
    if (v.is_negative()){
        return -(-v).as_ulong();
    }else{
        return v.as_ulong();
    }
}

template<typename FieldT>
long field_to_signed_long(FieldT v){
    if (v.is_negative()){
        return -(-v).as_ulong();
    }else{
        return v.as_ulong();
    }
}

template<typename FieldT>
FieldT integer_division(const FieldT a, unsigned int d){
    libff::bigint<FieldT::num_limbs> q, r;
    q = a.as_bigint() / (int) d;
    r = a - d * q;

    // We need truncation towards -inf
    if (r < 0){
        //r += d;
        q -= 1;
    }
    return q;
}

#endif //GADGET_UTILS_H
