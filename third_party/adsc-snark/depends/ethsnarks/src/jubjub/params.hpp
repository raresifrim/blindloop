#ifndef JUBJUB_PARAMS_HPP_
#define JUBJUB_PARAMS_HPP_

#include "ethsnarks.hpp"


namespace ethsnarks {

namespace jubjub {

class Params {
public:
    // Base point
    const FieldT Gx;
    const FieldT Gy;

    // twisted Edwards parameters
    const FieldT a;
    const FieldT d;

    // Montgomery parameters
    const FieldT A;
    const FieldT scale;

    Params() :
        Gx(default_inner_ec_pp::inner2outer(libff::G1<default_inner_ec_pp>::G1_one.Y)), // G1 is in inverted coordinates
        Gy(default_inner_ec_pp::inner2outer(libff::G1<default_inner_ec_pp>::G1_one.X)),
        a(default_inner_ec_pp::inner2outer(libff::G1<default_inner_ec_pp>::coeff_a)),
        d(default_inner_ec_pp::inner2outer(libff::G1<default_inner_ec_pp>::coeff_d)),
        A(default_inner_ec_pp::inner2outer(libff::G1<default_inner_ec_pp>::coeff_a - 2)),
        scale("1")
            {
//#ifdef DEBUG
//                std::cout << "Params (Jubjub)" << std::endl;
//                std::cout << "Gx " << Gx << std::endl;
//                std::cout << "Gy " << Gy << std::endl;
//                std::cout << "a " << a << std::endl;
//                std::cout << "d " << d << std::endl;
//                std::cout << "A " << A << std::endl;
//                std::cout << "scale " << scale << std::endl;
//#endif
                assert(libff::G1<default_inner_ec_pp>::initialized);
                assert(libff::G1<default_inner_ec_pp>::G1_one.Z == libff::G1<default_inner_ec_pp>::G1_one.X*libff::G1<default_inner_ec_pp>::G1_one.Y);
                assert(d == A - 2);
            }
};


// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_PARAMS_HPP_
#endif
