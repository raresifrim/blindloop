#ifndef JUBJUB_FIXEDMULT_HPP_
#define JUBJUB_FIXEDMULT_HPP_

// Copyright (c) 2018 @HarryR
// License: LGPL-3.0+

#include "gadgets/lookup_2bit.hpp"
#include "gadgets/lookup_3bit_zcash.hpp"
#include "jubjub/adder.hpp"
#include "jubjub/montgomery.hpp"


namespace ethsnarks {

namespace jubjub {


/**
* Implements scalar multiplication using a fixed base point and a 2-bit lookup window 
*
*     input bits 0...n   with 2 bit lookup  windows
*   +--------+----------+------------+-----------+---....
*   |  0-2   |    3-4   |    5-6     |    7-8    |   9-.
*   +--------+----------+------------+-----------+---....
*      | |        | |        | |          | |         | |
*   +------+   +------+    +------+     +------+     +...
*   | LUT0 |   | LUT1 |    | LUT2 |     | LUTn |     |
*   +------+   +------+    +------+     +------+     +...
*       |          |          |            |            |
*   +-----------------+   +---------+  +---------+   +...
*   |      ADDER 0    |---| ADDER 1 |--| ADDER n |---|
*   +-----------------+   +---------+  +---------+   +...
*
*/
class fixed_base_mul : public GadgetT {
public:
	//const VariableArrayT& m_scalar;

	std::vector<PointAdder> m_adders;
	std::vector<lookup_2bit_gadget> m_windows_x;
	std::vector<lookup_2bit_gadget> m_windows_y;

	fixed_base_mul(
		ProtoboardT &in_pb,
		const Params& in_params,
		const FieldT& in_base_x,
		const FieldT& in_base_y,
		const VariableArrayT& in_scalar,
		const std::string &annotation_prefix
	);

	void generate_r1cs_constraints ();

	void generate_r1cs_witness ();

	const VariableT& result_x() const;

	const VariableT& result_y() const;
};


/**
* Implements scalar multiplication using a fixed base point and a 3-bit lookup window in edwards coordinates
*
*
*/
class fixed_base_mul_ed_3b : public GadgetT {
    public:
        //const VariableArrayT& m_scalar;

        std::vector<PointAdder> m_adders;
        std::vector<lookup_3bitx2_zcash_gadget> m_windows;

    fixed_base_mul_ed_3b(
                ProtoboardT &in_pb,
                const Params& in_params,
                const FieldT& in_base_x,
                const FieldT& in_base_y,
                const VariableArrayT& in_scalar,
                const std::string &annotation_prefix
        );

    void generate_r1cs_constraints ();

    void generate_r1cs_witness ();

    const VariableT& result_x() const;

    const VariableT& result_y() const;
};

/**
* Implements scalar multiplication using a fixed base point and a 3-bit lookup window in montgomery coordinates
* scalar must be 0 < s < p - n/3
*
*/
class fixed_base_mul_mg_3b : public GadgetT {
public:
    //const VariableArrayT& m_scalar;

    std::vector<MontgomeryAdder> m_adders;
    std::vector<PointAdder> m_adders_ed; // edwards point addition for large numbers, that could lead to special case not covered by incomplete montgomery point addition
    std::vector<lookup_3bitx2_zcash_gadget> m_windows;
    std::shared_ptr<PointAdder> m_sub;
    std::shared_ptr<MontgomeryToEdwards> m_point_converter;

    fixed_base_mul_mg_3b(
            ProtoboardT &in_pb,
            const Params& in_params,
            const FieldT& in_base_x,
            const FieldT& in_base_y,
            const VariableArrayT &in_scalar,
            const std::string &annotation_prefix
    );

    void generate_r1cs_constraints ();

    void generate_r1cs_witness ();

    const VariableT& result_x() const;

    const VariableT& result_y() const;
};

// namespace jubjub
}

// namespace ethsnarks
}

// JUBJUB_FIXEDMULT_HPP_
#endif
