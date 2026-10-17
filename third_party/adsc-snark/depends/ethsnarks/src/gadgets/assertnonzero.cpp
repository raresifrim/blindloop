// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "gadgets/assertnonzero.hpp"
#include "utils.hpp"
#include <libsnark/gadgetlib1/gadgets/basic_gadgets.hpp>

using libsnark::generate_boolean_r1cs_constraint;

namespace ethsnarks {


AssertNonZero::AssertNonZero(
	ProtoboardT& in_pb,
    const VariableT& in_var,
    const std::string &annotation_prefix
) :
	GadgetT(in_pb, annotation_prefix),
	m_X(in_var),
	m_M(make_variable(in_pb, FMT(this->annotation_prefix, ".M")))
{

}

void AssertNonZero::generate_r1cs_constraints()
{

	this->pb.add_r1cs_constraint(
		ConstraintT(m_X, m_M, libsnark::ONE),
		FMT(this->annotation_prefix, " X * (1/X) = 1"));
}


void AssertNonZero::generate_r1cs_witness()
{
	const auto X = this->pb.val(m_X);
    assert(!X.is_zero());
    this->pb.val(m_M) = X.inverse();
}

	
// namespace ethsnarks
}
