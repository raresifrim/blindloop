// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "jubjub/adder.hpp"
#include "utils.hpp"


namespace ethsnarks {

namespace jubjub {


PointAdder::PointAdder(
    ProtoboardT& in_pb,
    const Params& in_params,
    const LinearCombinationT in_X1,
    const LinearCombinationT in_Y1,
    const LinearCombinationT in_X2,
    const LinearCombinationT in_Y2,
    const std::string &annotation_prefix
) :
    GadgetT(in_pb, annotation_prefix),
    m_params(in_params),
    m_X1(in_X1), m_Y1(in_Y1),
    m_X2(in_X2), m_Y2(in_Y2),
    m_beta(make_variable(in_pb, FMT(annotation_prefix, ".beta"))),
    m_gamma(make_variable(in_pb, FMT(annotation_prefix, ".gamma"))),
    //m_delta(make_variable(in_pb, FMT(annotation_prefix, ".delta"))),
    //m_epsilon(make_variable(in_pb, FMT(annotation_prefix, ".epsilon"))),

    m_rho(make_variable(in_pb, FMT(annotation_prefix, ".rho"))),

    m_tau(make_variable(in_pb, FMT(annotation_prefix, ".tau"))),
    m_X3(make_variable(in_pb, FMT(annotation_prefix, ".X3"))),
    m_Y3(make_variable(in_pb, FMT(annotation_prefix, ".Y3")))
{

}


void PointAdder::generate_r1cs_constraints()
{
    this->pb.add_r1cs_constraint(
        ConstraintT(m_X1, m_Y2, m_beta),
            FMT(annotation_prefix, ".beta = X1 * Y2"));

    this->pb.add_r1cs_constraint(
        ConstraintT(m_Y1, m_X2, m_gamma),
            FMT(annotation_prefix, ".gamma = Y1 * X2"));

//    this->pb.add_r1cs_constraint(
//        ConstraintT(m_Y1, m_Y2, m_delta),
//            FMT(annotation_prefix, ".delta = Y1 * Y2"));
//
//    this->pb.add_r1cs_constraint(
//        ConstraintT(m_X1, m_X2, m_epsilon),
//            FMT(annotation_prefix, ".epsilon = X1 * X2"));

    this->pb.add_r1cs_constraint(
        ConstraintT(m_X1 + m_Y1, m_Y2 - m_params.a*m_X2, m_rho),
            FMT(annotation_prefix, ".rho = (x1 + y1)*(y2 -ax2)"));

//    this->pb.add_r1cs_constraint(
//        ConstraintT(m_delta, m_epsilon, m_tau),
//            FMT(annotation_prefix, ".tau = delta * epsilon"));

    this->pb.add_r1cs_constraint(
            ConstraintT(m_params.d*m_beta, m_gamma, m_tau),
            FMT(annotation_prefix, ".tau = d * beta * gamma"));

//    this->pb.add_r1cs_constraint(
//        ConstraintT(m_X3, 1 + (m_params.d*m_tau), m_beta + m_gamma),
//            FMT(annotation_prefix, ".x3 * (1 + (d*tau)) == (beta + gamma) "));

    this->pb.add_r1cs_constraint(
            ConstraintT(m_X3, 1 + m_tau, m_beta + m_gamma),
            FMT(annotation_prefix, ".x3 * (1 + tau) == (beta + gamma) "));

//    this->pb.add_r1cs_constraint(
//        ConstraintT(m_Y3, 1 - (m_params.d*m_tau), m_delta + ((-m_params.a)*m_epsilon)),
//            FMT(annotation_prefix, ".y3 * (1 - (d*tau)) == (delta - a*epsilon) "));

    this->pb.add_r1cs_constraint(
            ConstraintT(m_Y3, 1 - m_tau, m_rho - m_beta + ((m_params.a)*m_gamma)),
            FMT(annotation_prefix, ".y3 * (1 - tau) == (rho - beta + a*gamma) "));
}


const VariableT& PointAdder::result_x() const
{
    return m_X3;
}


const VariableT& PointAdder::result_y() const
{
    return m_Y3;
}


void PointAdder::generate_r1cs_witness()
{
    this->pb.val(m_beta) = this->pb.lc_val(m_X1) * this->pb.lc_val(m_Y2);

    this->pb.val(m_gamma) = this->pb.lc_val(m_Y1) * this->pb.lc_val(m_X2);

    //this->pb.val(m_delta) = this->pb.val(m_Y1) * this->pb.val(m_Y2);
    //this->pb.val(m_epsilon) = this->pb.val(m_X1) * this->pb.val(m_X2);
    this->pb.val(m_rho) = (this->pb.lc_val(m_X1) + this->pb.lc_val(m_Y1)) * (this->pb.lc_val(m_Y2) - m_params.a*this->pb.lc_val(m_X2));

    //this->pb.val(m_tau) = this->pb.val(m_delta) * this->pb.val(m_epsilon);
    this->pb.val(m_tau) = m_params.d*this->pb.val(m_beta) * this->pb.val(m_gamma);

    //auto x3_rhs = (FieldT::one() + (m_params.d * this->pb.val(m_tau))).inverse();
    //this->pb.val(m_X3) = (this->pb.val(m_beta)+this->pb.val(m_gamma)) * x3_rhs;
    auto x3_rhs = (FieldT::one() + this->pb.val(m_tau)).inverse();
    this->pb.val(m_X3) = (this->pb.val(m_beta)+this->pb.val(m_gamma)) * x3_rhs;

    //auto y3_rhs = (FieldT::one() - (m_params.d * this->pb.val(m_tau))).inverse();
    //this->pb.val(m_Y3) = (this->pb.val(m_delta)+( -m_params.a * this->pb.val(m_epsilon))) * y3_rhs;
    auto y3_rhs = (FieldT::one() - this->pb.val(m_tau)).inverse();
    this->pb.val(m_Y3) = (this->pb.val(m_rho)-this->pb.val(m_beta)+( m_params.a * this->pb.val(m_gamma))) * y3_rhs;
}


// namespace jubjub
}

// namespace ethsnarks
}
