// Copyright (c) 2018 HarryR
// License: LGPL-3.0+

#ifndef ETHSNARKS_SHAMIRPOLY_HPP_
#define ETHSNARKS_SHAMIRPOLY_HPP_


#include "ethsnarks.hpp"
#include "utils.hpp"

namespace ethsnarks {


/**
* Implements the polynomial from Shamir's secret-sharing scheme
*
*   f(x) = a_0 + \sum_{i=1}^{k-1} a_i x^i
*
* See: https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing
*/
class shamir_poly : public GadgetT
{
public:
    const VariableT &input;
    const VariableArrayT &alpha;

    const VariableArrayT intermediate_squares;
    const VariableArrayT intermediate_total;

    shamir_poly(
        ProtoboardT &in_pb,
        const VariableT &in_input,
        const VariableArrayT &in_alpha,
        const std::string &annotation_prefix
    ) :
        GadgetT(in_pb, annotation_prefix),

        input(in_input),
        alpha(in_alpha),

        intermediate_squares( make_var_array(pb, in_alpha.size(), FMT(annotation_prefix, ".intermediate_squares")) ),
        intermediate_total( make_var_array(pb, in_alpha.size(), FMT(annotation_prefix, ".intermediate_total")) )
    {
        assert( in_alpha.size() >= 2 );
    }

    const VariableT& result() const
    {
        return intermediate_total[intermediate_total.size() - 1];
    }
    
    /**
    * Constraints are:
    *
    *   A * B - C = 0
    *
    * For the intermediate squares:
    *
    *   (1     * S[0])  - 1      = 0
    *   (input * input) - S[2 ]  = 0
    *   (S[i]  * S[i])  - S[i+1] = 0
    *   ...
    *
    * For the totals:
    *
    *   (A[0] * S[0]) - T[0]            = 0
    *   (A[i] * S[i]) - (T[i] - T[i-1]) = 0
    *   ...
    *
    * For `k` rounds there are `(2*k)-1` constraints
    */
    void generate_r1cs_constraints()
    {
        for( size_t i = 0; i < alpha.size(); i++ )
        {            
            // Intermediate squares
            if( i == 0 ) {
                this->pb.add_r1cs_constraint(
                    ConstraintT(
                        intermediate_squares[i],
                        FieldT::one(),
                        FieldT::one()),
                    FMT(this->annotation_prefix, ".squares[%zu] * 1 = 1", i));
            }
            else if( i == 1 ) {
                // (input * input) - S[2] = 0
                this->pb.add_r1cs_constraint(
                    ConstraintT(
                        input,
                        input,
                        intermediate_squares[i+1]),
                    FMT(this->annotation_prefix, ".squares[%zu] = input * input", i));
            }
            else if( i < (alpha.size() - 1) ) {
                // (I * S[i]) - S[i+1] = 0
                this->pb.add_r1cs_constraint(
                    ConstraintT(
                        input,
                        intermediate_squares[i],
                        intermediate_squares[i+1]),
                    FMT(this->annotation_prefix, ".squares[%zu] = input * squares[%zu]", i+1, i));
            }

            // Totals
            // TODO: convert into a single LinearCombinationT?
            if( i == 0 ) {
                // (A[0] * S[0]) - T[0] = 0
                this->pb.add_r1cs_constraint(
                    ConstraintT(
                        alpha[i],
                        intermediate_squares[i],
                        intermediate_total[i]),
                    FMT(this->annotation_prefix, ".total[%zu] = alpha[%zu] * squares[%zu]", i, i, i));
            }
            else {
                // (A[i] * S[i]) - (T[i] - T[i-1]) = 0
                this->pb.add_r1cs_constraint(
                    ConstraintT(
                        alpha[i],
                        intermediate_squares[i],
                        (intermediate_total[i] - intermediate_total[i-1])),
                    FMT(this->annotation_prefix, ".alpha[%zu] * squares[%zu] = (total[%zu] - total[%zu])", i, i, i, i-1));
            }
        }
    }

    /**
    * f(x) = a_0 + \sum_{i=1}^{k-1} a_i x^i
    *
    *   S[0] = 1
    *   S[1...k] = input^i
    *   T[i] = A[i] * S[i]
    *
    * Which becomes:
    *
    *   T[0] = A[0] * S[0] = A[0] * 1 = A[0]
    *   T[1] = T[0] + (A[1] * S[1]) = T[0] + (A[i] * input)
    *   T[2] = T[1] + (A[2] * S[2]) = T[1] + (A[i] * input^2)
    *   etc.
    *
    * Where
    *
    *   T = totals (intermediates)
    *   A = alpha (secret input)
    *   S = intermediate squares, used to multiply alpha to get total
    */
    void generate_r1cs_witness()
    {
        FieldT total = FieldT::zero();

        for( size_t i = 0; i < alpha.size(); i++ )
        {
            if( i == 0 ) {
                this->pb.val(intermediate_squares[i]) = FieldT::one();
            }
            else {
                this->pb.val(intermediate_squares[i]) = this->pb.val(input)^i;
            }

            total += this->pb.val(alpha[i]) * this->pb.val(intermediate_squares[i]);

            this->pb.val(intermediate_total[i]) = total;
        }
    }

    void generate_r1cs_witness( const FieldT &in_input )
    {
        this->pb.val(input) = in_input;

        this->generate_r1cs_witness();
    }
};


// namespace ethsnarks
}

// ETHSNARKS_SHAMIRPOLY_HPP_
#endif
