/** @file
 *****************************************************************************

 Implementation of interfaces for duplex voter gadget.

 See duplex_voter_gadget.hpp

 *****************************************************************************/

#include "duplex_voter_gadget.hpp"

template<typename FieldT>
void duplex_voter_gadget<FieldT>::generate_r1cs_constraints()
{
    input_limit_gadget->generate_r1cs_constraints();
    division->generate_r1cs_constraints();
}

template<typename FieldT>
void duplex_voter_gadget<FieldT>::generate_r1cs_witness()
{
    input_limit_gadget->generate_r1cs_witness();
    division->generate_r1cs_witness();
}

