/** @file
 *****************************************************************************

 Declaration of interfaces for sequence check gadget

 The sequency check gadget has a state and checks, that the state is
 incremented by 1

 *****************************************************************************/

#ifndef SEQUENCE_CHECK_GADGET_H
#define SEQUENCE_CHECK_GADGET_H

#include "depends/libsnark/libsnark/gadgetlib1/gadget.hpp"
#include "state_gadget.hpp"

// sequence check gadget
// checks n = n_old + 1
template<typename FieldT>
class sequence_check_gadget : public libsnark::gadget<FieldT> {
private:
public:
    pb_state<FieldT> &n;

    sequence_check_gadget(libsnark::protoboard<FieldT>& pb,
                          pb_state<FieldT> &value,
                          state_gadget<FieldT> &s_gadget,
                          const std::string &annotation_prefix="") :
            libsnark::gadget<FieldT>(pb, annotation_prefix), n(value)
    {
        s_gadget.add_state(n);
    }

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

#include "sequence_check_gadget.tcc"

#endif // SEQUENCE_CHECK_GADGET_H