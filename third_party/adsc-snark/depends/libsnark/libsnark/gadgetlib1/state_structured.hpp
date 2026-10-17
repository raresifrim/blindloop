#ifndef STATE_STRUCTURED_HPP
#define STATE_STRUCTURED_HPP

#include <cstdint>
#include <memory>

#include <libsnark/gadgetlib1/pb_variable.hpp>

using namespace libsnark;

template<typename FieldT>
class pb_state_structured {
public:
    pb_variable<FieldT> in;
    pb_variable<FieldT> out;
    const FieldT initial_value;

    pb_state_structured(structured_protoboard<FieldT> &pb, size_t block_in_id, size_t block_out_id, FieldT initial_value=FieldT::zero(), const std::string &annotation=""):
            in(), out(), initial_value(initial_value)
    {
        in.allocate_from_block(pb, block_in_id, FMT(annotation, ".in"));
        out.allocate_from_block(pb, block_out_id, FMT(annotation, ".out"));
    }

    pb_state_structured(const pb_variable<FieldT> &in, const pb_variable<FieldT> &out, FieldT initial_value=FieldT::zero()):
        in(in), out(out), initial_value(initial_value)
    {
    }

    void init(protoboard<FieldT> &pb);
    void update(protoboard<FieldT> &pb);
};

template<typename FieldT>
class state_manager {
public:
    structured_protoboard<FieldT> &pb;
    size_t id_block_in;
    size_t id_block_out;
    std::vector<pb_state_structured<FieldT>> states;

    state_manager(structured_protoboard<FieldT> &pb, size_t id_block_in, size_t id_block_out) :
            pb(pb),
            id_block_in(id_block_in),
            id_block_out(id_block_out),
            states()
    {
    }

    void init();

    void update();

    void add_state(const pb_state_structured<FieldT> &state);

    pb_state_structured<FieldT> allocate_state(FieldT initial_value=FieldT::zero());



};

#include "state_structured.tcc"

#endif //STATE_STRUCTURED_HPP
