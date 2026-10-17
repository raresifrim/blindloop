/** @file
 *****************************************************************************

 Implementation of interfaces for state gadget.

 See state_gadget.hpp .

 *****************************************************************************/

#include "state_gadget.hpp"

template<typename FieldT>
void pb_state<FieldT>::init(libsnark::protoboard<FieldT> &pb) {
    pb.val(in) = initial_value;
    pb.val(out) = initial_value;
}

template<typename FieldT>
void pb_state<FieldT>::update(libsnark::protoboard<FieldT> &pb) {
    pb.val(in) = pb.val(out);
}

template<typename FieldT>
void pb_state<FieldT>::allocate(libsnark::protoboard<FieldT> &pb, const std::string &annotation){
    in.allocate(pb, FMT(annotation, ".in"));
    out.allocate(pb, FMT(annotation, ".out"));
}

template<typename FieldT>
void state_gadget_pedersen<FieldT>::generate_r1cs_constraints ()
{
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(1, digest_in, m_pedersen_in->result_x()), FMT(this->annotation_prefix, "(digest_in=pedersen_in_digest)"));
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(1, digest_out, m_pedersen_out->result_x()), FMT(this->annotation_prefix, "(digest_out=pedersen_out_digest)"));
    for(size_t i=0; i < variables.size(); i++){
        pack_in_gadgets[i].generate_r1cs_constraints(true);
        pack_out_gadgets[i].generate_r1cs_constraints(true);
    }
    m_pedersen_in->generate_r1cs_constraints();
    m_pedersen_out->generate_r1cs_constraints();
}

template<typename FieldT>
void state_gadget_pedersen<FieldT>::generate_r1cs_witness ()
{
    for(size_t i=0; i < variables.size(); i++){
        pack_in_gadgets[i].generate_r1cs_witness_from_packed();
        pack_out_gadgets[i].generate_r1cs_witness_from_packed();
    }
    m_pedersen_in->generate_r1cs_witness();
    m_pedersen_out->generate_r1cs_witness();
    this->pb.val(digest_in) = this->pb.val(m_pedersen_in->result_x());
    this->pb.val(digest_out) = this->pb.val(m_pedersen_out->result_x());
}

template<typename FieldT>
void state_gadget_pedersen<FieldT>::init ()
{
    for(size_t i = 0; i < variables.size(); i++){
        variables[i].init(this->pb);
    }
}

template<typename FieldT>
void state_gadget_pedersen<FieldT>::allocate ()
{
    for(size_t i=0; i < this->variables.size(); i++){
        int offset;
        libsnark::pb_variable_array<FieldT> bits_in, bits_out;
        bits_in.allocate(this->pb, variables[i].bits_stored, FMT(this->annotation_prefix, ".bits_in_%d", i));
        state_in_bits.insert(state_in_bits.end(), bits_in.begin(), bits_in.end());
        libsnark::pb_linear_combination<FieldT> val_in;
        // shift value, if it is signed
        offset = variables[i].is_signed ? 1 << (variables[i].bits_stored - 1) : 0;
        val_in.assign(this->pb, variables[i].in + offset*libsnark::ONE);
        libsnark::packing_gadget<FieldT> pack_in(this->pb, bits_in, val_in, FMT(this->annotation_prefix, ".pack_state_in_%i", i));


        bits_out.allocate(this->pb, variables[i].bits_stored, FMT(this->annotation_prefix, ".bits_out_%d", i));
        state_out_bits.insert(state_out_bits.end(), bits_out.begin(), bits_out.end());
        libsnark::pb_linear_combination<FieldT> val_out;
        offset = variables[i].is_signed ? 1 << (variables[i].bits_stored - 1) : 0;
        val_out.assign(this->pb, variables[i].out + offset*libsnark::ONE);
        libsnark::packing_gadget<FieldT> pack_out(this->pb, bits_out, val_out, FMT(this->annotation_prefix, ".pack_state_out_%i", i));

        pack_in_gadgets.push_back(pack_in);
        pack_out_gadgets.push_back(pack_out);
    }

    m_pedersen_in.reset(new ethsnarks::jubjub::PedersenHash(this->pb, params, "State storage", state_in_bits, FMT(this->annotation_prefix, ".m_pedersen_in")));
    m_pedersen_out.reset(new ethsnarks::jubjub::PedersenHash(this->pb, params, "State storage", state_out_bits, FMT(this->annotation_prefix, ".m_pedersen_out")));
}

template<typename FieldT>
void state_gadget_pedersen<FieldT>::add_state(const pb_state<FieldT> &state)
{
    assert(state.bits_stored > 0);
    variables.push_back(state);
}

template<typename FieldT>
void state_gadget_pedersen<FieldT>::update ()
{
    for(size_t i = 0; i < variables.size(); i++){
        variables[i].update(this->pb);
    }
}

template<typename FieldT>
FieldT state_gadget_pedersen<FieldT>::get_current_state_digest()
{
    this->generate_r1cs_witness();
    return this->pb.val(digest_in);
}

template<typename FieldT>
void state_gadget_poseidon<FieldT>::generate_r1cs_constraints ()
{
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(1, digest_in, m_hash_in->result()), FMT(this->annotation_prefix, "(digest_in=hash_in_result)"));
    this->pb.add_r1cs_constraint(libsnark::r1cs_constraint<FieldT>(1, digest_out, m_hash_out->result()), FMT(this->annotation_prefix, "(digest_out=hash_out_result)"));
    m_hash_in->generate_r1cs_constraints();
    m_hash_out->generate_r1cs_constraints();
}

template<typename FieldT>
void state_gadget_poseidon<FieldT>::generate_r1cs_witness ()
{
    m_hash_in->generate_r1cs_witness();
    m_hash_out->generate_r1cs_witness();
    m_hash_in->result().evaluate(this->pb);
    m_hash_out->result().evaluate(this->pb);
    this->pb.val(digest_in) = this->pb.lc_val(m_hash_in->result());
    this->pb.val(digest_out) = this->pb.lc_val(m_hash_out->result());
}

template<typename FieldT>
void state_gadget_poseidon<FieldT>::init ()
{
    for(size_t i = 0; i < variables.size(); i++){
        variables[i].init(this->pb);
    }
}

template<typename FieldT>
void state_gadget_poseidon<FieldT>::allocate ()
{
    for(size_t i = 0; i < variables.size(); i++){
        inputs_in.push_back(variables[i].in);
        inputs_out.push_back(variables[i].out);
    }
    m_hash_in.reset(new ethsnarks::PoseidonSponge_Precomputed<false>(this->pb, inputs_in, FMT(this->annotation_prefix, ".m_hash_in")));
    m_hash_out.reset(new ethsnarks::PoseidonSponge_Precomputed<false>(this->pb, inputs_out, FMT(this->annotation_prefix, ".m_hash_out")));
}

template<typename FieldT>
void state_gadget_poseidon<FieldT>::add_state(const pb_state<FieldT> &state)
{
    assert(state.bits_stored > 0);
    variables.push_back(state);
}

template<typename FieldT>
void state_gadget_poseidon<FieldT>::update ()
{
    for(size_t i = 0; i < variables.size(); i++){
        variables[i].update(this->pb);
    }
}

template<typename FieldT>
FieldT state_gadget_poseidon<FieldT>::get_current_state_digest()
{
    this->generate_r1cs_witness();
    return this->pb.val(digest_in);
}