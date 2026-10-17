/** @file
 *****************************************************************************

 Declaration of interfaces for state gadget

 State gadget computes hashes for state and state-update. There are two versions:
 1. state_gadget_pedersen: Uses pedersen hash, needs to serialize state
 2. state_gadget_poseidon: Uses poseidon hash, no serialization of state

 *****************************************************************************/

#ifndef STATE_GADGET_H
#define STATE_GADGET_H

#include <cstdint>
#include <memory>

#include "depends/libsnark/libsnark/gadgetlib1/gadget.hpp"
#include "depends/libsnark/libsnark/gadgetlib1/protoboard.hpp"

#include "depends/ethsnarks/src/jubjub/pedersen_hash.hpp"
#include "depends/ethsnarks/src/gadgets/poseidon_orig.hpp"

template<typename FieldT>
class pb_state {
public:
    libsnark::pb_variable<FieldT> in;
    libsnark::pb_variable<FieldT> out;
    const int bits_stored; // how many bits need to be stored for this state
    const bool is_signed;
    const FieldT initial_value;
    pb_state(int bits_stored=16, bool is_signed=true, FieldT initial_value=FieldT::zero()):
            in(), out(), bits_stored(bits_stored), is_signed(is_signed), initial_value(initial_value)
    {
    }

    pb_state(const libsnark::pb_variable<FieldT> &in, const libsnark::pb_variable<FieldT> &out, int bits_stored=16, bool is_signed=true, FieldT initial_value=FieldT::zero()):
        in(in), out(out), bits_stored(bits_stored), is_signed(is_signed), initial_value(initial_value)
    {
    }

    void allocate(libsnark::protoboard<FieldT> &pb, const std::string &annotation="");

    void init(libsnark::protoboard<FieldT> &pb);
    void update(libsnark::protoboard<FieldT> &pb);
};

template<typename FieldT>
class state_gadget_pedersen : public libsnark::gadget<FieldT>{
private:
    const ethsnarks::jubjub::Params params;
    std::vector<pb_state<FieldT>> variables;
    std::shared_ptr<ethsnarks::jubjub::PedersenHash> m_pedersen_in;
    std::shared_ptr<ethsnarks::jubjub::PedersenHash> m_pedersen_out;
    std::vector<libsnark::packing_gadget<FieldT>> pack_in_gadgets;
    std::vector<libsnark::packing_gadget<FieldT>> pack_out_gadgets;

    libsnark::pb_variable_array<FieldT> state_in_bits;
    libsnark::pb_variable_array<FieldT> state_out_bits;

    // These two variables are overhead and cost two constraints (equality)
    // But the variables they are set equal to are allocated in pedersen hash gadget
    // and therefore cannot be easily made public
    const libsnark::pb_variable<FieldT> &digest_in;
    const libsnark::pb_variable<FieldT> &digest_out;
public:

    state_gadget_pedersen(libsnark::protoboard<FieldT> &pb,
                 std::vector<pb_state<FieldT>> variables,
                 const libsnark::pb_variable<FieldT> &digest_in,
                 const libsnark::pb_variable<FieldT> &digest_out,
                 const std::string &annotation_prefix=""):
            libsnark::gadget<FieldT>(pb, annotation_prefix),
                         variables(variables),
                        pack_in_gadgets(), pack_out_gadgets(),
                         digest_in(digest_in), digest_out(digest_out)
    {

        libsnark::pb_linear_combination_array<FieldT> variables_in;
        libsnark::pb_linear_combination_array<FieldT> variables_out;
        for(size_t i=0; i < variables.size(); i++){
            variables_in.push_back(variables[i].in);
            variables_out.push_back(variables[i].out);
        }

    };

    void generate_r1cs_constraints ();

    void generate_r1cs_witness ();

    /**
     * allocate variables in protoboard
     * Allocate has to be called before init
     * Usually, these things are completed in the constructor of the gadget,
     * however, moving allocate outside allows adding additional states
     */
    void allocate();

    void add_state(const pb_state<FieldT> &state);

    void init();
    void update();

    FieldT get_current_state_digest();
};


template<typename FieldT>
class state_gadget_poseidon : public libsnark::gadget<FieldT>{
private:
    std::vector<pb_state<FieldT>> variables;
    std::shared_ptr<ethsnarks::PoseidonSponge_Precomputed<false>> m_hash_in;
    std::shared_ptr<ethsnarks::PoseidonSponge_Precomputed<false>> m_hash_out;

    ethsnarks::LinearCombinationArrayT inputs_in;
    ethsnarks::LinearCombinationArrayT inputs_out;

    const libsnark::pb_variable<FieldT> &digest_in;
    const libsnark::pb_variable<FieldT> &digest_out;
public:

    state_gadget_poseidon(libsnark::protoboard<FieldT> &pb,
                          std::vector<pb_state<FieldT>> variables,
                          const libsnark::pb_variable<FieldT> &digest_in,
                          const libsnark::pb_variable<FieldT> &digest_out,
                          const std::string &annotation_prefix=""):
            libsnark::gadget<FieldT>(pb, annotation_prefix),
            variables(variables),
            digest_in(digest_in), digest_out(digest_out)
    {

        libsnark::pb_linear_combination_array<FieldT> variables_in;
        libsnark::pb_linear_combination_array<FieldT> variables_out;
        for(size_t i=0; i < variables.size(); i++){
            variables_in.push_back(variables[i].in);
            variables_out.push_back(variables[i].out);
        }

    };

    void generate_r1cs_constraints ();

    void generate_r1cs_witness ();

    /**
     * allocate variables in protoboard
     * Allocate has to be called before init
     * Usually, these things are completed in the constructor of the gadget,
     * however, moving allocate outside allows adding additional states
     */
    void allocate();

    void add_state(const pb_state<FieldT> &state);

    void init();
    void update();

    FieldT get_current_state_digest();
};

//template<typename FieldT>
//using state_gadget = state_gadget_pedersen<FieldT>;

template<typename FieldT>
using state_gadget = state_gadget_poseidon<FieldT>;

#include "state_gadget.tcc"

#endif //STATE_GADGET_H
