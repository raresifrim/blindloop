/** @file
*****************************************************************************

strawman ADSC-SNARK

An ADSC-SNARK proves iterative and stateful computations on authenticated data  
*****************************************************************************/

#ifndef STRAWMAN_ADSCSNARK_TCC_
#define STRAWMAN_ADSCSNARK_TCC_

#include "strawman_adscsnark.hpp"

template<typename ppT>
std::ostream& operator<<(std::ostream &out, const strawman_adscsnark_proof<ppT> &proof)
{
    out << proof.snark_proof << OUTPUT_NEWLINE;
    out << proof.hash  << OUTPUT_NEWLINE;
    return out;
}

template<typename ppT>
std::istream& operator>>(std::istream &in, strawman_adscsnark_proof<ppT> &proof)
{
    in >> proof.snark_proof;
    libff::consume_OUTPUT_NEWLINE(in);
    in >> proof.hash;
    libff::consume_OUTPUT_NEWLINE(in);
    return in;
}

template<typename FieldT>
void linear_combination_remap(libsnark::linear_combination<FieldT> &lc, const std::map<size_t, size_t> &variable_map){
    for(size_t i = 0; i < lc.terms.size(); ++i){
        lc.terms[i].index = variable_map.at(lc.terms[i].index);
    }
}

template<typename FieldT>
libsnark::r1cs_constraint<FieldT> r1cs_constraint_remap(const libsnark::r1cs_constraint<FieldT> &constraint, const std::map<size_t, size_t> &variable_map){
    libsnark::r1cs_constraint<FieldT> result(constraint);
    linear_combination_remap<FieldT>(result.a, variable_map);
    linear_combination_remap<FieldT>(result.b, variable_map);
    linear_combination_remap<FieldT>(result.c, variable_map);
    return result;
}

template<typename ppT>
std::vector<strawman_adscsnark_authentication_keypair<ppT>> strawman_adscsnark_generator_auth(const std::vector<size_t> &private_input_blocks){
    size_t num_keys = 1;
    if(private_input_blocks.size() > 0){
        num_keys = private_input_blocks.size();
    }
    std::vector<strawman_adscsnark_authentication_keypair<ppT>> auth_keys;
    auth_keys.reserve(num_keys);
    for(size_t i = 0; i < num_keys; ++i){
        auth_keys.push_back(libsnark::eddsa_sf_generate<EC_Inner<ppT>>());
    }
    return auth_keys;
}

template<typename ppT>
strawman_adscsnark_relation<libff::Fr<ppT>> r1cs_example_to_r1cs_strawman_adsc(const libsnark::r1cs_adsc_example<libff::Fr<ppT>> &example, const std::vector<strawman_adscsnark_authentication_keypair<ppT>> &keys, const std::vector<size_t> &private_input_blocks){
    strawman_adscsnark_relation<libff::Fr<ppT>> relation;

    relation.primary_input_size = example.primary_input[0].size();
    relation.private_input_size = example.private_input[0].size();
    relation.state_size = example.state_assignment[0].size();
    relation.witness_size = example.witness_assignment[0].size();
    relation.iterations = example.primary_input.size();

    std::vector<size_t> accumulated_input_block_size;
    libsnark::pb_variable<libff::Fr<ppT>> dummy;

    relation.variable_map[0] = 0;
    if(private_input_blocks.size() == 0)
    {
        // Default case, just one authentication key for entire private-input-block
        accumulated_input_block_size.push_back(relation.private_input_size);
    } else
    {
        // Otherwise check, that all inputs are covered
        size_t acc = 0;
        for(size_t i = 0; i < private_input_blocks.size(); ++i){
            assert(private_input_blocks[i] != 0);
            acc += private_input_blocks[i];
            accumulated_input_block_size.push_back(acc);
        }
        assert(acc == relation.private_input_size);
    }
    assert(keys.size() == accumulated_input_block_size.size());

    // public input/output
    for(size_t i = 0; i < relation.primary_input_size; ++i){
        dummy.allocate(relation.pb);
        relation.variable_map[1+i] = dummy.index;
    }

    // digest for state
    relation.state_in_digest.allocate(relation.pb, "state_in_digest");
    relation.state_out_digest.allocate(relation.pb, "state_out_digest");
    relation.s_gadget.reset(new state_gadget<libff::Fr<ppT>>(relation.pb, {}, relation.state_in_digest, relation.state_out_digest, "state_gadget"));
    relation.counter.allocate(relation.pb, "counter");
    relation.sc_gadget.reset(new sequence_check_gadget<libff::Fr<ppT>>(relation.pb, relation.counter, *relation.s_gadget, "sequece_check_gadget"));


    // private input
    for(size_t i = 0; i < relation.private_input_size; ++i){
        dummy.allocate(relation.pb, FMT("private_input_", "%d", i));
        relation.variable_map[1+relation.primary_input_size+i] = dummy.index;
    }

    // private input signatures
    {
        size_t j = 0;
        for (size_t i = 0; i < keys.size(); ++i) {
            relation.signature_gadgets.push_back(signature_gadget<libff::Fr<ppT>>(relation.pb, keys[i].pubkey, FMT("signature_gadget", "%d", i)));
            // connect private inputs to corresponding signature gadget
            while(j  < accumulated_input_block_size[i]){
                relation.signature_gadgets[i].add_variable(relation.variable_map[1+relation.primary_input_size+j]);
                ++j;
            }
            // last input is counter
            relation.signature_gadgets[i].add_variable(relation.counter.in);
        }
    }


    // states
    for(size_t i = 0; i < 2*relation.state_size; ++i){
        dummy.allocate(relation.pb, FMT("state_", "%d", i));
        relation.variable_map[1+relation.primary_input_size+relation.private_input_size+i] = dummy.index;
    }

    // Connect state variables to state gadget
    for(size_t i = 0; i < relation.state_size; ++i){
        relation.s_gadget->add_state(pb_state<libff::Fr<ppT>>(libsnark::pb_variable<libff::Fr<ppT>>(relation.variable_map.at(1+relation.primary_input_size+relation.private_input_size+i)),
                                                              libsnark::pb_variable<libff::Fr<ppT>>(relation.variable_map.at(1+relation.primary_input_size+relation.private_input_size+relation.state_size+i))));
    }

    // witness
    for(size_t i = 0; i < relation.witness_size; ++i){
        dummy.allocate(relation.pb, FMT("witness_", "%d", i));
        relation.variable_map[1+relation.primary_input_size+relation.private_input_size+2*relation.state_size+i] = dummy.index;
    }

    // additional witness variables from state and signature gadgets
    for(size_t i = 0; i < relation.signature_gadgets.size(); ++i){
        relation.signature_gadgets[i].allocate();
    }
    relation.s_gadget->allocate();


    // add constraints for state and signatures
    relation.sc_gadget->generate_r1cs_constraints();
    for(size_t i = 0; i < relation.signature_gadgets.size(); ++i){
        relation.signature_gadgets[i].generate_r1cs_constraints();
    }
    relation.s_gadget->generate_r1cs_constraints();

    // add original constraints
    for(size_t i = 0; i < example.constraint_system.constraints.size(); ++i){
        relation.pb.add_r1cs_constraint(r1cs_constraint_remap(example.constraint_system.constraints[i], relation.variable_map), FMT("c_", "%d", i));
    }

    relation.pb.set_input_sizes(relation.primary_input_size + 2); // state digests are additional inputs

    // Store r1cs separately, because generator can change constraint system (swap AB if beneficial)
    relation.constraint_system = relation.pb.get_constraint_system();
    return relation;

}

template<typename ppT>
strawman_adscsnark_signature<ppT> strawman_adscsnark_authenticate(const strawman_adscsnark_authentication_key<ppT> &ak, size_t iteration, const std::vector<libff::Fr<ppT>> &values){
    static const libsnark::PoseidonParameters<ppT> param;
    std::vector<libff::Fq<EC_Inner<ppT>>> msg;
    msg.reserve(values.size() + 1);
    for(size_t i = 0; i < values.size(); ++i){
        msg.push_back(libff::convert_field<libff::Fq<EC_Inner<ppT>>>(values[i]));
    }
    msg.push_back(libff::Fq<EC_Inner<ppT>>(iteration));
    strawman_adscsnark_signature<ppT> sig = libsnark::eddsa_poseidon_sign(param, ak, msg);
    return sig;
}


template<typename ppT>
strawman_adscsnark_keypair<ppT> strawman_adscsnark_generator(strawman_adscsnark_relation<libff::Fr<ppT>> &relation,
                                                           const strawman_adscsnark_variable_assignment<ppT> &initial_state,
                                                           const std::vector<strawman_adscsnark_authentication_keypair<ppT>> &keys){

    assert(initial_state.size() == relation.state_size);

    // Compute new variable assignments (contains additionally 2 public inputs [state disgests], and several witness variables for signature and hash constraints)
    // initialize state
    relation.pb.val(relation.counter.in) = 0;

    // assign state
    for(size_t i = 0; i < relation.state_size; ++i){
        relation.pb.val(relation.variable_map.at(1+relation.primary_input_size+relation.private_input_size+relation.state_size+i)) = initial_state[i];
    }

    strawman_adscsnark_keypair<ppT> keypair;
    libsnark::r1cs_gg_ppzksnark_keypair<ppT> snark_keypair = libsnark::r1cs_gg_ppzksnark_generator<ppT>(relation.constraint_system);

    keypair.pk = snark_keypair.pk;
    keypair.vk = snark_keypair.vk;

    relation.s_gadget->generate_r1cs_witness();
    keypair.initial_proof.hash = relation.pb.val(relation.state_out_digest);

    for(size_t i = 0; i < keys.size(); ++i) {
        keypair.aks.push_back(keys[i].privkey);
    }
    return keypair;
}

template<typename ppT>
strawman_adscsnark_proof<ppT> strawman_adscsnark_prover(const strawman_adscsnark_proving_key<ppT> &pk,
                                                          strawman_adscsnark_relation<libff::Fr<ppT>> &relation,
                                                          const strawman_adscsnark_primary_input<ppT> &primary_input,
                                                          const strawman_adscsnark_variable_assignment<ppT> &private_input,
                                                          const strawman_adscsnark_variable_assignment<ppT> &state_assignment,
                                                          const strawman_adscsnark_variable_assignment<ppT> &witness_assignment,
                                                          const std::vector<strawman_adscsnark_signature<ppT>> &signatures){
    strawman_adscsnark_proof<ppT> proof;
    libsnark::r1cs_gg_ppzksnark_primary_input<ppT> new_primary_input;
    libsnark::r1cs_gg_ppzksnark_primary_input<ppT> new_auxiliary_input;

    // assign original primary input
    for(size_t i = 0; i < primary_input.size(); ++i){
        relation.pb.val(relation.variable_map.at(1+i)) = primary_input[i];
    }
    // assign private input
    for(size_t i = 0; i < private_input.size(); ++i){
        relation.pb.val(relation.variable_map.at(1+relation.primary_input_size+i)) = private_input[i];
    }
    // assign state
    relation.s_gadget->update();

    // assign state update
    for(size_t i = 0; i < state_assignment.size(); ++i){
        relation.pb.val(relation.variable_map.at(1+relation.primary_input_size+relation.private_input_size+relation.state_size+i)) = state_assignment[i];
    }
    // assign original witness
    for(size_t i = 0; i < witness_assignment.size(); ++i){
        relation.pb.val(relation.variable_map.at(1+relation.primary_input_size+relation.private_input_size+2*relation.state_size+i)) = witness_assignment[i];
    }
    // increase counter
    relation.sc_gadget->generate_r1cs_witness();
    // assign digest variables and hash function witness
    relation.s_gadget->generate_r1cs_witness();
    // assign signature witness
    for (size_t i = 0; i < relation.signature_gadgets.size(); ++i) {
        relation.signature_gadgets[i].generate_r1cs_witness(signatures[i]);
    }

    strawman_adscsnark_variable_assignment<ppT> assignment = relation.pb.full_variable_assignment();

    proof.hash = relation.pb.val(relation.state_out_digest);
    proof.snark_proof = libsnark::r1cs_gg_ppzksnark_prover(pk, relation.constraint_system,relation.pb.primary_input(), relation.pb.auxiliary_input());
    return proof;
}

template<typename ppT>
strawman_adscsnark_processed_verification_key<ppT> strawman_adscsnark_verifier_process_vk(const strawman_adscsnark_verification_key<ppT> &vk){
    return libsnark::r1cs_gg_ppzksnark_verifier_process_vk(vk);
}

template<typename ppT>
bool strawman_adscsnark_online_verifier(const strawman_adscsnark_processed_verification_key<ppT> &pvk,
                                                     const strawman_adscsnark_primary_input<ppT> &primary_input,
                                                     const strawman_adscsnark_proof<ppT> &proof,
                                                     const strawman_adscsnark_proof<ppT> &proof_previous){
    libsnark::r1cs_gg_ppzksnark_primary_input<ppT> new_primary_input(primary_input);

    // Add digests
    new_primary_input.push_back(proof_previous.hash);
    new_primary_input.push_back(proof.hash);

    return libsnark::r1cs_gg_ppzksnark_online_verifier_strong_IC(pvk, new_primary_input, proof.snark_proof);

}

#endif // STRAWMAN_ADSCSNARK_TCC_



