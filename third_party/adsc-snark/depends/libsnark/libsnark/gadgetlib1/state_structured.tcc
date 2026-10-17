#ifndef STATE_STRUCTURED_TCC
#define STATE_STRUCTURED_TCC

template<typename FieldT>
void pb_state_structured<FieldT>::init(protoboard<FieldT> &pb) {
    pb.val(in) = initial_value;
    pb.val(out) = initial_value;
}

template<typename FieldT>
void pb_state_structured<FieldT>::update(protoboard<FieldT> &pb) {
    pb.val(in) = pb.val(out);
}

template<typename FieldT>
void state_manager<FieldT>::init() {
    for(size_t i = 0; i < states.size(); i++){
        states[i].init(this->pb);
    }
}

template<typename FieldT>
void state_manager<FieldT>::update() {
    for(size_t i = 0; i < states.size(); i++){
        states[i].update(this->pb);
    }
}

template<typename FieldT>
void state_manager<FieldT>::add_state(const pb_state_structured<FieldT> &state) {
    states.push_back(state);
}

template<typename FieldT>
pb_state_structured<FieldT> state_manager<FieldT>::allocate_state(FieldT initial_value) {
    pb_state_structured<FieldT> state(this->pb, id_block_in, id_block_out, initial_value);
    states.push_back(state);
}


#endif //STATE_STRUCTURED_TCC