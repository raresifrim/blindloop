#ifndef PROTOBOARD_STRUCTURED_TCC
#define PROTOBOARD_STRUCTURED_TCC

#include <assert.h>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace libsnark {

template<typename FieldT>
structured_protoboard<FieldT>::structured_protoboard() : protoboard<FieldT>(), last_block_id(0)
{}

template<typename FieldT>
size_t structured_protoboard<FieldT>::get_block_size(size_t blockid) const
{
    return blocks.at(blockid).size;
}

template<typename FieldT>
size_t structured_protoboard<FieldT>::get_block_start(size_t blockid) const
{
    return blocks.at(blockid).start;
}

template<typename FieldT>
size_t structured_protoboard<FieldT>::get_block_allocated_variables(size_t blockid) const
{
    return blocks.at(blockid).next_free_var;
}

template<typename FieldT>
r1cs_variable_assignment<FieldT> structured_protoboard<FieldT>::get_free_assignment() const
{
    block_info_t last_block = blocks.at(last_block_id);
    return r1cs_variable_assignment<FieldT>(this->values.begin() + last_block.start + last_block.size - 1,
        this->values.end());
}


template<typename FieldT>
r1cs_variable_assignment<FieldT> structured_protoboard<FieldT>::get_block_assignment(size_t blockid) const
{
    block_info_t block = blocks.at(blockid);
    return r1cs_variable_assignment<FieldT>(this->values.begin() + block.start - 1, this->values.begin() + block.start + block.size - 1);
}

template<typename FieldT>
bool structured_protoboard<FieldT>::blocks_fully_allocated() const
{
    bool result = true;
    for(auto pair: blocks){
        result &= (pair.second.next_free_var == pair.second.start + pair.second.size);
    }
    return result;
}

template<typename FieldT>
void structured_protoboard<FieldT>::reserve_block(size_t blockid, size_t size)
{
    block_info_t block;

    // Check whether block already reserved
    assert(blocks.find(blockid) == blocks.end());
    block.size = size;
    block.start = this->next_free_var;
    block.next_free_var = this->next_free_var;

    for (size_t i = 0; i < size; i++){
        this->allocate_var_index(FMT("reserved_block_", "%lu_%lu", blockid, i));
    }

    blocks[blockid] = block;
    last_block_id = blockid;

}

template<typename FieldT>
var_index_t structured_protoboard<FieldT>::allocate_block_var_index(size_t blockid, const std::string &annotation)
{
    block_info_t &block = blocks.at(blockid);
    assert(block.next_free_var < block.start + block.size);

#ifdef DEBUG
    assert(annotation != "");
    this->constraint_system.variable_annotations[this->next_free_var] = annotation;
#else
    libff::UNUSED(annotation);
#endif

    return block.next_free_var++;
}

}
#endif //PROTOBOARD_STRUCTURED_TCC
