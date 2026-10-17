/**
 *
 *  Structured Protoboard allows to reserve blocks of variables
 *  Useful for allocating variables out of order
 *  (i.e. public inputs do not need to be allocated before witness)
 *
 */

#ifndef PROTOBOARD_STRUCTURED_HPP
#define PROTOBOARD_STRUCTURED_HPP

#include <libsnark/gadgetlib1/protoboard.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/r1cs.hpp>

namespace libsnark {

struct block_info_t {
    size_t start;
    size_t size;
    var_index_t  next_free_var;
};

template<typename FieldT>
class structured_protoboard : public protoboard<FieldT>{
private:
    std::map<size_t, block_info_t> blocks;
    size_t last_block_id;

public:
    structured_protoboard();

    size_t get_block_size(size_t blockid) const;
    size_t get_block_start(size_t blockid) const;
    size_t get_block_allocated_variables(size_t blockid) const;
    bool blocks_fully_allocated() const;
    r1cs_variable_assignment<FieldT> get_block_assignment(size_t blockid) const;
    r1cs_variable_assignment<FieldT> get_free_assignment() const;

    void reserve_block(size_t blockid, size_t size);

    friend class pb_variable<FieldT>;
private:
    var_index_t allocate_block_var_index(size_t blockid, const std::string &annotation="");
};

}

#include <libsnark/gadgetlib1/protoboard_structured.tcc>
#endif //PROTOBOARD_STRUCTURED_HPP
