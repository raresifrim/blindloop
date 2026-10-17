/** @file
 *****************************************************************************

 Declaration of interfaces for comparison gadgets

 Provides additional comparison gadgets including:

 limit_gadget: limits a value by a maximum and a minimum. If value is out
 of bounds, the output value is set to the maximum/minimum

 assert_positive_gadget: checks, whether a value is larger or equal to zero
 *****************************************************************************/

#ifndef COMP_GADGETS_H
#define COMP_GADGETS_H

#include <memory>

#include "libsnark/gadgetlib1/gadget.hpp"
#include "libsnark/gadgetlib1/protoboard.hpp"
#include "libsnark/gadgetlib1/gadgets/basic_gadgets.hpp"

template<typename FieldT>
class limit_gadget : public libsnark::gadget<FieldT> {
    // Limits value to range (min, max)
private:
    libsnark::pb_variable<FieldT> too_large;
    libsnark::pb_variable<FieldT> too_small;
    libsnark::pb_variable<FieldT> dum1;
    libsnark::pb_variable<FieldT> dum2;
    libsnark::pb_variable<FieldT> l_limited_value;

    std::shared_ptr<libsnark::comparison_gadget<FieldT> > comp_lower;
    std::shared_ptr<libsnark::comparison_gadget<FieldT> > comp_upper;

public:
    const size_t n;
    const int min;
    const int max;
    const libsnark::pb_linear_combination<FieldT> value;
    const libsnark::pb_variable<FieldT> limited_value;

    limit_gadget(libsnark::protoboard<FieldT>& pb,
                      const size_t n,
                      const int min,
                      const int max,
                      const libsnark::linear_combination<FieldT> &value,
                      const libsnark::pb_variable<FieldT> &limited_value,
                      const std::string &annotation_prefix="") :
            libsnark::gadget<FieldT>(pb, annotation_prefix), n(n), min(min), max(max), value(pb, value), limited_value(limited_value)
    {
        too_large.allocate(pb, FMT(this->annotation_prefix, " too large"));
        too_small.allocate(pb, FMT(this->annotation_prefix, " too small"));
        l_limited_value.allocate(pb, FMT(this->annotation_prefix, " l limited value"));
        dum1.allocate(pb, FMT(this->annotation_prefix, " dum1"));
        dum2.allocate(pb, FMT(this->annotation_prefix, " dum2"));

        libsnark::pb_linear_combination<FieldT> lc_min;
        libsnark::pb_linear_combination<FieldT> lc_max;
        lc_min.assign(this->pb, this->min);
        lc_max.assign(this->pb, this->max);
        comp_lower.reset(new libsnark::comparison_gadget<FieldT>(pb, this->n, this->value, lc_min, too_small, dum1,
                                                    FMT(this->annotation_prefix, " comp lower")));
        comp_upper.reset(new libsnark::comparison_gadget<FieldT>(pb, this->n, lc_max, this->value, too_large, dum2,
                                                       FMT(this->annotation_prefix, " comp upper")));

    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class limit_max_gadget : public libsnark::gadget<FieldT> {
    // Limits value to a maximum
private:
    libsnark::pb_variable<FieldT> too_large;
    libsnark::pb_variable<FieldT> too_small;
    libsnark::pb_variable<FieldT> dum1;
    libsnark::pb_variable<FieldT> l_limited_value;

    std::shared_ptr<libsnark::comparison_gadget<FieldT> > comp_lower;
    std::shared_ptr<libsnark::comparison_gadget<FieldT> > comp_upper;

public:
    const size_t n;
    const int max;
    const libsnark::pb_linear_combination<FieldT> value;
    const libsnark::pb_variable<FieldT> limited_value;

    limit_max_gadget(libsnark::protoboard<FieldT>& pb,
                      const size_t n,
                      const int max,
                      const libsnark::pb_linear_combination<FieldT> &value,
                      const libsnark::pb_variable<FieldT> &limited_value,
                      const std::string &annotation_prefix="") :
            libsnark::gadget<FieldT>(pb, annotation_prefix), n(n), max(max), value(value), limited_value(limited_value)
    {
        too_large.allocate(pb, FMT(this->annotation_prefix, ".too_large"));
        l_limited_value.allocate(pb, FMT(this->annotation_prefix, ".l_limited_value"));
        dum1.allocate(pb, FMT(this->annotation_prefix, ".dum1"));

        libsnark::pb_linear_combination<FieldT> lc_max;
        lc_max.assign(this->pb, this->max);
        comp_upper.reset(new libsnark::comparison_gadget<FieldT>(pb, this->n, lc_max, this->value, too_large, dum1,
                                                       FMT(this->annotation_prefix, " comp upper")));

    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class limit_min_gadget : public libsnark::gadget<FieldT> {
    // Limits value to range (min, max)
private:
    libsnark::pb_variable<FieldT> too_small;
    libsnark::pb_variable<FieldT> dum1;
    libsnark::pb_variable<FieldT> l_limited_value;

    std::shared_ptr<libsnark::comparison_gadget<FieldT> > comp_lower;

public:
    const size_t n;
    const int min;
    const libsnark::pb_linear_combination<FieldT> value;
    const libsnark::pb_variable<FieldT> limited_value;

    limit_min_gadget(libsnark::protoboard<FieldT>& pb,
                      const size_t n,
                      const int min,
                      const libsnark::pb_linear_combination<FieldT> &value,
                      const libsnark::pb_variable<FieldT> &limited_value,
                      const std::string &annotation_prefix="") :
            libsnark::gadget<FieldT>(pb, annotation_prefix), n(n), min(min), value(value), limited_value(limited_value)
    {
        too_small.allocate(pb, FMT(this->annotation_prefix, ".too_small"));
        l_limited_value.allocate(pb, FMT(this->annotation_prefix, ".l_limited_value"));
        dum1.allocate(pb, FMT(this->annotation_prefix, ".dum1"));

        libsnark::pb_linear_combination<FieldT> lc_min;
        lc_min.assign(this->pb, this->min);
        comp_lower.reset(new libsnark::comparison_gadget<FieldT>(pb, this->n, this->value, lc_min, too_small, dum1,
                                                    FMT(this->annotation_prefix, ".comp_lower")));
    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};

template<typename FieldT>
class assert_positive_gadget : public libsnark::gadget<FieldT> {
    // Asserts value to be positive
private:
    libsnark::pb_variable_array<FieldT> value_bits;
    std::shared_ptr<libsnark::packing_gadget<FieldT> > pack_value;

public:
    const size_t n;
    const libsnark::pb_linear_combination<FieldT> value;

    assert_positive_gadget(libsnark::protoboard<FieldT>& pb,
                 const size_t n,
                 const libsnark::pb_linear_combination<FieldT> &value,
                 const std::string &annotation_prefix="") :
            libsnark::gadget<FieldT>(pb, annotation_prefix), n(n),  value(value)
    {
        value_bits.allocate(pb, n, FMT(this->annotation_prefix, " value"));

        pack_value.reset(new libsnark::packing_gadget<FieldT>(pb, value_bits, value,
                                                       FMT(this->annotation_prefix, " pack_value")));
    };

    void generate_r1cs_constraints();
    void generate_r1cs_witness();
};


#include "comp_gadgets.tcc"
#endif //COMP_GADGETS_H
