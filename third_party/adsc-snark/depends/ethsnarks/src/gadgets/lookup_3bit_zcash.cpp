#include "lookup_3bit_zcash.hpp"
#include "utils.hpp"


namespace ethsnarks {

lookup_3bit_zcash_gadget::lookup_3bit_zcash_gadget(
    ProtoboardT &in_pb,
    const std::vector<FieldT> in_constants,
    const LinearCombinationArrayT in_bits,
    const std::string& annotation_prefix
) :
    GadgetT(in_pb, annotation_prefix),
    c(in_constants),
    b(in_bits),
    r(make_variable(in_pb, FMT(this->annotation_prefix, ".r"))),
    b12(make_variable(in_pb, FMT(this->annotation_prefix, ".b12")))
{
    assert( in_constants.size() == 8 );
}


const VariableT& lookup_3bit_zcash_gadget::result()
{
    return r;
}


void lookup_3bit_zcash_gadget::generate_r1cs_constraints()
{
    this->pb.add_r1cs_constraint(
        ConstraintT(
            b[1], b[2], b12
        ), FMT(this->annotation_prefix, ".b12"));

    // Verify 
    this->pb.add_r1cs_constraint(
        ConstraintT(
            b[0]
        ,
        -c[0] + c[1] +
        b[1] * (c[0] - c[2] - c[1] + c[3]) +
        b[2] * (c[0] - c[4] - c[1] + c[5]) +
        b12 * (-c[0] + c[2] + c[4] - c[6] + c[1] - c[3] - c[5] + c[7])
        ,
        r - c[0] + b[1]*(c[0] - c[2]) + b[2]*(c[0] - c[4]) + b12*(-c[0] + c[2] + c[4] - c[6])),
        FMT(this->annotation_prefix, ".result"));
}


void lookup_3bit_zcash_gadget::generate_r1cs_witness ()
{
    auto b1 = this->pb.lc_val(b[1]);
    auto b2 = this->pb.lc_val(b[2]);

    this->pb.val(b12) = b1 * b2;

    auto i = b.get_field_element_from_bits(this->pb).as_ulong();
    this->pb.val(r) = c[i];
}


lookup_3bitx2_zcash_gadget::lookup_3bitx2_zcash_gadget(
        ProtoboardT &in_pb,
        const std::vector<FieldT> in_constants_u,
        const std::vector<FieldT> in_constants_v,
        const LinearCombinationArrayT in_bits,
        const std::string& annotation_prefix
) :
        GadgetT(in_pb, annotation_prefix),
        u(in_constants_u),
        v(in_constants_v),
        b(in_bits),
        r_u(make_variable(in_pb, FMT(this->annotation_prefix, ".ru"))),
        r_v(make_variable(in_pb, FMT(this->annotation_prefix, ".rv"))),
        b12(make_variable(in_pb, FMT(this->annotation_prefix, ".b12")))
{
    assert( in_constants_u.size() == 8 );
    assert( in_constants_v.size() == 8 );
}


const VariableT& lookup_3bitx2_zcash_gadget::result_u()
{
    return r_u;
}

const VariableT& lookup_3bitx2_zcash_gadget::result_v()
{
    return r_v;
}


void lookup_3bitx2_zcash_gadget::generate_r1cs_constraints()
{
    this->pb.add_r1cs_constraint(
            ConstraintT(
                    b[1], b[2], b12
            ), FMT(this->annotation_prefix, ".b12"));

    this->pb.add_r1cs_constraint(
            ConstraintT(
                    b[0]
                    ,
                    -u[0] + u[1] +
                    b[1] * (u[0] - u[2] - u[1] + u[3]) +
                    b[2] * (u[0] - u[4] - u[1] + u[5]) +
                    b12 * (-u[0] + u[2] + u[4] - u[6] + u[1] - u[3] - u[5] + u[7])
                    ,
                    r_u - u[0] + b[1]*(u[0] - u[2]) + b[2]*(u[0] - u[4]) + b12*(-u[0] + u[2] + u[4] - u[6])),
            FMT(this->annotation_prefix, ".result_u"));

    this->pb.add_r1cs_constraint(
            ConstraintT(
                    b[0]
                    ,
                    -v[0] + v[1] +
                    b[1] * (v[0] - v[2] - v[1] + v[3]) +
                    b[2] * (v[0] - v[4] - v[1] + v[5]) +
                    b12 * (-v[0] + v[2] + v[4] - v[6] + v[1] - v[3] - v[5] + v[7])
                    ,
                    r_v - v[0] + b[1]*(v[0] - v[2]) + b[2]*(v[0] - v[4]) + b12*(-v[0] + v[2] + v[4] - v[6])),
            FMT(this->annotation_prefix, ".result_v"));
}


void lookup_3bitx2_zcash_gadget::generate_r1cs_witness ()
{
    auto b1 = this->pb.lc_val(b[1]);
    auto b2 = this->pb.lc_val(b[2]);

    this->pb.val(b12) = b1 * b2;

    auto i = b.get_field_element_from_bits(this->pb).as_ulong();
    this->pb.val(r_u) = u[i];
    this->pb.val(r_v) = v[i];
}


// namespace ethsnarks
}
