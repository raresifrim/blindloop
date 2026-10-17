/** @file
 *****************************************************************************

 Implementation of snark-friendly Poseidon hash gadgets

 see poseidon_orig.h

 *****************************************************************************/

#include "ethsnarks.hpp"
#include "poseidon_orig.hpp"

namespace ethsnarks {

    const char* poseidon_rc[] = POSEIDON_PARAM_RC;
    const char* poseidon_mds[] = POSEIDON_PARAM_MDS;

    void poseidon_constants_fill_precomputed(unsigned n_constants, std::vector<FieldT> &result){
        assert(n_constants == POSEIDON_PARAM_NUM_RC);
        result.reserve(n_constants);
        for (unsigned i = 0; i < n_constants; i++)
        {
            result.push_back(FieldT(poseidon_rc[i]));
        }
    }

    void poseidon_matrix_fill_precomputed(unsigned t, std::vector<FieldT> &result)
    {
        assert(t == POSEIDON_PARAM_T);
        result.reserve(t*t);

        for( unsigned i = 0; i < t; i++ )
        {
            for( unsigned j = 0; j < t; j++ )
            {
                result.emplace_back(FieldT(poseidon_mds[i*t+j]));
            }
        }
    }

    ThirdPower_gadget::ThirdPower_gadget(ProtoboardT &pb, const std::string &annotation_prefix) :
            GadgetT(pb, annotation_prefix),
            x2(make_variable(pb, FMT(annotation_prefix, ".x2"))),
            x3(make_variable(pb, FMT(annotation_prefix, ".x3")))
    {
    }

    void ThirdPower_gadget::generate_r1cs_constraints(const linear_combination<FieldT>& x) const
    {
        pb.add_r1cs_constraint(ConstraintT(x, x, x2), ".x^2 = x * x");
        pb.add_r1cs_constraint(ConstraintT(x2, x, x3), ".x^3 = x2 * x");
    }

    void ThirdPower_gadget::generate_r1cs_witness(const FieldT& val_x) const
    {
        const auto val_x2 = val_x * val_x;
        const auto val_x3 = val_x2 * val_x;
        this->pb.val(x2) = val_x2;
        this->pb.val(x3) = val_x3;
    }

    const VariableT& ThirdPower_gadget::result() const
    {
        return x3;
    }

    FifthPower_gadget::FifthPower_gadget(ProtoboardT &pb, const std::string &annotation_prefix) :
            GadgetT(pb, annotation_prefix),
            x2(make_variable(pb, FMT(annotation_prefix, ".x2"))),
            x4(make_variable(pb, FMT(annotation_prefix, ".x4"))),
            x5(make_variable(pb, FMT(annotation_prefix, ".x5")))
    {
    }

    void FifthPower_gadget::generate_r1cs_constraints(const linear_combination<FieldT>& x) const
    {
        pb.add_r1cs_constraint(ConstraintT(x, x, x2), ".x^2 = x * x");
        pb.add_r1cs_constraint(ConstraintT(x2, x2, x4), ".x^4 = x2 * x2");
        pb.add_r1cs_constraint(ConstraintT(x, x4, x5), ".x^5 = x * x4");
    }

    void FifthPower_gadget::generate_r1cs_witness(const FieldT& val_x) const
    {
        const auto val_x2 = val_x * val_x;
        const auto val_x4 = val_x2 * val_x2;
        const auto val_x5 = val_x4 * val_x;
        this->pb.val(x2) = val_x2;
        this->pb.val(x4) = val_x4;
        this->pb.val(x5) = val_x5;
    }

    const VariableT& FifthPower_gadget::result() const
    {
        return x5;
    }

    ThirteenthPower_gadget::ThirteenthPower_gadget(ProtoboardT &pb, const std::string &annotation_prefix) :
            GadgetT(pb, annotation_prefix),
            x2(make_variable(pb, FMT(annotation_prefix, ".x2"))),
            x4(make_variable(pb, FMT(annotation_prefix, ".x4"))),
            x8(make_variable(pb, FMT(annotation_prefix, ".x8"))),
            x12(make_variable(pb, FMT(annotation_prefix, ".x12"))),
            x13(make_variable(pb, FMT(annotation_prefix, ".x13")))
    {
    }

    void ThirteenthPower_gadget::generate_r1cs_constraints(const linear_combination<FieldT>& x) const
    {
        pb.add_r1cs_constraint(ConstraintT(x, x, x2), ".x^2 = x * x");
        pb.add_r1cs_constraint(ConstraintT(x2, x2, x4), ".x^4 = x2 * x2");
        pb.add_r1cs_constraint(ConstraintT(x4, x4, x8), ".x^8 = x4 * x4");
        pb.add_r1cs_constraint(ConstraintT(x8, x4, x12), ".x^12 = x8 * x4");
        pb.add_r1cs_constraint(ConstraintT(x, x12, x13), ".x^13 = x * x12");
    }

    void ThirteenthPower_gadget::generate_r1cs_witness(const FieldT& val_x) const
    {
        const auto val_x2 = val_x * val_x;
        const auto val_x4 = val_x2 * val_x2;
        const auto val_x8 = val_x4 * val_x4;
        const auto val_x12 = val_x8 * val_x4;
        const auto val_x13 = val_x * val_x12;
        this->pb.val(x2) = val_x2;
        this->pb.val(x4) = val_x4;
        this->pb.val(x8) = val_x8;
        this->pb.val(x12) = val_x12;
        this->pb.val(x13) = val_x13;
    }

    const VariableT& ThirteenthPower_gadget::result() const
    {
        return x13;
    }

    EleventhPower_gadget::EleventhPower_gadget(ProtoboardT &pb, const std::string &annotation_prefix) :
            GadgetT(pb, annotation_prefix),
            x2(make_variable(pb, FMT(annotation_prefix, ".x2"))),
            x4(make_variable(pb, FMT(annotation_prefix, ".x4"))),
            x8(make_variable(pb, FMT(annotation_prefix, ".x8"))),
            x10(make_variable(pb, FMT(annotation_prefix, ".x10"))),
            x11(make_variable(pb, FMT(annotation_prefix, ".x11")))
    {
    }

    void EleventhPower_gadget::generate_r1cs_constraints(const linear_combination<FieldT>& x) const
    {
        pb.add_r1cs_constraint(ConstraintT(x, x, x2), ".x^2 = x * x");
        pb.add_r1cs_constraint(ConstraintT(x2, x2, x4), ".x^4 = x2 * x2");
        pb.add_r1cs_constraint(ConstraintT(x4, x4, x8), ".x^8 = x4 * x4");
        pb.add_r1cs_constraint(ConstraintT(x8, x2, x10), ".x^10 = x8 * x2");
        pb.add_r1cs_constraint(ConstraintT(x, x10, x11), ".x^11 = x * x10");
    }

    void EleventhPower_gadget::generate_r1cs_witness(const FieldT& val_x) const
    {
        const auto val_x2 = val_x * val_x;
        const auto val_x4 = val_x2 * val_x2;
        const auto val_x8 = val_x4 * val_x4;
        const auto val_x10 = val_x8 * val_x2;
        const auto val_x11 = val_x * val_x10;
        this->pb.val(x2) = val_x2;
        this->pb.val(x4) = val_x4;
        this->pb.val(x8) = val_x8;
        this->pb.val(x10) = val_x10;
        this->pb.val(x11) = val_x11;
    }

    const VariableT& EleventhPower_gadget::result() const
    {
        return x11;
    }

    PoseidonHashToBits::PoseidonHashToBits(
            ProtoboardT& in_pb,
            const LinearCombinationArrayT& in_values,
            const std::string& annotation_prefix
    ) :
            GadgetT(in_pb, annotation_prefix),
            m_hash(in_pb, in_values, FMT(this->annotation_prefix, ".hash")),
            m_tobits(in_pb, m_hash.result(), FMT(this->annotation_prefix, ".tobits"))
    { }


    /**
    * Resulting bits
    */
    const VariableArrayT& PoseidonHashToBits::result() const
    {
        return m_tobits.result();
    }


    void PoseidonHashToBits::generate_r1cs_constraints ()
    {
        m_hash.generate_r1cs_constraints();
        m_tobits.generate_r1cs_constraints();
    }


    void PoseidonHashToBits::generate_r1cs_witness ()
    {
        m_hash.generate_r1cs_witness();
        m_tobits.generate_r1cs_witness();
    }

}