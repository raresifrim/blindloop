/** @file
 *****************************************************************************

 Declaration of interfaces for snark-friendly Poseidon hash

 this implementation corresponds to the original poseidon paper
 https://eprint.iacr.org/2019/458

 constants are fixed and have been precomputed with the poseidon authors'
 tool: https://extgit.iaik.tugraz.at/krypto/hadeshash

 this includes the Poseidon permutation and a sponge construction for
 hashing variable-size messages
 *****************************************************************************/


#ifndef ETHSNARKS_POSEIDON_ORIG_HPP_
#define ETHSNARKS_POSEIDON_ORIG_HPP_



#include "ethsnarks.hpp"
#include "utils.hpp"
#include "poseidon_precomputed_parameters.h"
#include "field2bits_strict.hpp"

namespace ethsnarks {

using libsnark::linear_combination;
using libsnark::linear_term;

extern const char* poseidon_rc[];
extern const char* poseidon_mds[];

struct PoseidonConstants
{
	std::vector<FieldT> C; // `t` constants
	std::vector<FieldT> M; // `t * t` matrix of constants
};

void poseidon_matrix_fill_precomputed(unsigned t, std::vector<FieldT> &result);
void poseidon_constants_fill_precomputed(unsigned n_constants, std::vector<FieldT> &result);

class EleventhPower_gadget : public GadgetT {
public:
    const VariableT x2;
    const VariableT x4;
    const VariableT x8;
    const VariableT x10;
    const VariableT x11;

    static const int alpha = 11;

    EleventhPower_gadget(
            ProtoboardT &pb,
            const std::string& annotation_prefix
    );

    void generate_r1cs_constraints(const linear_combination<FieldT>& x) const;

    void generate_r1cs_witness(const FieldT& val_x) const;

    const VariableT& result() const;
};

class ThirteenthPower_gadget : public GadgetT {
public:
    const VariableT x2;
    const VariableT x4;
    const VariableT x8;
    const VariableT x12;
    const VariableT x13;

    static const int alpha = 13;

    ThirteenthPower_gadget(
            ProtoboardT &pb,
            const std::string& annotation_prefix
    );

    void generate_r1cs_constraints(const linear_combination<FieldT>& x) const;

    void generate_r1cs_witness(const FieldT& val_x) const;

    const VariableT& result() const;
};

class FifthPower_gadget : public GadgetT {
public:
	const VariableT x2;
	const VariableT x4;
	const VariableT x5;

    static const int alpha = 5;

	FifthPower_gadget(
		ProtoboardT &pb,
		const std::string& annotation_prefix
	);

	void generate_r1cs_constraints(const linear_combination<FieldT>& x) const;

	void generate_r1cs_witness(const FieldT& val_x) const;

    const VariableT& result() const;
};

class ThirdPower_gadget : public GadgetT {
public:
    const VariableT x2;
    const VariableT x3;

    static const int alpha = 3;

    ThirdPower_gadget(
            ProtoboardT &pb,
            const std::string& annotation_prefix
    );

    void generate_r1cs_constraints(const linear_combination<FieldT>& x) const;

    void generate_r1cs_witness(const FieldT& val_x) const;

    const VariableT& result() const;
};



/**
* One round of the Poseidon permutation:
*
*    - takes a state of `t` elements
*    - adds the round constant to each element in the state
*    - performs exponentiation on the first `n` elements of the state
*    - creates `o` outputs, mixed using a matrix vector transform
*
* This generic version can be used as either a 'full', 'partial' or 'last' round.
* It avoids computing as many constraints as is possible, given all the information.
*/
template<typename SBox_gadget, unsigned param_t, unsigned nSBox, unsigned nInputs, unsigned nOutputs>
class Poseidon_Round : public GadgetT {
public:		
	const std::vector<FieldT> C_i;
	const std::vector<FieldT>& M;
	const LinearCombinationArrayT state;
	const std::vector<SBox_gadget> sboxes;
	const LinearCombinationArrayT outputs;

	static std::vector<SBox_gadget> make_sboxes(
		ProtoboardT& in_pb,
		const std::string& annotation_prefix )
	{
		std::vector<SBox_gadget> ret;

		ret.reserve(nSBox);
		for( unsigned h = 0; h < nSBox; h++ )
		{
			ret.emplace_back( in_pb, FMT(annotation_prefix, ".sbox[%u]", h) );
		}

		return ret;
	}

	static LinearCombinationArrayT make_outputs(
		ProtoboardT& in_pb,
		const std::vector<FieldT>& in_C_i,
		const std::vector<FieldT>& in_M,
		const LinearCombinationArrayT& in_state,
		const std::vector<SBox_gadget>& in_sboxes,
		unsigned output_offset)
	{
        LinearCombinationArrayT ret;

		for( unsigned i = output_offset; i < nOutputs + output_offset; i++ )
		{
			const unsigned M_offset = i * param_t;

			// Any element which isn't passed through an sbox
			// Can be accumulated separately as part of the constant term
			FieldT constant_term;
			for( unsigned j = nSBox; j < param_t; j++ ) {
				constant_term += in_C_i[j] * in_M[M_offset+j];
			}

			linear_combination<FieldT> lc;
			lc.terms.reserve(param_t);
			if( nSBox < param_t )
			{
				lc.add_term(libsnark::ONE, constant_term);
			}			

			// Add S-Boxes to the output row
			for( unsigned s = 0; s < nSBox; s++ )
			{
				lc.add_term(in_sboxes[s].result(), in_M[M_offset+s]);
			}

			// Then add inputs (from the state) multiplied by the matrix element
			for( unsigned k = nSBox; k < nInputs; k++ )
			{
				lc = lc + (in_state[k] * in_M[M_offset+k]);
			}
            LinearCombinationT pb_lc;
            pb_lc.assign(in_pb, lc);
			ret.emplace_back(pb_lc);
		}
		return ret;
	}

	Poseidon_Round(
		ProtoboardT &in_pb,
		const std::vector<FieldT> in_C_i, // The ethsnarks implementation only assigns one round constant to each round, but it should be t according to paper
		const std::vector<FieldT>& in_M,
		const VariableArrayT& in_state,
		unsigned output_offset,
		const std::string& annotation_prefix
	) :
		Poseidon_Round(in_pb, in_C_i, in_M, VariableArrayT_to_lc(in_state), output_offset, annotation_prefix)
	{ }

	Poseidon_Round(
		ProtoboardT &in_pb,
		const std::vector<FieldT> in_C_i,
		const std::vector<FieldT>& in_M,
		const LinearCombinationArrayT& in_state,
		unsigned output_offset,
		const std::string& annotation_prefix
	) :
		GadgetT(in_pb, annotation_prefix),
		C_i(in_C_i),
		M(in_M),
		state(in_state),
		sboxes(make_sboxes(in_pb, annotation_prefix)),
		outputs(make_outputs(in_pb, in_C_i, in_M, in_state, sboxes, output_offset))
	{
		assert( nInputs <= param_t );
		assert( nOutputs <= param_t );
	}

	void generate_r1cs_witness() const
	{
		for( unsigned h = 0; h < nSBox; h++ )
		{
			auto value = C_i[h];
			if( h < nInputs ) {
				value += lc_val(this->pb, state[h]); // this->pb.val(state[h]);
			}
			sboxes[h].generate_r1cs_witness( value );
		}
	}

	void generate_r1cs_constraints() const
	{
		for( unsigned h = 0; h < nSBox; h++ )
		{
			if( h < nInputs ) {
				sboxes[h].generate_r1cs_constraints( state[h] + C_i[h] );
			}
			else {
				sboxes[h].generate_r1cs_constraints( C_i[h] );
			}
		}
	}
};

template<unsigned param_t, unsigned param_F, unsigned param_P>
const PoseidonConstants& poseidon_params()
{
    static PoseidonConstants constants;
    static bool initialized = false;

    if (!initialized){
        poseidon_constants_fill_precomputed(param_t * (param_F + param_P), constants.C);
        poseidon_matrix_fill_precomputed(param_t, constants.M);
        initialized = true;
    }

    return constants;
}

template<typename SBox_gadget, unsigned param_t, unsigned param_c, unsigned param_F, unsigned param_P, unsigned nInputs, unsigned nOutputs, bool constrainOutputs=true>
class Poseidon_gadget_T : public GadgetT
{
protected:
	typedef Poseidon_Round<SBox_gadget, param_t, param_t, nInputs, param_t> FirstRoundT;    // ingests `nInput` elements, expands to `t` elements using round constants
	typedef Poseidon_Round<SBox_gadget, param_t, param_c, param_t, param_t> PartialRoundT;  // partial round only runs sbox on `c` elements (capacity)
	typedef Poseidon_Round<SBox_gadget, param_t, param_t, param_t, param_t> FullRoundT;     // full bandwidth
	typedef Poseidon_Round<SBox_gadget, param_t, param_t, param_t, nOutputs> LastRoundT;   // squeezes state into `nOutputs`

	typedef const VariableT& var_output_t;
	typedef const VariableArrayT& var_outputs_t;

	static constexpr unsigned partial_begin = (param_F/2);
	static constexpr unsigned partial_end = (partial_begin + param_P);
	static constexpr unsigned total_rounds = param_F + param_P;

public:
	const LinearCombinationArrayT inputs;
	const PoseidonConstants& constants;
	
	FirstRoundT first_round;	
	std::vector<FullRoundT> prefix_full_rounds;
	std::vector<PartialRoundT> partial_rounds;
	std::vector<FullRoundT> suffix_full_rounds;
	LastRoundT last_round;

	// When `constrainOutputs==true`, need variables to store outputs
	const VariableArrayT _output_vars;

	template<typename T>
	static const std::vector<T> make_rounds(
		unsigned n_begin, unsigned n_end,
		ProtoboardT& pb,
		const LinearCombinationArrayT& inputs,
		const PoseidonConstants& constants,
		const std::string& annotation_prefix)
	{
		std::vector<T> result;
		result.reserve(n_end - n_begin);

		for( unsigned i = n_begin; i < n_end; i++ )
		{
			const auto& state = (i == n_begin) ? inputs : result.back().outputs;
			result.emplace_back(pb, std::vector<FieldT>(constants.C.begin()+i*param_t, constants.C.begin()+(i+1)*param_t), constants.M, state, 0, FMT(annotation_prefix, ".round[%u]", i));
		}

		return result;
	}

	static std::vector<FieldT> permute( std::vector<FieldT> inputs )
	{
		ProtoboardT pb;

		assert( inputs.size() == nInputs );
		auto var_inputs = make_var_array(pb, "input", inputs);

		Poseidon_gadget_T<SBox_gadget, param_t, param_c, param_F, param_P, nInputs, nOutputs, constrainOutputs> gadget(pb, var_inputs, 0, "gadget");
		gadget.generate_r1cs_witness();

/*
		// Debugging statements
		gadget.generate_r1cs_constraints();

		unsigned i = 0;
		const auto first_outputs = gadget.first_round.outputs;
		for( unsigned j = 0; j < first_outputs.size(); j++ ) {
			std::cout << "o[" << i << "][" << j << "] = ";
			pb.lc_val(first_outputs[j]).print();
		}
		std::cout << std::endl;

		for( const auto &prefix_round : gadget.prefix_full_rounds )
		{
			i += 1;
			const auto outputs = prefix_round.outputs;
			for( unsigned j = 0; j < outputs.size(); j++ ) {
				std::cout << "o[" << i << "][" << j << "] = ";
				pb.lc_val(outputs[j]).print();
			}
		}
		std::cout << std::endl;

		for( const auto &partial_round : gadget.partial_rounds )
		{
			i += 1;
			const auto outputs = partial_round.outputs;
			for( unsigned j = 0; j < outputs.size(); j++ ) {
				std::cout << "o[" << i << "][" << j << "] = ";
				pb.lc_val(outputs[j]).print();
			}
		}
		std::cout << std::endl;

		for( const auto &suffix_round : gadget.suffix_full_rounds )
		{
			i += 1;
			const auto outputs = suffix_round.outputs;
			for( unsigned j = 0; j < outputs.size(); j++ ) {
				std::cout << "o[" << i << "][" << j << "] = ";
				pb.lc_val(outputs[j]).print();
			}
		}
		std::cout << std::endl;

		const auto last_outputs = gadget.last_round.outputs;
		for( unsigned j = 0; j < last_outputs.size(); j++ ) {
			std::cout << "o[" << i << "][" << j << "] = ";
			pb.lc_val(last_outputs[j]).print();
		}
		std::cout << std::endl;

		if( ! pb.is_satisfied() ) {
			std::cerr << "Not satisfied\n";
		}

		std::cout << pb.num_constraints() << " constraints" << std::endl;
		// End debugging statements
*/
		return vals(pb, gadget.results());
	}

	Poseidon_gadget_T(
		ProtoboardT &pb,
		const LinearCombinationArrayT& in_inputs,
		unsigned output_offset,
		const std::string& annotation_prefix
	) :
		GadgetT(pb, annotation_prefix),
		inputs(in_inputs),
		constants(poseidon_params<param_t, param_F, param_P>()),
		first_round(pb, std::vector<FieldT>(constants.C.begin(), constants.C.begin()+param_t), constants.M, in_inputs, 0, FMT(annotation_prefix, ".round[0]")),
		prefix_full_rounds(
			make_rounds<FullRoundT>(
				1, partial_begin, pb,
				first_round.outputs, constants, annotation_prefix)),
		partial_rounds(
			make_rounds<PartialRoundT>(
				partial_begin, partial_end, pb,
				prefix_full_rounds.back().outputs, constants, annotation_prefix)),
		suffix_full_rounds(
			make_rounds<FullRoundT>(
				partial_end, total_rounds-1, pb,
				partial_rounds.back().outputs, constants, annotation_prefix)),
		last_round(pb, std::vector<FieldT>(constants.C.end()-param_t, constants.C.end()), constants.M, suffix_full_rounds.back().outputs, output_offset, FMT(annotation_prefix, ".round[%u]", total_rounds-1)),
		_output_vars(constrainOutputs ? make_var_array(pb, nOutputs, ".output") : VariableArrayT())
	{
                assert(param_t == POSEIDON_PARAM_T);
                assert(param_F == POSEIDON_PARAM_RF);
                assert(param_P == POSEIDON_PARAM_RP);
                assert(SBox_gadget::alpha == POSEIDON_PARAM_ALPHA);
	}

	template<bool x = constrainOutputs>
	typename std::enable_if<!x, LinearCombinationArrayT>::type
	results() const
	{
		return last_round.outputs;
	}

	template<bool x = constrainOutputs>
	typename std::enable_if<x, VariableArrayT>::type
	results() const
	{
		return _output_vars;
	}

	template<bool x = constrainOutputs, unsigned n = nOutputs>
	typename std::enable_if<!x && n == 1 , LinearCombinationT>::type
	result() const
	{
		return last_round.outputs[0];
	}

	template<bool x = constrainOutputs, unsigned n = nOutputs>
	typename std::enable_if<x && n == 1, VariableT>::type
	result() const
	{
		return _output_vars[0];
	}

	void generate_r1cs_constraints() const
	{
		first_round.generate_r1cs_constraints();

		for( auto& prefix_round : prefix_full_rounds ) {
			prefix_round.generate_r1cs_constraints();
		}

		for( auto& partial_round : partial_rounds ) {
			partial_round.generate_r1cs_constraints();
		}

		for( auto& suffix_round : suffix_full_rounds ) {
			suffix_round.generate_r1cs_constraints();
		}

		last_round.generate_r1cs_constraints();

		if( constrainOutputs )
		{
			unsigned i = 0;
			for( const auto &lc : last_round.outputs )
			{
				this->pb.add_r1cs_constraint(
					ConstraintT(lc, libsnark::ONE, _output_vars[i]),
					FMT(this->annotation_prefix, ".output[%u] = last_round.output[%u]", i, i));
				i += 1;
			}
		}
	}


	void generate_r1cs_witness() const
	{
		first_round.generate_r1cs_witness();

		for( auto& prefix_round : prefix_full_rounds ) {
			prefix_round.generate_r1cs_witness();
		}

		for( auto& partial_round : partial_rounds ) {
			partial_round.generate_r1cs_witness();
		}

		for( auto& suffix_round : suffix_full_rounds ) {
			suffix_round.generate_r1cs_witness();
		}

		last_round.generate_r1cs_witness();

		// When outputs are constrained, fill in the variable
		if( constrainOutputs )
		{
			unsigned i = 0;
			for( const auto &value : vals(pb, last_round.outputs) )
			{
				this->pb.val(_output_vars[i++]) = value;
			}
		}
	}
};


template<typename SBox_gadget, unsigned param_t, unsigned param_c, unsigned param_F, unsigned param_P, bool constrainOutputsSponge=true>
class PoseidonSponge_Gadget : public GadgetT {

protected:
    typedef Poseidon_gadget_T<SBox_gadget, param_t, param_c, param_F, param_P, param_t, param_t, false> PoseidonPermutation;
    typedef Poseidon_gadget_T<SBox_gadget, param_t, param_c, param_F, param_P, param_t, param_c, constrainOutputsSponge> LastPoseidonPermutation;

private:
    const LinearCombinationArrayT& inputs;
    std::vector<PoseidonPermutation> permutations;
    std::shared_ptr<LastPoseidonPermutation> last_permutation;

public:
    PoseidonSponge_Gadget(
            ProtoboardT &pb,
            const LinearCombinationArrayT& in_inputs,
            const std::string& annotation_prefix
    ) :
            GadgetT(pb, annotation_prefix),
            inputs(in_inputs)
    {
        unsigned int n_inputs = inputs.size();
        unsigned int r = param_t - param_c;
        unsigned int n_permutations = (n_inputs + r - 1) / r; // = ceil(n_inputs/r)
        for(size_t i = 0; i < n_permutations; i++){
            LinearCombinationArrayT lcs;
            std::vector<linear_combination<FieldT>> lin_combs;
            // first permutation, initial state is zero -> inputs are directly taken from message
            //in_inputs = LinearCombinationArrayT();


        	for(size_t j=0; j<param_c; j++){
        		lin_combs.push_back(linear_combination<FieldT>(0));
        	}
            for(size_t j=0; j<r; j++){
                if(i*r+j < n_inputs) {
                    lin_combs.push_back(linear_combination<FieldT>(inputs[i * r + j]));
                }else{
                    lin_combs.push_back(linear_combination<FieldT>(0)); // pad with zeros
                }
            }

            // inner permutation, add output from previous permutation
            if (i > 0) {
                auto outputs = permutations.back().results();
                for(size_t j=0; j < param_t; j++){
                    lin_combs[j] = lin_combs[j] + outputs[j];
                    //in_inputs[j].terms.insert(in_inputs[j].terms.end(), outputs[j].terms.begin(), outputs[j].terms.end());
                }
            }

            for(size_t j=0; j<param_t; j++){
                LinearCombinationT lc;
                lc.assign(pb, lin_combs[j]);
                lcs.push_back(lc);
            }

            if (i < n_permutations - 1) {
                permutations.push_back(PoseidonPermutation(pb,
                                                           lcs,
                                                           0,
                                                           FMT(annotation_prefix, ".perm%d", i)));
            }else{
                // last permutation
                last_permutation.reset(new LastPoseidonPermutation(pb, lcs, param_c, FMT(annotation_prefix, ".perm%d", i)));
            }
            
        }


    }

    template<bool x = constrainOutputsSponge>
    typename std::enable_if<!x, LinearCombinationT>::type
    result() const
    {
        return last_permutation->result();
    }

    template<bool x = constrainOutputsSponge>
    typename std::enable_if<x, VariableT>::type
    result() const
    {
        return last_permutation->result();
    }

    void generate_r1cs_constraints() const
    {
        for( auto& permutation : permutations ) {
            permutation.generate_r1cs_constraints();
        }
        last_permutation->generate_r1cs_constraints();
    }

    void generate_r1cs_witness() const
    {
        for( auto& permutation : permutations ) {
            permutation.generate_r1cs_witness();
        }
        last_permutation->generate_r1cs_witness();
    }

    static FieldT hash( std::vector<FieldT> inputs)
    {
        ProtoboardT pb;

        auto var_inputs = make_var_array(pb, "input", inputs);

        PoseidonSponge_Gadget<SBox_gadget, param_t, param_c, param_F, param_P, constrainOutputsSponge> gadget(pb, var_inputs, "gadget");
        gadget.generate_r1cs_witness();
        return pb.val(gadget.result());
    }

};



// Warning: This implementation does not seem to follow recommendation for parameter generation

// Recommended maximum according to paper beginning: t is 1280 / 2*security (128: 5-6, 90: 7, 60: 10-11, 30: 21)
// Later, recommendation is t = 5 (rate = 4)

#if POSEIDON_PARAM_ALPHA == 3
using SBox_Precomputed = ThirdPower_gadget;
#elif POSEIDON_PARAM_ALPHA == 5
using SBox_Precomputed = FifthPower_gadget;
#elif POSEIDON_PARAM_ALPHA == 11
using SBox_Precomputed = EleventhPower_gadget;
#elif POSEIDON_PARAM_ALPHA == 13
using SBox_Precomputed = ThirteenthPower_gadget;
#endif


template<unsigned nInputs, unsigned nOutputs, bool constrainOutputs=true>
using Poseidon_Precomputed = Poseidon_gadget_T<SBox_Precomputed, POSEIDON_PARAM_T, 1, POSEIDON_PARAM_RF, POSEIDON_PARAM_RP, nInputs, nOutputs, constrainOutputs>;

template<bool constrainOutputsSponge=true>
using PoseidonSponge_Precomputed = PoseidonSponge_Gadget<SBox_Precomputed, POSEIDON_PARAM_T, 1, POSEIDON_PARAM_RF, POSEIDON_PARAM_RP, constrainOutputsSponge>;

//template<unsigned nInputs, unsigned nOutputs, bool constrainOutputs=true>
//using Poseidon_x5_128 = Poseidon_gadget_T<FifthPower_gadget, 5, 1, 8, 57, nInputs, nOutputs, constrainOutputs>;
//
//template<unsigned nInputs, unsigned nOutputs, bool constrainOutputs=true>
//using Poseidon_x5_90 = Poseidon_gadget_T<FifthPower_gadget, 5, 1, 8, 39, nInputs, nOutputs, constrainOutputs>;
//
//template<unsigned nInputs, unsigned nOutputs, bool constrainOutputs=true>
//using Poseidon_x5_60 = Poseidon_gadget_T<FifthPower_gadget, 5, 1, 8, 25, nInputs, nOutputs, constrainOutputs>;
//
//template<unsigned nInputs, unsigned nOutputs, bool constrainOutputs=true>
//using Poseidon_x5_30 = Poseidon_gadget_T<FifthPower_gadget, 5, 1, 8, 11, nInputs, nOutputs, constrainOutputs>;

class PoseidonHashToBits : public GadgetT
{
public:
    PoseidonSponge_Precomputed<true> m_hash;
    field2bits_strict m_tobits;

    PoseidonHashToBits(
            ProtoboardT& in_pb,
            const LinearCombinationArrayT& in_values,
            const std::string& annotation_prefix);

    /**
    * Resulting bits
    */
    const VariableArrayT& result() const;

    void generate_r1cs_constraints ();

    void generate_r1cs_witness ();
};

// namespace ethsnarks
}

#endif
