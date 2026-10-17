// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "jubjub/fixed_base_mul.hpp"
#include "jubjub/point.hpp"

namespace ethsnarks {

namespace jubjub {


fixed_base_mul::fixed_base_mul(
	ProtoboardT &in_pb,
	const Params& in_params,
	const FieldT& in_base_x,
	const FieldT& in_base_y,
	const VariableArrayT& in_scalar,
	const std::string &annotation_prefix
) :
	GadgetT(in_pb, annotation_prefix)
{
	int window_size_bits = 2;
	assert( (in_scalar.size() % window_size_bits) == 0 );
	int window_size_items = 1 << window_size_bits;
	int n_windows = in_scalar.size() / window_size_bits;

//    std::cout << "fixed_base_mul: Generator  " << this->annotation_prefix << std::endl;
//    std::cout << "scalar ";
//    for (int i = 0; i < in_scalar.size(); i++){
//            std::cout << pb.val(in_scalar[i]);
//    }
//    std::cout << std::endl;

	FieldT start_x = in_base_x;
	FieldT start_y = in_base_y;
	FieldT x = in_base_x;
	FieldT y = in_base_y;

	// Precompute values for all lookup window tables
	for( int i = 0; i < n_windows; i++ )
	{
		std::vector<FieldT> lookup_x;
		std::vector<FieldT> lookup_y;

		// For each window, generate 4 points, in little endian:
		// (0,0) = 0 = 0
		// (1,0) = 1 = start 		# add
		// (0,1) = 2 = start+start	# double
		// (1,1) = 3 = 2+start 		# double and add
		for( int j = 0; j < window_size_items; j++ )
		{
			// When both bits are zero, add infinity (equivalent to zero)
			if( j == 0 ) {
				lookup_x.emplace_back(0);
				lookup_y.emplace_back(1);
				continue;
			}
			else {
				lookup_x.emplace_back(x);
				lookup_y.emplace_back(y);
			}

			// Affine addition
			// TODO: move into library
			const FieldT x1y2 = start_x * y;
			const FieldT y1x2 = start_y * x;
			const FieldT y1y2 = start_y * y;
			const FieldT x1x2 = start_x * x;
			const FieldT dx1x2y1y2 = in_params.d * x1x2 * y1y2;

			x = (x1y2 + y1x2) * (FieldT::one() + dx1x2y1y2).inverse();
			y = (y1y2 - (in_params.a * x1x2)) * (FieldT::one() - dx1x2y1y2).inverse();
		}

		const auto bits_begin = in_scalar.begin() + (i * window_size_bits);
		const VariableArrayT window_bits( bits_begin, bits_begin + window_size_bits );
		m_windows_x.emplace_back(in_pb, lookup_x, window_bits, FMT(annotation_prefix, ".windows_x[%d]", i));
		m_windows_y.emplace_back(in_pb, lookup_y, window_bits, FMT(annotation_prefix, ".windows_y[%d]", i));

		start_x = x;
		start_y = y;
	}

	// Chain adders together, adding output of previous adder with current window
	// First adder ads the first two windows together as there is no previous adder
	for( int i = 1; i < n_windows; i++ )
	{
		if( i == 1 ) {				
			m_adders.emplace_back(
				in_pb, in_params,
				m_windows_x[i-1].result(),
				m_windows_y[i-1].result(),
				m_windows_x[i].result(),
				m_windows_y[i].result(),
				FMT(this->annotation_prefix, ".adders[%d]", i));
		}
		else {
			m_adders.emplace_back(
				in_pb, in_params,
				m_adders[i-2].result_x(),
				m_adders[i-2].result_y(),
				m_windows_x[i].result(),
				m_windows_y[i].result(),
				FMT(this->annotation_prefix, ".adders[%d]", i));
		}
	}
}

void fixed_base_mul::generate_r1cs_constraints ()
{
	for( auto& lut_x : m_windows_x ) {
		lut_x.generate_r1cs_constraints();
	}

	for( auto& lut_y : m_windows_y ) {
		lut_y.generate_r1cs_constraints();
	}

	for( auto& adder : m_adders ) {
		adder.generate_r1cs_constraints();
	}
}

void fixed_base_mul::generate_r1cs_witness ()
{
	for( auto& lut_x : m_windows_x ) {
		lut_x.generate_r1cs_witness();
	}

	for( auto& lut_y : m_windows_y ) {
		lut_y.generate_r1cs_witness();
	}

	for( auto& adder : m_adders ) {
		adder.generate_r1cs_witness();
	}

//    std::cout << "fixed_base_mul: " << this->annotation_prefix << std::endl;
//    std::cout << "result: x=" << pb.val(this->result_x()) << " y=" << pb.val(this->result_y()) << std::endl;
//    std::cout << "base: x=" << m_windows_x[0].c[1] << " y=" << m_windows_y[0].c[1] << std::endl;
//    std::cout << "scalar ";
//    for (int i = 0; i < m_windows_x.size(); i++){
//        for(int j = 0; j < m_windows_x[i].b.size(); j++){
//            std::cout << pb.lc_val(m_windows_x[i].b[j]);
//        }
//    }
//    std::cout << std::endl;
}

const VariableT& fixed_base_mul::result_x() const {
	return m_adders.back().result_x();
}

const VariableT& fixed_base_mul::result_y() const {
	return m_adders.back().result_y();
}



fixed_base_mul_ed_3b::fixed_base_mul_ed_3b(
        ProtoboardT &in_pb,
        const Params& in_params,
        const FieldT& in_base_x,
        const FieldT& in_base_y,
        const VariableArrayT& in_scalar,
        const std::string &annotation_prefix
) :
        GadgetT(in_pb, annotation_prefix)
{
    int window_size_bits = 3;
    LinearCombinationArrayT scalar(in_scalar);
    //scalar.emplace_back(LinearCombinationT(pb, libsnark::ONE*0));
    //scalar.emplace_back(LinearCombinationT(pb, libsnark::ONE*0));
    //scalar.emplace_back(LinearCombinationT(pb, libsnark::ONE*0));

    // pad with zeros
    while(scalar.size() % window_size_bits != 0){
        scalar.emplace_back(LinearCombinationT(pb, libsnark::ONE*0));
    }

    int window_size_items = 1 << window_size_bits;
    int n_windows = scalar.size() / window_size_bits;

    FieldT start_x = in_base_x;
    FieldT start_y = in_base_y;
    FieldT x = in_base_x;
    FieldT y = in_base_y;

    // Precompute values for all lookup window tables
    for( int i = 0; i < n_windows; i++ )
    {
        std::vector<FieldT> lookup_x;
        std::vector<FieldT> lookup_y;

        // For each window, generate 8 points, in little endian:
        // (0,0,0) = 0 = 0
        // (1,0,0) = 1 = start 		# add
        // (0,1,0) = 2 = start+start	# double
        // (1,1,0) = 3 = 2+start 		# double and add
        // (0,0,1) = 4 =
        // (1,0,1) = 5 =
        // (0,1,1) = 6 =
        // (1,1,1) = 7 =
        for( int j = 0; j < window_size_items; j++ )
        {
            // When both bits are zero, add infinity (equivalent to zero)
            if( j == 0 ) {
                lookup_x.emplace_back(0);
                lookup_y.emplace_back(1);
                continue;
            }
            else {
                lookup_x.emplace_back(x);
                lookup_y.emplace_back(y);
            }

            // Affine addition
            const FieldT x1y2 = start_x * y;
            const FieldT y1x2 = start_y * x;
            const FieldT y1y2 = start_y * y;
            const FieldT x1x2 = start_x * x;
            const FieldT dx1x2y1y2 = in_params.d * x1x2 * y1y2;

            x = (x1y2 + y1x2) * (FieldT::one() + dx1x2y1y2).inverse();
            y = (y1y2 - (in_params.a * x1x2)) * (FieldT::one() - dx1x2y1y2).inverse();
        }

        const auto bits_begin = scalar.begin() + (i * window_size_bits);
        const LinearCombinationArrayT window_bits( bits_begin, bits_begin + window_size_bits );
        m_windows.emplace_back(in_pb, lookup_x, lookup_y, window_bits, FMT(annotation_prefix, ".windows[%d]", i));

        start_x = x;
        start_y = y;
    }

    // Chain adders together, adding output of previous adder with current window
    // First adder ads the first two windows together as there is no previous adder
    for( int i = 1; i < n_windows; i++ )
    {
        if( i == 1 ) {
            m_adders.emplace_back(
                    in_pb, in_params,
                    m_windows[i-1].result_u(),
                    m_windows[i-1].result_v(),
                    m_windows[i].result_u(),
                    m_windows[i].result_v(),
                    FMT(this->annotation_prefix, ".adders[%d]", i));
        }
        else {
            m_adders.emplace_back(
                    in_pb, in_params,
                    m_adders[i-2].result_x(),
                    m_adders[i-2].result_y(),
                    m_windows[i].result_u(),
                    m_windows[i].result_v(),
                    FMT(this->annotation_prefix, ".adders[%d]", i));
        }
    }
}

void fixed_base_mul_ed_3b::generate_r1cs_constraints ()
{
    for( auto& lut : m_windows ) {
        lut.generate_r1cs_constraints();
    }

    for( auto& adder : m_adders ) {
        adder.generate_r1cs_constraints();
    }
}

void fixed_base_mul_ed_3b::generate_r1cs_witness ()
{
    for( auto& lut : m_windows ) {
        lut.generate_r1cs_witness();
    }

    for( auto& adder : m_adders ) {
        adder.generate_r1cs_witness();
    }

//    std::cout << "fixed_base_mul_ed_3b: " << this->annotation_prefix << std::endl;
//    std::cout << "result: x=" << pb.val(this->result_x()) << " y=" << pb.val(this->result_y()) << std::endl;
//    std::cout << "base: x=" << m_windows[0].u[1] << " y=" << m_windows[0].v[1] << std::endl;
//    std::cout << "scalar ";
//    for (int i = 0; i < m_windows.size(); i++){
//        for(int j = 0; j < m_windows[i].b.size(); j++){
//            std::cout << pb.lc_val(m_windows[i].b[j]);
//        }
//    }
//    std::cout << std::endl;


}

const VariableT& fixed_base_mul_ed_3b::result_x() const {
    return m_adders.back().result_x();
}

const VariableT& fixed_base_mul_ed_3b::result_y() const {
    return m_adders.back().result_y();
}


fixed_base_mul_mg_3b::fixed_base_mul_mg_3b(
        ProtoboardT &in_pb,
        const Params& in_params,
        const FieldT& in_base_x,
        const FieldT& in_base_y,
        const VariableArrayT &in_scalar,
        const std::string &annotation_prefix
) :
        GadgetT(in_pb, annotation_prefix)
{
    LinearCombinationArrayT scalar(in_scalar);
    int window_size_bits = 3;

    // pad with zeros
    while(scalar.size() % window_size_bits != 0){
        scalar.emplace_back(LinearCombinationT(pb, libsnark::ONE*0));
    }

    int window_size_items = 1 << window_size_bits;
    int n_windows = scalar.size() / window_size_bits;
    int n_windows_mg = default_inner_ec_pp::Fp_type::ceil_size_in_bits() / window_size_bits - 1;
    n_windows_mg = n_windows_mg > n_windows ? n_windows : n_windows_mg; // min (n_windows_mg, n_windows)
    EdwardsPoint base(in_base_x, in_base_y);
    EdwardsPoint current(base);
    EdwardsPoint start(base);
    EdwardsPoint final(FieldT::zero(), FieldT::one());

    // Precompute values for all lookup window tables
    for( int i = 0; i < n_windows; i++ )
    {
        std::vector<FieldT> lookup_x;
        std::vector<FieldT> lookup_y;

        // For each window, generate 8 points, in little endian:
        // (0,0,0) = 0 = 0
        // (1,0,0) = 1 = start 		# add
        // (0,1,0) = 2 = start+start	# double
        // (1,1,0) = 3 = 2+start 		# double and add
        // (0,0,1) = 4 =
        // (1,0,1) = 5 =
        // (0,1,1) = 6 =
        // (1,1,1) = 7 =
        EdwardsPoint pts[window_size_items-1];
        for (int j = 0; j < window_size_items - 1; j++){
            pts[j] = current;
            current = current.add(start, in_params);
        }
        if (i < n_windows_mg) {
            for (int j = 0; j < window_size_items; j++) {
                if (j == 0) {
                    MontgomeryPoint mg = pts[window_size_items-2].as_montgomery(in_params);
                    lookup_x.emplace_back(mg.x);
                    lookup_y.emplace_back(mg.y);
                } else {
                    MontgomeryPoint mg = pts[window_size_items-2].add(pts[j - 1], in_params).as_montgomery(in_params);
                    lookup_x.emplace_back(mg.x);
                    lookup_y.emplace_back(mg.y);
                }
            }
        }else{
            for (int j = 0; j < window_size_items; j++) {
                if (j == 0) {
                    EdwardsPoint ed = pts[window_size_items-2];
                    lookup_x.emplace_back(ed.x);
                    lookup_y.emplace_back(ed.y);
                } else {
                    EdwardsPoint ed = pts[window_size_items-2].add(pts[j - 1], in_params);
                    lookup_x.emplace_back(ed.x);
                    lookup_y.emplace_back(ed.y);
                }
            }
        }
        const auto bits_begin = scalar.begin() + (i * window_size_bits);
        const LinearCombinationArrayT window_bits( bits_begin, bits_begin + window_size_bits );
        m_windows.emplace_back(in_pb, lookup_x, lookup_y, window_bits, FMT(annotation_prefix, ".windows[%d]", i));
        final = final.add(pts[window_size_items-2], in_params);
        start = current;
    }

    // Chain adders together, adding output of previous adder with current window
    // First adder adds the first two windows together as there is no previous adder
    VariableT previous_x, previous_y;
    previous_x = m_windows[0].result_u();
    previous_y = m_windows[0].result_v();
    for( int i = 1; i < n_windows; i++ )
    {
        if (i < n_windows_mg) {
            m_adders.emplace_back(
                    in_pb, in_params,
                    previous_x,
                    previous_y,
                    m_windows[i].result_u(),
                    m_windows[i].result_v(),
                    FMT(this->annotation_prefix, ".adders[%d]", i));
            previous_x = m_adders.back().result_x();
            previous_y = m_adders.back().result_y();

            if(i == n_windows_mg - 1){
                // After last montgomery adder, insert montgomery to edwards converter
                // Convert to affine edwards coordinates
                m_point_converter.reset(new MontgomeryToEdwards(in_pb, in_params, previous_x, previous_y, FMT(this->annotation_prefix, ".mg2ed")));
                previous_x = m_point_converter->result_x();
                previous_y = m_point_converter->result_y();
            }
        }else{
            m_adders_ed.emplace_back(
                    in_pb, in_params,
                    previous_x,
                    previous_y,
                    m_windows[i].result_u(),
                    m_windows[i].result_v(),
                    FMT(this->annotation_prefix, ".adders_ed[%d]", i));
            previous_x = m_adders_ed.back().result_x();
            previous_y = m_adders_ed.back().result_y();
        }
    }

    // Subtract additional base points that were added previously to avoid special zero addition cases
    EdwardsPoint ed = final.neg();
    m_sub.reset(new PointAdder(in_pb, in_params, LinearCombinationT(pb, libsnark::ONE*ed.x), LinearCombinationT(pb, libsnark::ONE*ed.y), previous_x, previous_y,
                                    FMT(this->annotation_prefix, ".sub")));

}

void fixed_base_mul_mg_3b::generate_r1cs_constraints ()
{
    for( auto& lut : m_windows ) {
        lut.generate_r1cs_constraints();
    }

    for( auto& adder : m_adders ) {
        adder.generate_r1cs_constraints();
    }

    m_point_converter->generate_r1cs_constraints();

    for( auto& adder : m_adders_ed ) {
        adder.generate_r1cs_constraints();
    }

    m_sub->generate_r1cs_constraints();
}

void fixed_base_mul_mg_3b::generate_r1cs_witness ()
{
    for( auto& lut : m_windows ) {
        lut.generate_r1cs_witness();
    }

    for( auto& adder : m_adders ) {
        adder.generate_r1cs_witness();
    }

    m_point_converter->generate_r1cs_witness();

    for( auto& adder : m_adders_ed ) {
        adder.generate_r1cs_witness();
    }

    m_sub->generate_r1cs_witness();
}

const VariableT& fixed_base_mul_mg_3b::result_x() const {
    return m_sub->result_x();
}

const VariableT& fixed_base_mul_mg_3b::result_y() const {
    return m_sub->result_y();
}

// namespace jubjub
}

// namespace ethsnarks
}
