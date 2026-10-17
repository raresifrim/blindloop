// This is an open source non-commercial project. Dear PVS-Studio, please check it.
// PVS-Studio Static Code Analyzer for C, C++ and C#: http://www.viva64.com

#include "gadgets/mimc.hpp"
#include "utils.hpp"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/positional_options.hpp>

namespace po = boost::program_options;

using std::cout;
using std::cerr;
using std::endl;
using std::string;
using ethsnarks::FieldT;


int main( int argc, char **argv )
{
	ethsnarks::ppT::init_public_params();

	po::options_description desc("Options");
	po::positional_options_description p;
	p.add("command", 1);
	p.add("subargs", -1);

	int rounds = 91;
	bool verbose = false;
	string seed = "mimc";
	string key_opt("0");
	string cmd = "help";
	std::vector<string> subargs;

	desc.add_options()
		("help", "display usage information")
		("rounds,r", po::value<decltype(rounds)>(&rounds)->default_value(rounds), "number of rounds")
		("seed,s", po::value<decltype(seed)>(&seed)->default_value(seed), "seed for round constants")
		("key,k", po::value<decltype(key_opt)>(&key_opt), "initial key")
		("verbose,v", po::bool_switch(&verbose), "display settings")
		("command", po::value<decltype(cmd)>(&cmd), "Sub-command")
		("subargs", po::value<decltype(subargs)>(&subargs), "Arguments for command")
	;

	po::variables_map vm;
	auto parsed = po::command_line_parser(argc, argv)
					 .options(desc)
					 .positional(p)
					 .allow_unregistered()
					 .run();
	po::store(parsed, vm);
	po::notify(vm);

	FieldT key(key_opt.c_str());

	const auto round_constants = ethsnarks::MiMC_gadget::constants(seed.c_str(), rounds);

	if( verbose ) {
		cerr << "# exponent 7" << endl;
		cerr << "# rounds " << rounds << endl;
		cerr << "# seed " << seed << endl;
		cerr << "# key "; key.print();
	}

	if( cmd == "constants" )
	{
		for( const auto& c_i : round_constants )
		{
			c_i.print();
		}
	}
	else if( cmd == "encrypt" )
	{
		if( subargs.size() == 0 )
		{
			cerr << "Requires arguments" << endl;
			return 2;
		}

		for( const auto& w : subargs )
		{
			const FieldT x(w.c_str());
			ethsnarks::mimc(round_constants, x, key).print();
			key = ethsnarks::mimc(round_constants, key, key);
		}
	}
	else if( cmd == "hash" )
	{
		if( subargs.size() == 0 )
		{
			cerr << "Requires arguments" << endl;
			return 3;
		}

		std::vector<FieldT> msgs;
		msgs.reserve(subargs.size());
		for( const auto& x : subargs )
		{
			msgs.emplace_back(x.c_str());
		}

		ethsnarks::mimc_hash(msgs, key).print();
	}
	else
	{
		cerr << "Usage: " << argv[0] << " <constants|encrypt|hash> [args ...]" << endl << endl;
		cerr << desc << endl;
		return 1;
	}

	return 0;
}