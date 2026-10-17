/** @file
 *****************************************************************************

 Profiling program that exercises the strawman ADSC-SNARK (authenticate, generate, prove,
 then verify) on a synthetic R1CS instance.

 *****************************************************************************/

#include <cassert>
#include <cstdio>
#include <boost/program_options.hpp>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>

#include <libsnark/common/curve/curve_properties.hpp>
#include <libsnark/common/default_types/r1cs_gg_ppzkadscsnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_ext_examples.hpp>
#include <libsnark/zk_proof_systems/ppzksnark/r1cs_gg_ppzksnark/r1cs_gg_ppzksnark.hpp>

#include "strawman_adscsnark.hpp"

#define APPLICATION_NAME "Strawman ADSC-SNARK profiling application"

using namespace libsnark;
typedef default_r1cs_gg_ppzkadscsnark_pp PP;

struct adscsnark_profile_t {
    size_t public_inputs_size;
    size_t private_inputs_size;
    size_t state_size;
    size_t witness_size;
    size_t security_parameter;

    long long authentication_runtime;
    long long generator_runtime;
    long long verifier_preprocessing_runtime;
    long long prover_runtime;
    long long verifier_runtime;
    size_t circuit_num_constraints;
    size_t prover_key_size;
    size_t verifier_key_size;
    size_t proof_size;
    size_t authenticator_key_size;

    adscsnark_profile_t& operator+=(const adscsnark_profile_t& other){
        this->authentication_runtime += other.authentication_runtime;
        this->prover_runtime += other.prover_runtime;
        this->verifier_runtime += other.verifier_runtime;
        return *this;
    }
    adscsnark_profile_t& operator/=(int d){
        this->authentication_runtime /= d;
        this->prover_runtime /= d;
        this->verifier_runtime /= d;
        return *this;
    }
};

void display_info(){
    PP::init_public_params();
    std::cout << "Info " APPLICATION_NAME << std::endl;
    libff::print_compilation_info();
    std::cout << "Base field size " << libff::Fq<PP>::num_bits << " bits" << std::endl;
    std::cout << "Scalar field size " << libff::Fr<PP>::num_bits << " bits" << std::endl;
}


adscsnark_profile_t profile_strawman_adscsnark(
        size_t num_constraints,
        size_t public_io_size,
        size_t private_input_size,
        size_t state_size,
        size_t samples){

    long long tstart, tend;
    std::vector<adscsnark_profile_t> profile_measurements(samples);

    adscsnark_profile_t profile_result = {
            .public_inputs_size = public_io_size,
            .private_inputs_size = private_input_size,
            .state_size = state_size,
            .witness_size = 0,
            .security_parameter = libff::Fr<PP>::num_bits,
            .authentication_runtime = 0,
            .generator_runtime = 0,
            .verifier_preprocessing_runtime = 0,
            .prover_runtime = 0,
            .verifier_runtime = 0,
            .circuit_num_constraints = 0,
            .prover_key_size = 0,
            .verifier_key_size = 0,
            .proof_size = 0,
            .authenticator_key_size = 0,
    };

    r1cs_adsc_example<libff::Fr<PP> > example = generate_r1cs_adsc_example_with_field_input<libff::Fr<PP> >(num_constraints, public_io_size, private_input_size, state_size, samples);

    std::vector<strawman_adscsnark_authentication_keypair<PP>> auth_keys = strawman_adscsnark_generator_auth<PP>();
    strawman_adscsnark_relation<libff::Fr<PP>> relation = r1cs_example_to_r1cs_strawman_adsc<PP>(example, auth_keys);

    profile_result.witness_size = relation.constraint_system.num_variables() - public_io_size;
    profile_result.circuit_num_constraints = relation.constraint_system.num_constraints();

    tstart = libff::get_nsec_cpu_time();
    strawman_adscsnark_keypair<PP> keypair = strawman_adscsnark_generator<PP>(relation, example.state_assignment[0], auth_keys);
    tend = libff::get_nsec_cpu_time();
    profile_result.generator_runtime = tend - tstart;

    tstart = libff::get_nsec_cpu_time();
    strawman_adscsnark_processed_verification_key<PP> pvk = strawman_adscsnark_verifier_process_vk<PP>(keypair.vk);
    tend = libff::get_nsec_cpu_time();
    profile_result.verifier_preprocessing_runtime = tend - tstart;

    strawman_adscsnark_proof<PP> previous_proof = keypair.initial_proof;
    for(size_t t = 0; t < samples; ++t) {
        tstart = libff::get_nsec_cpu_time();
        strawman_adscsnark_signature<PP> signature = strawman_adscsnark_authenticate<PP>(keypair.aks[0], t, example.private_input[t]);



        tend = libff::get_nsec_cpu_time();
        profile_measurements[t].authentication_runtime = tend - tstart;


        tstart = libff::get_nsec_cpu_time();
        strawman_adscsnark_proof<PP> proof = strawman_adscsnark_prover<PP>(keypair.pk,
                                                                               relation,
                                                                               example.primary_input[t],
                                                                               example.private_input[t],
                                                                               example.state_assignment[t+1],
                                                                               example.witness_assignment[t],
                                                                                 {signature});
        tend = libff::get_nsec_cpu_time();
        profile_measurements[t].prover_runtime = tend - tstart;

        if(t == 0){
            profile_result.proof_size = get_serialized_size(proof);
        }

        tstart = libff::get_nsec_cpu_time();
        bool verified = strawman_adscsnark_online_verifier<PP>(pvk, example.primary_input[t], proof, previous_proof);
        tend = libff::get_nsec_cpu_time();
        profile_measurements[t].verifier_runtime = tend - tstart;

        previous_proof = proof;
        if(!verified){
            throw std::runtime_error("Proof does not verify");
        }
    }

    // Average time measurements
    for(size_t i = 0; i < samples; ++i){
        profile_result += profile_measurements[i];
    }
    profile_result /= samples;
    return profile_result;
}

int parse_range(std::vector<int> &range){
    switch(range.size()){
        case 1:
            range.push_back(range[0]);
            range.push_back(1);
            break;
        case 2:
            range.push_back(1);
            break;
        case 3:
            break;
        default:
            return -1;
    }
    return 0;
}

size_t pow2(int k){
    if (k < 0){
        return 0;
    }else if (k == 0){
        return 1;
    }else{
        return 2 << (k-1);
    }
}

int main(int argc, const char * argv[])
{
    namespace po = boost::program_options;
    std::vector<int> private_inputs_range;
    std::vector<int> state_range;
    int num_constraints;
    int public_io_size;
    int samples;

    PP::init_public_params();
    libsnark::EC_Inner<PP>::init_public_params();

#ifndef DEBUG
    // We do not want to print profiling info at runtime, we will print results at the end
    libff::inhibit_profiling_info = true;
    libff::inhibit_profiling_counters = true;
#endif

    std::cout << "Running " APPLICATION_NAME << std::endl;

    po::options_description desc("Usage");
    po::variables_map vm;
    desc.add_options()
            ("help", "show help")
            ("info", "show compilation info")
            ("profile", "run the profiler")
            ("samples", po::value<int>(&samples)->default_value(10), "number of samples for timing measurements")
            ("public-io,p", po::value<int>(&public_io_size)->default_value(-1), "number of public inputs/outputs")
            ("constraints,c", po::value<int>(&num_constraints)->default_value(10), "2^x number of constraints")
            ("private-inputs,i", po::value< std::vector<int> >(&private_inputs_range)->multitoken()->default_value(std::vector<int>{10}, "10"),
                    "2^x number of private inputs. Single number or range: start end [stepsize]")
            ("state-size,s", po::value< std::vector<int> >(&state_range)->multitoken()->default_value(std::vector<int>{10}, "10"),
                    "2^x number of state variables. Single number or range: start end [stepsize]");

    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help") || argc <= 1){
        std::cout << desc << std::endl;
        return 1;
    }

    if (vm.count("info")) {
        display_info();
        return 1;
    }

    if (parse_range(private_inputs_range)){
        std::cout << "Arguments private-inputs invalid. Provide single number or range." << std::endl;
        return -1;
    }

    if (parse_range(state_range)){
        std::cout << "Arguments state-size invalid. Provide single number or range." << std::endl;
        return -1;
    }

    if (num_constraints < 1) {
        std::cout << "Set number of constraints at least to 1" << std::endl;
        return -1;
    }

    if (samples <= 0){
        std::cout << "Set samples to at least 1" << std::endl;
        return -1;
    }

    if (vm.count("profile")){
        adscsnark_profile_t profile;

        libff::print_header("Profiling");
        std::cout << "Num constraints: " << pow2(num_constraints) << " (2^" << num_constraints << ")" << std::endl;
        std::cout << "Public IO size: " << pow2(public_io_size) << " (2^" << public_io_size << ")" << std::endl;
        std::cout << "Security Parameter: " << libff::Fr<PP>::num_bits << std::endl;
        libff::print_separator();
        std::cout << "inputs, states, constraints, auth (s), prove (s), ver (s)" << std::endl;
        for(int private_inputs_num = private_inputs_range[0];
        private_inputs_num <= private_inputs_range[1];
        private_inputs_num += private_inputs_range[2]){
            for(int state_num = state_range[0];
                state_num <= state_range[1];
                state_num += state_range[2]) {
                profile = profile_strawman_adscsnark(pow2(num_constraints),
                                                      pow2(public_io_size),
                                                      pow2(private_inputs_num),
                                                      pow2(state_num),
                                                      samples);
                std::cout << pow2(private_inputs_num) << ", " << pow2(state_num) << ", "
                        << profile.circuit_num_constraints << ", "
                        << profile.authentication_runtime / 1e9  << ", "
                        << profile.prover_runtime / 1e9 << ", "
                        << profile.verifier_runtime / 1e9 << std::endl;
            }
        }
        libff::print_separator();
        std::cout << "Proof size: " << profile.proof_size << " bytes" << std::endl;
        std::cout << "Done." << std::endl;
        return 0;
    }

    return 0;
}
