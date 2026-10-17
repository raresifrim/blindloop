/** @file
 *****************************************************************************
 Profiling program that exercises the ppZKADSNARK (first generator, then prover,
 then verifier) on a synthetic R1CS instance.

 The command

     $ libsnark/zk_proof_systems/ppsnark/r1cs_ppzkadsnark/profiling/profile_r1cs_gg_ppsnark 1000 10 Fr

 exercises the ppZKADSNARK (first generator, then prover, then verifier) on an R1CS instance with 1000 equations and an input consisting of 10 field elements.

 (If you get the error `zmInit ERR:can't protect`, see the discussion [above](#elliptic-curve-choices).)

 The command

     $ libsnark/zk_proof_systems/ppsnark/r1cs_ppzkadsnark/profiling/profile_r1cs_gg_ppsnark 1000 10 bytes

 does the same but now the input consists of 10 bytes.

 *****************************************************************************
 * @author     This file is part of libsnark, developed by SCIPR Lab
 *             and contributors (see AUTHORS).
 * @copyright  MIT license (see LICENSE file)
 *****************************************************************************/
#include <cassert>
#include <cstdio>
#include <boost/program_options.hpp>

#include <libff/common/profiling.hpp>
#include <libff/common/utils.hpp>
#include <libff/common/default_types/ec_pp.hpp>

#include <libsnark/common/default_types/r1cs_ppzkadsnark_pp.hpp>
#include <libsnark/relations/constraint_satisfaction_problems/r1cs/examples/r1cs_ext_examples.hpp>
#include <libsnark/zk_proof_systems/ppzkadsnark/r1cs_ppzkadsnark/examples/run_r1cs_ppzkadsnark.hpp>
#include <libsnark/reductions/r1cs_to_r1cs/r1cs_to_r1cs.hpp>


#define APPLICATION_NAME "zk ADSNARK profiling application"

using namespace libsnark;
typedef default_r1cs_ppzkadsnark_pp PP;

struct adsnark_profile_t {
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

    adsnark_profile_t& operator+=(const adsnark_profile_t& other){
        this->authentication_runtime += other.authentication_runtime;
        this->prover_runtime += other.prover_runtime;
        this->verifier_runtime += other.verifier_runtime;
        return *this;
    }
    adsnark_profile_t& operator/=(int d){
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
    std::cout << "Base field size " << libff::Fq<PP::snark_pp>::num_bits << " bits" << std::endl;
    std::cout << "Scalar field size " << libff::Fr<PP::snark_pp>::num_bits << " bits" << std::endl;
}

adsnark_profile_t profile_r1cs_ppzkadsnark(
        bool public_verifiability,
        size_t num_constraints,
        size_t private_input_size,
        size_t samples){

    long long tstart, tend;
    std::vector<adsnark_profile_t> profile_measurements(samples);
    adsnark_profile_t profile_result = {
            .public_inputs_size = 0,
            .private_inputs_size = private_input_size,
            .state_size = 0,
            .witness_size = 0,
            .security_parameter = libff::Fr<PP::snark_pp>::num_bits,
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
    const size_t public_io_size = 0;
    const size_t state_size = 0;
    const size_t iterations = 1;

    //r1cs_example<libff::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>> example = generate_r1cs_example_with_field_input<libff::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>> (num_constraints, private_input_size);
    r1cs_adsc_example<libff::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>> example = generate_r1cs_adsc_example_with_field_input<libff::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>>(num_constraints, public_io_size, private_input_size, state_size, iterations);
    r1cs_constraint_system<libff::Fr<snark_pp<default_r1cs_ppzkadsnark_pp>>> constraint_system = example.constraint_system;

    constraint_system.primary_input_size = private_input_size; // The ADSNARK implementation uses primary input as private input and does not consider actual primary (public) input
    constraint_system.auxiliary_input_size -= private_input_size;

    profile_result.witness_size = constraint_system.num_variables() - public_io_size - private_input_size - 2*state_size;

    profile_result.circuit_num_constraints = constraint_system.num_constraints();

    tstart = libff::get_nsec_cpu_time();
    r1cs_ppzkadsnark_auth_keys<PP> auth_keys = r1cs_ppzkadsnark_auth_generator<PP>();
    r1cs_ppzkadsnark_keypair<PP> keypair = r1cs_ppzkadsnark_generator<PP>(constraint_system, auth_keys.pap);
    tend = libff::get_nsec_cpu_time();
    profile_result.generator_runtime = tend - tstart;

    tstart = libff::get_nsec_cpu_time();
    r1cs_ppzkadsnark_processed_verification_key<PP> pvk = r1cs_ppzkadsnark_verifier_process_vk<PP>(keypair.vk);
    tend = libff::get_nsec_cpu_time();
    profile_result.verifier_preprocessing_runtime = tend - tstart;


    std::vector<libff::Fr<snark_pp<PP>>> data;
    data.reserve(private_input_size);
    std::vector<labelT> labels;
    labels.reserve(private_input_size);
    for (size_t i = 0; i < private_input_size; i++) {
        labels.emplace_back(labelT());
        data.emplace_back(example.private_input[0][i]);
    }

    for(size_t t = 0; t < samples; ++t) {
        std::vector<r1cs_ppzkadsnark_auth_data<PP>> auth_data;

        tstart = libff::get_nsec_cpu_time();
        if (public_verifiability)
        {
            auth_data = r1cs_ppzkadsnark_auth_sign<PP>(data,auth_keys.sak,labels);
        }else
        {
            auth_data = r1cs_ppzkadsnark_auth_sign_symmetric<PP>(data,auth_keys.sak,labels);
        }
        tend = libff::get_nsec_cpu_time();
        profile_measurements[t].authentication_runtime = tend - tstart;


        tstart = libff::get_nsec_cpu_time();
        r1cs_ppzkadsnark_proof<PP> proof = r1cs_ppzkadsnark_prover<PP>(keypair.pk,
                                                                         constraint_system,
                                                                         example.private_input[0],
                                                                         example.witness_assignment[0],
                                                                         auth_data);

        tend = libff::get_nsec_cpu_time();
        profile_measurements[t].prover_runtime = tend - tstart;

        if(t == 0){
            profile_result.proof_size = libff::get_serialized_size(proof);
            if (public_verifiability)
            {
                profile_result.proof_size += libff::get_serialized_size(auth_data);
            }
        }

        tstart = libff::get_nsec_cpu_time();
        bool verified;
        if (public_verifiability)
        {
            verified = r1cs_ppzkadsnark_online_verifier(pvk, auth_data, proof, auth_keys.pak, labels);
        } else
        {
            verified = r1cs_ppzkadsnark_online_verifier(pvk, proof, auth_keys.sak, labels);
        }
        tend = libff::get_nsec_cpu_time();
        profile_measurements[t].verifier_runtime = tend - tstart;

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
    const int public_io_size = -1;
    std::vector<int> private_inputs_range;
    int num_constraints;
    int samples;
    int state_size;
    bool public_verifiability;

    PP::init_public_params();

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
            ("constraints,c", po::value<int>(&num_constraints)->default_value(10), "2^x number of constraints")
            ("private-inputs,i", po::value< std::vector<int> >(&private_inputs_range)->multitoken()->default_value(std::vector<int>{10}, "10"),
                    "2^x number of private inputs. Single number or range: start end [stepsize]")
            ("state-size,s", po::value<int>(&state_size)->default_value(-1),
             "state-size. Must be -1 (not supported)")
            ("public-verifiability", po::value<bool>(&public_verifiability)->default_value(true), "enable public verifiability (true), or use designated verifier (false)");

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

    if (state_size != -1){
        std::cout << "State size not supported. Must be -1" << std::endl;
        return -1;
    }

    if (samples <= 0){
        std::cout << "Set samples to at least 1" << std::endl;
        return -1;
    }

    if (vm.count("profile")){
        adsnark_profile_t profile;

        libff::print_header("Profiling");
        std::cout << "Public verifiability: " << public_verifiability << std::endl;
        std::cout << "Num constraints: " << pow2(num_constraints) << " (2^" << num_constraints << ")" << std::endl;
        std::cout << "Public IO size: " << pow2(public_io_size) << " (2^" << public_io_size << ")" << std::endl;
        std::cout << "Security Parameter: " << libff::Fr<PP::snark_pp>::num_bits << std::endl;
        libff::print_separator();
        std::cout << "inputs, states, constraints, auth (s), prove (s), ver (s)" << std::endl;
        for(int private_inputs_num = private_inputs_range[0];
        private_inputs_num <= private_inputs_range[1];
        private_inputs_num += private_inputs_range[2]){
            profile = profile_r1cs_ppzkadsnark(
                                                public_verifiability,
                                                pow2(num_constraints),
                                               pow2(private_inputs_num),
                                               samples);
            std::cout << pow2(private_inputs_num) << ", " << 0 << ", "
                    << profile.circuit_num_constraints << ", "
                    << profile.authentication_runtime / 1e9  << ", "
                    << profile.prover_runtime / 1e9 << ", "
                    << profile.verifier_runtime / 1e9 << std::endl;

        }
        libff::print_separator();
        std::cout << "Proof size: " << profile.proof_size << " bytes" << std::endl;
        std::cout << "Done." << std::endl;
        return 0;
    }

    return 0;
}
