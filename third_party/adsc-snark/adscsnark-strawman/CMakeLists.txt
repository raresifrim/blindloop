add_executable(
        profile_strawman_adscsnark
        EXCLUDE_FROM_ALL

        profile_strawman_adscsnark.cpp;
)

target_link_libraries(
        profile_strawman_adscsnark

        snark
        snark_crypto
        ethsnarks_jubjub
        ${Boost_LIBRARIES}
)



