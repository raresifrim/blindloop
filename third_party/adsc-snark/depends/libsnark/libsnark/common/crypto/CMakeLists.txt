add_library(
        snark_crypto

        STATIC
        digest/sha.cpp
        signature/eddsa.cpp
        mac/hmac.cpp
)
target_link_libraries(
        snark_crypto
        ${CRYPTO_LIBRARIES}
)
target_include_directories(
        snark_crypto

        PUBLIC
        ${DEPENDS_DIR}/libff
)

add_executable(
        common_crypto_digest_test
        EXCLUDE_FROM_ALL

        tests/test_digest.cpp
)
target_link_libraries(
        common_crypto_digest_test

        snark
        snark_crypto
)

add_executable(
        common_crypto_signature_test
        EXCLUDE_FROM_ALL

        tests/test_signature.cpp
)
target_link_libraries(
        common_crypto_signature_test

        snark
        snark_crypto
)

add_executable(
        common_crypto_mac_test
        EXCLUDE_FROM_ALL

        tests/test_mac.cpp
)
target_link_libraries(
        common_crypto_mac_test

        snark
        snark_crypto
)

add_executable(
        common_crypto_poseidon_test_vectors
        EXCLUDE_FROM_ALL

        tests/poseidon_test_vectors.cpp
)

target_link_libraries(
        common_crypto_poseidon_test_vectors

        snark
        snark_crypto
)