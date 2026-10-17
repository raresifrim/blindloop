include_directories(.)

add_library(ethsnarks_io STATIC export.cpp import.cpp stubs.cpp)
add_library(ethsnarks_common STATIC utils.cpp crypto/blake2b.c)
target_link_libraries(ethsnarks_common ff crypto)
target_link_libraries(ethsnarks_io nlohmann_json ${CMAKE_THREAD_LIBS_INIT})
target_include_directories(ethsnarks_io PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(verify verify.cpp)
target_link_libraries(verify
		ethsnarks_gadgets
		gmpxx
		gmp)

#add_library(ethsnarks_verify SHARED verify_dll.cpp)
#target_link_libraries(ethsnarks_verify ethsnarks_common)

if( NOT ${ETHSNARKS_DISABLE_TESTS} )
	add_subdirectory(test)
endif()

add_subdirectory(r1cs_gg_ppzksnark_zok)
add_subdirectory(gadgets)
add_subdirectory(jubjub)

#add_library(ethsnarks_crypto crypto/signatures/eddsa.cpp)
#target_link_libraries(ethsnarks_crypto ethsnarks_common ethsnarks_jubjub snark_crypto)

if( NOT ${ETHSNARKS_DISABLE_PINOCCHIO} )
	add_subdirectory(pinocchio)
endif()

if( NOT ${ETHSNARKS_DISABLE_UTILS} )
	add_subdirectory(utils)
endif()

