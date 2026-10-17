include_directories(.)

#aabadd_subdirectory(gtest EXCLUDE_FROM_ALL)

if(${CURVE} STREQUAL "BN128")
  include_directories(ate-pairing/include)
  include_directories(xbyak)
  add_library(
    zm
    STATIC

    ate-pairing/src/zm.cpp
    ate-pairing/src/zm2.cpp
  )
endif()

if("${WITH_SUPERCOP}")
  include_directories(libsnark-supercop/include)

  enable_language(ASM)

  file(GLOB_RECURSE SUPERCOP_SRCS libsnark-supercop/*.c libsnark-supercop/*.s)

  add_library(
    snark_supercop
    STATIC

    ${SUPERCOP_SRCS}
  )

  target_link_libraries(
    snark_supercop

    ${CRYPTO_LIBRARIES}
  )
endif()

if(NOT "${USE_LINKED_LIBRARIES}")
  OPTION(IS_LIBFF_PARENT OFF)
  add_subdirectory(libff)

  OPTION(IS_LIBFQFFT_PARENT OFF)
  add_subdirectory(libfqfft)

  add_subdirectory(libsnark/libsnark)

  add_subdirectory(ethsnarks/src)
endif()


set(SHA3_USE_KECCAK ON)
add_definitions(-DSHA3_USE_KECCAK=1)

#aabadd_subdirectory(json)

#aabadd_subdirectory(SHA3IUF)
