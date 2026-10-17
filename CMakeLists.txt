# CMakeLists.txt — the IPCEI benchmark suite (built by build.sh).
#
# Targets:
#   ipcei_zk          PID (ADSC-SNARK) and flag (Groth16) proofs + BN254 Schnorr,
#                     on the vendored third_party/adsc-snark (curve BN254)
#   ipcei_sig         Ed25519 uplink / downlink signatures (OpenSSL)
#   zk_selftest       checks every proof and signature verifies; times the signatures
#   (protocol and NTT benches: added below as they exist)
#
# Library locations come from build.sh (-DOPENFHE_ROOT, -DSEAL_ROOT, ...); every
# bench build of one backend (stock, Intel HEXL, rvv-hexl) is its own build dir.
cmake_minimum_required(VERSION 3.16)
project(ipcei_benches C CXX)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

include(${CMAKE_CURRENT_SOURCE_DIR}/benches/common/Platform.cmake)

find_package(OpenSSL REQUIRED COMPONENTS Crypto)

# ---------------------------------------------------------------- ZK (vendored ADSC-SNARK)
# The same options on every platform, so the ZK timings stay comparable: BN254,
# portable field arithmetic (no assembly), single thread, -O2 without an ISA flag.
set(ADSC_DIR ${CMAKE_CURRENT_SOURCE_DIR}/third_party/adsc-snark)
set(CURVE BN254 CACHE STRING "" FORCE)
set(OPT_FLAGS "-O2" CACHE STRING "" FORCE)
set(USE_ASM OFF CACHE BOOL "" FORCE)
set(MULTICORE OFF CACHE BOOL "" FORCE)
set(WITH_PROCPS OFF CACHE BOOL "" FORCE)
set(WITH_SUPERCOP OFF CACHE BOOL "" FORCE)
set(ETHSNARKS_DISABLE_TESTS ON CACHE BOOL "" FORCE)
add_subdirectory(${ADSC_DIR} ${CMAKE_BINARY_DIR}/adsc-snark EXCLUDE_FROM_ALL)

# The fork configures its sources through directory properties (add_definitions,
# include_directories): give our ZK library exactly the same ones.
get_directory_property(ADSC_DEFS DIRECTORY ${ADSC_DIR} COMPILE_DEFINITIONS)
get_directory_property(ADSC_INCS DIRECTORY ${ADSC_DIR} INCLUDE_DIRECTORIES)

add_library(ipcei_zk STATIC benches/common/ipcei/zk.cpp ${ADSC_DIR}/application/gadgets/utils.cpp)
set_target_properties(ipcei_zk PROPERTIES CXX_STANDARD 14 CXX_STANDARD_REQUIRED ON)
target_compile_definitions(ipcei_zk PRIVATE ${ADSC_DEFS})
target_compile_options(ipcei_zk PRIVATE -O2 -w)
target_include_directories(ipcei_zk PRIVATE ${ADSC_INCS} ${ADSC_DIR})
target_include_directories(ipcei_zk PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/benches/common)
target_link_libraries(ipcei_zk PUBLIC snark snark_crypto ff OpenSSL::Crypto)  # as the fork's controller_scenario

# ---------------------------------------------------------------- harness
add_library(ipcei_sig STATIC benches/common/ipcei/sig.cpp)
set_target_properties(ipcei_sig PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_include_directories(ipcei_sig PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/benches/common)
target_link_libraries(ipcei_sig PUBLIC OpenSSL::Crypto)

add_executable(zk_selftest benches/common/zk_selftest.cpp)
set_target_properties(zk_selftest PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
target_link_libraries(zk_selftest PRIVATE ipcei_zk ipcei_sig)

# ---------------------------------------------------------------- FHE libraries
# One build directory per backend (stock / intel-hexl / rvv-hexl); build.sh passes the
# matching installs. OPENFHE_N32_ROOT is optional (binfhe at NATIVE_SIZE=32).
set(DEPS ${CMAKE_CURRENT_SOURCE_DIR}/deps)
set(IPCEI_BACKEND "stock" CACHE STRING "stock | intel-hexl | rvv-hexl (recorded in every result)")
set(SEAL_ROOT ${DEPS}/stock/seal CACHE PATH "SEAL install prefix (lib/libseal-4.1.a)")
set(SEAL_HEXL_LIB "" CACHE FILEPATH "HEXL library SEAL was built against (empty: none, or SEAL_ROOT/lib/libhexl.a)")
set(OPENFHE_ROOT ${DEPS}/stock/openfhe-n64 CACHE PATH "OpenFHE install prefix, NATIVE_SIZE=64")
set(OPENFHE_N32_ROOT "" CACHE PATH "OpenFHE install prefix, NATIVE_SIZE=32 (optional)")

add_compile_options(-O3 ${NATIVE_FLAG})
find_package(Threads REQUIRED)

# ---- SEAL (an install prefix: build_seal.sh, or rvv-hexl's make seal)
file(GLOB SEAL_LIB "${SEAL_ROOT}/lib/libseal-*.a" "${SEAL_ROOT}/lib64/libseal-*.a")
file(GLOB SEAL_INCLUDES "${SEAL_ROOT}/include/SEAL-*")
if(SEAL_HEXL_LIB STREQUAL "" AND EXISTS "${SEAL_ROOT}/lib/libhexl.a")
  set(SEAL_HEXL_LIB "${SEAL_ROOT}/lib/libhexl.a")   # Intel HEXL fetched by SEAL (build_seal.sh copies it)
endif()
if(SEAL_LIB AND SEAL_INCLUDES)
  file(GLOB seal_config "${SEAL_ROOT}/include/SEAL-*/seal/util/config.h")
  file(STRINGS "${seal_config}" seal_hexl REGEX "^#define SEAL_USE_INTEL_HEXL")
  if(seal_hexl AND SEAL_HEXL_LIB STREQUAL "")
    message(FATAL_ERROR "SEAL under ${SEAL_ROOT} uses HEXL: pass -DSEAL_HEXL_LIB=<libhexl.a>")
  endif()
  if(NOT seal_hexl)
    set(SEAL_HEXL_LIB "")
  endif()
  message(STATUS "SEAL: ${SEAL_LIB} (HEXL: ${SEAL_HEXL_LIB})")
endif()

# ---- OpenFHE (find_openfhe: Platform.cmake)
set(OPENFHE_INC_SUFFIXES openfhe openfhe/core openfhe/pke openfhe/binfhe openfhe/cereal)
function(ipcei_openfhe tgt root)
  find_library(${tgt}_PKE OPENFHEpke PATHS "${root}/lib" "${root}/lib64" NO_DEFAULT_PATH)
  find_library(${tgt}_CORE OPENFHEcore PATHS "${root}/lib" "${root}/lib64" NO_DEFAULT_PATH)
  find_library(${tgt}_BINFHE OPENFHEbinfhe PATHS "${root}/lib" "${root}/lib64" NO_DEFAULT_PATH)
  set(incs "${root}/include")
  foreach(s ${OPENFHE_INC_SUFFIXES})
    list(APPEND incs "${root}/include/${s}")
  endforeach()
  target_include_directories(${tgt} PRIVATE ${incs})
  target_link_libraries(${tgt} PRIVATE ${${tgt}_PKE} ${${tgt}_BINFHE} ${${tgt}_CORE})
  file(GLOB hexl "${root}/lib/libhexl*" "${root}/lib64/libhexl*")   # Intel HEXL installed with OpenFHE
  if(hexl)
    list(GET hexl 0 hexl)
    target_link_libraries(${tgt} PRIVATE ${hexl})
  endif()
  set_target_properties(${tgt} PROPERTIES BUILD_RPATH "${root}/lib;${root}/lib64")
  # the installed package records the version (OpenFHE's version.h needs a define
  # that only exists while OpenFHE itself is built)
  file(GLOB vfile "${root}/lib/OpenFHE/OpenFHEConfigVersion.cmake" "${root}/lib64/OpenFHE/OpenFHEConfigVersion.cmake")
  set(PACKAGE_VERSION "unknown")
  if(vfile)
    list(GET vfile 0 vfile)
    include(${vfile})
  endif()
  target_compile_definitions(${tgt} PRIVATE IPCEI_OPENFHE_VERSION="${PACKAGE_VERSION}")
  omp_setup(${tgt})
endfunction()

function(ipcei_bench tgt src)
  add_executable(${tgt} ${src})
  set_target_properties(${tgt} PROPERTIES CXX_STANDARD 17 CXX_STANDARD_REQUIRED ON)
  target_compile_definitions(${tgt} PRIVATE IPCEI_BACKEND="${IPCEI_BACKEND}")
  target_link_libraries(${tgt} PRIVATE ipcei_zk ipcei_sig Threads::Threads)
endfunction()

# ---------------------------------------------------------------- protocol benches
if(SEAL_LIB AND SEAL_INCLUDES)
  ipcei_bench(bfv_seal benches/bfv/seal_protocol.cpp)
  target_include_directories(bfv_seal PRIVATE ${SEAL_INCLUDES})
  target_link_libraries(bfv_seal PRIVATE ${SEAL_LIB} ${SEAL_HEXL_LIB})
  add_executable(ntt_seal benches/ntt/seal_ntt.cpp)
  set_target_properties(ntt_seal PROPERTIES CXX_STANDARD 17)
  target_include_directories(ntt_seal PRIVATE ${SEAL_INCLUDES})
  target_link_libraries(ntt_seal PRIVATE ${SEAL_LIB} ${SEAL_HEXL_LIB} Threads::Threads)
else()
  message(WARNING "SEAL not found under ${SEAL_ROOT}: bfv_seal and ntt_seal not built")
endif()

if(EXISTS "${OPENFHE_ROOT}/include/openfhe")
  ipcei_bench(bfv_openfhe benches/bfv/openfhe_protocol.cpp)
  ipcei_openfhe(bfv_openfhe ${OPENFHE_ROOT})
  ipcei_bench(tfhe_openfhe benches/tfhe/openfhe_protocol.cpp)
  ipcei_openfhe(tfhe_openfhe ${OPENFHE_ROOT})
  add_executable(tfhe_lut_openfhe benches/tfhe/openfhe_lut_compare.cpp)
  set_target_properties(tfhe_lut_openfhe PROPERTIES CXX_STANDARD 17)
  ipcei_openfhe(tfhe_lut_openfhe ${OPENFHE_ROOT})
  add_executable(ntt_openfhe benches/ntt/openfhe_ntt.cpp)
  set_target_properties(ntt_openfhe PROPERTIES CXX_STANDARD 17)
  ipcei_openfhe(ntt_openfhe ${OPENFHE_ROOT})
else()
  message(WARNING "OpenFHE not found under ${OPENFHE_ROOT}: OpenFHE benches not built")
endif()

if(NOT OPENFHE_N32_ROOT STREQUAL "" AND EXISTS "${OPENFHE_N32_ROOT}/include/openfhe")
  ipcei_bench(tfhe_openfhe_n32 benches/tfhe/openfhe_protocol.cpp)
  ipcei_openfhe(tfhe_openfhe_n32 ${OPENFHE_N32_ROOT})
endif()
