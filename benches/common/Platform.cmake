# Platform.cmake — cross-platform locations & flags for the FHE benches.
# include() this right after project() in each bench CMakeLists.
# Works on Apple-Silicon macOS (Homebrew), x86-64 Linux, and riscv64 Linux.
#
# Provides:
#   NATIVE_FLAG            native-arch optimisation flag (-mcpu/-march=...)
#   BREW_PREFIX           Homebrew prefix on macOS (empty on Linux)
#   DEP_INCLUDE DEP_LIB   header/lib roots for gmp/gmpxx (Homebrew or /usr)
#   OPENSSL_PREFIX        prefix holding openssl headers + libcrypto
#   omp_setup(<target>)   function: wire OpenMP onto a target, portably
#   find_openfhe(<root>)  macro: sets OPENFHE_PKE/CORE/BINFHE (+ OPENFHE_HEXL)

# ---------------------------------------------------------------------------
# ISA flag. SINGLE SOURCE OF TRUTH: build.sh passes the value already computed by
# benches/common/detect_env.sh as -DNATIVE_FLAG=..., so the shell builds
# (SEAL, OpenFHE) and the CMake bench builds cannot disagree about the target ISA.
#
# This file previously duplicated that decision as a two-branch "arm64 -> -mcpu=native,
# everything else -> -march=native". That silently produced `-march=native` on riscv64,
# which GCC rejects outright:
#     g++: error: '-march=native': ISA string must begin with rv32 or rv64
# — while detect_env.sh had long since grown a correct RISC-V probe. Duplicated logic,
# only one copy maintained. Hence the override below, plus a RISC-V-aware fallback so a
# bare `cmake -S ... -B ...` (no build.sh) still configures correctly.
if(NOT DEFINED NATIVE_FLAG OR NATIVE_FLAG STREQUAL "")
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    set(NATIVE_FLAG "-mcpu=native")
  elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
    # Mirrors detect_env.sh: -march=native is unreliable on RISC-V (depends on the GCC
    # version and kernel hwprobe), so probe explicit profiles newest-first. RISCV_MARCH
    # forces one. rva23u64 needs GCC 14+; rv64gcv (RV64GC + Vector 1.0) needs GCC 13+;
    # rv64gc is the no-vector floor.
    include(CheckCXXCompilerFlag)
    if(DEFINED ENV{RISCV_MARCH} AND NOT "$ENV{RISCV_MARCH}" STREQUAL "")
      set(NATIVE_FLAG "-march=$ENV{RISCV_MARCH}")
    else()
      check_cxx_compiler_flag("-march=rva23u64" RV_HAS_RVA23U64)
      check_cxx_compiler_flag("-march=rv64gcv"  RV_HAS_RV64GCV)
      if(RV_HAS_RVA23U64)
        set(NATIVE_FLAG "-march=rva23u64")
      elseif(RV_HAS_RV64GCV)
        set(NATIVE_FLAG "-march=rv64gcv")
      else()
        set(NATIVE_FLAG "-march=rv64gc")
      endif()
    endif()
  else()
    set(NATIVE_FLAG "-march=native")
  endif()
  message(STATUS "NATIVE_FLAG auto-detected: ${NATIVE_FLAG} (${CMAKE_SYSTEM_PROCESSOR})")
else()
  message(STATUS "NATIVE_FLAG from caller: ${NATIVE_FLAG}")
endif()

set(BREW_PREFIX "")
if(APPLE)
  find_program(BREW_EXE brew)
  if(BREW_EXE)
    execute_process(COMMAND ${BREW_EXE} --prefix
                    OUTPUT_VARIABLE BREW_PREFIX OUTPUT_STRIP_TRAILING_WHITESPACE)
  endif()
  if(NOT BREW_PREFIX)
    set(BREW_PREFIX "/opt/homebrew")   # sane default if brew isn't on PATH
  endif()
endif()

if(BREW_PREFIX)
  set(DEP_INCLUDE "${BREW_PREFIX}/include")
  set(DEP_LIB     "${BREW_PREFIX}/lib")
  set(OPENSSL_PREFIX "${BREW_PREFIX}/opt/openssl@3")
else()
  set(DEP_INCLUDE "/usr/include")
  set(DEP_LIB     "/usr/lib")
  set(OPENSSL_PREFIX "/usr")
endif()

# Wire OpenMP onto a target. Apple clang has no built-in OpenMP, so we point it
# at Homebrew libomp by hand; gcc/clang on Linux expose it via find_package.
function(omp_setup tgt)
  if(APPLE)
    target_compile_options(${tgt} PRIVATE -Xpreprocessor -fopenmp)
    target_include_directories(${tgt} PRIVATE "${BREW_PREFIX}/opt/libomp/include")
    target_link_libraries(${tgt} PRIVATE "${BREW_PREFIX}/opt/libomp/lib/libomp.dylib")
  else()
    find_package(OpenMP REQUIRED)
    target_link_libraries(${tgt} PRIVATE OpenMP::OpenMP_CXX)
  endif()
endfunction()

# Locate the three OpenFHE shared libs under <root>, tolerating lib/lib64 and
# .so/.dylib. Sets OPENFHE_PKE / OPENFHE_CORE / OPENFHE_BINFHE in the caller, plus
# OPENFHE_HEXL (empty unless <root> is an Intel-HEXL-enabled OpenFHE install).
macro(find_openfhe root)
  find_library(OPENFHE_PKE    OPENFHEpke    PATHS "${root}/lib" "${root}/lib64" NO_DEFAULT_PATH)
  find_library(OPENFHE_CORE   OPENFHEcore   PATHS "${root}/lib" "${root}/lib64" NO_DEFAULT_PATH)
  find_library(OPENFHE_BINFHE OPENFHEbinfhe PATHS "${root}/lib" "${root}/lib64" NO_DEFAULT_PATH)

  # ---- Intel HEXL variant ----
  # OpenFHE's third-party/intel-hexl ExternalProject installs HEXL with
  # -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX}, i.e. into the SAME prefix as OpenFHE
  # itself. So the header lands at <root>/include/hexl/hexl.hpp — one level ABOVE the
  # <root>/include/openfhe/... dirs the benches list individually, and therefore not on
  # their include path.
  #
  # That matters because once OpenFHE is built WITH_INTEL_HEXL=ON, its *installed public*
  # headers include it unconditionally:
  #     include/openfhe/core/math/hal/intnat-hexl/mubintvecnathexl.h:39
  #         #include "hexl/hexl.hpp"
  # which is reached from openfhe.h, so every consumer of a HEXL-enabled OpenFHE needs
  # <root>/include on its include path. OpenFHE's own build does precisely this, via
  # include_directories(${CMAKE_INSTALL_PREFIX}/include) in intel-hexl.cmake.
  #
  # Adding it here (rather than in each of the three bench CMakeLists, which build their
  # include lists differently) fixes BFV, NTT and TFHE in one place. It is inert for the
  # stock and n32 installs: <root>/include exists there too, just with no hexl/ inside.
  include_directories("${root}/include")

  # Link HEXL explicitly when present. With BUILD_SHARED=ON the OpenFHE .so already carries
  # a DT_NEEDED on libhexl.so, so this is usually redundant — but OpenFHE's HEXL headers are
  # partly inline/template, so a bench TU can emit references of its own. Cache var is
  # OPENFHE_HEXL_LIB; OPENFHE_HEXL is a plain var so it expands to nothing when absent
  # (a bare -NOTFOUND would otherwise land in target_link_libraries and break the link).
  find_library(OPENFHE_HEXL_LIB hexl PATHS "${root}/lib" "${root}/lib64" NO_DEFAULT_PATH)
  if(OPENFHE_HEXL_LIB)
    set(OPENFHE_HEXL "${OPENFHE_HEXL_LIB}")
    message(STATUS "OpenFHE: Intel HEXL backend detected — ${OPENFHE_HEXL_LIB}")
  else()
    set(OPENFHE_HEXL "")
  endif()
endmacro()
