# Vendored: ADSC-SNARK (Reinhart et al.)

A pinned copy of the ADSC-SNARK applications repository and the parts of its
dependencies that its build uses, so the benchmark suite builds the end zones' input
proofs (r1cs_gg_ppzkadscsnark) from one stable libsnark, without network access.

Origin: https://github.com/johannes-reinhart/adsc-snark
  commit 8f4621037a99bd1d82fafa24011e265374c6c893
Submodules at the commits pinned by that commit:
  depends/ethsnarks: cf16cf12f02ccd7dc3feb2658e8912511ed47ac5
  depends/libff: 70b453a454963bbec3de61b643771ce2e671fa75
  depends/libfqfft: 599dd3f37e1c9a0779b955d92a69e8912ec6b410
  depends/libsnark: 57a3466ebcd41dd5635a7b53dd7c988b327dc6be
  depends/libsnark-supercop: b04a0ea2c7d7422d74a512ce848e762196f48149
  (libsnark: branch adscsnark; libff, libfqfft, ethsnarks: branch acdev, of the author's forks
   github.com/johannes-reinhart/{libsnark,libff,libfqfft,ethsnarks})
Copied on 2026-10-17.

Trimmed (not needed by the build, removed):
- every nested depends/ tree inside libff, libfqfft and libsnark (ate-pairing, xbyak, gtest,
  duplicate libff/libfqfft copies): the top-level depends/CMakeLists.txt builds libff,
  libfqfft and libsnark/libsnark from depends/; ate-pairing/xbyak are only used for CURVE=BN128
  (the suite uses BN254, a portable curve in this libff)
- depends/libsnark-supercop (only for WITH_SUPERCOP=ON; the suite builds with OFF)
- depends/ethsnarks except src/ (the only part depends/CMakeLists.txt adds)
- .git metadata

Licenses: the ADSC-SNARK code, libsnark, libff and libfqfft are MIT (see each LICENSE);
ethsnarks is LGPL-3.0 (depends/ethsnarks/LICENSE). Keep these files with the code.

Build options used by the suite: -DCURVE=BN254 -DUSE_ASM=OFF -DWITH_PROCPS=OFF
-DWITH_SUPERCOP=OFF -DOPT_FLAGS=-O2 (the same flags on every platform, so the ZK timings
stay comparable). Local changes to the vendored sources:
- CMakeLists.txt and depends/libsnark/CMakeLists.txt: FIND_PACKAGE(Boost ... program_options)
  is QUIET instead of REQUIRED. Only the demo and profiling executables use Boost, and none of
  them is built by default, so machines without libboost-program-options-dev can build.
