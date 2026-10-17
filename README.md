# blindloop

**A closed control loop, computed blind and proven:** end-to-end FHE + ZKP benchmarks of a secure-actuation protocol on embedded nodes.

End-to-end benchmarks of the IPCEI sensor protocol. An **end node** encrypts its sensor
flags, proves its PID control step and its flags in zero knowledge, and signs the uplink.
A **central node** verifies everything, evaluates on the ciphertexts, and returns a signed
encrypted decision, which the end node verifies and decrypts.

Each bench reports every protocol step per round (median / mean / min / max over the
measured rounds), plus the end-node, central-node and end-to-end totals. One-time setup
(key generation, SNARK key generation) is not reported.

| bench | scheme | library | evaluation |
|---|---|---|---|
| `bfv_seal` | BFV | Microsoft SEAL 4.1.2 | seeded-LWE uplink, promote + trace, degree-5 product tree with an algebraic MAC tag |
| `bfv_openfhe` | BFV | OpenFHE 1.5.1 | the same protocol, with OpenFHE's own best parameters |
| `tfhe_openfhe` | TFHE (GINX) | OpenFHE 1.5.1 binfhe | `--mode flags`: the end node sends one-bit flags, the central node ANDs them; `--mode stress`: the end node sends the raw readings bit by bit, the central node runs a bit-serial comparator per sensor, then the AND |
| `tfhe_openfhe_n32` | TFHE (GINX) | OpenFHE 1.5.1, `NATIVE_SIZE=32` | as above, 32-bit words |

Every protocol bench also runs these, for real, in every round:

- **ADSC proof**: one ADSC-SNARK (Reinhart et al.) per round over the end node's authenticated sensor data, with a state commitment chained across rounds. It covers two things:
  - the PID controller step;
  - the flags, wherever the end node sends flags (BFV, and TFHE `--mode flags`): each threshold sensor authenticates its reading, and the circuit computes `flag_i = reading_i < threshold_i` against the central node's public thresholds.

  The readings and the flags stay private.
- **Signatures**: Ed25519 (OpenSSL) on both links. This was measured about 7× faster than a BN254 Schnorr signature.

The ZK code is the vendored [`third_party/adsc-snark`](third_party/adsc-snark/VENDORED.md). It always uses BN254, portable field arithmetic and a single thread, so ZK timings stay comparable across machines.

Microbenches: `ntt_seal` and `ntt_openfhe` (forward/inverse NTT per size and prime width), `tfhe_lut_openfhe` (LUT vs gate evaluation), and `zk_selftest` (checks that every proof and signature verifies and that tampering is rejected, and times each operation).

## Backends

`build.sh` builds SEAL and OpenFHE once per backend, and builds the benches once against each:

| backend | when | SEAL | OpenFHE |
|---|---|---|---|
| `stock` | always | as released | as released, `NATIVE_SIZE` 64 and 32 |
| `intel-hexl` | x86-64 with AVX-512 | `-DSEAL_USE_INTEL_HEXL=ON` (HEXL 1.2.5) | openfhe-hexl v1.5.1.0 overlay (HEXL 1.2.6), `NATIVE_SIZE=64` only |
| `rvv-hexl` | riscv64 with V | built by the [rvv-hexl](https://github.com/raresifrim/rvv-hexl) checkout | the same overlay with rvv-hexl's patches, `NATIVE_SIZE` 64 and 32 |

For `rvv-hexl`, clone rvv-hexl next to this repo, or set `RVV_HEXL_DIR`. `build.sh` then runs
its `make seal` / `make openfhe WITH_RVV_HEXL=ON`. Those first reinstall rvv-hexl, so the
benches always measure rvv-hexl at its current commit, which `BUILD_INFO` records.

## Build and run

```sh
./build.sh --packages     # first time: also installs cmake, gmp, OpenSSL, boost, libomp
./build.sh                # every backend this CPU supports; --backends "stock" to pick
./run.sh                  # all benches of all built backends -> results/<host>/REPORT.md
```

- **Layout:**
  - library installs go in `deps/<backend>/`
  - benches go in `build/<backend>/`
  - each run writes `results/<host>/<backend>/<bench>.json` (the breakdown) and `.txt` (the console output), plus `REPORT.md` and `summary.json`
- **Rebuilds:** libraries are rebuilt only when their configuration changes. `FORCE=1 ./build.sh` rebuilds them anyway.
- **Comparing runs:** `tools/report.py results/a results/b` compares runs side by side in `results/COMPARE.md`.
- **Compiler and flags:** clang++ on macOS, g++ on Linux. On riscv64 it uses the newest g++ that accepts `-march=rva23u64`. The ISA flag is `-mcpu=native`, `-march=native` or `-march=rva23u64`; see [`benches/common/detect_env.sh`](benches/common/detect_env.sh).
- **Shorter runs:** `./run.sh --rounds 3 --stress-rounds 1 --only "bfv_seal tfhe_flags"`.

Run on an otherwise idle machine: the benches measure wall-clock time.

### Boards with several core types

On big.LITTLE boards, build and run once per core type. Each core type gets its own `deps/`, `build/` and `results/` directories:

```sh
ARM_CPU=cortex-a78 ./build.sh && ARM_CPU=cortex-a78 ./run.sh --launch "taskset -c 4-7"
ARM_CPU=cortex-a55 ./build.sh && ARM_CPU=cortex-a55 ./run.sh --launch "taskset -c 0-3"
```

On the SpaceMiT K3, the binaries are the same for both clusters, so only the run differs:

```sh
./run.sh --label k3-x100 --launch "taskset -c 0-7"
./run.sh --label k3-a100 --launch "$RVV_HEXL_DIR/build/tools/ailaunch"
```

## Protocol notes

- **Uplink:** the end node sends its encrypted flags as seeded LWE: a 32-byte seed plus the bit-packed `b` values. The central node expands `a` from the seed.
- **BFV:** the central node lifts the LWE samples into an RLWE ciphertext and computes the product tree. The MAC tag `Y(alpha)` lets the end node check the result.
- **TFHE:** the central node bootstraps gate by gate on the LWE ciphertexts. There is no MAC tag in this design.
- **The flags stay private, but they aren't bound to the ciphertexts:** the ADSC proof shows the flags are honest comparisons of authenticated readings without revealing them. Nothing in the proof yet ties those flags to the FHE ciphertexts of the uplink. For TFHE that needs an encryption-correctness check inside the circuit; for BFV it needs a lattice proof of encryption.

## Copyright

Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
All rights reserved. See [COPYRIGHT](COPYRIGHT).

The vendored code under `third_party/` keeps its own licenses; see [`third_party/adsc-snark/VENDORED.md`](third_party/adsc-snark/VENDORED.md).
