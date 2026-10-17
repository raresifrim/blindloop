# blindloop

**A closed control loop, computed blind and proven:** end-to-end FHE + ZKP benchmarks of a secure-actuation protocol on embedded nodes.

The use case is NXP's window-lift control (IPCEI A14), see [`scenario.hpp`](benches/common/ipcei/scenario.hpp). Three **end zones** each encrypt their own signals:

| end zone | signals | what it encrypts (flags) |
|---|---|---|
| **passenger** (the actuator) | window button UP/OFF/DOWN, 12-bit window position, 4 motor-error flags | button up/down, Full Up, Full Down, motor error |
| **driver side** | overwrite button for the passenger window UP/OFF/DOWN, child-lock | overwrite up/down, child-lock |
| **ignition control ECU** | Klem 15 | Klem |

The **central compute** (the Process APP) evaluates the motor command blind and sends it back to the passenger zone, which executes it. The command is Motor+, Motor- or Off:

```
dir    = overwrite != OFF ? overwrite : (child_lock ? OFF : passenger_button)
Motor+ : dir = UP   and not Full Up   and Klem and no motor error
Motor- : dir = DOWN and not Full Down and Klem and no motor error
else Off
```

**Threat model:**
- The end zones see their own raw values and share key material, provisioned into their HSEs.
- The central compute must stay blind, and every value on the bus is protected.
- No zone knows another zone's message layout; the central compute aligns the messages.

Every round covers one case of the decision. The first 12 rounds cover each case once, so a default run (12 rounds plus 1 warm-up) exercises all of them.

Each bench reports every protocol step per round (median / mean / min / max over the measured rounds), per zone, plus:
- each zone's total;
- the **critical path**: the end zones work in parallel, so the slowest uplink, then the central compute, then the passenger's downlink;
- the sequential sum of all steps.

One-time setup (key generation, provisioning, SNARK key generation) is not reported.

| bench | scheme | library | what the central compute does |
|---|---|---|---|
| `bfv_seal` | BFV | Microsoft SEAL 4.1.2 | lifts each zone's seeded LWE values to RLWE (EvalTrace), evaluates the decision on MAC-tagged polynomials |
| `bfv_openfhe` | BFV | OpenFHE 1.5.1 | aligns the zones' packed ciphertexts with rotations, evaluates the decision with a packed MAC (evaluation form, 3 instances) |
| `tfhe_openfhe` | TFHE (GINX) | OpenFHE 1.5.1 binfhe | `--mode flags`: the zones send their derived bits and the decision takes 11 bootstrapped gates; `--mode stress`: the zones send their raw signals bit by bit and the central compute also derives Full Up / Full Down (two 12-bit comparators) and the motor-error OR |
| `tfhe_openfhe_n32` | TFHE (GINX) | OpenFHE 1.5.1, `NATIVE_SIZE=32` | as above, 32-bit words |

Every protocol bench also runs these, for real, in every round:

- **ADSC proofs:** one ADSC-SNARK (Reinhart et al.) per end zone and round.
  - **What it proves:** the zone's sensors authenticate their raw values, and the circuit derives exactly the bits the zone encrypts (Full Up / Full Down from the private position, the OR of the error flags), checking that 0/1 values are boolean and that a 3-position switch never reports both directions.
  - **What stays private:** the raw values and the bits.
  - **Freshness:** the chained state is a round counter, so a proof is valid only in its own round.
- **Signatures:** Ed25519 (OpenSSL) on every link. This was measured about 7× faster than a BN254 Schnorr signature.

The ZK code is the vendored [`third_party/adsc-snark`](third_party/adsc-snark/VENDORED.md). It always uses BN254, portable field arithmetic and a single thread, so ZK timings stay comparable across machines.

Microbenches: `ntt_seal` and `ntt_openfhe` (forward/inverse NTT per size and prime width), `tfhe_lut_openfhe` (LUT vs gate evaluation), and `zk_selftest` (checks every zone's proof in both encodings and both signature schemes, checks that replays and tampering are rejected, and times each operation).

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
- **Shorter runs:** `./run.sh --rounds 3 --stress-rounds 1 --only "bfv_seal tfhe_flags"` (fewer than 12 rounds skips some cases).

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

- **Uplink:** every zone sends seeded ciphertexts: one 32-byte seed per zone and round plus the bit-packed `b` values (the `a` parts are regenerated by the central compute from the seed).
- **BFV:** a homomorphic MAC (Catalano–Fiore) computed alongside the decision lets the passenger zone check that the central compute evaluated exactly the agreed function. TFHE has no MAC in this design.
- **The proven bits aren't bound to the ciphertexts yet:** the ADSC proofs show each zone's bits come from its authenticated sensor data without revealing them. Nothing in the proofs ties those bits to the zone's FHE ciphertexts. For TFHE that needs an encryption-correctness check inside the circuit; for BFV a lattice proof of encryption.

## Copyright

Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
All rights reserved. See [COPYRIGHT](COPYRIGHT).

The vendored code under `third_party/` keeps its own licenses; see [`third_party/adsc-snark/VENDORED.md`](third_party/adsc-snark/VENDORED.md).
