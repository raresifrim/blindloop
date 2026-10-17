ADSC-SNARK Applications and Benchmarking
================================================================================

This repository contains demo applications for ADSC-SNARK. It also provides
an implementation of a strawman ADSC-SNARK, which arithmetizes signature
verification and collision resistant hash functions in the relation. 

The ADSC-SNARK and corresponding benchmarking routines
are implemented in the libsnark submodule

The demo applications are:

1. A flight control law including flight envelope protections as well as lateral and longitudinal control for fixed wing aircraft in normal flight conditions
2. A 3-DOF PID flight control law for a quadrotor aircraft

The following instructions have been tested on **Ubuntu 24.04**

--------------------------------------------------------------------------------
Build instructions
--------------------------------------------------------------------------------

0. Install build tools and dependencies

```
sudo apt-get install build-essential cmake libgmp3-dev libssl-dev pkg-config libboost-all-dev
```

1. Clone submodules

```
git submodule init && git submodule update
```

2. Configure

```
mkdir build && cd build
cmake ..  
```
BN254 will be used as the default elliptic curve.
For other elliptic curves, add -DCURVE=<CURVE> in the configure step and replace <CURVE> with any of:
- BN254
- BN183
- BN124
- GMV181
- GMV97
- GMV58

Example:

```
cmake -DCURVE=BN183 ..
```

3. Build

Demo Applications: Flight Control and 3 DOF PID Controller

```
cmake --build . --target flightcontrol_scenario controller_scenario -j 8
```

Profiling Applications for ADSC-SNARKs

```
cmake --build . --target profile_strawman_adscsnark profile_r1cs_gg_ppzkadscsnark profile_r1cs_ppzkadsnark profile_sc_lego_gro16 -j 8
```

--------------------------------------------------------------------------------
Run instructions
--------------------------------------------------------------------------------

### Demo Application: Fixed wing flight control law

```
./application/flightcontrol_scenario --all --rounds 1000 --scenario 6
```

* --file option lets the parties communicate via disc, otherwise communication is in RAM
* --silent option reduces outputs to console for more accurate profiling
* without --all, generator, sensor, device (prover) or verifier can be run individually with options --generator, --sensor, --device or --verifier
* --rounds is the number of iterations the flight control law is invoked
* choose scenario 0 - 6 for different inputs to the flight controller:
  * 0: Equilibrium - All control inputs are 0
  * 1: Pull up - Pilot pulls stick for nose up command
  * 2: Push down - Pushes stick for nose down command
  * 3: Curve left - Pilot pushes stick to left for roll command
  * 4: Curve right - Pilot pushes stick to right for roll command
  * 5: Stall - Angle-of-attack increases with pilot pulling stick triggering angle-of-attack protection. After pushing stick for 0.5s, protection is turned off.
  * 6: Overspeed - Aircraft speed first increases and then decreases, triggering and releasing high-speed protection


### Demo Application: 3 DOF PID Controller

```
./application/controller_scenario --all --rounds 10
```

* --file option lets the parties communicate via disc, otherwise communication is in RAM
* --silent option reduces outputs to console for more accurate profiling
* without --all, generator, sensor, device (prover) or verifier can be run individually with options --generator, --sensor, --device or --verifier

### Profiling Applications:
Profile ADSC-SNARKs for 2^1 - 2^4 inputs and 2^1 - 2^4 states

- **profile_strawman_adscsnark**: ADSC-SNARK with arithmetized hash function and signature verification
- **profile_r1cs_gg_ppzkadscsnark**: The ADSC-SNARK by Reinhart et al.
- **profile_r1cs_ppzkadsnark**: The AD-SNARK by Backes et al. (S&P'15)
- **profile_r1cs_gg_ppzkadscsnark**: An SC-SNARK by functional composition of LegoGro16, Campanelli et al.  (CCS'19)
```
./adscsnark-strawman/profile_strawman_adscsnark --profile -i 1 4 -s 1 4
./depends/libsnark/libsnark/profile_r1cs_gg_ppzkadscsnark --profile -i 1 4 -s 1 4
./depends/libsnark/libsnark/profile_r1cs_ppzkadsnark --profile -i 1 4
./depends/libsnark/libsnark/profile_sc_lego_gro16 --profile -s 1 4
```

--------------------------------------------------------------------------------
Troubleshooting
--------------------------------------------------------------------------------

For large inputs, AD-SNARK by Backes et. al. (profile_r1cs_ppzkadsnark) requires 
a lot of stack memory. If the OS reports memory violations, try to increase
the stack size before launching the binary:

```
ulimit -s unlimited
```
