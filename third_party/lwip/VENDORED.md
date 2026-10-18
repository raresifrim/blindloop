# lwIP (vendored)

lwIP 2.2.1, tag `STABLE-2_2_1_RELEASE` (commit 77dcd25a72509eb83f72b033d219b1d40cd8eb95) of
https://github.com/lwip-tcpip/lwip, BSD-3-Clause (COPYING).

Trimmed to what the suite builds: `src/core` (the TCP/IPv4 sources listed in CMakeLists.txt),
`src/core/ipv4`, `src/netif/ethernet.c` and the headers (`src/include/lwip`, `netif`, `compat`;
the apps headers removed; the PPP headers stay, `init.c` and `memp.c` include them). No source file is modified.

Used by the end zones' emulated Ethernet link (benches/common/ipcei/net.cpp): the stack an
MCU-class end node runs (NO_SYS=1, raw API, as in NXP's S32K3 RTD / FreeRTOS lwIP
integrations), with an in-memory network interface in place of the MAC driver. Its
configuration is benches/common/ipcei/lwip_port/lwipopts.h.
