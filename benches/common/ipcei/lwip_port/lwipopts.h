/* Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
 * All rights reserved.
 *
 * lwIP configuration of the emulated end-zone stack: an MCU-class node without an OS
 * (NO_SYS=1, raw TCP API, no sockets or netconn), IPv4 over Ethernet with a static ARP
 * entry for its single peer, standard 1500-byte MTU. Checksums are computed in software by
 * default; the bench's --eth-offload switches them off per interface, as when the MAC
 * computes them (LWIP_CHECKSUM_CTRL_PER_NETIF). Buffers are sized for the largest message
 * of the suite (the SEAL downlink, about 0.5 MB, written in window-sized chunks). */
#ifndef IPCEI_LWIPOPTS_H
#define IPCEI_LWIPOPTS_H

#define NO_SYS                      1
#define SYS_LIGHTWEIGHT_PROT        0
#define LWIP_NETCONN                0
#define LWIP_SOCKET                 0
#define LWIP_TIMERS                 1

#define LWIP_IPV4                   1
#define LWIP_IPV6                   0
#define LWIP_ARP                    1
#define ETHARP_SUPPORT_STATIC_ENTRIES 1
#define LWIP_ETHERNET               1
#define LWIP_ICMP                   0
#define LWIP_RAW                    0
#define LWIP_UDP                    0
#define LWIP_TCP                    1
#define LWIP_DHCP                   0
#define LWIP_AUTOIP                 0
#define LWIP_ACD                    0
#define LWIP_IGMP                   0
#define LWIP_DNS                    0
#define IP_REASSEMBLY               0
#define IP_FRAG                     0
#define LWIP_NETIF_LOOPBACK         0
#define LWIP_HAVE_LOOPIF            0
#define LWIP_STATS                  0
#define LWIP_TCP_KEEPALIVE          0
#define LWIP_CHECKSUM_CTRL_PER_NETIF 1

#define MEM_ALIGNMENT               8
#define MEM_SIZE                    (1024 * 1024)
#define MEMP_NUM_PBUF               64
#define MEMP_NUM_TCP_PCB            8
#define MEMP_NUM_TCP_PCB_LISTEN     8
#define MEMP_NUM_TCP_SEG            512
#define PBUF_POOL_SIZE              512
#define PBUF_POOL_BUFSIZE           1536

#define TCP_MSS                     1460
#define TCP_WND                     (44 * TCP_MSS)
#define TCP_SND_BUF                 (44 * TCP_MSS)
#define TCP_SND_QUEUELEN            (4 * TCP_SND_BUF / TCP_MSS)
#define TCP_OVERSIZE                TCP_MSS

#endif
