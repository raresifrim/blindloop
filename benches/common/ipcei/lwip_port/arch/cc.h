/* Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
 * All rights reserved.
 *
 * lwIP platform port for the emulated end-zone stack: hosted build (macOS, Linux), standard
 * integer types and byte order from the toolchain, diagnostics to stderr. */
#ifndef IPCEI_LWIP_ARCH_CC_H
#define IPCEI_LWIP_ARCH_CC_H

#include <stdio.h>
#include <stdlib.h>

#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define BYTE_ORDER BIG_ENDIAN
#else
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#define LWIP_PLATFORM_DIAG(x) do { fprintf(stderr, "lwip: "); fprintf x; } while (0)
#define LWIP_PLATFORM_ASSERT(x) do { fprintf(stderr, "lwip assertion \"%s\" failed at %s:%d\n", x, __FILE__, __LINE__); abort(); } while (0)

#define LWIP_RAND() ((u32_t)rand())
#define LWIP_TIMEVAL_PRIVATE 0

#endif
