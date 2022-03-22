/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

/* ! @file
@brief This file contains basic type definitions that are platform dependent.
*/

#ifndef SSI_PAL_TYPES_PLAT_H
#define SSI_PAL_TYPES_PLAT_H
/* Host specific types for standard (ISO-C99) compilant platforms */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

typedef uintptr_t SaSiVirtAddr_t;
typedef uint32_t SaSiBool_t;
typedef uint32_t SaSiStatus;

#define SaSiError_t   SaSiStatus
#define SASI_INFINITE 0xFFFFFFFFUL

#define CEXPORT_C
#define CIMPORT_C

/* Define macros for host to SeP endianess conversion (for host wrappers) */
#include <endian.h>
#include <byteswap.h>
#if __BYTE_ORDER == __BIG_ENDIAN
#define cpu_to_le16(x) bswap_16(x)
#define le16_to_cpu(x) bswap_16(x)
#define cpu_to_le32(x) bswap_32(x)
#define le32_to_cpu(x) bswap_32(x)
#else /* __LITTLE_ENDIAN */
#define cpu_to_le16(x) x
#define le16_to_cpu(x) x
#define cpu_to_le32(x) x
#define le32_to_cpu(x) x
#endif /* __BYTE_ORDER */

#endif /* SSI_PAL_TYPES_PLAT_H */
