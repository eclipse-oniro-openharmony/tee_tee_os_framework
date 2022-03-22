/* ***************************************************************************
 * This confidential and proprietary software may be used only as authorized *
 * by a licensing agreement from ARM Israel.                                 *
 * Copyright (C) 2015 ARM Limited or its affiliates. All rights reserved.    *
 * The entire notice above must be reproduced on all authorized copies and   *
 * copies may only be made to the extent permitted by a licensing agreement  *
 * from ARM Israel.                                                          *
 * ************************************************************************** */

#ifndef _SSI_UTIL_ERROR_H
#define _SSI_UTIL_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

/* !
@file
@brief This module contains the definitions of the UTIL module errors.
*/

/* ******************** */
/* Util return codes   */
/* ******************** */

#define SASI_UTIL_OK 0x00UL

#define SASI_UTIL_MODULE_ERROR_BASE 0x80000000

#define SASI_UTIL_INVALID_KEY_TYPE               (SASI_UTIL_MODULE_ERROR_BASE + 0x00UL)
#define SASI_UTIL_DATA_IN_POINTER_INVALID_ERROR  (SASI_UTIL_MODULE_ERROR_BASE + 0x01UL)
#define SASI_UTIL_DATA_IN_SIZE_INVALID_ERROR     (SASI_UTIL_MODULE_ERROR_BASE + 0x02UL)
#define SASI_UTIL_DATA_OUT_POINTER_INVALID_ERROR (SASI_UTIL_MODULE_ERROR_BASE + 0x03UL)
#define SASI_UTIL_DATA_OUT_SIZE_INVALID_ERROR    (SASI_UTIL_MODULE_ERROR_BASE + 0x04UL)
#define SASI_UTIL_FATAL_ERROR                    (SASI_UTIL_MODULE_ERROR_BASE + 0x05UL)
#define SASI_UTIL_ILLEGAL_PARAMS_ERROR           (SASI_UTIL_MODULE_ERROR_BASE + 0x06UL)
#define SASI_UTIL_BAD_ADDR_ERROR                 (SASI_UTIL_MODULE_ERROR_BASE + 0x07UL)
#define SASI_UTIL_EK_DOMAIN_INVALID_ERROR        (SASI_UTIL_MODULE_ERROR_BASE + 0x08UL)
#define SASI_UTIL_KDR_INVALID_ERROR              (SASI_UTIL_MODULE_ERROR_BASE + 0x09UL)
#define SASI_UTIL_LCS_INVALID_ERROR              (SASI_UTIL_MODULE_ERROR_BASE + 0x0AUL)
#define SASI_UTIL_SESSION_KEY_ERROR              (SASI_UTIL_MODULE_ERROR_BASE + 0x0BUL)
#define SASI_UTIL_MUTEX_ERROR                    (SASI_UTIL_MODULE_ERROR_BASE + 0x0CUL)
#define SASI_UTIL_INVALID_USER_KEY_SIZE          (SASI_UTIL_MODULE_ERROR_BASE + 0x0DUL)
#define SASI_UTIL_ILLEGAL_LCS_FOR_OPERATION_ERR  (SASI_UTIL_MODULE_ERROR_BASE + 0x0EUL)

#ifdef __cplusplus
}
#endif

#endif /* _SSI_UTIL_ERROR_H */
