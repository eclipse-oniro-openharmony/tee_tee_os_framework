/* **************************************************************
 *  Copyright 2014 (c) Discretix Technologies Ltd.              *
 *  This software is protected by copyright, international      *
 *  treaties and various patents. Any copy, reproduction or     *
 *  otherwise use of this software must be authorized in a      *
 *  license agreement and include this Copyright Notice and any *
 *  other notices specified in the license agreement.           *
 *  Any redistribution in binary form must be authorized in the *
 *  license agreement and include this Copyright Notice and     *
 *  any other notices specified in the license agreement and/or *
 *  in materials provided with the binary distribution.         *
 * ************************************************************* */

#ifndef __CC_ACL_H__
#define __CC_ACL_H__

#include "dx_pal_types.h"

/* *********************** Typedefs *************************** */
typedef enum {
    ACCESS_READ,
    ACCESS_READ_WRITE,
} AccessType_e;

/* ********************** Functions *************************** */

/* !
 * Checks if a pointer to a block of memory is valid in a given
 * platform. The platform implementation details should reside in
 * platform target domain.
 *
 * \param type Type of access.
 * \param addr User pointer to start of block to check
 * \param size Size of block to check
 *
 * \return uint32_t Returns DX_SUCCESS if the memory block may be valid,
 *         nonzero error if it is definitely invalid
 */
uint32_t DxCcAcl_IsBuffAccessOk(AccessType_e type, void *addr, size_t size);

#endif
